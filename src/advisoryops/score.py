"""Stage 4 of the pipeline: priority scoring with healthcare-aware dimensions.

Reads correlated issues and assigns a numeric score + priority label (P0–P3)
to each issue.  Two scoring versions are available:

v1 — keyword-only baseline
    Pure regex matching on title + summary + issue_id text.
    Fast and deterministic.  Used as the base for v2.
    Score ranges (tunable via PRIORITY_THRESHOLDS):
    P0 ≥ 150 · P1 ≥ 100 · P2 ≥ 60 · P3 < 60

v2 — healthcare-aware (default)
    Runs all v1 factors first, then adds five healthcare-specific dimensions:
    1. Source authority weight — CISA ICS-Medical (+20), ICS (+15), generic CISA (+10)
    2. Device context signals — infusion pump (+25), ventilator (+25), PACS (+15), EHR (+10)
    3. Patch feasibility — no patch (+20), EOL (+15), firmware (+10)
    4. Clinical impact — life-sustaining (+30), patient safety (+25), ICU (+20), PHI (+15)
    5. FDA risk class — Class III (+30), Class II (+10), Class I (+0)

Optional AI pass (``--ai-score``, v2 only):
    Issues where deterministic scoring found *no* device/clinical signals are
    sent to ``classify_healthcare_relevance`` (ai_score.py).  The AI result
    can add a score boost: medical_device +20, healthcare_it +15, adjacent +5.
    Issues with deterministic signals are skipped — no API cost for those.

Score explanation (``why`` list):
    Every scoring step appends a human-readable string to ``why`` so analysts
    can understand exactly why an issue got its score.  The final entry is
    always ``"priority: P<n> (score=<n>)"``.

Outputs:
  outputs/scored/issues_scored.jsonl  — all issues with score/priority/why/actions
  outputs/scored/alerts.jsonl         — filtered subset (≥ min_priority, ≤ top)
  outputs/scored/meta.json            — run metadata + counts
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    if not path.exists():
        raise FileNotFoundError(f"Input issues file not found: {path}")
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if isinstance(obj, dict):
                items.append(obj)
    return items


def _write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")


@dataclass(frozen=True)
class ScoreResult:
    score: int
    priority: str
    actions: List[str]
    why: List[str]
    unknowns: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# v1 scoring tables — keyword patterns (fixed in Phase 3 Task 3.1)
# ---------------------------------------------------------------------------

_KEYWORDS: List[Tuple[re.Pattern[str], int, str]] = [
    (re.compile(r"\bactively exploited\b", re.I), 40, "keyword: actively exploited (+40)"),
    (re.compile(r"\bknown exploited\b|\bkev\b", re.I), 80, "keyword: KEV/known exploited (+80)"),
    (re.compile(r"\bremote code execution\b|\brce\b", re.I), 30, "keyword: RCE (+30)"),
    (re.compile(r"\bauthentication bypass\b|\bauth bypass\b", re.I), 25, "keyword: auth bypass (+25)"),
    (re.compile(r"\bprivilege escalation\b|\bpriv esc\b", re.I), 20, "keyword: privilege escalation (+20)"),
    (re.compile(r"\barbitrary code\b|\bcode execution\b", re.I), 25, "keyword: code execution (+25)"),
    (re.compile(r"\bdata exfiltration\b|\bexfiltration\b", re.I), 15, "keyword: data exfiltration (+15)"),
    (re.compile(r"\binformation disclosure\b", re.I), 15, "keyword: information disclosure (+15)"),
    (re.compile(r"\bsql injection\b|\bsqli\b", re.I), 15, "keyword: SQLi (+15)"),
    (re.compile(r"\bdenial of service\b|\bdos\b", re.I), 5, "keyword: DoS (+5)"),
    (re.compile(r"\bproof of concept\b|\bpoc\b", re.I), 10, "keyword: PoC (+10)"),
]


# ---------------------------------------------------------------------------
# Tunable priority thresholds — adjust these to calibrate alert distribution
# ---------------------------------------------------------------------------
PRIORITY_THRESHOLDS = {
    "P0": 150,   # score >= 150  (KEV + healthcare stacked, or multiple critical signals)
    "P1": 100,   # score 100–149 (significant: KEV source, or strong healthcare context)
    "P2": 60,    # score 60–99   (moderate concern)
    "P3": 0,     # score < 60    (informational)
}


def _priority_from_score(score: int, thresholds: Optional[Dict[str, int]] = None) -> str:
    t = thresholds or PRIORITY_THRESHOLDS
    if score >= t["P0"]:
        return "P0"
    if score >= t["P1"]:
        return "P1"
    if score >= t["P2"]:
        return "P2"
    return "P3"


def _actions_for_priority(priority: str) -> List[str]:
    if priority == "P0":
        return ["notify", "ingest", "track"]
    if priority == "P1":
        return ["ingest", "track"]
    if priority == "P2":
        return ["track"]
    return ["log"]


def _priority_rank(p: str) -> int:
    m = {"P0": 3, "P1": 2, "P2": 1, "P3": 0}
    return m.get((p or "").strip().upper(), -1)


def score_issue(issue: Dict[str, Any]) -> ScoreResult:
    score = 0
    why: List[str] = []

    issue_type = (issue.get("issue_type") or "").strip().lower()
    issue_id = (issue.get("issue_id") or "").strip()

    if issue_type == "cve":
        score += 10
        why.append("base: issue_type=cve (+10)")
    else:
        score += 2
        why.append("base: issue_type!=cve (+2)")

    sources = issue.get("sources") or []
    src_text = " ".join(str(s) for s in sources).lower() if isinstance(sources, list) else str(sources).lower()
    if "kev" in src_text or "cisa-kev" in src_text:
        score += 80
        why.append("source: KEV source (+80)")

    title = str(issue.get("title") or "")
    summary = str(issue.get("summary") or "")
    text = f"{issue_id}\n{title}\n{summary}"

    for rx, pts, label in _KEYWORDS:
        if rx.search(text):
            score += pts
            why.append(label)

    links = issue.get("links") or []
    link_text = " ".join(str(l) for l in links).lower() if isinstance(links, list) else str(links).lower()
    if "nvd.nist.gov/vuln/detail/" in link_text:
        score += 5
        why.append("link: NVD detail present (+5)")

    priority = _priority_from_score(score)
    actions = _actions_for_priority(priority)
    why.append(f"priority: {priority} (score={score})")
    return ScoreResult(score=score, priority=priority, actions=actions, why=why)


# ---------------------------------------------------------------------------
# v2 scoring tables — healthcare context dimensions (Phase 3 Task 3.2)
# ---------------------------------------------------------------------------

# Dimension 1: Source authority weight
# Key: exact source_id prefix match; value: (points, label)
# Applied to the *highest-authority* source present (no double-counting).
_SOURCE_AUTHORITY_EXACT: List[Tuple[str, int, str]] = [
    ("cisa-icsma", 20, "source-authority: CISA ICS-Medical (+20)"),
    ("cisa-icsa",  15, "source-authority: CISA ICS (+15)"),
]
_SOURCE_AUTHORITY_CISA_GENERIC = (10, "source-authority: CISA generic (+10)")

# Dimension 2: Device context signals — life-critical > monitoring > imaging > general
_DEVICE_SIGNALS: List[Tuple[re.Pattern[str], int, str]] = [
    (
        re.compile(r"\binfusion pump\b|\binsulin pump\b|\bdrug pump\b|\biv pump\b", re.I),
        25,
        "device: infusion/drug pump (+25)",
    ),
    (
        re.compile(r"\bventilator\b|\brespir(ator|atory)\b|\blife support\b", re.I),
        25,
        "device: ventilator/life-support (+25)",
    ),
    (
        re.compile(r"\bdefibrillator\b|\baed\b|\bpacemaker\b|\bimplantable\b|\bcardiac implant\b", re.I),
        25,
        "device: cardiac implant/defibrillator (+25)",
    ),
    (
        re.compile(
            r"\bpatient monitor\b|\bcentral monitor\b|\bvital signs?\b|\becg\b|\bekg\b"
            r"|\bcardiac monitor\b|\bbedside monitor\b",
            re.I,
        ),
        20,
        "device: patient monitor (+20)",
    ),
    (
        re.compile(
            r"\bpacs\b|\bdicom\b|\bradiology\b|\bimaging\b|\bmri\b|\bct scan\b"
            r"|\bx.?ray\b|\bultrasound\b|\bpet scan\b|\bfluoroscop\b",
            re.I,
        ),
        15,
        "device: medical imaging/PACS (+15)",
    ),
    (
        re.compile(r"\behr\b|\bemr\b|\belectronic health record\b|\belectronic medical record\b", re.I),
        10,
        "device: EHR/EMR (+10)",
    ),
    (
        re.compile(r"\bhospital\b|\bclinic\b|\bmedical device\b|\bhealthcare\b|\bhealth care\b", re.I),
        10,
        "device: healthcare context (+10)",
    ),
]

# Dimension 3: Patch feasibility indicators — harder to fix = higher urgency
_PATCH_SIGNALS: List[Tuple[re.Pattern[str], int, str]] = [
    (
        re.compile(
            r"\bno patch\b|\bno fix\b|\bunpatched\b"
            r"|\bno (available )?(patch|fix|update)\b"
            r"|\bpatch (is )?not available\b",
            re.I,
        ),
        20,
        "patch: no patch available (+20)",
    ),
    (
        re.compile(
            r"\bend.of.life\b|\bend of support\b|\beol\b"
            r"|\bdecommissioned\b|\bno longer supported\b",
            re.I,
        ),
        15,
        "patch: end of life/decommissioned (+15)",
    ),
    (
        re.compile(r"\bvendor.managed\b|\bvendor patch\b|\bcontact vendor\b|\breach out.*vendor\b", re.I),
        10,
        "patch: vendor-managed remediation (+10)",
    ),
    (
        re.compile(r"\bfirmware\b", re.I),
        10,
        "patch: firmware update required (+10)",
    ),
]

# Dimension 4: Clinical impact indicators — patient harm potential
_CLINICAL_SIGNALS: List[Tuple[re.Pattern[str], int, str]] = [
    (
        re.compile(r"\blife.sustaining\b|\blife support\b", re.I),
        30,
        "clinical: life-sustaining impact (+30)",
    ),
    (
        re.compile(r"\bpatient safety\b", re.I),
        25,
        "clinical: patient safety (+25)",
    ),
    (
        re.compile(r"\bicu\b|\bintensive care\b|\bcritical care unit\b", re.I),
        20,
        "clinical: ICU/critical care (+20)",
    ),
    (
        re.compile(
            r"\bphi\b|\bprotected health information\b"
            r"|\bpatient (data|record|information)\b",
            re.I,
        ),
        15,
        "clinical: PHI/patient data (+15)",
    ),
    (
        re.compile(r"\bclinical\b", re.I),
        5,
        "clinical: clinical context (+5)",
    ),
]


def _score_fda_risk_class(issue: Dict[str, Any]) -> Tuple[int, List[str]]:
    """Calculate FDA risk class bonus.

    Calibrated against real healthcare corpus distribution:
    - Class III: +30 (promotes critical devices from P3 to P2, P2 to P1)
    - Class II: +10 (modest nudge, Class II is 72% of FDA recalls)
    - Class I:  +0  (genuinely low-risk devices, no bonus)
    - null:     +0  (don't fake certainty)
    """
    rc = issue.get("fda_risk_class")
    if rc == "3":
        return 30, ["fda-risk-class: Class III highest-risk device (+30)"]
    if rc == "2":
        return 10, ["fda-risk-class: Class II moderate-risk device (+10)"]
    return 0, []


def _score_kev_medical_device(issue: Dict[str, Any]) -> Tuple[int, List[str]]:
    """Highest priority signal: actively exploited medical device vulnerability.

    +40 bonus when a CVE is both in CISA's KEV catalog and affects a medical device.
    Stacks with existing KEV bonuses (+80 source, +80 keyword).
    """
    if issue.get("is_kev_medical_device"):
        return 40, ["kev-medical-device: actively exploited medical device (+40)"]
    return 0, []


def _score_source_authority(src_text: str) -> Tuple[int, str]:
    """Return the highest-authority source bonus for the given source string."""
    for prefix, pts, label in _SOURCE_AUTHORITY_EXACT:
        if prefix in src_text:
            return pts, label
    if "cisa-" in src_text and "kev" not in src_text:
        pts, label = _SOURCE_AUTHORITY_CISA_GENERIC
        return pts, label
    return 0, ""


def score_issue_v2(issue: Dict[str, Any], _weights=None) -> ScoreResult:
    """Healthcare-aware scorer (v2).

    Runs all v1 factors first, then adds five healthcare-specific dimensions:
      1. Source authority weight — tier-weight scaled from source_weights.json
      2. Device context signals (infusion pump, ventilator, PACS, etc.)
      3. Patch feasibility indicators (no patch, EOL, firmware)
      4. Clinical impact indicators (patient safety, life-sustaining, ICU)
      5. FDA risk class — Class III (+30), Class II (+10), Class I (+0)
      + Healthcare source bonus — +50 if any source is tier-1 medical-specific

    Scores are fully deterministic — same input always produces the same output.
    """
    from .source_weights import load_source_weights

    # Run v1 first to get the base keyword score + why list.
    # Strip the trailing "priority: ..." entry from v1.why because we will
    # recalculate priority after adding healthcare dimension points.
    v1 = score_issue(issue)
    score = v1.score
    why: List[str] = [w for w in v1.why if not w.startswith("priority:")]

    sources: List[str] = list(issue.get("sources") or [])

    title = str(issue.get("title") or "")
    summary = str(issue.get("summary") or "")
    issue_id = str(issue.get("issue_id") or "")
    text = f"{issue_id}\n{title}\n{summary}"

    # --- Dimension 1: Source authority (tier-weight scaled) ---
    weights = _weights if _weights is not None else load_source_weights()
    max_w = weights.max_weight(sources)
    if max_w > 0.0:
        auth_pts = round(weights.base_authority_points * max_w)
        tier_num = next(
            (weights.tier_for(s) for s in sources if weights.weight_for(s) == max_w),
            None,
        )
        tier_label = f"tier-{tier_num}" if tier_num else "unknown-tier"
        score += auth_pts
        why.append(f"source-authority: {tier_label} weight={max_w:.1f} (+{auth_pts})")

    # Healthcare tier-1 medical source bonus
    if weights.any_healthcare_medical(sources):
        score += weights.healthcare_bonus
        why.append(f"healthcare-source: tier-1 medical source (+{weights.healthcare_bonus})")

    # --- Dimension 2: Device context signals ---
    for rx, pts, label in _DEVICE_SIGNALS:
        if rx.search(text):
            score += pts
            why.append(label)

    # --- Dimension 3: Patch feasibility ---
    for rx, pts, label in _PATCH_SIGNALS:
        if rx.search(text):
            score += pts
            why.append(label)

    # --- Dimension 4: Clinical impact ---
    for rx, pts, label in _CLINICAL_SIGNALS:
        if rx.search(text):
            score += pts
            why.append(label)

    # --- Dimension 5: FDA risk class ---
    fda_pts, fda_why = _score_fda_risk_class(issue)
    if fda_pts:
        score += fda_pts
        why.extend(fda_why)

    priority = _priority_from_score(score)
    actions = _actions_for_priority(priority)
    why.append(f"priority: {priority} (score={score})")
    return ScoreResult(score=score, priority=priority, actions=actions, why=why)


def score_issues(
    *,
    in_issues: str = "outputs/correlate/issues.jsonl",
    out_root_scored: str = "outputs/scored",
    min_priority: str = "P1",
    top: int = 50,
    scoring_version: str = "v2",
    ai_score: bool = False,
    ai_score_model: str = "gpt-4o-mini",
    ai_score_cache_root: str = "outputs/ai_cache",
    _ai_classify_fn=None,
    _weights=None,
):
    started_at = _utc_now_iso()

    min_priority_u = (min_priority or "P3").strip().upper()
    if min_priority_u not in ("P0", "P1", "P2", "P3"):
        raise ValueError("--min-priority must be one of P0,P1,P2,P3")
    if top < 0:
        raise ValueError("--top must be >= 0")

    scoring_version_u = (scoring_version or "v2").strip().lower()
    if scoring_version_u not in ("v1", "v2"):
        raise ValueError("--scoring-version must be v1 or v2")
    _scorer = score_issue_v2 if scoring_version_u == "v2" else score_issue

    in_path = Path(in_issues)
    out_root = Path(out_root_scored)
    out_root.mkdir(parents=True, exist_ok=True)

    issues = _read_jsonl(in_path)

    # Load source weights once for the whole run (injected in tests via _weights)
    from .source_weights import load_source_weights as _load_sw
    _sw = _weights if _weights is not None else _load_sw()

    scored_rows: List[Dict[str, Any]] = []
    for iss in issues:
        res = _scorer(iss, _weights=_sw)
        row = dict(iss)
        row["score"] = res.score
        row["priority"] = res.priority
        row["actions"] = res.actions
        row["why"] = list(res.why)
        row["unknowns"] = list(res.unknowns)

        # Source authority provenance fields
        sources: List[str] = list(row.get("sources") or [])
        max_w = _sw.max_weight(sources, default=0.0)
        if max_w > 0.0:
            best_src = max(sources, key=lambda s: _sw.weight_for(s, 0.0))
            effective_w = max_w
        else:
            # No recognised source — neutral weight, use first source as label
            best_src = sources[0] if sources else ""
            effective_w = 0.5
        row["source_authority_weight"] = round(effective_w, 4)
        row["highest_authority_source"] = best_src

        scored_rows.append(row)

    # --- Optional AI healthcare classification pass ---
    ai_classify_count = 0
    if ai_score and scoring_version_u == "v2":
        from .ai_score import classify_healthcare_relevance

        _AI_BOOST = {
            "medical_device": (20, "ai-classify: medical_device (+20)"),
            "healthcare_it": (15, "ai-classify: healthcare_it (+15)"),
            "healthcare_adjacent": (5, "ai-classify: healthcare_adjacent (+5)"),
        }

        for row in scored_rows:
            # Skip if deterministic scoring already found device/clinical signals
            why = row.get("why") or []
            has_hc_signal = any(
                w.startswith("device:") or w.startswith("clinical:") or w.startswith("source-authority:")
                for w in why
            )
            if has_hc_signal:
                row["healthcare_category"] = "deterministic"
                continue

            clf = classify_healthcare_relevance(
                row,
                model=ai_score_model,
                cache_root=ai_score_cache_root,
                _call_fn=_ai_classify_fn,
            )
            ai_classify_count += 1
            row["healthcare_category"] = clf.category
            row["generated_by"] = "ai"

            # --- Wire ALL trust/provenance fields from AI classification ---
            if clf.handling_warnings:
                row.setdefault("handling_warnings", []).extend(clf.handling_warnings)
            if clf.evidence_gaps:
                row.setdefault("evidence_gaps", []).extend(clf.evidence_gaps)
                # evidence_gaps also populate unknowns (what we don't know)
                row.setdefault("unknowns", []).extend(clf.evidence_gaps)
            if clf.extracted_facts:
                row["extracted_facts"] = clf.extracted_facts
            if clf.inferred_facts:
                row["inferred_facts"] = clf.inferred_facts
            if clf.confidence_by_field:
                row["confidence_by_field"] = clf.confidence_by_field
            if clf.evidence_sources:
                row["evidence_sources"] = clf.evidence_sources
            row["insufficient_evidence"] = clf.insufficient_evidence
            row["classification"] = {
                "category": clf.category,
                "confidence": clf.confidence,
                "reasoning": clf.reasoning,
                "device_types": clf.device_types,
            }

            if clf.confidence >= 0.70 and clf.category in _AI_BOOST:
                pts, label = _AI_BOOST[clf.category]
                row["score"] = row["score"] + pts
                row["why"].append(label)
                # Recalculate priority with updated score
                new_priority = _priority_from_score(row["score"])
                # Strip old priority entry and replace
                row["why"] = [w for w in row["why"] if not w.startswith("priority:")]
                row["why"].append(f"priority: {new_priority} (score={row['score']})")
                row["priority"] = new_priority
                row["actions"] = _actions_for_priority(new_priority)

        print(f"  AI classify: {ai_classify_count} issues sent to AI classifier")

    scored_rows.sort(key=lambda r: (-int(r.get("score", 0)), str(r.get("issue_id", ""))))

    min_rank = _priority_rank(min_priority_u)
    alerts = [r for r in scored_rows if _priority_rank(str(r.get("priority", ""))) >= min_rank]
    if top > 0:
        alerts = alerts[:top]

    out_scored = out_root / "issues_scored.jsonl"
    out_alerts = out_root / "alerts.jsonl"
    out_meta = out_root / "meta.json"

    _write_jsonl(out_scored, scored_rows)
    _write_jsonl(out_alerts, alerts)

    meta = {
        "started_at": started_at,
        "finished_at": _utc_now_iso(),
        "inputs": {"in_issues": str(in_path)},
        "params": {
            "min_priority": min_priority_u,
            "top": int(top),
            "scoring_version": scoring_version_u,
            "ai_score": bool(ai_score),
            "ai_score_model": ai_score_model if ai_score else None,
        },
        "outputs": {
            "issues_scored_jsonl": str(out_scored),
            "alerts_jsonl": str(out_alerts),
            "meta_json": str(out_meta),
        },
        "counts": {
            "issues_in": len(issues),
            "issues_scored": len(scored_rows),
            "alerts": len(alerts),
            "ai_classified": ai_classify_count,
        },
    }
    out_meta.write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print("Score summary:")
    print(f"  Input:        {in_path}")
    print(f"  Scored:       {out_scored}")
    print(f"  Alerts:       {out_alerts}")
    print(f"  Meta:         {out_meta}")
    print(f"  Issues:       {len(scored_rows)}")
    print(f"  Alerts:       {len(alerts)}  (min={min_priority_u}, top={top})")

    return out_scored, out_alerts, out_meta
