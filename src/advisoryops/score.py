from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


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


_KEYWORDS: List[Tuple[re.Pattern[str], int, str]] = [
    (re.compile(r"\\bactively exploited\\b", re.I), 40, "keyword: actively exploited (+40)"),
    (re.compile(r"\\bknown exploited\\b|\\bkev\\b", re.I), 80, "keyword: KEV/known exploited (+80)"),
    (re.compile(r"\\bremote code execution\\b|\\brce\\b", re.I), 30, "keyword: RCE (+30)"),
    (re.compile(r"\\bauthentication bypass\\b|\\bauth bypass\\b", re.I), 25, "keyword: auth bypass (+25)"),
    (re.compile(r"\\bprivilege escalation\\b|\\bpriv esc\\b", re.I), 20, "keyword: privilege escalation (+20)"),
    (re.compile(r"\\barbitrary code\\b|\\bcode execution\\b", re.I), 25, "keyword: code execution (+25)"),
    (re.compile(r"\\bdata exfiltration\\b|\\bexfiltration\\b", re.I), 15, "keyword: data exfiltration (+15)"),
    (re.compile(r"\\binformation disclosure\\b", re.I), 15, "keyword: information disclosure (+15)"),
    (re.compile(r"\\bsql injection\\b|\\bsqli\\b", re.I), 15, "keyword: SQLi (+15)"),
    (re.compile(r"\\bdenial of service\\b|\\bdos\\b", re.I), 5, "keyword: DoS (+5)"),
    (re.compile(r"\\bproof of concept\\b|\\bpoc\\b", re.I), 10, "keyword: PoC (+10)"),
]


def _priority_from_score(score: int) -> str:
    if score >= 100:
        return "P0"
    if score >= 70:
        return "P1"
    if score >= 40:
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
    text = f"{issue_id}\\n{title}\\n{summary}"

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


def score_issues(
    *,
    in_issues: str = "outputs/correlate/issues.jsonl",
    out_root_scored: str = "outputs/scored",
    min_priority: str = "P1",
    top: int = 50,
):
    started_at = _utc_now_iso()

    min_priority_u = (min_priority or "P3").strip().upper()
    if min_priority_u not in ("P0", "P1", "P2", "P3"):
        raise ValueError("--min-priority must be one of P0,P1,P2,P3")
    if top < 0:
        raise ValueError("--top must be >= 0")

    in_path = Path(in_issues)
    out_root = Path(out_root_scored)
    out_root.mkdir(parents=True, exist_ok=True)

    issues = _read_jsonl(in_path)

    scored_rows: List[Dict[str, Any]] = []
    for iss in issues:
        res = score_issue(iss)
        row = dict(iss)
        row["score"] = res.score
        row["priority"] = res.priority
        row["actions"] = res.actions
        row["why"] = res.why
        scored_rows.append(row)

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
        "params": {"min_priority": min_priority_u, "top": int(top)},
        "outputs": {
            "issues_scored_jsonl": str(out_scored),
            "alerts_jsonl": str(out_alerts),
            "meta_json": str(out_meta),
        },
        "counts": {"issues_in": len(issues), "issues_scored": len(scored_rows), "alerts": len(alerts)},
    }
    out_meta.write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\\n", encoding="utf-8")

    print("Score summary:")
    print(f"  Input:        {in_path}")
    print(f"  Scored:       {out_scored}")
    print(f"  Alerts:       {out_alerts}")
    print(f"  Meta:         {out_meta}")
    print(f"  Issues:       {len(scored_rows)}")
    print(f"  Alerts:       {len(alerts)}  (min={min_priority_u}, top={top})")

    return out_scored, out_alerts, out_meta
