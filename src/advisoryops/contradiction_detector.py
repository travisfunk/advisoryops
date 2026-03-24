"""Deterministic cross-source contradiction detection (Task 8.5).

For each correlated issue with 2+ contributing sources, compare key fields
across signal texts to find agreements, contradictions, and unique contributions.

This is the v1 deterministic implementation — no AI calls.  It extracts
severity keywords, CVE mentions, and patch-status indicators from per-source
signal text and compares them.

Main entry point::

    from advisoryops.contradiction_detector import detect_contradictions

    issues = [...]  # list of issue dicts from correlate/score
    annotated = detect_contradictions(issues)
    # each issue now has a ``source_consensus`` dict

``source_consensus`` schema::

    {
      "agreed":   ["vendor is Philips", "affects IntelliSpace"],
      "contradicted": [
        {"field": "severity", "source_a": "CISA says Critical", "source_b": "vendor says High"}
      ],
      "unique_contributions": {
        "cisa-icsma": ["provides CVE detail"],
        "claroty-team82": ["provides exploit PoC reference"]
      }
    }
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Set, Tuple


# ---------------------------------------------------------------------------
# Extraction helpers — pull structured facts from free-text signal fields
# ---------------------------------------------------------------------------

_SEVERITY_RE = re.compile(
    r"\b(critical|high|medium|moderate|low|informational)\b",
    re.IGNORECASE,
)

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

_PATCH_INDICATORS: List[Tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bno (available )?(patch|fix|update)\b|\bunpatched\b|\bno fix\b", re.I), "no_patch"),
    (re.compile(r"\bpatch(ed| available| released)\b|\bfix(ed| available| released)\b|\bupdate available\b", re.I), "patch_available"),
    (re.compile(r"\bworkaround\b|\bmitigat(e|ion)\b", re.I), "workaround"),
]

_EXPLOIT_INDICATORS: List[Tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bactively exploited\b|\bin the wild\b|\bknown exploit\b", re.I), "actively_exploited"),
    (re.compile(r"\bproof of concept\b|\bpoc\b", re.I), "poc_available"),
]


def _signal_text(sig: Dict[str, Any]) -> str:
    """Concatenate title + summary + guid from a signal dict for text search."""
    parts = [
        str(sig.get("title") or ""),
        str(sig.get("summary") or ""),
        str(sig.get("guid") or ""),
    ]
    return " ".join(parts)


def _extract_severities(text: str) -> Set[str]:
    """Extract unique severity labels from text, normalized to lower case."""
    found = set()
    for m in _SEVERITY_RE.finditer(text):
        sev = m.group(1).lower()
        if sev == "moderate":
            sev = "medium"
        found.add(sev)
    return found


def _extract_cves(text: str) -> Set[str]:
    return {m.upper() for m in _CVE_RE.findall(text)}


def _extract_patch_status(text: str) -> Set[str]:
    found = set()
    for rx, label in _PATCH_INDICATORS:
        if rx.search(text):
            found.add(label)
    return found


def _extract_exploit_status(text: str) -> Set[str]:
    found = set()
    for rx, label in _EXPLOIT_INDICATORS:
        if rx.search(text):
            found.add(label)
    return found


# ---------------------------------------------------------------------------
# Per-source fact extraction
# ---------------------------------------------------------------------------

def _source_facts(signals: List[Dict[str, Any]], source_id: str) -> Dict[str, Any]:
    """Gather extracted facts for all signals from a single source."""
    severities: Set[str] = set()
    cves: Set[str] = set()
    patch_status: Set[str] = set()
    exploit_status: Set[str] = set()
    links: Set[str] = set()

    for sig in signals:
        if str(sig.get("source") or "") != source_id:
            continue
        text = _signal_text(sig)
        severities.update(_extract_severities(text))
        cves.update(_extract_cves(text))
        patch_status.update(_extract_patch_status(text))
        exploit_status.update(_extract_exploit_status(text))
        link = str(sig.get("link") or "")
        if link:
            links.add(link)

    return {
        "severities": severities,
        "cves": cves,
        "patch_status": patch_status,
        "exploit_status": exploit_status,
        "links": links,
    }


# ---------------------------------------------------------------------------
# Consensus builder
# ---------------------------------------------------------------------------

def _build_consensus(
    source_facts: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    """Compare facts across sources and produce the source_consensus dict."""
    agreed: List[str] = []
    contradicted: List[Dict[str, str]] = []
    unique_contributions: Dict[str, List[str]] = {}

    sources = sorted(source_facts.keys())

    # --- Severity comparison ---
    all_sevs = {src: facts["severities"] for src, facts in source_facts.items()}
    non_empty_sevs = {src: s for src, s in all_sevs.items() if s}

    if len(non_empty_sevs) >= 2:
        union_sevs = set()
        for s in non_empty_sevs.values():
            union_sevs.update(s)
        intersection_sevs = set.intersection(*non_empty_sevs.values())

        if intersection_sevs:
            agreed.append(f"severity: {', '.join(sorted(intersection_sevs))}")

        # Find disagreements — sources that mention different severity levels
        sev_sources = sorted(non_empty_sevs.keys())
        for i in range(len(sev_sources)):
            for j in range(i + 1, len(sev_sources)):
                sa, sb = sev_sources[i], sev_sources[j]
                diff_a = non_empty_sevs[sa] - non_empty_sevs[sb]
                diff_b = non_empty_sevs[sb] - non_empty_sevs[sa]
                if diff_a or diff_b:
                    contradicted.append({
                        "field": "severity",
                        "source_a": f"{sa} says {', '.join(sorted(non_empty_sevs[sa]))}",
                        "source_b": f"{sb} says {', '.join(sorted(non_empty_sevs[sb]))}",
                    })
    elif len(non_empty_sevs) == 1:
        src, sevs = next(iter(non_empty_sevs.items()))
        unique_contributions.setdefault(src, []).append(
            f"provides severity: {', '.join(sorted(sevs))}"
        )

    # --- CVE comparison ---
    all_cves = {src: facts["cves"] for src, facts in source_facts.items()}
    non_empty_cves = {src: c for src, c in all_cves.items() if c}

    if len(non_empty_cves) >= 2:
        intersection_cves = set.intersection(*non_empty_cves.values())
        if intersection_cves:
            agreed.append(f"CVEs: {', '.join(sorted(intersection_cves))}")

        # Unique CVEs per source
        for src, cves in sorted(non_empty_cves.items()):
            others = set()
            for other_src, other_cves in non_empty_cves.items():
                if other_src != src:
                    others.update(other_cves)
            unique = cves - others
            if unique:
                unique_contributions.setdefault(src, []).append(
                    f"unique CVEs: {', '.join(sorted(unique))}"
                )
    elif len(non_empty_cves) == 1:
        src, cves = next(iter(non_empty_cves.items()))
        unique_contributions.setdefault(src, []).append(
            f"provides CVE detail: {', '.join(sorted(cves))}"
        )

    # --- Patch status comparison ---
    all_patch = {src: facts["patch_status"] for src, facts in source_facts.items()}
    non_empty_patch = {src: p for src, p in all_patch.items() if p}

    if len(non_empty_patch) >= 2:
        intersection_patch = set.intersection(*non_empty_patch.values())
        if intersection_patch:
            agreed.append(f"patch status: {', '.join(sorted(intersection_patch))}")

        # Contradictions: one says patch_available, another says no_patch
        patch_srcs = sorted(non_empty_patch.keys())
        for i in range(len(patch_srcs)):
            for j in range(i + 1, len(patch_srcs)):
                sa, sb = patch_srcs[i], patch_srcs[j]
                pa, pb = non_empty_patch[sa], non_empty_patch[sb]
                if ("patch_available" in pa and "no_patch" in pb) or \
                   ("no_patch" in pa and "patch_available" in pb):
                    contradicted.append({
                        "field": "patch_status",
                        "source_a": f"{sa} says {', '.join(sorted(pa))}",
                        "source_b": f"{sb} says {', '.join(sorted(pb))}",
                    })
    elif len(non_empty_patch) == 1:
        src, patches = next(iter(non_empty_patch.items()))
        unique_contributions.setdefault(src, []).append(
            f"provides patch info: {', '.join(sorted(patches))}"
        )

    # --- Exploit status comparison ---
    all_exploit = {src: facts["exploit_status"] for src, facts in source_facts.items()}
    non_empty_exploit = {src: e for src, e in all_exploit.items() if e}

    if len(non_empty_exploit) >= 2:
        intersection_exploit = set.intersection(*non_empty_exploit.values())
        if intersection_exploit:
            agreed.append(f"exploit status: {', '.join(sorted(intersection_exploit))}")
    elif len(non_empty_exploit) == 1:
        src, exploits = next(iter(non_empty_exploit.items()))
        unique_contributions.setdefault(src, []).append(
            f"provides exploit info: {', '.join(sorted(exploits))}"
        )

    # --- Unique links per source ---
    all_links = {src: facts["links"] for src, facts in source_facts.items()}
    if len(all_links) >= 2:
        for src in sources:
            others_links: Set[str] = set()
            for other_src, other_links in all_links.items():
                if other_src != src:
                    others_links.update(other_links)
            unique_links = all_links.get(src, set()) - others_links
            if unique_links:
                unique_contributions.setdefault(src, []).append(
                    f"unique links ({len(unique_links)})"
                )

    return {
        "agreed": sorted(agreed),
        "contradicted": contradicted,
        "unique_contributions": {k: sorted(v) for k, v in sorted(unique_contributions.items())},
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_contradictions(
    issues: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Annotate each multi-source issue with a ``source_consensus`` dict.

    Single-source issues get an empty consensus structure.
    Issues are modified in place and also returned.

    Returns the annotated issue list and a summary dict with counts.
    """
    multi_source_count = 0
    contradiction_count = 0

    for issue in issues:
        sources = list(issue.get("sources") or [])
        signals = list(issue.get("signals") or [])

        if len(sources) < 2:
            issue["source_consensus"] = {
                "agreed": [],
                "contradicted": [],
                "unique_contributions": {},
            }
            continue

        multi_source_count += 1

        # Extract facts per source from individual signals
        facts_by_source = {}
        for src in sources:
            facts_by_source[src] = _source_facts(signals, src)

        # Enrich with issue-level text (title + summary) which contains
        # merged content from all sources.  Extract facts from this combined
        # text and merge into each source's fact set so that "agreed" fields
        # get populated even when individual RSS signals are sparse.
        issue_text = f"{issue.get('title', '')} {issue.get('summary', '')}"
        if issue_text.strip():
            shared_sevs = _extract_severities(issue_text)
            shared_cves = _extract_cves(issue_text)
            shared_patch = _extract_patch_status(issue_text)
            shared_exploit = _extract_exploit_status(issue_text)
            for src in sources:
                facts_by_source[src]["severities"].update(shared_sevs)
                facts_by_source[src]["cves"].update(shared_cves)
                facts_by_source[src]["patch_status"].update(shared_patch)
                facts_by_source[src]["exploit_status"].update(shared_exploit)

        consensus = _build_consensus(facts_by_source)
        issue["source_consensus"] = consensus

        if consensus["contradicted"]:
            contradiction_count += 1

    return issues


def detect_contradictions_with_summary(
    issues: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Like detect_contradictions but also returns a summary dict."""
    annotated = detect_contradictions(issues)
    multi_source = sum(1 for i in annotated if len(i.get("sources") or []) >= 2)
    contradictions = sum(1 for i in annotated if i.get("source_consensus", {}).get("contradicted"))
    summary = {
        "total_issues": len(annotated),
        "multi_source_issues": multi_source,
        "issues_with_contradictions": contradictions,
    }
    return annotated, summary
