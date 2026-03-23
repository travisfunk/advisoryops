"""Deterministic what-changed tracker between pipeline runs (Task 8.7).

Compares the current scored pipeline output against a previous run's snapshot
and produces a list of change records describing what moved.

Diffed fields: severity (priority), score, source count, CVE list, patch
status keywords in title/summary.

Output: a list of change dicts, each with::

    {
      "issue_id":       "CVE-2024-1234",
      "change_type":    "severity_changed|new_issue|removed_issue|score_changed|new_source|cve_added|patch_status_changed",
      "summary":        "Priority upgraded from P2 to P1",
      "detected_at":    "2026-03-23T...",
      "previous_value": "P2",
      "new_value":      "P1"
    }

Main entry point::

    from advisoryops.change_tracker import detect_changes, write_changes

    changes = detect_changes(current_issues, previous_issues)
    write_changes(changes, Path("outputs/community_public/changes.jsonl"))
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


_PATCH_AVAILABLE_RE = re.compile(
    r"(?<!\bno )\bpatch(ed| available| released)\b|\bfix(ed| available| released)\b|\bupdate available\b",
    re.I,
)
_NO_PATCH_RE = re.compile(
    r"\bno (available )?(patch|fix|update)\b|\bunpatched\b|\bno fix\b",
    re.I,
)


def _patch_status(issue: Dict[str, Any]) -> str:
    """Infer patch status from title + summary text."""
    text = f"{issue.get('title', '')} {issue.get('summary', '')}"
    has_patch = bool(_PATCH_AVAILABLE_RE.search(text))
    no_patch = bool(_NO_PATCH_RE.search(text))
    if has_patch and not no_patch:
        return "patch_available"
    if no_patch and not has_patch:
        return "no_patch"
    if has_patch and no_patch:
        return "mixed"
    return "unknown"


def detect_changes(
    current_issues: List[Dict[str, Any]],
    previous_issues: List[Dict[str, Any]],
    *,
    detected_at: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Compare current vs previous issue lists and return change records.

    Parameters
    ----------
    current_issues : list of issue dicts (scored or correlated)
    previous_issues : list of issue dicts from the previous run
    detected_at : ISO timestamp override (default: now)

    Returns
    -------
    List of change record dicts.
    """
    ts = detected_at or _utc_now_iso()
    changes: List[Dict[str, Any]] = []

    prev_by_id = {i["issue_id"]: i for i in previous_issues}
    curr_by_id = {i["issue_id"]: i for i in current_issues}

    prev_ids = set(prev_by_id.keys())
    curr_ids = set(curr_by_id.keys())

    # New issues
    for iid in sorted(curr_ids - prev_ids):
        iss = curr_by_id[iid]
        changes.append({
            "issue_id": iid,
            "change_type": "new_issue",
            "summary": f"New issue detected: {iss.get('title', '')[:80]}",
            "detected_at": ts,
            "previous_value": None,
            "new_value": iid,
        })

    # Removed issues
    for iid in sorted(prev_ids - curr_ids):
        changes.append({
            "issue_id": iid,
            "change_type": "removed_issue",
            "summary": f"Issue no longer present in pipeline output",
            "detected_at": ts,
            "previous_value": iid,
            "new_value": None,
        })

    # Changed issues
    for iid in sorted(curr_ids & prev_ids):
        curr = curr_by_id[iid]
        prev = prev_by_id[iid]

        # Priority / severity change
        curr_pri = curr.get("priority", "")
        prev_pri = prev.get("priority", "")
        if curr_pri and prev_pri and curr_pri != prev_pri:
            changes.append({
                "issue_id": iid,
                "change_type": "severity_changed",
                "summary": f"Priority changed from {prev_pri} to {curr_pri}",
                "detected_at": ts,
                "previous_value": prev_pri,
                "new_value": curr_pri,
            })

        # Score change (threshold: delta >= 10 to avoid noise)
        curr_score = curr.get("score", 0)
        prev_score = prev.get("score", 0)
        if abs(curr_score - prev_score) >= 10:
            changes.append({
                "issue_id": iid,
                "change_type": "score_changed",
                "summary": f"Score changed from {prev_score} to {curr_score}",
                "detected_at": ts,
                "previous_value": str(prev_score),
                "new_value": str(curr_score),
            })

        # New sources
        curr_sources = set(curr.get("sources") or [])
        prev_sources = set(prev.get("sources") or [])
        new_sources = curr_sources - prev_sources
        if new_sources:
            changes.append({
                "issue_id": iid,
                "change_type": "new_source",
                "summary": f"New source(s) reporting: {', '.join(sorted(new_sources))}",
                "detected_at": ts,
                "previous_value": str(sorted(prev_sources)),
                "new_value": str(sorted(curr_sources)),
            })

        # New CVEs added
        curr_cves = set(curr.get("cves") or [])
        prev_cves = set(prev.get("cves") or [])
        new_cves = curr_cves - prev_cves
        if new_cves:
            changes.append({
                "issue_id": iid,
                "change_type": "cve_added",
                "summary": f"New CVE(s) associated: {', '.join(sorted(new_cves))}",
                "detected_at": ts,
                "previous_value": str(sorted(prev_cves)),
                "new_value": str(sorted(curr_cves)),
            })

        # Patch status change
        curr_patch = _patch_status(curr)
        prev_patch = _patch_status(prev)
        if curr_patch != prev_patch and curr_patch != "unknown" and prev_patch != "unknown":
            direction = "released" if curr_patch == "patch_available" else "reverted"
            changes.append({
                "issue_id": iid,
                "change_type": "patch_status_changed",
                "summary": f"Patch status {direction}: {prev_patch} → {curr_patch}",
                "detected_at": ts,
                "previous_value": prev_patch,
                "new_value": curr_patch,
            })

    return changes


def load_snapshot(path: Path) -> List[Dict[str, Any]]:
    """Load a JSONL snapshot file."""
    if not path.exists():
        return []
    items: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            items.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return items


def write_changes(changes: List[Dict[str, Any]], path: Path) -> Path:
    """Write change records to a JSONL file (append mode)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as f:
        for c in changes:
            f.write(json.dumps(c, ensure_ascii=False, sort_keys=True) + "\n")
    return path


def save_snapshot(issues: List[Dict[str, Any]], path: Path) -> Path:
    """Save current issues as a snapshot for the next run's comparison."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for iss in issues:
            f.write(json.dumps(iss, ensure_ascii=False, sort_keys=True) + "\n")
    return path
