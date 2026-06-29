"""Recommendation feedback recorder and loader.

Provides a simple append-only feedback mechanism for analysts to flag
recommendation quality issues.  Feedback is stored in JSONL format at
``outputs/feedback.jsonl`` by default.

Usage::

    from advisoryops.feedback import record_feedback, load_feedback

    record_feedback("CVE-2024-1234", "SEGMENTATION_VLAN_ISOLATION", "incorrect",
                    comment="Vendor says this doesn't apply to our firmware version")

    entries = load_feedback(issue_id="CVE-2024-1234")

Feedback types: incorrect, too_aggressive, too_conservative, missing_context, helpful
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

FEEDBACK_TYPES = frozenset({
    "incorrect",
    "too_aggressive",
    "too_conservative",
    "missing_context",
    "helpful",
})

_DEFAULT_PATH = Path("outputs/feedback.jsonl")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def record_feedback(
    issue_id: str,
    recommendation_id: str,
    feedback_type: str,
    *,
    comment: str = "",
    path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Append a feedback entry to the JSONL file.

    Args:
        issue_id: The issue being commented on.
        recommendation_id: Pattern ID or recommendation identifier.
        feedback_type: One of FEEDBACK_TYPES.
        comment: Optional free-text comment.
        path: Override output path (default: outputs/feedback.jsonl).

    Returns:
        The recorded entry dict.

    Raises:
        ValueError: if feedback_type is not in FEEDBACK_TYPES.
    """
    if feedback_type not in FEEDBACK_TYPES:
        raise ValueError(
            f"Invalid feedback_type {feedback_type!r}. "
            f"Must be one of: {sorted(FEEDBACK_TYPES)}"
        )

    entry: Dict[str, Any] = {
        "issue_id": issue_id,
        "recommendation_id": recommendation_id,
        "feedback_type": feedback_type,
        "comment": comment,
        "timestamp": _utc_now_iso(),
    }

    out = path or _DEFAULT_PATH
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")

    return entry


def load_feedback(
    issue_id: Optional[str] = None,
    *,
    path: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    """Read feedback entries, optionally filtered by issue_id.

    Args:
        issue_id: If provided, only return entries for this issue.
        path: Override input path (default: outputs/feedback.jsonl).

    Returns:
        List of feedback entry dicts.
    """
    src = path or _DEFAULT_PATH
    if not src.exists():
        return []

    entries: List[Dict[str, Any]] = []
    for line in src.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if issue_id and obj.get("issue_id") != issue_id:
            continue
        entries.append(obj)
    return entries
