#!/usr/bin/env python3
"""Re-run healthcare_filter classification against the existing corpus.

Loads the already-emitted JSON artifacts in ``outputs/community_public/``,
re-runs ``classify_healthcare_category`` on every healthcare-relevant
issue, writes the updated artifacts back in place, and then calls
``_publish_to_docs`` to copy them into ``docs/``.

No API calls, no AI, no pipeline run. Deterministic and free — the
classifier is pure Python over already-available fields.

Usage:
    python scripts/retag_corpus.py
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

from advisoryops.community_build import _publish_to_docs
from advisoryops.healthcare_filter import classify_healthcare_category


REPO_ROOT = Path(__file__).resolve().parent.parent
COMMUNITY_ROOT = REPO_ROOT / "outputs" / "community_public"


def _retag_issue_list(issues: List[Dict[str, Any]]) -> Counter:
    """Reclassify every healthcare_relevant issue in place. Return counts."""
    counts: Counter = Counter()
    for issue in issues:
        if issue.get("healthcare_relevant"):
            issue["healthcare_category"] = classify_healthcare_category(issue)
            counts[issue["healthcare_category"]] += 1
        else:
            counts["not_healthcare"] += 1
    return counts


def _retag_json_file(path: Path) -> Counter:
    if not path.exists():
        print(f"  skipped (missing): {path.name}")
        return Counter()
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "issues" in data:
        issues = data["issues"]
        before = Counter(i.get("healthcare_category") for i in issues if i.get("healthcare_relevant"))
        after = _retag_issue_list(issues)
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    elif isinstance(data, list):
        before = Counter(i.get("healthcare_category") for i in data if i.get("healthcare_relevant"))
        after = _retag_issue_list(data)
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    else:
        print(f"  skipped (unexpected shape): {path.name}")
        return Counter()
    print(f"  {path.name}: {sum(after.values())} rows reclassified")
    print(f"    before: {dict(before)}")
    print(f"    after:  {dict(after)}")
    return after


def _retag_jsonl_file(path: Path) -> Counter:
    if not path.exists():
        print(f"  skipped (missing): {path.name}")
        return Counter()
    issues = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    before = Counter(i.get("healthcare_category") for i in issues if i.get("healthcare_relevant"))
    after = _retag_issue_list(issues)
    with path.open("w", encoding="utf-8") as fh:
        for issue in issues:
            fh.write(json.dumps(issue, ensure_ascii=False))
            fh.write("\n")
    print(f"  {path.name}: {sum(after.values())} rows reclassified")
    print(f"    before: {dict(before)}")
    print(f"    after:  {dict(after)}")
    return after


def main() -> None:
    if not COMMUNITY_ROOT.exists():
        raise SystemExit(f"Community root does not exist: {COMMUNITY_ROOT}")

    print(f"Re-tagging corpus at {COMMUNITY_ROOT}")
    print()

    _retag_json_file(COMMUNITY_ROOT / "feed_latest.json")
    _retag_json_file(COMMUNITY_ROOT / "feed_healthcare.json")
    _retag_jsonl_file(COMMUNITY_ROOT / "issues_public.jsonl")

    print()
    print("Copying to docs/...")
    _publish_to_docs(COMMUNITY_ROOT, REPO_ROOT)


if __name__ == "__main__":
    main()
