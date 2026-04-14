"""Part 2: examine the 178 FDA-derived MD issues that DO NOT have a Z-NNNN
recall number in their title. What sources are they from? Is there another
way to identify their cache records?"""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FEED = REPO / "docs" / "feed_latest.json"
ENF_CACHE = REPO / "outputs" / "fda_safety_comms_cache"
OPENFDA_CACHE = REPO / "outputs" / "openfda_cache"

FDA_SOURCES = {
    "openfda-recalls-historical",
    "openfda-device-recalls",
    "openfda-device-events",
    "fda-medwatch",
    "fda-safety-comms-historical",
}
RECALL_RE = re.compile(r"\bZ-\d{4}-\d{4}\b", re.IGNORECASE)


def has_fda_source(issue):
    return bool(set(issue.get("sources") or []) & FDA_SOURCES)


def main():
    with FEED.open(encoding="utf-8") as f:
        issues = json.load(f)
    md = [i for i in issues if i.get("healthcare_category") == "medical_device"]
    fda_md = [i for i in md if has_fda_source(i)]

    no_recall = [i for i in fda_md if not RECALL_RE.search(str(i.get("title") or ""))]
    print(f"FDA-derived MD issues with no Z-NNNN in title: {len(no_recall)}\n")

    # Break down by source
    src_counter = Counter()
    for issue in no_recall:
        srcs = tuple(sorted(issue.get("sources") or []))
        src_counter[srcs] += 1
    print("=== Source combinations ===")
    for srcs, c in src_counter.most_common():
        print(f"  {c:4d}  {srcs}")
    print()

    # Sample 15 issues
    print("=== Sample (15) ===")
    for i, issue in enumerate(no_recall[:15], 1):
        print(f"[{i}] {issue.get('issue_id','?')}")
        print(f"    sources: {issue.get('sources')}")
        print(f"    title: {(issue.get('title') or '')[:100]}")
        print(f"    summary: {(issue.get('summary') or '')[:200]}")
        print()

    # Check if openfda_cache has records we could match against
    if OPENFDA_CACHE.exists():
        openfda_files = list(OPENFDA_CACHE.glob("recall_*.json"))
        print(f"outputs/openfda_cache: {len(openfda_files)} recall_* files")
        if openfda_files:
            # inspect one
            sample = json.loads(openfda_files[0].read_text(encoding="utf-8"))
            print(f"  sample keys: {list(sample.keys())[:20]}")
            print(f"  sample recalling_firm: {sample.get('recalling_firm')!r}")
            print(f"  sample product_description: {str(sample.get('product_description') or '')[:100]!r}")
    else:
        print(f"outputs/openfda_cache: does not exist")


if __name__ == "__main__":
    main()
