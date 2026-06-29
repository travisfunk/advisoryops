"""Pick representative issues for Feature 3 prompt calibration.

Selects one issue from each major source category to test how the
clinical summary feature handles different input shapes.
"""
from __future__ import annotations

import json
import random
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FEED = REPO_ROOT / "outputs" / "community_public" / "feed_healthcare.json"

# Source categorization for sampling
SOURCE_BUCKETS = {
    "cisa_icsma": ["cisa-icsma", "cisa-icsma-historical"],
    "openfda_recall": ["openfda-recalls-historical", "openfda-device-recalls"],
    "fda_enforcement": ["fda-safety-comms-historical"],
    "vendor_psirt": ["philips-psirt", "siemens-productcert-psirt"],
    "cisa_ncas": ["cisa-ncas-alerts", "cisa-ncas-analysis"],
    "international": ["mhra-uk-alerts", "health-canada-recalls", "health-canada-recalls-historical"],
}


def categorize(issue: dict) -> str | None:
    src = issue.get("highest_authority_source", "")
    for bucket, sources in SOURCE_BUCKETS.items():
        if src in sources:
            return bucket
    return None


def main():
    if not FEED.exists():
        print(f"ERROR: Feed not found at {FEED}")
        return 1

    with open(FEED, "r", encoding="utf-8") as f:
        data = json.load(f)
    issues = data if isinstance(data, list) else data.get("issues", [])

    print(f"Total healthcare issues: {len(issues)}")

    # Bucket by source category
    buckets = defaultdict(list)
    for issue in issues:
        cat = categorize(issue)
        if cat:
            buckets[cat].append(issue)

    print("\nIssues per source category:")
    for cat in SOURCE_BUCKETS:
        print(f"  {cat:20s}  {len(buckets.get(cat, [])):4d}")

    # For each category, pick samples that are RICH (long summary) and SPARSE (short summary)
    print("\n" + "=" * 70)
    print("CALIBRATION SAMPLES")
    print("=" * 70)

    random.seed(42)  # Reproducible selection

    samples = []

    for cat, cat_issues in buckets.items():
        if not cat_issues:
            continue

        # Sort by summary length to find rich and sparse examples
        with_summary = [(i, len(i.get("summary", "") or "")) for i in cat_issues]
        with_summary.sort(key=lambda x: x[1])

        # Pick the richest example from this category
        if with_summary:
            richest = with_summary[-1][0]
            samples.append((cat, "rich", richest))

        # Pick a sparse example (bottom 25%) if different from richest
        if len(with_summary) >= 4:
            sparse_pool = [i for i, _ in with_summary[: len(with_summary) // 4]]
            sparse = random.choice(sparse_pool)
            if sparse["issue_id"] != richest["issue_id"]:
                samples.append((cat, "sparse", sparse))

    # Print samples
    for cat, kind, issue in samples:
        print(f"\n{'─' * 70}")
        print(f"CATEGORY: {cat}  ({kind})")
        print(f"issue_id:  {issue.get('issue_id')}")
        print(f"priority:  {issue.get('priority')}  score: {issue.get('score')}")
        print(f"source:    {issue.get('highest_authority_source')}")
        print(f"fda_class: {issue.get('fda_risk_class') or '(none)'}")
        print(f"category:  {issue.get('healthcare_category') or '(none)'}")
        print(f"\nTITLE:")
        print(f"  {(issue.get('title') or '')[:200]}")
        print(f"\nSUMMARY ({len(issue.get('summary') or '')} chars):")
        summary = issue.get("summary") or ""
        # Truncate long summaries for display but show length
        display = summary[:500] + ("..." if len(summary) > 500 else "")
        print(f"  {display}")
        cves = issue.get("cves") or []
        if cves:
            print(f"\nCVEs: {', '.join(cves[:5])}")

    print("\n" + "=" * 70)
    print(f"TOTAL CALIBRATION SAMPLES: {len(samples)}")
    print("=" * 70)
    print("\nCopy the issue_ids above. We'll use these to test prompts before")
    print("running on the full P0/P1/P2 corpus.")

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())