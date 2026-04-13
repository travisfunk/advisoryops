"""Phase 1 diagnostic for Problem 9 — pharmaceutical leakage."""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FEED = REPO / "docs" / "feed_latest.json"

PHARMA_TITLE = re.compile(
    r"(medicines?\s+recall|drug\s+recall|pharmaceutical\s+recall"
    r"|solution\s+for\s+injection|oral\s+tablet|oral\s+solution"
    r"|\bampoule\b|hydrochloride|prolonged-release"
    r"|\bmg/ml\b|\bi\.u\./ml\b|injection\s+bp|\bsyrup\b"
    r"|film-coated\s+tablets?|\binhaler\b"
    r"|class\s+[1-4]\s+medicines)",
    re.IGNORECASE,
)

def load(path):
    with path.open(encoding="utf-8") as f:
        return json.load(f)

def main():
    issues = load(FEED)
    print(f"Loaded {len(issues)} issues from {FEED.name}\n")

    md_issues = [i for i in issues if i.get("healthcare_category") == "medical_device"]
    print(f"medical_device bucket total: {len(md_issues)}")

    # Title-based pharma matching (no summary — too noisy)
    md_pharma = [i for i in md_issues if PHARMA_TITLE.search(str(i.get("title") or ""))]
    print(f"medical_device bucket pharma (title match): {len(md_pharma)}")
    print()

    # By-source scan corpus-wide for mixed sources
    for src_id in ("mhra-uk-alerts", "fda-medwatch"):
        src_records = [i for i in issues if src_id in (i.get("sources") or [])]
        src_pharma = [i for i in src_records if PHARMA_TITLE.search(str(i.get("title") or ""))]
        src_pharma_md = [i for i in src_pharma if i.get("healthcare_category") == "medical_device"]
        src_non_pharma = [i for i in src_records if not PHARMA_TITLE.search(str(i.get("title") or ""))]
        src_non_pharma_md = [i for i in src_non_pharma if i.get("healthcare_category") == "medical_device"]
        print(f"=== {src_id} ===")
        print(f"  Total records: {len(src_records)}")
        print(f"  Pharma-title records: {len(src_pharma)} (medical_device: {len(src_pharma_md)})")
        print(f"  Non-pharma records:   {len(src_non_pharma)} (medical_device: {len(src_non_pharma_md)})")
        print(f"  Pharma samples (first 5):")
        for i in src_pharma[:5]:
            print(f"    - {(i.get('title') or '')[:120]}")
        print(f"  Non-pharma samples (first 5):")
        for i in src_non_pharma[:5]:
            print(f"    - {(i.get('title') or '')[:120]}")
        print()

    # Corpus-wide breakdown of source_ids by count
    src_counter = Counter()
    for i in issues:
        for s in i.get("sources") or []:
            src_counter[s] += 1

    # Show all sources (for Travis's scope call)
    print("=== All sources and counts (top 40) ===")
    for s, c in src_counter.most_common(40):
        print(f"  {s:45s}  {c:5d}")

    # Which sources contribute pharma-titled records anywhere?
    src_pharma_counter = Counter()
    for i in issues:
        if PHARMA_TITLE.search(str(i.get("title") or "")):
            for s in i.get("sources") or []:
                src_pharma_counter[s] += 1
    print("\n=== Sources producing pharma-titled records (corpus-wide) ===")
    for s, c in src_pharma_counter.most_common():
        print(f"  {s:45s}  {c:5d}")

    # Final summary for mission go/no-go
    print(f"\n=== DECISION ===")
    print(f"medical_device bucket pharma count: {len(md_pharma)}")
    print(f"Threshold for proceeding:           45")
    print(f"Mission scope decision: {'PROCEED' if len(md_pharma) <= 45 else 'STOP AND REPORT'}")

if __name__ == "__main__":
    main()
