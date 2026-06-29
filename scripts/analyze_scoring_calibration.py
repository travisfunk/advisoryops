"""Pre-Feature-1 calibration analysis — v2."""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUTS = REPO_ROOT / "outputs"


def analyze_score_distribution(issues, label=""):
    print(f"\n{'='*70}")
    print(f"SCORE DISTRIBUTION {label}")
    print("="*70)

    scores = [float(i.get("score", 0)) for i in issues if i.get("score") is not None]
    if not scores:
        print("  No scores found.")
        return

    scores.sort()
    n = len(scores)
    print(f"  Issues: {n}")
    print(f"  Min:          {scores[0]:.0f}")
    print(f"  25th pctile:  {scores[n // 4]:.0f}")
    print(f"  Median:       {scores[n // 2]:.0f}")
    print(f"  75th pctile:  {scores[3 * n // 4]:.0f}")
    print(f"  90th pctile:  {scores[int(n * 0.9)]:.0f}")
    print(f"  99th pctile:  {scores[int(n * 0.99)]:.0f}")
    print(f"  Max:          {scores[-1]:.0f}")
    print(f"  Mean:         {sum(scores) / n:.1f}")

    buckets = Counter()
    for s in scores:
        if s >= 200: buckets["200+"] += 1
        elif s >= 150: buckets["150-199 (P0)"] += 1
        elif s >= 100: buckets["100-149"] += 1
        elif s >= 75: buckets["75-99"] += 1
        elif s >= 50: buckets["50-74"] += 1
        elif s >= 25: buckets["25-49"] += 1
        else: buckets["<25"] += 1

    print("\n  Distribution:")
    for bucket in ["200+", "150-199 (P0)", "100-149", "75-99", "50-74", "25-49", "<25"]:
        count = buckets.get(bucket, 0)
        pct = (count / n * 100) if n else 0
        bar = "#" * int(pct / 2)
        print(f"    {bucket:15s}  {count:5d}  ({pct:5.1f}%)  {bar}")


def analyze_priority_distribution(issues):
    print(f"\n{'='*70}")
    print("PRIORITY DISTRIBUTION")
    print("="*70)

    priorities = Counter(i.get("priority", "?") for i in issues)
    total = sum(priorities.values())
    for prio in ["P0", "P1", "P2", "P3", "?"]:
        count = priorities.get(prio, 0)
        pct = (count / total * 100) if total else 0
        print(f"    {prio}  {count:5d}  ({pct:5.1f}%)")


def analyze_sources(issues):
    print(f"\n{'='*70}")
    print("SOURCE BREAKDOWN (highest_authority_source)")
    print("="*70)

    sources = Counter()
    for issue in issues:
        src = issue.get("highest_authority_source", "?")
        sources[str(src)] += 1

    total = sum(sources.values())
    for src, count in sources.most_common(30):
        pct = (count / total * 100) if total else 0
        print(f"    {src:50s}  {count:5d}  ({pct:5.1f}%)")


def analyze_healthcare_tagging(issues):
    print(f"\n{'='*70}")
    print("HEALTHCARE TAGGING BREAKDOWN")
    print("="*70)

    hc_relevant = [i for i in issues if i.get("healthcare_relevant")]
    hc_categories = Counter(i.get("healthcare_category", "") for i in hc_relevant)

    print(f"  Total issues:          {len(issues)}")
    print(f"  Healthcare-relevant:   {len(hc_relevant)}")
    print(f"  % healthcare-relevant: {len(hc_relevant)/len(issues)*100:.1f}%")
    print("\n  Healthcare categories:")
    for cat, count in hc_categories.most_common():
        label = cat if cat else "(no category)"
        print(f"    {label:40s}  {count:5d}")


def analyze_recall_cache():
    print(f"\n{'='*70}")
    print("OPENFDA RECALL CACHE — DEVICE CLASS AVAILABILITY")
    print("="*70)

    # Try both possible paths
    candidates = [
        OUTPUTS / "openfda_cache",
        OUTPUTS / "openfda_recalls_cache",
    ]
    recall_dir = next((c for c in candidates if c.exists()), None)

    if not recall_dir:
        print("  Recall cache directory not found in any expected location.")
        print("  Tried:")
        for c in candidates:
            print(f"    {c}")
        return

    print(f"  Cache dir: {recall_dir}")
    recall_files = list(recall_dir.glob("recall_*.json"))
    print(f"  Recall files: {len(recall_files)}")

    if not recall_files:
        return

    # Analyze a sample for speed (full analysis is slow on 14K+ files)
    import random
    sample_size = min(2000, len(recall_files))
    sample = random.sample(recall_files, sample_size)

    device_class_counts = Counter()
    has_product_code = 0
    has_device_name = 0

    for f in sample:
        try:
            with open(f, "r", encoding="utf-8") as fh:
                rec = json.load(fh)
        except Exception:
            continue

        dc = rec.get("device_class") or (rec.get("openfda", {}) or {}).get("device_class")
        if not dc:
            device_class_counts["(missing)"] += 1
        else:
            if isinstance(dc, list):
                dc = dc[0] if dc else ""
            device_class_counts[str(dc)] += 1

        if rec.get("product_code") or (rec.get("openfda", {}) or {}).get("product_code"):
            has_product_code += 1
        if (rec.get("openfda", {}) or {}).get("device_name") or rec.get("product_description"):
            has_device_name += 1

    print(f"\n  Sample of {sample_size} recalls:")
    for cls in ["1", "2", "3", "(missing)"]:
        count = device_class_counts.get(cls, 0)
        pct = (count / sample_size * 100)
        print(f"    Class {cls:10s}  {count:5d}  ({pct:5.1f}%)")

    other = sample_size - sum(device_class_counts.get(c, 0) for c in ["1", "2", "3", "(missing)"])
    if other > 0:
        print(f"    Other values: {other}")
        for cls, count in device_class_counts.most_common():
            if cls not in {"1", "2", "3", "(missing)"}:
                print(f"      '{cls}': {count}")

    print(f"\n  Field availability:")
    print(f"    Has product_code:  {has_product_code}/{sample_size} ({has_product_code/sample_size*100:.1f}%)")
    print(f"    Has device_name:   {has_device_name}/{sample_size} ({has_device_name/sample_size*100:.1f}%)")


def main():
    print("=" * 70)
    print("ADVISORYOPS CALIBRATION v2 — AGAINST NEW FEED")
    print("=" * 70)

    feed_latest = OUTPUTS / "community_public" / "feed_latest.json"
    feed_hc = OUTPUTS / "community_public" / "feed_healthcare.json"

    if not feed_latest.exists() or not feed_hc.exists():
        print("Feeds not found.")
        return 1

    print(f"feed_latest.json:      {feed_latest.stat().st_size / 1024 / 1024:.1f} MB")
    print(f"feed_healthcare.json:  {feed_hc.stat().st_size / 1024 / 1024:.1f} MB")

    with open(feed_latest, "r", encoding="utf-8") as f:
        data_latest = json.load(f)
    with open(feed_hc, "r", encoding="utf-8") as f:
        data_hc = json.load(f)

    issues_latest = data_latest if isinstance(data_latest, list) else data_latest.get("issues", [])
    issues_hc = data_hc if isinstance(data_hc, list) else data_hc.get("issues", [])

    print(f"\nTotal issues (latest):     {len(issues_latest)}")
    print(f"Healthcare issues:         {len(issues_hc)}")

    analyze_score_distribution(issues_latest, "— ALL ISSUES")
    analyze_score_distribution(issues_hc, "— HEALTHCARE ONLY")
    analyze_priority_distribution(issues_hc)
    analyze_sources(issues_hc)
    analyze_healthcare_tagging(issues_latest)
    analyze_recall_cache()

    print("\n" + "=" * 70)
    print("DONE")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())