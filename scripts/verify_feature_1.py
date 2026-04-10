"""Feature 1 verification — did FDA risk class extraction and scoring work correctly?"""
from __future__ import annotations

import json
import random
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUTS = REPO_ROOT / "outputs"


def main():
    feed_hc_path = OUTPUTS / "community_public" / "feed_healthcare.json"
    feed_all_path = OUTPUTS / "community_public" / "feed_latest.json"

    if not feed_hc_path.exists():
        print(f"ERROR: {feed_hc_path} not found")
        return 1

    with open(feed_hc_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    issues = data if isinstance(data, list) else data.get("issues", [])

    with open(feed_all_path, "r", encoding="utf-8") as f:
        data_all = json.load(f)
    issues_all = data_all if isinstance(data_all, list) else data_all.get("issues", [])

    print("=" * 70)
    print("FEATURE 1 VERIFICATION — FDA RISK CLASS")
    print("=" * 70)
    print(f"Total healthcare issues: {len(issues)}")
    print(f"Total all issues:        {len(issues_all)}")

    # === Coverage analysis ===
    print("\n" + "=" * 70)
    print("COVERAGE")
    print("=" * 70)

    rc_counts = Counter()
    for issue in issues:
        rc = issue.get("fda_risk_class")
        if rc is None:
            rc_counts["(null)"] += 1
        else:
            rc_counts[str(rc)] += 1

    total = len(issues)
    for cls in ["1", "2", "3", "(null)"]:
        count = rc_counts.get(cls, 0)
        pct = (count / total * 100) if total else 0
        label = f"Class {cls}" if cls != "(null)" else "No class"
        print(f"  {label:15s}  {count:4d}  ({pct:5.1f}%)")

    populated = total - rc_counts.get("(null)", 0)
    print(f"\n  Total with risk class: {populated} / {total} ({populated/total*100:.1f}%)")

    # Same analysis for full feed
    rc_all = Counter()
    for issue in issues_all:
        rc = issue.get("fda_risk_class")
        rc_all[str(rc) if rc else "(null)"] += 1
    populated_all = len(issues_all) - rc_all.get("(null)", 0)
    print(f"  Total in full feed:    {populated_all} / {len(issues_all)} ({populated_all/len(issues_all)*100:.1f}%)")

    # === Priority distribution shift ===
    print("\n" + "=" * 70)
    print("PRIORITY DISTRIBUTION (healthcare feed)")
    print("=" * 70)

    prio_all = Counter(i.get("priority", "?") for i in issues)
    prio_class_3 = Counter(i.get("priority", "?") for i in issues if i.get("fda_risk_class") == "3")
    prio_class_2 = Counter(i.get("priority", "?") for i in issues if i.get("fda_risk_class") == "2")
    prio_class_1 = Counter(i.get("priority", "?") for i in issues if i.get("fda_risk_class") == "1")
    prio_null = Counter(i.get("priority", "?") for i in issues if i.get("fda_risk_class") is None)

    print(f"\n  All healthcare issues:")
    for p in ["P0", "P1", "P2", "P3"]:
        count = prio_all.get(p, 0)
        pct = count / total * 100 if total else 0
        print(f"    {p}  {count:4d}  ({pct:5.1f}%)")

    def _show(label, counter, denom):
        if denom == 0:
            return
        print(f"\n  {label} ({denom} issues):")
        for p in ["P0", "P1", "P2", "P3"]:
            count = counter.get(p, 0)
            pct = count / denom * 100
            print(f"    {p}  {count:4d}  ({pct:5.1f}%)")

    _show("Class III only", prio_class_3, sum(prio_class_3.values()))
    _show("Class II only", prio_class_2, sum(prio_class_2.values()))
    _show("Class I only", prio_class_1, sum(prio_class_1.values()))
    _show("No class assigned", prio_null, sum(prio_null.values()))

    # === Score distribution comparison ===
    print("\n" + "=" * 70)
    print("SCORE DISTRIBUTION BY RISK CLASS")
    print("=" * 70)

    def score_stats(issues_subset, label):
        scores = [float(i.get("score", 0)) for i in issues_subset if i.get("score") is not None]
        if not scores:
            print(f"\n  {label}: no issues")
            return
        scores.sort()
        n = len(scores)
        print(f"\n  {label} ({n} issues):")
        print(f"    Min:    {scores[0]:.0f}")
        print(f"    Median: {scores[n//2]:.0f}")
        print(f"    Mean:   {sum(scores)/n:.1f}")
        print(f"    Max:    {scores[-1]:.0f}")

    score_stats([i for i in issues if i.get("fda_risk_class") == "3"], "Class III")
    score_stats([i for i in issues if i.get("fda_risk_class") == "2"], "Class II")
    score_stats([i for i in issues if i.get("fda_risk_class") == "1"], "Class I")
    score_stats([i for i in issues if i.get("fda_risk_class") is None], "No class")

    # === Spot check Class III ===
    print("\n" + "=" * 70)
    print("CLASS III SPOT CHECK (first 10)")
    print("=" * 70)

    class_3 = [i for i in issues if i.get("fda_risk_class") == "3"]
    if not class_3:
        print("\n  No Class III issues found. That's suspicious — expected at least a few.")
    else:
        print(f"\n  {len(class_3)} Class III issues total. Showing first 10:\n")
        for idx, issue in enumerate(class_3[:10], 1):
            title = (issue.get("title", "") or "")[:100]
            score = issue.get("score", "?")
            prio = issue.get("priority", "?")
            source = issue.get("highest_authority_source", "?")
            print(f"  {idx:2d}. [{prio}] score={score} | {source}")
            print(f"      {title}")
            # Show reasoning if 'why' field is populated
            why = issue.get("why") or []
            rc_reasons = [w for w in why if "fda-risk-class" in str(w)]
            if rc_reasons:
                print(f"      reason: {rc_reasons[0]}")
            print()

    # === Spot check Class I ===
    print("\n" + "=" * 70)
    print("CLASS I SPOT CHECK (first 5)")
    print("=" * 70)

    class_1 = [i for i in issues if i.get("fda_risk_class") == "1"]
    if not class_1:
        print("\n  No Class I issues found.")
    else:
        print(f"\n  {len(class_1)} Class I issues total. Showing first 5:\n")
        for idx, issue in enumerate(class_1[:5], 1):
            title = (issue.get("title", "") or "")[:100]
            score = issue.get("score", "?")
            prio = issue.get("priority", "?")
            print(f"  {idx:2d}. [{prio}] score={score}")
            print(f"      {title}")
            print()

    # === Check why field is populated ===
    print("\n" + "=" * 70)
    print("SCORING REASONING — 'why' FIELD CHECK")
    print("=" * 70)

    has_why_with_rc = sum(
        1 for i in issues
        if any("fda-risk-class" in str(w) for w in (i.get("why") or []))
    )
    print(f"\n  Issues with FDA risk class in 'why' field: {has_why_with_rc}")
    print(f"  (Should match Class II + Class III count: {rc_counts.get('2', 0) + rc_counts.get('3', 0)})")

    # === Sanity ===
    print("\n" + "=" * 70)
    print("SANITY CHECKS")
    print("=" * 70)

    warnings = []

    # Class III should generally have higher scores than Class I
    c3_scores = [float(i.get("score", 0)) for i in issues if i.get("fda_risk_class") == "3"]
    c1_scores = [float(i.get("score", 0)) for i in issues if i.get("fda_risk_class") == "1"]
    if c3_scores and c1_scores:
        c3_mean = sum(c3_scores) / len(c3_scores)
        c1_mean = sum(c1_scores) / len(c1_scores)
        if c3_mean <= c1_mean:
            warnings.append(
                f"WARN: Class III mean score ({c3_mean:.1f}) <= Class I mean ({c1_mean:.1f}). "
                "Expected Class III to be higher."
            )
        else:
            print(f"  OK: Class III mean ({c3_mean:.1f}) > Class I mean ({c1_mean:.1f}) — as expected")

    # Populated count should be > 0
    if populated == 0:
        warnings.append("WARN: Zero issues have fda_risk_class populated. Feature is not working.")
    else:
        print(f"  OK: {populated} issues have risk class populated")

    # Any issues at P0 now?
    p0_count = sum(1 for i in issues if i.get("priority") == "P0")
    print(f"  P0 healthcare issues after Feature 1: {p0_count}")
    print(f"  (Was 1 before Feature 1. Any increase means Class III promotion worked.)")

    if warnings:
        print("\n  WARNINGS:")
        for w in warnings:
            print(f"    {w}")

    print("\n" + "=" * 70)
    print("VERIFICATION COMPLETE")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())