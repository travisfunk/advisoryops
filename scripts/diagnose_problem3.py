"""Phase 1 diagnosis for Problem 3 residual.

How many FDA-derived medical_device records have empty vendor /
affected_products? What enforcement-cache fields carry that information?
"""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FEED = REPO / "docs" / "feed_latest.json"
ENF_CACHE = REPO / "outputs" / "fda_safety_comms_cache"

FDA_SOURCES = {
    "openfda-recalls-historical",
    "openfda-device-recalls",
    "openfda-device-events",
    "fda-medwatch",
    "fda-safety-comms-historical",
}

# Recall number pattern: Z-NNNN-YYYY (appears in title of FDA-derived issues)
RECALL_RE = re.compile(r"\bZ-\d{4}-\d{4}\b", re.IGNORECASE)


def has_fda_source(issue):
    return bool(set(issue.get("sources") or []) & FDA_SOURCES)


def find_recall_number(issue):
    """Pull Z-NNNN-YYYY from the title if present."""
    for field in ("title", "issue_id"):
        text = str(issue.get(field) or "")
        m = RECALL_RE.search(text)
        if m:
            return m.group(0).upper()
    return None


def load_enforcement_record(recall_number):
    path = ENF_CACHE / f"enf_{recall_number}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def main():
    with FEED.open(encoding="utf-8") as f:
        issues = json.load(f)
    md = [i for i in issues if i.get("healthcare_category") == "medical_device"]
    print(f"medical_device bucket total: {len(md)}")

    fda_md = [i for i in md if has_fda_source(i)]
    print(f"FDA-derived medical_device: {len(fda_md)}\n")

    # Gap counts
    gap_vendor = [i for i in fda_md if not i.get("vendor")]
    gap_products = [i for i in fda_md if not i.get("affected_products")]
    gap_both = [i for i in fda_md if not i.get("vendor") and not i.get("affected_products")]
    both_set = [i for i in fda_md if i.get("vendor") and i.get("affected_products")]
    print("=== Gap analysis (FDA-derived medical_device bucket) ===")
    print(f"  vendor empty:             {len(gap_vendor)}")
    print(f"  affected_products empty:  {len(gap_products)}")
    print(f"  both empty:               {len(gap_both)}")
    print(f"  both populated:           {len(both_set)}")
    print()

    # Enforcement-cache lookup success rate
    with_recall_num = 0
    with_enf_record = 0
    without_recall_num = 0
    without_enf_record = 0
    enf_field_presence = Counter()
    for issue in gap_vendor:
        rn = find_recall_number(issue)
        if not rn:
            without_recall_num += 1
            continue
        with_recall_num += 1
        rec = load_enforcement_record(rn)
        if not rec:
            without_enf_record += 1
            continue
        with_enf_record += 1
        # Track which fields are populated
        for field in ("recalling_firm", "product_description", "openfda",
                      "code_info", "product_res_number", "reason_for_recall"):
            v = rec.get(field)
            if v:
                if isinstance(v, dict):
                    if v.get("manufacturer_name") or v.get("device_name"):
                        enf_field_presence[f"{field}.manufacturer_or_device_name"] += 1
                    else:
                        enf_field_presence[f"{field}.nonempty_dict"] += 1
                else:
                    enf_field_presence[field] += 1
    print("=== Enforcement-cache lookup rate (on records with empty vendor) ===")
    print(f"  gap_vendor records:                  {len(gap_vendor)}")
    print(f"  title contained Z-NNNN-YYYY:         {with_recall_num}")
    print(f"  enforcement record found in cache:   {with_enf_record}")
    print(f"  no recall number in title:           {without_recall_num}")
    print(f"  recall number but no cache file:     {without_enf_record}")
    print()

    print("=== Enforcement field population (across enf records we found) ===")
    for f, c in enf_field_presence.most_common():
        pct = 100.0 * c / max(with_enf_record, 1)
        print(f"  {f:50s} {c:4d}  ({pct:.0f}%)")
    print()

    # Sample 10 issues, show current state + enforcement-cache contents
    print("=== Sample: 10 gap_vendor issues with enforcement records ===\n")
    samples_shown = 0
    for issue in gap_vendor:
        if samples_shown >= 10:
            break
        rn = find_recall_number(issue)
        if not rn:
            continue
        rec = load_enforcement_record(rn)
        if not rec:
            continue
        samples_shown += 1
        print(f"[{samples_shown}] {issue.get('issue_id', '?')}")
        print(f"    title: {(issue.get('title') or '')[:100]}")
        print(f"    current vendor: {issue.get('vendor')!r}")
        print(f"    current affected_products: {issue.get('affected_products')}")
        print(f"    summary (first 200 chars): {(issue.get('summary') or '')[:200]}")
        print(f"    enforcement recalling_firm: {rec.get('recalling_firm')!r}")
        product_desc = str(rec.get('product_description') or '')[:200]
        print(f"    enforcement product_description: {product_desc!r}")
        code_info = str(rec.get('code_info') or '')[:120]
        print(f"    enforcement code_info: {code_info!r}")
        openfda = rec.get('openfda') or {}
        if openfda:
            print(f"    enforcement openfda.device_name: {openfda.get('device_name')}")
            print(f"    enforcement openfda.manufacturer_name: {openfda.get('manufacturer_name')}")
        print()


if __name__ == "__main__":
    main()
