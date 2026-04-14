"""Part 3: test parsers for titles and summaries on openfda-recalls-historical
records without Z-NNNN IDs."""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FEED = REPO / "docs" / "feed_latest.json"

FDA_SOURCES = {
    "openfda-recalls-historical",
    "openfda-device-recalls",
    "openfda-device-events",
    "fda-medwatch",
    "fda-safety-comms-historical",
}
RECALL_RE = re.compile(r"\bZ-\d{4}-\d{4}\b", re.IGNORECASE)
# Title like "Automated External Defibrillators (Non-Wearable) recall (Philips Medical Systems)"
TITLE_VENDOR_RE = re.compile(r" recall \((.+?)\)\s*$")


def has_fda_source(issue):
    return bool(set(issue.get("sources") or []) & FDA_SOURCES)


def parse_title_vendor(title):
    m = TITLE_VENDOR_RE.search(title or "")
    if m:
        return m.group(1).strip()
    return None


def parse_summary_pipes(summary):
    """Summary format: '<narrative> | <product/models> | <vendor> | Device: ...'
    Returns (product_text, vendor_text) or (None, None)."""
    if not summary or "|" not in summary:
        return None, None
    parts = [p.strip() for p in summary.split("|")]
    product = None
    vendor = None
    for i, p in enumerate(parts):
        if p.lower().startswith("device:") or p.lower().startswith("device :"):
            # The two preceding pipes are vendor then product
            if i >= 2:
                vendor = parts[i-1] or None
                product = parts[i-2] or None
            break
    return product, vendor


def main():
    with FEED.open(encoding="utf-8") as f:
        issues = json.load(f)
    md = [i for i in issues if i.get("healthcare_category") == "medical_device"]
    fda_md = [i for i in md if has_fda_source(i)]
    no_recall = [i for i in fda_md if not RECALL_RE.search(str(i.get("title") or ""))]
    print(f"FDA-derived MD issues without Z-NNNN in title: {len(no_recall)}\n")

    title_vendor_hit = 0
    summary_product_hit = 0
    summary_vendor_hit = 0
    both_hit = 0
    samples = []
    for issue in no_recall:
        tv = parse_title_vendor(str(issue.get("title") or ""))
        sp, sv = parse_summary_pipes(str(issue.get("summary") or ""))
        if tv:
            title_vendor_hit += 1
        if sp:
            summary_product_hit += 1
        if sv:
            summary_vendor_hit += 1
        if (tv or sv) and sp:
            both_hit += 1
        if len(samples) < 12 and tv and sp:
            samples.append((issue, tv, sv, sp))

    print("=== Extraction coverage on the 178 non-Z-NNNN issues ===")
    print(f"  title vendor extracted:    {title_vendor_hit}")
    print(f"  summary product extracted: {summary_product_hit}")
    print(f"  summary vendor extracted:  {summary_vendor_hit}")
    print(f"  both (vendor + product):   {both_hit}")
    print()

    print("=== Samples ===")
    for i, (issue, tv, sv, sp) in enumerate(samples, 1):
        print(f"[{i}] {issue.get('issue_id','?')}")
        print(f"    title: {str(issue.get('title') or '')[:100]}")
        print(f"    title->vendor: {tv!r}")
        print(f"    summary->vendor: {sv!r}")
        print(f"    summary->product: {sp[:100]!r}")
        print()


if __name__ == "__main__":
    main()
