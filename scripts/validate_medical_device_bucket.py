#!/usr/bin/env python3
"""Regression guard for the medical_device bucket.

Loads docs/feed_latest.json, filters to healthcare_category == 'medical_device',
and asserts none of the vendors are well-known general-IT companies that
slipped through in the past (pre-classifier-tightening).

Exit 0 on pass. Exit 1 if any general-IT vendor is present in the bucket,
which means the classifier regressed or a new data source is leaking noise.

Usage:
    python scripts/validate_medical_device_bucket.py
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FEED_PATH = REPO_ROOT / "docs" / "feed_latest.json"

# Vendors that must never appear in the medical_device bucket. These are
# large general-IT companies — Philips Healthcare / Siemens Healthineers
# belong to their healthcare divisions and are deliberately not on this list.
GENERAL_IT_VENDORS = {
    "Microsoft",
    "Google",
    "Adobe",
    "Cisco",
    "Citrix",
    "Oracle",
    "IBM",
    "VMware",
    "Apple",
    "Mozilla",
    "Samsung",
}

# Sources whose issues should, in principle, carry an FDA risk class. Used
# for the soft "FDA coverage" metric below — not a hard failure condition.
FDA_DERIVED_SOURCES = {
    "openfda-recalls-historical",
    "openfda-device-recalls",
    "openfda-device-events",
    "fda-medwatch",
    "fda-safety-comms-historical",
}

# Pharmaceutical source IDs that must never contribute to this bucket.
# Mirrors tests/test_no_pharmaceutical_sources.py. See Problem 9 diagnosis.
PHARMA_SOURCE_IDS = {
    "fda-medwatch",
    "mhra-uk-alerts",
}

# Title-level pharmaceutical keyword patterns — belt-and-suspenders for
# records that might slip in from a new mixed-content source.
PHARMA_TITLE_RE = re.compile(
    r"(medicines?\s+recall|drug\s+recall|pharmaceutical\s+recall"
    r"|solution\s+for\s+injection|oral\s+tablet|oral\s+solution"
    r"|\bampoule\b|hydrochloride|prolonged-release"
    r"|\bmg/ml\b|\bi\.u\./ml\b|injection\s+bp|\bsyrup\b"
    r"|film-coated\s+tablets?|\binhaler\b"
    r"|class\s+[1-4]\s+medicines)",
    re.IGNORECASE,
)


def main() -> int:
    if not FEED_PATH.exists():
        print(f"FAIL: {FEED_PATH} not found")
        return 1

    data = json.loads(FEED_PATH.read_text(encoding="utf-8"))
    issues = data.get("issues", data) if isinstance(data, dict) else data
    medical = [i for i in issues if i.get("healthcare_category") == "medical_device"]

    leaks = []
    for issue in medical:
        vendor = (issue.get("vendor") or "").strip()
        if vendor in GENERAL_IT_VENDORS:
            leaks.append(issue)

    print(f"medical_device issues: {len(medical)}")
    print()
    print("Sample (first 5):")
    for issue in medical[:5]:
        vendor = issue.get("vendor") or "(none)"
        products = issue.get("affected_products") or []
        print(f"  {issue.get('issue_id','?')[:30]:30s} vendor={vendor!r:30s} products={products[:2]}")

    if leaks:
        print()
        print(f"FAIL: {len(leaks)} general-IT vendor leaks found in medical_device bucket:")
        for issue in leaks[:10]:
            print(f"  {issue.get('issue_id')} vendor={issue.get('vendor')!r}")
        return 1

    # Pharmaceutical leak check — records from known pharma sources or with
    # pharma-flavored titles must never appear in the medical_device bucket.
    pharma_src_leaks = [
        i for i in medical
        if set(i.get("sources") or []) & PHARMA_SOURCE_IDS
    ]
    pharma_title_leaks = [
        i for i in medical
        if PHARMA_TITLE_RE.search(str(i.get("title") or ""))
    ]
    if pharma_src_leaks or pharma_title_leaks:
        print()
        print(
            f"FAIL: pharmaceutical content found in medical_device bucket "
            f"({len(pharma_src_leaks)} by source, {len(pharma_title_leaks)} by title):"
        )
        for issue in (pharma_src_leaks + pharma_title_leaks)[:10]:
            print(f"  {issue.get('issue_id')} title={(issue.get('title') or '')[:80]!r}")
        return 1

    # Soft metric — flag (not fail) regressions in FDA coverage. A rising
    # null count would suggest the enforcement-cache lookup is losing hits,
    # either because cache files went stale or the recall-number parser
    # drifted. Printed prominently so CI / eyeballing surfaces it.
    fda_derived = [
        i for i in medical
        if any(s in FDA_DERIVED_SOURCES for s in (i.get("sources") or []))
    ]
    fda_null = [i for i in fda_derived if not i.get("fda_risk_class")]
    print()
    print(
        f"METRIC: FDA-derived medical_device issues with null fda_risk_class: "
        f"{len(fda_null)} / {len(fda_derived)}"
    )
    if fda_null:
        print(
            "        (these are expected for MAUDE / RSS-only sources; "
            "watch the ratio for regressions)"
        )

    # Soft metric — vendor + affected_products coverage on FDA-derived rows.
    # Problem 3 residual extraction (2026-04-13) filled these from the
    # enforcement cache + title/summary parsers. A rising empty count means
    # the extractors are losing hits; a ratio that holds steady across
    # rebuilds means the extraction is durable.
    fda_no_vendor = [i for i in fda_derived if not i.get("vendor")]
    fda_no_products = [i for i in fda_derived if not i.get("affected_products")]
    print(
        f"METRIC: FDA-derived medical_device issues with empty vendor: "
        f"{len(fda_no_vendor)} / {len(fda_derived)}"
    )
    print(
        f"METRIC: FDA-derived medical_device issues with empty affected_products: "
        f"{len(fda_no_products)} / {len(fda_derived)}"
    )

    print()
    print("PASS: no general-IT vendor leaks in medical_device bucket")
    print("PASS: no pharmaceutical records in medical_device bucket")
    return 0


if __name__ == "__main__":
    sys.exit(main())
