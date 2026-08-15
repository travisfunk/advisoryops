"""Validate medical-device CVEs against the full CISA KEV catalog.

This module deliberately reads the raw discovered CISA KEV dataset rather than
using KEV-enriched issues from the correlated feed. Correlation intentionally
caps ordinary per-source signal loading for performance, so it is not a valid
basis for a claim about the *entire* KEV catalog.

The nightly workflow runs this after the community feed is built and publishes
an auditable JSON report beside the feed. It also annotates docs/meta.json so
``kev_md_cve_overlap`` has an explicit full-catalog scope.
"""
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set, Tuple


_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        if isinstance(obj, dict):
            rows.append(obj)
    return rows


def _cves_from_values(values: Iterable[Any]) -> Set[str]:
    cves: Set[str] = set()
    for value in values:
        if value is None:
            continue
        cves.update(m.upper() for m in _CVE_RE.findall(str(value)))
    return cves


def _structured_cves(record: Dict[str, Any]) -> Set[str]:
    """Return CVEs explicitly assigned to a record, not incidental prose mentions."""
    values: List[Any] = []
    structured = record.get("cves") or []
    if isinstance(structured, str):
        values.append(structured)
    elif isinstance(structured, list):
        values.extend(structured)

    # Correlated feed issues are keyed by CVE when a CVE is known. CISA KEV
    # discovery records use guid as the canonical cveID. Restricting extraction
    # to these fields avoids counting CVEs that are merely mentioned in prose.
    values.extend((record.get("issue_id"), record.get("guid")))
    return _cves_from_values(values)


def _norm_vendor(value: Any) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _vendor_sets(
    medical_device_rows: Iterable[Dict[str, Any]],
    kev_rows: Iterable[Dict[str, Any]],
) -> Tuple[Set[str], Set[str]]:
    md_vendors = {
        v
        for row in medical_device_rows
        if (v := _norm_vendor(row.get("vendor")))
    }
    kev_vendors = {
        v
        for row in kev_rows
        if (v := _norm_vendor(row.get("kev_vendor") or row.get("vendor")))
    }
    return md_vendors, kev_vendors


def build_report(
    feed_rows: List[Dict[str, Any]],
    kev_rows: List[Dict[str, Any]],
) -> Dict[str, Any]:
    medical_device_rows = [
        row for row in feed_rows if row.get("healthcare_category") == "medical_device"
    ]

    kev_cves: Set[str] = set()
    for row in kev_rows:
        kev_cves.update(_structured_cves(row))

    md_cves: Set[str] = set()
    for row in medical_device_rows:
        md_cves.update(_structured_cves(row))

    overlap = sorted(md_cves & kev_cves)

    md_vendors, kev_vendors = _vendor_sets(medical_device_rows, kev_rows)
    vendor_exact = sorted(md_vendors & kev_vendors)

    partial_pairs: Set[Tuple[str, str]] = set()
    for md_vendor in md_vendors:
        if len(md_vendor) < 4:
            continue
        for kev_vendor in kev_vendors:
            if len(kev_vendor) < 4:
                continue
            if md_vendor in kev_vendor or kev_vendor in md_vendor:
                if md_vendor != kev_vendor:
                    partial_pairs.add((md_vendor, kev_vendor))

    generated_at = datetime.now(timezone.utc).isoformat()
    return {
        "generated_at": generated_at,
        "comparison_scope": "full_cisa_kev_catalog",
        "comparison_key": "exact_cve_id",
        "kev_records_loaded": len(kev_rows),
        "kev_unique_cves": len(kev_cves),
        "medical_device_records": len(medical_device_rows),
        "medical_device_unique_cves": len(md_cves),
        "cve_overlap_count": len(overlap),
        "cve_overlap_ids": overlap,
        "vendor_exact_overlap_count": len(vendor_exact),
        "vendor_exact_overlap": vendor_exact,
        "vendor_partial_overlap_count": len(partial_pairs),
        "vendor_partial_overlap": [
            {"medical_device_vendor": a, "kev_vendor": b}
            for a, b in sorted(partial_pairs)
        ],
        "methodology": {
            "kev_side": (
                "All records from outputs/discover/cisa-kev-json/items.jsonl; "
                "CVE IDs are taken from structured cves and the KEV guid/cveID field"
            ),
            "medical_device_side": (
                "All published feed records where healthcare_category == medical_device; "
                "CVE IDs are taken from structured cves and CVE-keyed issue_id values"
            ),
            "primary_overlap_test": "Exact set intersection of normalized CVE IDs",
            "vendor_checks": (
                "Secondary sanity checks using normalized exact vendor names and substring matches "
                "for names at least four characters long"
            ),
        },
    }


def update_meta(meta_path: Path, report: Dict[str, Any]) -> None:
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    if not isinstance(meta, dict):
        raise ValueError(f"{meta_path}: expected a JSON object")

    stats = meta.setdefault("methodology_stats", {})
    if not isinstance(stats, dict):
        raise ValueError(f"{meta_path}: methodology_stats must be a JSON object")

    # Preserve kev_enriched as the number of feed issues carrying KEV fields.
    # The overlap metric below is intentionally replaced with the independently
    # computed full-catalog result so its scope is no longer ambiguous.
    stats["kev_catalog_records"] = report["kev_records_loaded"]
    stats["kev_catalog_unique_cves"] = report["kev_unique_cves"]
    stats["medical_device_unique_cves"] = report["medical_device_unique_cves"]
    stats["kev_md_cve_overlap"] = report["cve_overlap_count"]
    stats["kev_md_cve_overlap_ids"] = report["cve_overlap_ids"]
    stats["kev_md_vendor_overlap"] = report["vendor_exact_overlap_count"]
    stats["kev_md_vendor_partial_overlap"] = report["vendor_partial_overlap_count"]
    stats["kev_comparison_scope"] = report["comparison_scope"]
    stats["kev_comparison_key"] = report["comparison_key"]
    stats["kev_comparison_generated_at"] = report["generated_at"]

    meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def run(
    *,
    feed_path: Path,
    kev_path: Path,
    out_path: Path,
    meta_path: Path | None = None,
    min_kev_cves: int = 1000,
) -> Dict[str, Any]:
    feed = json.loads(feed_path.read_text(encoding="utf-8"))
    if not isinstance(feed, list):
        raise ValueError(f"{feed_path}: expected a JSON array")

    kev_rows = _read_jsonl(kev_path)
    report = build_report(feed, kev_rows)

    if report["kev_unique_cves"] < min_kev_cves:
        raise RuntimeError(
            "CISA KEV input appears truncated: "
            f"only {report['kev_unique_cves']} unique CVEs; expected at least {min_kev_cves}"
        )
    if report["medical_device_records"] == 0:
        raise RuntimeError("No medical_device records found in the published feed")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    if meta_path is not None:
        update_meta(meta_path, report)

    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--feed", type=Path, default=Path("docs/feed_latest.json"))
    parser.add_argument(
        "--kev-jsonl",
        type=Path,
        default=Path("outputs/discover/cisa-kev-json/items.jsonl"),
    )
    parser.add_argument("--meta", type=Path, default=Path("docs/meta.json"))
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("docs/kev_full_catalog_overlap.json"),
    )
    parser.add_argument("--min-kev-cves", type=int, default=1000)
    args = parser.parse_args()

    report = run(
        feed_path=args.feed,
        kev_path=args.kev_jsonl,
        out_path=args.out,
        meta_path=args.meta,
        min_kev_cves=args.min_kev_cves,
    )

    print("Full CISA KEV / medical-device overlap verification:")
    print(f"  KEV records loaded:        {report['kev_records_loaded']}")
    print(f"  KEV unique CVEs:           {report['kev_unique_cves']}")
    print(f"  Medical-device records:    {report['medical_device_records']}")
    print(f"  Medical-device CVEs:       {report['medical_device_unique_cves']}")
    print(f"  Exact CVE overlap:         {report['cve_overlap_count']}")
    print(f"  Exact vendor overlap:      {report['vendor_exact_overlap_count']}")
    print(f"  Partial vendor pairs:      {report['vendor_partial_overlap_count']}")
    print(f"  Wrote: {args.out}")
    print(f"  Updated: {args.meta}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
