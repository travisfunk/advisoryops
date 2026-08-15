from __future__ import annotations

import json
from pathlib import Path

from advisoryops.kev_full_catalog import build_report, run


def test_build_report_uses_full_kev_rows_and_exact_cve_intersection() -> None:
    feed = [
        {
            "issue_id": "CVE-2026-0001",
            "cves": ["CVE-2026-0001"],
            "healthcare_category": "medical_device",
            "vendor": "Acme Medical",
        },
        {
            "issue_id": "CVE-2026-0002",
            "cves": ["CVE-2026-0002"],
            "healthcare_category": "healthcare_adjacent",
            "vendor": "Other",
        },
    ]
    kev = [
        {"guid": "CVE-2026-0001", "kev_vendor": "Acme Medical"},
        {"guid": "CVE-2026-9999", "kev_vendor": "Unrelated Vendor"},
        {"title": "Known exploited CVE-2025-12345", "kev_vendor": "Third Vendor"},
    ]

    report = build_report(feed, kev)

    assert report["comparison_scope"] == "full_cisa_kev_catalog"
    assert report["kev_records_loaded"] == 3
    assert report["kev_unique_cves"] == 3
    assert report["medical_device_records"] == 1
    assert report["medical_device_unique_cves"] == 1
    assert report["cve_overlap_count"] == 1
    assert report["cve_overlap_ids"] == ["CVE-2026-0001"]
    assert report["vendor_exact_overlap"] == ["acme medical"]


def test_run_updates_meta_with_explicit_full_catalog_scope(tmp_path: Path) -> None:
    feed_path = tmp_path / "feed.json"
    kev_path = tmp_path / "kev.jsonl"
    meta_path = tmp_path / "meta.json"
    out_path = tmp_path / "report.json"

    feed_path.write_text(
        json.dumps([
            {
                "issue_id": "CVE-2026-1111",
                "cves": ["CVE-2026-1111"],
                "healthcare_category": "medical_device",
                "vendor": "DeviceCo",
            }
        ]),
        encoding="utf-8",
    )
    kev_path.write_text(
        "\n".join([
            json.dumps({"guid": "CVE-2026-2222", "kev_vendor": "EnterpriseCo"}),
            json.dumps({"guid": "CVE-2026-3333", "kev_vendor": "OtherCo"}),
        ]) + "\n",
        encoding="utf-8",
    )
    meta_path.write_text(
        json.dumps({"methodology_stats": {"kev_enriched": 1, "kev_md_cve_overlap": 99}}),
        encoding="utf-8",
    )

    report = run(
        feed_path=feed_path,
        kev_path=kev_path,
        out_path=out_path,
        meta_path=meta_path,
        min_kev_cves=2,
    )

    assert report["cve_overlap_count"] == 0
    written = json.loads(out_path.read_text(encoding="utf-8"))
    assert written["kev_unique_cves"] == 2

    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    stats = meta["methodology_stats"]
    assert stats["kev_enriched"] == 1
    assert stats["kev_md_cve_overlap"] == 0
    assert stats["kev_comparison_scope"] == "full_cisa_kev_catalog"
    assert stats["kev_comparison_key"] == "exact_cve_id"
