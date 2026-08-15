from __future__ import annotations

from advisoryops.kev_medical_device_reconcile import (
    reconcile_rows,
    strict_kev_medical_device,
)


def test_healthcare_adjacent_kev_is_not_medical_device_and_legacy_bonus_is_removed():
    rows = [
        {
            "issue_id": "CVE-2026-1000",
            "cves": ["CVE-2026-1000"],
            "healthcare_category": "healthcare_it",
            "is_kev_medical_device": True,
            "score": 120,
            "priority": "P1",
            "actions": ["ingest", "track"],
            "why": [
                "source: KEV source (+80)",
                "kev-medical-device: actively exploited medical device (+40)",
                "priority: P1 (score=120)",
            ],
        }
    ]

    stats = reconcile_rows(rows, {"CVE-2026-1000"})
    row = rows[0]

    assert row["is_kev_medical_device"] is False
    assert row["score"] == 80
    assert row["priority"] == "P2"
    assert row["actions"] == ["track"]
    assert not any(str(item).startswith("kev-medical-device:") for item in row["why"])
    assert stats["legacy_flags_corrected"] == 1
    assert stats["bonuses_removed"] == 1


def test_medical_device_exact_kev_cve_gets_flag_and_bonus():
    rows = [
        {
            "issue_id": "CVE-2026-2000",
            "cves": ["CVE-2026-2000"],
            "healthcare_category": "medical_device",
            "is_kev_medical_device": False,
            "score": 80,
            "priority": "P2",
            "actions": ["track"],
            "why": ["priority: P2 (score=80)"],
        }
    ]

    stats = reconcile_rows(rows, {"CVE-2026-2000"})
    row = rows[0]

    assert row["is_kev_medical_device"] is True
    assert row["score"] == 120
    assert row["priority"] == "P1"
    assert row["actions"] == ["ingest", "track"]
    assert any(str(item).startswith("kev-medical-device:") for item in row["why"])
    assert stats["strict_kev_medical_device"] == 1
    assert stats["bonuses_added"] == 1


def test_incidental_cve_in_summary_does_not_create_overlap():
    row = {
        "issue_id": "advisory-123",
        "cves": [],
        "healthcare_category": "medical_device",
        "summary": "Background discussion mentions CVE-2026-3000 but does not assign it.",
    }

    assert strict_kev_medical_device(row, {"CVE-2026-3000"}) is False


def test_medical_device_non_kev_row_stays_unflagged():
    rows = [
        {
            "issue_id": "CVE-2026-4000",
            "cves": ["CVE-2026-4000"],
            "healthcare_category": "medical_device",
            "is_kev_medical_device": False,
            "score": 70,
            "priority": "P2",
            "actions": ["track"],
            "why": ["priority: P2 (score=70)"],
        }
    ]

    stats = reconcile_rows(rows, {"CVE-2026-9999"})

    assert rows[0]["is_kev_medical_device"] is False
    assert rows[0]["score"] == 70
    assert stats["strict_kev_medical_device"] == 0
    assert stats["legacy_flags_corrected"] == 0
