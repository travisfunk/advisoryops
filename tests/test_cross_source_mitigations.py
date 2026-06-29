"""Tests for cross-source CVE mitigation correlation."""
from __future__ import annotations

import pytest

from advisoryops.source_mitigations import correlate_mitigations_by_cve


def _make_issue(issue_id, cves=None, source_mitigations=None, **kw):
    base = {
        "issue_id": issue_id,
        "title": f"Test {issue_id}",
        "summary": "Test",
        "sources": ["cisa-icsma"],
        "cves": cves or [],
        "source_mitigations": source_mitigations or [],
        "priority": "P0",
    }
    base.update(kw)
    return base


class TestCorrelationByCVE:

    def test_fills_empty_issue_from_shared_cve(self):
        issues = [
            _make_issue("ISS-1", cves=["CVE-2024-1234"], source_mitigations=[
                {"source": "cisa-icsma", "source_tier": 1, "action": "Apply patch",
                 "citation": "ICSMA-1", "url": "https://cisa.gov/1", "mitigation_type": "patch"},
            ]),
            _make_issue("ISS-2", cves=["CVE-2024-1234"], source_mitigations=[]),
        ]
        count = correlate_mitigations_by_cve(issues)
        assert count == 1
        assert len(issues[1]["source_mitigations"]) == 1
        assert "via CVE-2024-1234" in issues[1]["source_mitigations"][0]["source"]

    def test_cross_source_flag_set(self):
        issues = [
            _make_issue("ISS-1", cves=["CVE-2024-1234"], source_mitigations=[
                {"source": "cisa-icsma", "source_tier": 1, "action": "Isolate device",
                 "citation": "IC-1", "url": "https://cisa.gov/1", "mitigation_type": "network"},
            ]),
            _make_issue("ISS-2", cves=["CVE-2024-1234"]),
        ]
        correlate_mitigations_by_cve(issues)
        assert issues[1]["source_mitigations"][0]["cross_source"] is True

    def test_does_not_overwrite_existing(self):
        existing_mit = {"source": "tenable", "source_tier": 2, "action": "Existing",
                        "citation": "T-1", "url": "https://t.com", "mitigation_type": "patch"}
        issues = [
            _make_issue("ISS-1", cves=["CVE-2024-1234"], source_mitigations=[
                {"source": "cisa-icsma", "source_tier": 1, "action": "Apply patch",
                 "citation": "IC-1", "url": "https://cisa.gov/1", "mitigation_type": "patch"},
            ]),
            _make_issue("ISS-2", cves=["CVE-2024-1234"], source_mitigations=[existing_mit]),
        ]
        count = correlate_mitigations_by_cve(issues)
        assert count == 0
        assert issues[1]["source_mitigations"] == [existing_mit]

    def test_empty_cves_returns_zero(self):
        issues = [
            _make_issue("ISS-1", cves=[], source_mitigations=[]),
            _make_issue("ISS-2", cves=[], source_mitigations=[]),
        ]
        count = correlate_mitigations_by_cve(issues)
        assert count == 0

    def test_no_matching_cves(self):
        issues = [
            _make_issue("ISS-1", cves=["CVE-2024-1111"], source_mitigations=[
                {"source": "cisa", "source_tier": 1, "action": "Patch",
                 "citation": "C-1", "url": "https://c.gov", "mitigation_type": "patch"},
            ]),
            _make_issue("ISS-2", cves=["CVE-2024-9999"]),
        ]
        count = correlate_mitigations_by_cve(issues)
        assert count == 0
        assert issues[1].get("source_mitigations") == []

    def test_deduplicates_actions(self):
        mit = {"source": "cisa", "source_tier": 1, "action": "Apply patch",
               "citation": "C-1", "url": "https://c.gov", "mitigation_type": "patch"}
        issues = [
            _make_issue("ISS-1", cves=["CVE-2024-1234", "CVE-2024-5678"],
                        source_mitigations=[mit]),
            _make_issue("ISS-2", cves=["CVE-2024-1234", "CVE-2024-5678"]),
        ]
        correlate_mitigations_by_cve(issues)
        # Same action from same source via two CVEs should only appear once
        assert len(issues[1]["source_mitigations"]) == 1

    def test_multiple_sources(self):
        issues = [
            _make_issue("ISS-1", cves=["CVE-2024-1234"], source_mitigations=[
                {"source": "cisa", "source_tier": 1, "action": "Apply patch",
                 "citation": "C-1", "url": "https://c.gov", "mitigation_type": "patch"},
            ]),
            _make_issue("ISS-3", cves=["CVE-2024-1234"], source_mitigations=[
                {"source": "vendor", "source_tier": 3, "action": "Update firmware",
                 "citation": "V-1", "url": "https://v.com", "mitigation_type": "patch"},
            ]),
            _make_issue("ISS-2", cves=["CVE-2024-1234"]),
        ]
        correlate_mitigations_by_cve(issues)
        assert len(issues[2]["source_mitigations"]) == 2
