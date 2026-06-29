"""Tests that source_mitigations and iocs flow through _feed_entry()."""
from __future__ import annotations

import pytest

from advisoryops.community_build import _feed_entry


def _make_issue(**overrides):
    base = {
        "issue_id": "CVE-2024-TEST",
        "issue_type": "cve",
        "title": "Test Issue",
        "summary": "Test summary",
        "canonical_link": "",
        "cves": [],
        "sources": ["cisa-icsma"],
        "published_dates": [],
        "first_seen_at": "",
        "last_seen_at": "",
        "score": 100,
        "priority": "P1",
        "actions": [],
    }
    base.update(overrides)
    return base


class TestFeedEntryPassthrough:

    def test_source_mitigations_passed_through(self):
        mits = [
            {
                "source": "cisa-icsma",
                "source_tier": 1,
                "action": "Apply patch v2.0",
                "citation": "ICSMA-2024-001",
                "url": "https://cisa.gov/icsma-001",
                "mitigation_type": "patch",
            }
        ]
        issue = _make_issue(source_mitigations=mits)
        entry = _feed_entry(issue)
        assert entry["source_mitigations"] == mits

    def test_iocs_passed_through(self):
        iocs = [
            {"type": "cve", "value": "CVE-2024-1234", "source": "cisa-icsma"},
            {"type": "ip", "value": "10.0.0.1", "source": "mandiant-blog"},
        ]
        issue = _make_issue(iocs=iocs)
        entry = _feed_entry(issue)
        assert entry["iocs"] == iocs

    def test_missing_fields_default_empty(self):
        issue = _make_issue()
        entry = _feed_entry(issue)
        assert entry["source_mitigations"] == []
        assert entry["iocs"] == []
