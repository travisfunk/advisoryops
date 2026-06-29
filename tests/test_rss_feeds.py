"""Feature 3 — Filtered RSS feed output tests.

Tests:
  - _write_rss produces valid XML
  - Custom title/description appear in channel
  - Filtered feeds contain only expected items
  - Item count respects top limit
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

import pytest


def _sample_issues():
    return [
        {
            "issue_id": "CVE-2024-0001",
            "title": "Critical pacemaker vuln",
            "canonical_link": "https://example.com/1",
            "summary": "Pacemaker RCE",
            "published_dates": ["2024-01-01"],
            "priority": "P0",
            "score": 200,
            "healthcare_relevant": True,
            "fda_risk_class": "3",
            "is_kev_medical_device": True,
        },
        {
            "issue_id": "CVE-2024-0002",
            "title": "Infusion pump info disclosure",
            "canonical_link": "https://example.com/2",
            "summary": "Info disclosure in pump firmware",
            "published_dates": ["2024-02-01"],
            "priority": "P2",
            "score": 75,
            "healthcare_relevant": True,
            "fda_risk_class": "2",
            "is_kev_medical_device": False,
        },
        {
            "issue_id": "CVE-2024-0003",
            "title": "Browser XSS",
            "canonical_link": "https://example.com/3",
            "summary": "XSS in Chrome",
            "published_dates": ["2024-03-01"],
            "priority": "P3",
            "score": 25,
            "healthcare_relevant": False,
            "fda_risk_class": None,
            "is_kev_medical_device": False,
        },
        {
            "issue_id": "CVE-2024-0004",
            "title": "High priority router vuln",
            "canonical_link": "https://example.com/4",
            "summary": "Router RCE",
            "published_dates": ["2024-04-01"],
            "priority": "P1",
            "score": 120,
            "healthcare_relevant": False,
            "is_kev_medical_device": False,
        },
    ]


class TestWriteRss:
    def test_produces_valid_xml(self, tmp_path):
        from advisoryops.community_build import _write_rss
        out = tmp_path / "test.xml"
        _write_rss(out, _sample_issues(), top=10)
        assert out.exists()
        tree = ET.parse(str(out))
        root = tree.getroot()
        assert root.tag == "rss"
        assert root.attrib["version"] == "2.0"

    def test_custom_title_and_description(self, tmp_path):
        from advisoryops.community_build import _write_rss
        out = tmp_path / "test.xml"
        _write_rss(out, _sample_issues(), top=10,
                    title="My Custom Feed", description="Custom desc")
        tree = ET.parse(str(out))
        channel = tree.find(".//channel")
        assert channel.find("title").text == "My Custom Feed"
        assert channel.find("description").text == "Custom desc"

    def test_item_count_respects_top(self, tmp_path):
        from advisoryops.community_build import _write_rss
        out = tmp_path / "test.xml"
        _write_rss(out, _sample_issues(), top=2)
        tree = ET.parse(str(out))
        items = tree.findall(".//item")
        assert len(items) == 2

    def test_items_have_required_fields(self, tmp_path):
        from advisoryops.community_build import _write_rss
        out = tmp_path / "test.xml"
        _write_rss(out, _sample_issues(), top=10)
        tree = ET.parse(str(out))
        items = tree.findall(".//item")
        for item in items:
            assert item.find("title") is not None
            assert item.find("link") is not None
            assert item.find("guid") is not None
            assert item.find("description") is not None


class TestFilteredFeeds:
    def test_healthcare_filter(self, tmp_path):
        from advisoryops.community_build import _write_rss
        issues = _sample_issues()
        hc = [i for i in issues if i.get("healthcare_relevant")]
        out = tmp_path / "feed_healthcare.xml"
        _write_rss(out, hc, top=100)
        tree = ET.parse(str(out))
        items = tree.findall(".//item")
        assert len(items) == 2  # Only the 2 healthcare issues

    def test_class_3_filter(self, tmp_path):
        from advisoryops.community_build import _write_rss
        issues = _sample_issues()
        c3 = [i for i in issues if i.get("fda_risk_class") == "3"]
        out = tmp_path / "feed_class_3.xml"
        _write_rss(out, c3, top=100)
        tree = ET.parse(str(out))
        items = tree.findall(".//item")
        assert len(items) == 1
        assert "pacemaker" in items[0].find("title").text.lower()

    def test_kev_medical_device_filter(self, tmp_path):
        from advisoryops.community_build import _write_rss
        issues = _sample_issues()
        kev_med = [i for i in issues if i.get("is_kev_medical_device")]
        out = tmp_path / "feed_kev_med.xml"
        _write_rss(out, kev_med, top=100)
        tree = ET.parse(str(out))
        items = tree.findall(".//item")
        assert len(items) == 1

    def test_p0_p1_filter(self, tmp_path):
        from advisoryops.community_build import _write_rss
        issues = _sample_issues()
        high = [i for i in issues if i.get("priority") in ("P0", "P1")]
        out = tmp_path / "feed_p0_p1.xml"
        _write_rss(out, high, top=100)
        tree = ET.parse(str(out))
        items = tree.findall(".//item")
        assert len(items) == 2  # P0 pacemaker + P1 router

    def test_empty_feed_is_valid_xml(self, tmp_path):
        from advisoryops.community_build import _write_rss
        out = tmp_path / "empty.xml"
        _write_rss(out, [], top=100)
        tree = ET.parse(str(out))
        items = tree.findall(".//item")
        assert len(items) == 0
