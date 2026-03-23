"""Tests for advisoryops.contradiction_detector (Task 8.5)."""
from __future__ import annotations

import pytest

from advisoryops.contradiction_detector import (
    detect_contradictions,
    detect_contradictions_with_summary,
    _extract_severities,
    _extract_cves,
    _extract_patch_status,
    _extract_exploit_status,
    _source_facts,
    _build_consensus,
)


# ---------------------------------------------------------------------------
# Extraction helper tests
# ---------------------------------------------------------------------------

class TestExtractSeverities:
    def test_critical(self):
        assert _extract_severities("CVSS Critical vulnerability") == {"critical"}

    def test_multiple(self):
        assert _extract_severities("High severity, some say Medium") == {"high", "medium"}

    def test_moderate_normalizes(self):
        assert _extract_severities("Moderate risk") == {"medium"}

    def test_empty(self):
        assert _extract_severities("no severity mentioned") == set()

    def test_case_insensitive(self):
        assert _extract_severities("LOW risk HIGH impact") == {"low", "high"}


class TestExtractCves:
    def test_single(self):
        assert _extract_cves("Fixed CVE-2024-1234 today") == {"CVE-2024-1234"}

    def test_multiple(self):
        result = _extract_cves("CVE-2024-1234 and CVE-2024-5678")
        assert result == {"CVE-2024-1234", "CVE-2024-5678"}

    def test_none(self):
        assert _extract_cves("no cve here") == set()


class TestExtractPatchStatus:
    def test_patch_available(self):
        assert "patch_available" in _extract_patch_status("Patch released for v3.2")

    def test_no_patch(self):
        assert "no_patch" in _extract_patch_status("No patch available yet")

    def test_workaround(self):
        assert "workaround" in _extract_patch_status("Apply the workaround")

    def test_empty(self):
        assert _extract_patch_status("nothing relevant") == set()


class TestExtractExploitStatus:
    def test_actively_exploited(self):
        assert "actively_exploited" in _extract_exploit_status("Actively exploited in the wild")

    def test_poc(self):
        assert "poc_available" in _extract_exploit_status("PoC published on GitHub")

    def test_empty(self):
        assert _extract_exploit_status("no exploit info") == set()


# ---------------------------------------------------------------------------
# Source facts extraction
# ---------------------------------------------------------------------------

class TestSourceFacts:
    def test_extracts_from_matching_source(self):
        signals = [
            {"source": "cisa-icsma", "title": "Critical vuln CVE-2024-1234", "summary": "Patch released", "link": "https://example.com/1"},
            {"source": "vendor-psirt", "title": "High severity issue", "summary": "No fix available", "link": "https://vendor.com/1"},
        ]
        facts = _source_facts(signals, "cisa-icsma")
        assert "critical" in facts["severities"]
        assert "CVE-2024-1234" in facts["cves"]
        assert "patch_available" in facts["patch_status"]
        assert "https://example.com/1" in facts["links"]

    def test_ignores_other_sources(self):
        signals = [
            {"source": "vendor-psirt", "title": "High severity", "summary": "", "link": ""},
        ]
        facts = _source_facts(signals, "cisa-icsma")
        assert facts["severities"] == set()


# ---------------------------------------------------------------------------
# Consensus builder
# ---------------------------------------------------------------------------

class TestBuildConsensus:
    def test_severity_agreement(self):
        facts = {
            "src_a": {"severities": {"critical"}, "cves": set(), "patch_status": set(), "exploit_status": set(), "links": set()},
            "src_b": {"severities": {"critical"}, "cves": set(), "patch_status": set(), "exploit_status": set(), "links": set()},
        }
        consensus = _build_consensus(facts)
        assert "severity: critical" in consensus["agreed"]
        assert consensus["contradicted"] == []

    def test_severity_contradiction(self):
        facts = {
            "src_a": {"severities": {"critical"}, "cves": set(), "patch_status": set(), "exploit_status": set(), "links": set()},
            "src_b": {"severities": {"high"}, "cves": set(), "patch_status": set(), "exploit_status": set(), "links": set()},
        }
        consensus = _build_consensus(facts)
        assert len(consensus["contradicted"]) == 1
        assert consensus["contradicted"][0]["field"] == "severity"

    def test_patch_contradiction(self):
        facts = {
            "src_a": {"severities": set(), "cves": set(), "patch_status": {"patch_available"}, "exploit_status": set(), "links": set()},
            "src_b": {"severities": set(), "cves": set(), "patch_status": {"no_patch"}, "exploit_status": set(), "links": set()},
        }
        consensus = _build_consensus(facts)
        assert any(c["field"] == "patch_status" for c in consensus["contradicted"])

    def test_unique_cve_contributions(self):
        facts = {
            "src_a": {"severities": set(), "cves": {"CVE-2024-1111", "CVE-2024-2222"}, "patch_status": set(), "exploit_status": set(), "links": set()},
            "src_b": {"severities": set(), "cves": {"CVE-2024-1111"}, "patch_status": set(), "exploit_status": set(), "links": set()},
        }
        consensus = _build_consensus(facts)
        assert "CVEs: CVE-2024-1111" in consensus["agreed"]
        assert "src_a" in consensus["unique_contributions"]
        contribs = consensus["unique_contributions"]["src_a"]
        assert any("CVE-2024-2222" in c for c in contribs)

    def test_single_source_severity_unique(self):
        facts = {
            "src_a": {"severities": {"high"}, "cves": set(), "patch_status": set(), "exploit_status": set(), "links": set()},
            "src_b": {"severities": set(), "cves": set(), "patch_status": set(), "exploit_status": set(), "links": set()},
        }
        consensus = _build_consensus(facts)
        assert "src_a" in consensus["unique_contributions"]

    def test_empty_consensus_when_no_facts(self):
        facts = {
            "src_a": {"severities": set(), "cves": set(), "patch_status": set(), "exploit_status": set(), "links": set()},
            "src_b": {"severities": set(), "cves": set(), "patch_status": set(), "exploit_status": set(), "links": set()},
        }
        consensus = _build_consensus(facts)
        assert consensus["agreed"] == []
        assert consensus["contradicted"] == []


# ---------------------------------------------------------------------------
# Integration: detect_contradictions
# ---------------------------------------------------------------------------

class TestDetectContradictions:
    def _make_issue(self, issue_id, sources, signals):
        return {
            "issue_id": issue_id,
            "sources": sources,
            "signals": signals,
            "title": "",
            "summary": "",
        }

    def test_single_source_gets_empty_consensus(self):
        issue = self._make_issue("CVE-2024-0001", ["src_a"], [
            {"source": "src_a", "title": "Critical RCE", "summary": "", "link": ""},
        ])
        result = detect_contradictions([issue])
        assert result[0]["source_consensus"]["agreed"] == []
        assert result[0]["source_consensus"]["contradicted"] == []

    def test_multi_source_agreement(self):
        issue = self._make_issue("CVE-2024-0002", ["cisa", "vendor"], [
            {"source": "cisa", "title": "Critical CVE-2024-0002", "summary": "Patch released", "link": "https://cisa.gov/1"},
            {"source": "vendor", "title": "Critical CVE-2024-0002", "summary": "Patch released for v2.0", "link": "https://vendor.com/1"},
        ])
        result = detect_contradictions([issue])
        consensus = result[0]["source_consensus"]
        assert any("critical" in a for a in consensus["agreed"])
        assert consensus["contradicted"] == []

    def test_multi_source_severity_contradiction(self):
        issue = self._make_issue("CVE-2024-0003", ["cisa", "vendor"], [
            {"source": "cisa", "title": "Critical vulnerability", "summary": "", "link": ""},
            {"source": "vendor", "title": "High severity issue", "summary": "", "link": ""},
        ])
        result = detect_contradictions([issue])
        consensus = result[0]["source_consensus"]
        assert len(consensus["contradicted"]) >= 1
        assert consensus["contradicted"][0]["field"] == "severity"

    def test_multi_source_patch_contradiction(self):
        issue = self._make_issue("CVE-2024-0004", ["cisa", "vendor"], [
            {"source": "cisa", "title": "CVE-2024-0004", "summary": "No patch available", "link": ""},
            {"source": "vendor", "title": "CVE-2024-0004", "summary": "Patch released v3.1", "link": ""},
        ])
        result = detect_contradictions([issue])
        consensus = result[0]["source_consensus"]
        assert any(c["field"] == "patch_status" for c in consensus["contradicted"])

    def test_unique_contributions_links(self):
        issue = self._make_issue("CVE-2024-0005", ["src_a", "src_b"], [
            {"source": "src_a", "title": "vuln", "summary": "", "link": "https://a.com/1"},
            {"source": "src_b", "title": "vuln", "summary": "", "link": "https://b.com/1"},
        ])
        result = detect_contradictions([issue])
        uc = result[0]["source_consensus"]["unique_contributions"]
        # Both should have unique links
        assert "src_a" in uc or "src_b" in uc

    def test_multiple_issues_processed(self):
        issues = [
            self._make_issue("CVE-2024-0010", ["a"], [
                {"source": "a", "title": "test", "summary": "", "link": ""},
            ]),
            self._make_issue("CVE-2024-0011", ["a", "b"], [
                {"source": "a", "title": "Critical", "summary": "", "link": ""},
                {"source": "b", "title": "High", "summary": "", "link": ""},
            ]),
        ]
        result = detect_contradictions(issues)
        assert len(result) == 2
        assert "source_consensus" in result[0]
        assert "source_consensus" in result[1]


class TestDetectContradictionsWithSummary:
    def test_summary_counts(self):
        issues = [
            {
                "issue_id": "CVE-2024-0001",
                "sources": ["a"],
                "signals": [{"source": "a", "title": "test", "summary": "", "link": ""}],
            },
            {
                "issue_id": "CVE-2024-0002",
                "sources": ["a", "b"],
                "signals": [
                    {"source": "a", "title": "Critical", "summary": "", "link": ""},
                    {"source": "b", "title": "High", "summary": "", "link": ""},
                ],
            },
        ]
        annotated, summary = detect_contradictions_with_summary(issues)
        assert summary["total_issues"] == 2
        assert summary["multi_source_issues"] == 1
        assert summary["issues_with_contradictions"] == 1
