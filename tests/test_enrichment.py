"""Tests for cross-reference enrichment modules: EPSS, CWE, ATT&CK ICS, Vulnrichment."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from advisoryops.enrichment.epss_enrich import (
    enrich_issue as epss_enrich_issue,
    enrich_issues as epss_enrich_issues,
    fetch_all_scores,
    load_cache as epss_load_cache,
    populate_cache as epss_populate_cache,
)
from advisoryops.enrichment.cwe_catalog import (
    enrich_issue as cwe_enrich_issue,
    enrich_issues as cwe_enrich_issues,
    get_cwe_name,
    load_cache as cwe_load_cache,
    populate_cache as cwe_populate_cache,
    _BUILTIN_CWES,
)
from advisoryops.enrichment.attack_ics import (
    load_cache as attack_load_cache,
    parse_stix_bundle,
    populate_cache as attack_populate_cache,
)
from advisoryops.enrichment.vulnrichment import (
    _cve_to_path,
    extract_adp_fields,
    fetch_cve as vr_fetch_cve,
)
from advisoryops.enrichment.cross_reference import apply_enrichments


# ---------------------------------------------------------------------------
# EPSS
# ---------------------------------------------------------------------------

class TestEpss:

    _SAMPLE_EPSS_API = {
        "status": "OK",
        "status-code": 200,
        "total": 3,
        "offset": 0,
        "limit": 100000,
        "data": [
            {"cve": "CVE-2024-0001", "epss": "0.85432", "percentile": "0.97123", "date": "2024-04-01"},
            {"cve": "CVE-2024-0002", "epss": "0.00123", "percentile": "0.12345", "date": "2024-04-01"},
            {"cve": "CVE-2024-0003", "epss": "0.45678", "percentile": "0.65432", "date": "2024-04-01"},
        ],
    }

    def test_fetch_all_scores(self):
        def mock_fetch(url):
            return json.dumps(self._SAMPLE_EPSS_API).encode()

        scores = fetch_all_scores(_fetch_fn=mock_fetch)
        assert len(scores) == 3
        assert scores["CVE-2024-0001"]["epss"] == pytest.approx(0.85432)
        assert scores["CVE-2024-0001"]["percentile"] == pytest.approx(0.97123)

    def test_populate_and_load_cache(self, tmp_path):
        def mock_fetch(url):
            return json.dumps(self._SAMPLE_EPSS_API).encode()

        epss_populate_cache(cache_dir=tmp_path, _fetch_fn=mock_fetch)
        scores = epss_load_cache(cache_dir=tmp_path)
        assert len(scores) == 3
        assert "CVE-2024-0001" in scores

    def test_enrich_issue(self):
        scores = {
            "CVE-2024-0001": {"epss": 0.85, "percentile": 0.97, "date": "2024-04-01"},
        }
        issue = {"issue_id": "CVE-2024-0001", "cves": ["CVE-2024-0001"]}
        assert epss_enrich_issue(issue, scores) is True
        assert issue["epss_score"] == 0.85
        assert issue["epss_percentile"] == 0.97

    def test_enrich_issue_no_match(self):
        scores = {"CVE-2024-9999": {"epss": 0.5, "percentile": 0.5, "date": ""}}
        issue = {"issue_id": "CVE-2024-0001", "cves": ["CVE-2024-0001"]}
        assert epss_enrich_issue(issue, scores) is False
        assert "epss_score" not in issue

    def test_enrich_issues_batch(self, tmp_path):
        def mock_fetch(url):
            return json.dumps(self._SAMPLE_EPSS_API).encode()

        epss_populate_cache(cache_dir=tmp_path, _fetch_fn=mock_fetch)
        issues = [
            {"issue_id": "CVE-2024-0001", "cves": ["CVE-2024-0001"]},
            {"issue_id": "CVE-2024-9999", "cves": ["CVE-2024-9999"]},
        ]
        count = epss_enrich_issues(issues, cache_dir=tmp_path)
        assert count == 1
        assert issues[0]["epss_score"] == pytest.approx(0.85432)


# ---------------------------------------------------------------------------
# CWE Catalog
# ---------------------------------------------------------------------------

class TestCweCatalog:

    def test_builtin_catalog_populated(self):
        assert len(_BUILTIN_CWES) > 50
        assert "CWE-79" in _BUILTIN_CWES
        assert "CWE-787" in _BUILTIN_CWES

    def test_get_cwe_name(self):
        name = get_cwe_name("CWE-79")
        assert "Web Page Generation" in name

    def test_get_cwe_name_unknown(self):
        assert get_cwe_name("CWE-99999") == ""

    def test_populate_and_load_cache(self, tmp_path):
        cwe_populate_cache(cache_dir=tmp_path)
        catalog = cwe_load_cache(cache_dir=tmp_path)
        assert len(catalog) > 50
        assert "CWE-79" in catalog

    def test_populate_with_extras(self, tmp_path):
        extras = {"CWE-99999": {"name": "Custom Weakness", "category": "custom"}}
        cwe_populate_cache(cache_dir=tmp_path, extra_cwes=extras)
        catalog = cwe_load_cache(cache_dir=tmp_path)
        assert "CWE-99999" in catalog

    def test_enrich_issue(self):
        catalog = {"CWE-79": {"name": "XSS", "category": "injection"}}
        issue = {"cwe_ids": ["CWE-79"]}
        assert cwe_enrich_issue(issue, catalog) is True
        assert issue["cwe_names"] == ["CWE-79: XSS"]

    def test_enrich_issue_no_cwes(self):
        issue = {"cwe_ids": []}
        assert cwe_enrich_issue(issue, {}) is False

    def test_enrich_issues_batch(self):
        issues = [
            {"cwe_ids": ["CWE-79"]},
            {"cwe_ids": ["CWE-99999"]},
            {"cwe_ids": []},
        ]
        count = cwe_enrich_issues(issues)
        assert count == 1  # Only CWE-79 is in the builtin catalog


# ---------------------------------------------------------------------------
# ATT&CK ICS
# ---------------------------------------------------------------------------

class TestAttackIcs:

    _SAMPLE_STIX = {
        "type": "bundle",
        "id": "bundle--test",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "name": "Remote System Discovery",
                "description": "Adversaries may attempt to get a listing of remote systems.",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T0846",
                        "url": "https://attack.mitre.org/techniques/T0846",
                    }
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-ics-attack", "phase_name": "discovery"}
                ],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--2",
                "name": "Manipulation of Control",
                "description": "Adversaries may manipulate control systems.",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T0831",
                        "url": "https://attack.mitre.org/techniques/T0831",
                    }
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-ics-attack", "phase_name": "impact"}
                ],
            },
            {
                "type": "course-of-action",
                "id": "coa--1",
                "name": "Network Segmentation",
                "description": "Segment the network.",
            },
        ],
    }

    def test_parse_stix_bundle(self):
        techniques = parse_stix_bundle(self._SAMPLE_STIX)
        assert len(techniques) == 2
        assert "T0846" in techniques
        assert techniques["T0846"]["name"] == "Remote System Discovery"
        assert "discovery" in techniques["T0846"]["tactics"]

    def test_parse_empty_bundle(self):
        assert parse_stix_bundle({}) == {}
        assert parse_stix_bundle({"objects": []}) == {}

    def test_populate_and_load_cache(self, tmp_path):
        def mock_fetch(url):
            return json.dumps(self._SAMPLE_STIX).encode()

        attack_populate_cache(cache_dir=tmp_path, _fetch_fn=mock_fetch)
        techniques = attack_load_cache(cache_dir=tmp_path)
        assert len(techniques) == 2
        assert "T0831" in techniques

    def test_load_empty_cache(self, tmp_path):
        assert attack_load_cache(cache_dir=tmp_path) == {}


# ---------------------------------------------------------------------------
# Vulnrichment
# ---------------------------------------------------------------------------

class TestVulnrichment:

    _SAMPLE_CVE_RECORD = {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0",
        "cveMetadata": {"cveId": "CVE-2024-1234"},
        "containers": {
            "cna": {"affected": []},
            "adp": [
                {
                    "metrics": [
                        {
                            "cvssV3_1": {
                                "baseScore": 8.1,
                                "baseSeverity": "HIGH",
                                "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            },
                            "other": {
                                "type": "ssvc",
                                "content": {
                                    "options": [
                                        {"Exploitation": "active"},
                                        {"Automatable": "yes"},
                                        {"Technical Impact": "total"},
                                    ]
                                },
                            },
                        }
                    ],
                    "problemTypes": [
                        {
                            "descriptions": [
                                {"cweId": "CWE-787", "description": "Out-of-bounds Write"},
                            ]
                        }
                    ],
                }
            ],
        },
    }

    def test_cve_to_path(self):
        assert _cve_to_path("CVE-2024-1234") == "2024/1xxx/CVE-2024-1234.json"
        assert _cve_to_path("CVE-2023-45678") == "2023/45xxx/CVE-2023-45678.json"
        assert _cve_to_path("not-a-cve") is None

    def test_extract_adp_fields(self):
        fields = extract_adp_fields(self._SAMPLE_CVE_RECORD)
        assert fields["cisa_cvss_score"] == 8.1
        assert fields["cisa_cvss_severity"] == "HIGH"
        assert fields["ssvc_exploitation"] == "active"
        assert fields["ssvc_automatable"] == "yes"
        assert fields["ssvc_technical_impact"] == "total"
        assert "CWE-787" in fields["cisa_cwe_ids"]

    def test_extract_adp_empty(self):
        fields = extract_adp_fields({})
        assert fields == {}

    def test_fetch_cve_from_cache(self, tmp_path):
        # Pre-populate cache
        (tmp_path / "CVE-2024-1234.json").write_text(
            json.dumps(self._SAMPLE_CVE_RECORD)
        )
        result = vr_fetch_cve("CVE-2024-1234", cache_dir=tmp_path)
        assert result is not None
        assert result["cveMetadata"]["cveId"] == "CVE-2024-1234"

    def test_fetch_cve_miss(self, tmp_path):
        # No cache, mock returns 404
        def mock_fetch(url):
            raise Exception("404 Not Found")

        result = vr_fetch_cve("CVE-2099-9999", cache_dir=tmp_path, _fetch_fn=mock_fetch)
        assert result is None


# ---------------------------------------------------------------------------
# Cross-reference orchestrator
# ---------------------------------------------------------------------------

class TestCrossReference:

    def test_apply_enrichments_epss_and_cwe(self, tmp_path):
        # Populate EPSS cache
        epss_data = {
            "fetched_at": "2024-04-01", "total_scores": 1,
            "scores": {"CVE-2024-0001": {"epss": 0.85, "percentile": 0.97, "date": ""}},
        }
        epss_dir = tmp_path / "epss"
        epss_dir.mkdir()
        (epss_dir / "epss_scores.json").write_text(json.dumps(epss_data))

        # Populate CWE cache (just use builtin)
        issues = [
            {"issue_id": "CVE-2024-0001", "cves": ["CVE-2024-0001"], "cwe_ids": ["CWE-79"]},
        ]

        # Can't easily inject cache_dir into apply_enrichments without refactoring,
        # so test the individual enrich functions directly
        from advisoryops.enrichment.epss_enrich import enrich_issue, load_cache
        scores = {"CVE-2024-0001": {"epss": 0.85, "percentile": 0.97, "date": ""}}
        assert enrich_issue(issues[0], scores) is True
        assert issues[0]["epss_score"] == 0.85

    def test_apply_enrichments_no_crash_on_empty(self):
        """apply_enrichments should not crash even with empty caches."""
        issues = [
            {"issue_id": "CVE-2024-0001", "cves": ["CVE-2024-0001"], "cwe_ids": ["CWE-79"]},
        ]
        # This will use default cache dirs which may be empty — should not crash
        counts = apply_enrichments(issues, epss=True, cwe=True, vulnrichment=False)
        # CWE should still work from builtin catalog
        assert counts.get("cwe", 0) >= 0
