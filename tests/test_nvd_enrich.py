"""Tests for NVD enrichment, KEV field extraction, summary dedup, and action translation."""
from __future__ import annotations

import json
from pathlib import Path

from advisoryops.nvd_enrich import (
    _RateLimiter,
    _extract_nvd_fields,
    _parse_cpe_product,
    deduplicate_summary,
    enrich_issue,
    enrich_issues,
    generate_remediation_steps,
)


# ---------------------------------------------------------------------------
# Fixtures: realistic NVD API response fragments
# ---------------------------------------------------------------------------

def _nvd_cve_item(
    *,
    cve_id: str = "CVE-2008-0015",
    description: str = "Stack-based buffer overflow in Microsoft Video ActiveX Control.",
    base_score: float = 9.3,
    severity: str = "HIGH",
    vector: str = "AV:N/AC:M/Au:N/C:C/I:C/A:C",
    cwe: str = "CWE-119",
    cpe: str = "cpe:2.3:a:microsoft:video_activex_control:*:*:*:*:*:*:*:*",
    use_v31: bool = True,
) -> dict:
    """Build a realistic NVD CVE 2.0 item."""
    metrics = {}
    if use_v31:
        metrics["cvssMetricV31"] = [{
            "cvssData": {
                "baseScore": base_score,
                "baseSeverity": severity,
                "vectorString": vector,
            }
        }]
    else:
        metrics["cvssMetricV2"] = [{
            "cvssData": {
                "baseScore": base_score,
                "vectorString": vector,
            }
        }]

    return {
        "id": cve_id,
        "descriptions": [
            {"lang": "en", "value": description},
        ],
        "metrics": metrics,
        "weaknesses": [
            {"description": [{"lang": "en", "value": cwe}]},
        ],
        "configurations": [
            {
                "nodes": [{
                    "cpeMatch": [
                        {"criteria": cpe, "vulnerable": True},
                    ]
                }]
            }
        ],
    }


# ---------------------------------------------------------------------------
# NVD field extraction
# ---------------------------------------------------------------------------

class TestExtractNvdFields:

    def test_extracts_description(self):
        item = _nvd_cve_item(description="Buffer overflow in MSVIDCTL.DLL")
        fields = _extract_nvd_fields(item)
        assert fields["nvd_description"] == "Buffer overflow in MSVIDCTL.DLL"

    def test_extracts_cvss_v31(self):
        item = _nvd_cve_item(base_score=9.3, severity="CRITICAL", vector="CVSS:3.1/AV:N")
        fields = _extract_nvd_fields(item)
        assert fields["cvss_score"] == 9.3
        assert fields["cvss_severity"] == "CRITICAL"
        assert fields["cvss_vector"] == "CVSS:3.1/AV:N"

    def test_falls_back_to_v2(self):
        item = _nvd_cve_item(base_score=9.3, use_v31=False)
        fields = _extract_nvd_fields(item)
        assert fields["cvss_score"] == 9.3
        # v2 has no baseSeverity — should derive from score
        assert fields["cvss_severity"] == "CRITICAL"

    def test_v2_severity_derivation_medium(self):
        item = _nvd_cve_item(base_score=5.0, use_v31=False)
        fields = _extract_nvd_fields(item)
        assert fields["cvss_severity"] == "MEDIUM"

    def test_v2_severity_derivation_low(self):
        item = _nvd_cve_item(base_score=2.5, use_v31=False)
        fields = _extract_nvd_fields(item)
        assert fields["cvss_severity"] == "LOW"

    def test_extracts_cwe_ids(self):
        item = _nvd_cve_item(cwe="CWE-119")
        fields = _extract_nvd_fields(item)
        assert "CWE-119" in fields["cwe_ids"]

    def test_extracts_affected_products(self):
        item = _nvd_cve_item(cpe="cpe:2.3:a:microsoft:video_activex_control:*:*:*:*:*:*:*:*")
        fields = _extract_nvd_fields(item)
        assert len(fields["affected_products"]) >= 1
        assert "Microsoft" in fields["affected_products"][0]

    def test_empty_item_returns_partial(self):
        fields = _extract_nvd_fields({})
        assert fields.get("cwe_ids") == []
        assert fields.get("affected_products") == []


class TestParseCpeProduct:

    def test_standard_cpe(self):
        result = _parse_cpe_product("cpe:2.3:a:microsoft:internet_explorer:6.0:*:*:*:*:*:*:*")
        assert "Microsoft" in result
        assert "Internet Explorer" in result

    def test_wildcard_vendor(self):
        result = _parse_cpe_product("cpe:2.3:a:*:some_product:1.0:*:*:*:*:*:*:*")
        assert result == "Some Product"

    def test_wildcard_product(self):
        result = _parse_cpe_product("cpe:2.3:a:linux:*:*:*:*:*:*:*:*:*")
        assert result == "Linux"


# ---------------------------------------------------------------------------
# Caching
# ---------------------------------------------------------------------------

class TestNvdCache:

    def test_cached_cves_are_not_refetched(self, tmp_path: Path):
        cache_dir = tmp_path / "nvd_cache"
        cache_dir.mkdir()

        # Pre-populate cache
        cached_data = {
            "nvd_description": "Cached description",
            "cvss_score": 7.5,
            "cvss_severity": "HIGH",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L",
            "cwe_ids": ["CWE-79"],
            "affected_products": ["Acme Widget"],
        }
        (cache_dir / "CVE-2024-1234.json").write_text(json.dumps(cached_data))

        # Track if fetch was called
        fetch_called = []

        def mock_fetch(cve_id):
            fetch_called.append(cve_id)
            return {"nvd_description": "SHOULD NOT USE THIS"}

        issue = {"issue_id": "CVE-2024-1234", "cves": ["CVE-2024-1234"]}
        enrich_issue(issue, cache_dir=cache_dir, _fetch_fn=mock_fetch)

        # Should have used cache, NOT called the fetcher
        assert fetch_called == []
        assert issue["nvd_description"] == "Cached description"
        assert issue["cvss_score"] == 7.5

    def test_fetched_data_is_cached(self, tmp_path: Path):
        cache_dir = tmp_path / "nvd_cache"

        def mock_fetch(cve_id):
            return {
                "nvd_description": "Fresh from API",
                "cvss_score": 8.0,
                "cvss_severity": "HIGH",
                "cvss_vector": "CVSS:3.1/AV:N",
                "cwe_ids": ["CWE-89"],
                "affected_products": ["Test Product"],
            }

        issue = {"issue_id": "CVE-2024-5678", "cves": ["CVE-2024-5678"]}
        enrich_issue(issue, cache_dir=cache_dir, _fetch_fn=mock_fetch)

        assert issue["nvd_description"] == "Fresh from API"
        # Verify cache was written
        cache_file = cache_dir / "CVE-2024-5678.json"
        assert cache_file.exists()
        cached = json.loads(cache_file.read_text())
        assert cached["cvss_score"] == 8.0

    def test_enrich_issues_batch(self, tmp_path: Path):
        cache_dir = tmp_path / "nvd_cache"
        call_log = []

        def mock_fetch(cve_id):
            call_log.append(cve_id)
            return {
                "nvd_description": f"Desc for {cve_id}",
                "cvss_score": 7.0,
                "cvss_severity": "HIGH",
                "cvss_vector": "V",
                "cwe_ids": [],
                "affected_products": [],
            }

        issues = [
            {"issue_id": "CVE-2024-0001", "cves": ["CVE-2024-0001"]},
            {"issue_id": "CVE-2024-0002", "cves": ["CVE-2024-0002"]},
            {"issue_id": "UNK-abc123", "cves": []},  # no CVEs, should skip
        ]
        count = enrich_issues(issues, cache_dir=cache_dir, _fetch_fn=mock_fetch)
        assert count == 2
        assert len(call_log) == 2
        assert issues[0]["nvd_description"] == "Desc for CVE-2024-0001"
        assert issues[1]["nvd_description"] == "Desc for CVE-2024-0002"
        assert "nvd_description" not in issues[2]


# ---------------------------------------------------------------------------
# Summary deduplication
# ---------------------------------------------------------------------------

class TestSummaryDedup:

    def test_nvd_description_replaces_blob(self):
        issue = {
            "issue_id": "CVE-2008-0015",
            "summary": "CISA has added four new vulnerabilities to the KEV catalog. CVE-2008-0015 is a buffer overflow. CVE-2024-9999 is something else.",
            "nvd_description": "Stack-based buffer overflow in Microsoft Video ActiveX Control.",
        }
        deduplicate_summary(issue)
        assert issue["summary"] == "Stack-based buffer overflow in Microsoft Video ActiveX Control."
        assert "CISA has added four" in issue["source_summary"]

    def test_no_nvd_extracts_relevant_sentence(self):
        issue = {
            "issue_id": "CVE-2008-0015",
            "summary": "CISA has added four new vulnerabilities. CVE-2008-0015 is a buffer overflow in MSVIDCTL. CVE-2024-9999 is unrelated.",
        }
        deduplicate_summary(issue)
        assert "CVE-2008-0015" in issue["summary"]
        assert "CVE-2024-9999" not in issue["summary"]
        assert "CISA has added four" in issue["source_summary"]

    def test_no_change_when_no_nvd_and_single_cve(self):
        issue = {
            "issue_id": "CVE-2008-0015",
            "summary": "A buffer overflow vulnerability.",
        }
        deduplicate_summary(issue)
        # No NVD description, no other CVE mentioned — summary unchanged
        assert issue["summary"] == "A buffer overflow vulnerability."
        assert "source_summary" not in issue

    def test_non_cve_issue_unchanged(self):
        issue = {
            "issue_id": "UNK-abc123",
            "summary": "Some advisory about multiple things.",
        }
        deduplicate_summary(issue)
        assert issue["summary"] == "Some advisory about multiple things."


# ---------------------------------------------------------------------------
# Action label translation / remediation steps
# ---------------------------------------------------------------------------

class TestRemediationSteps:

    def test_kev_required_action_is_first_choice(self):
        issue = {
            "kev_required_action": "Apply mitigations per vendor instructions or discontinue use.",
            "summary": "Remote code execution vulnerability.",
        }
        steps = generate_remediation_steps(issue)
        assert steps[0] == "Apply mitigations per vendor instructions or discontinue use."

    def test_source_mitigations_used(self):
        issue = {
            "source_mitigations": [
                {"action": "Upgrade to version 2.0.1", "source": "vendor-advisory"},
            ],
            "summary": "Some vulnerability.",
        }
        steps = generate_remediation_steps(issue)
        assert "Upgrade to version 2.0.1" in steps

    def test_rce_type_guidance(self):
        issue = {
            "summary": "Remote code execution vulnerability in widget server.",
        }
        steps = generate_remediation_steps(issue)
        assert any("Isolate" in s for s in steps)

    def test_xss_type_guidance(self):
        issue = {
            "summary": "Cross-site scripting vulnerability.",
        }
        steps = generate_remediation_steps(issue)
        assert any("input validation" in s.lower() for s in steps)

    def test_sql_injection_guidance(self):
        issue = {
            "summary": "SQL injection in login form.",
        }
        steps = generate_remediation_steps(issue)
        assert any("database" in s.lower() for s in steps)

    def test_buffer_overflow_guidance(self):
        issue = {
            "summary": "Buffer overflow in network stack.",
        }
        steps = generate_remediation_steps(issue)
        assert any("Isolate" in s for s in steps)

    def test_default_guidance_when_no_context(self):
        issue = {
            "summary": "Unknown vulnerability type.",
        }
        steps = generate_remediation_steps(issue)
        assert any("vendor advisory" in s.lower() for s in steps)

    def test_kev_action_plus_source_mitigations_combined(self):
        issue = {
            "kev_required_action": "Apply patches by 2024-04-15.",
            "source_mitigations": [
                {"action": "Upgrade to v3.1", "source": "vendor"},
            ],
        }
        steps = generate_remediation_steps(issue)
        assert steps[0] == "Apply patches by 2024-04-15."
        assert "Upgrade to v3.1" in steps

    def test_deserialization_triggers_rce_guidance(self):
        issue = {
            "summary": "Deserialization of untrusted data allows remote execution.",
        }
        steps = generate_remediation_steps(issue)
        assert any("Isolate" in s for s in steps)


# ---------------------------------------------------------------------------
# KEV field extraction (feed parser level)
# ---------------------------------------------------------------------------

class TestKevFieldExtraction:

    def test_json_parser_preserves_kev_fields(self):
        from advisoryops.feed_parsers import parse_json_feed

        kev_payload = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2008-0015",
                    "vendorProject": "Microsoft",
                    "product": "Video ActiveX Control",
                    "vulnerabilityName": "Microsoft Video ActiveX Stack Buffer Overflow",
                    "dateAdded": "2022-01-10",
                    "shortDescription": "Stack-based buffer overflow.",
                    "requiredAction": "Apply updates per vendor instructions.",
                    "dueDate": "2022-07-10",
                }
            ]
        }
        items = parse_json_feed(kev_payload, source_id="cisa-kev-json", fetched_at="2026-03-24T00:00:00Z")
        assert len(items) == 1
        item = items[0]
        assert item["kev_required_action"] == "Apply updates per vendor instructions."
        assert item["kev_due_date"] == "2022-07-10"
        assert item["kev_vendor"] == "Microsoft"
        assert item["kev_product"] == "Video ActiveX Control"
        assert item["kev_vulnerability_name"] == "Microsoft Video ActiveX Stack Buffer Overflow"

    def test_csv_parser_preserves_kev_fields(self):
        from advisoryops.feed_parsers import parse_csv_feed

        csv_text = (
            "cveID,vendorProject,product,vulnerabilityName,dateAdded,shortDescription,requiredAction,dueDate\n"
            "CVE-2008-0015,Microsoft,Video ActiveX Control,Buffer Overflow,2022-01-10,"
            "Stack-based buffer overflow.,Apply updates per vendor instructions.,2022-07-10\n"
        )
        items = parse_csv_feed(csv_text, source_id="cisa-kev-csv", fetched_at="2026-03-24T00:00:00Z")
        assert len(items) == 1
        item = items[0]
        assert item["kev_required_action"] == "Apply updates per vendor instructions."
        assert item["kev_due_date"] == "2022-07-10"
        assert item["kev_vendor"] == "Microsoft"
        assert item["kev_product"] == "Video ActiveX Control"

    def test_kev_fields_flow_to_issue(self):
        """Simulate what community_build does: extract KEV fields from signals."""
        issue = {
            "issue_id": "CVE-2008-0015",
            "cves": ["CVE-2008-0015"],
            "vendor": "",
            "severity": "",
            "signals": [
                {
                    "source": "cisa-kev-json",
                    "kev_required_action": "Apply updates per vendor instructions.",
                    "kev_due_date": "2022-07-10",
                    "kev_vendor": "Microsoft",
                    "kev_product": "Video ActiveX Control",
                },
                {
                    "source": "cisa-ncas-current-activity",
                    # No KEV fields on this source
                },
            ],
        }

        # Replicate community_build KEV extraction logic
        _KEV_SOURCES = {"cisa-kev-json", "cisa-kev-csv"}
        _KEV_FIELDS = ("kev_required_action", "kev_due_date", "kev_vendor", "kev_product")
        for sig in issue.get("signals", []):
            if sig.get("source", "") not in _KEV_SOURCES:
                continue
            for field in _KEV_FIELDS:
                val = sig.get(field, "")
                if val and not issue.get(field):
                    issue[field] = val
        if not issue.get("vendor") and issue.get("kev_vendor"):
            issue["vendor"] = issue["kev_vendor"]

        assert issue["kev_required_action"] == "Apply updates per vendor instructions."
        assert issue["kev_due_date"] == "2022-07-10"
        assert issue["vendor"] == "Microsoft"


# ---------------------------------------------------------------------------
# Feed entry schema
# ---------------------------------------------------------------------------

class TestFeedEntrySchema:

    def test_new_fields_present_in_feed_entry(self):
        from advisoryops.community_build import _feed_entry

        issue = {
            "issue_id": "CVE-2008-0015",
            "cvss_score": 9.3,
            "cvss_severity": "CRITICAL",
            "cvss_vector": "AV:N/AC:M/Au:N/C:C/I:C/A:C",
            "cwe_ids": ["CWE-119"],
            "affected_products": ["Microsoft Video Activex Control"],
            "nvd_description": "Stack-based buffer overflow.",
            "kev_required_action": "Apply updates.",
            "kev_due_date": "2022-07-10",
            "remediation_steps": ["Apply updates.", "Isolate affected systems."],
            "source_summary": "CISA added four vulns...",
        }
        entry = _feed_entry(issue)

        assert entry["cvss_score"] == 9.3
        assert entry["cvss_severity"] == "CRITICAL"
        assert entry["cvss_vector"] == "AV:N/AC:M/Au:N/C:C/I:C/A:C"
        assert entry["cwe_ids"] == ["CWE-119"]
        assert entry["affected_products"] == ["Microsoft Video Activex Control"]
        assert entry["nvd_description"] == "Stack-based buffer overflow."
        assert entry["kev_required_action"] == "Apply updates."
        assert entry["kev_due_date"] == "2022-07-10"
        assert entry["remediation_steps"] == ["Apply updates.", "Isolate affected systems."]
        assert entry["source_summary"] == "CISA added four vulns..."

    def test_new_fields_default_to_empty(self):
        from advisoryops.community_build import _feed_entry

        issue = {"issue_id": "UNK-abc"}
        entry = _feed_entry(issue)

        assert entry["cvss_score"] == 0
        assert entry["cvss_severity"] == ""
        assert entry["cvss_vector"] == ""
        assert entry["cwe_ids"] == []
        assert entry["affected_products"] == []
        assert entry["nvd_description"] == ""
        assert entry["kev_required_action"] == ""
        assert entry["kev_due_date"] == ""
        assert entry["remediation_steps"] == []
        assert entry["source_summary"] == ""


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

class TestRateLimiter:

    def test_allows_up_to_max_requests(self):
        rl = _RateLimiter(max_requests=3, window_seconds=30)
        # Should not block for the first 3
        import time
        start = time.monotonic()
        for _ in range(3):
            rl.wait()
        elapsed = time.monotonic() - start
        assert elapsed < 1.0  # should be near-instant
