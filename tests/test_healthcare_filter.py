"""Tests for the healthcare relevance filter."""

from __future__ import annotations

import pytest

from advisoryops.healthcare_filter import is_healthcare_relevant, classify_healthcare_category


# -- helpers ----------------------------------------------------------------

def _issue(
    *,
    title: str = "",
    summary: str = "",
    vendor: str = "",
    sources: list[str] | None = None,
    healthcare_category: str = "",
) -> dict:
    return {
        "issue_id": "CVE-2024-0001",
        "title": title,
        "summary": summary,
        "vendor": vendor,
        "sources": sources or [],
        "healthcare_category": healthcare_category,
    }


# -- (a) healthcare-specific source ----------------------------------------

class TestHealthcareSource:
    @pytest.mark.parametrize("src", [
        "cisa-icsma",
        "fda-medwatch",
        "openfda-device-recalls",
        "openfda-device-events",
        "health-canada-recalls",
    ])
    def test_healthcare_source_is_relevant(self, src):
        assert is_healthcare_relevant(_issue(sources=[src])) is True

    def test_healthcare_source_among_others(self):
        issue = _issue(sources=["cisa-kev-csv", "cisa-icsma"])
        assert is_healthcare_relevant(issue) is True


# -- (b) keyword matching --------------------------------------------------

class TestKeywordMatching:
    @pytest.mark.parametrize("keyword", [
        "infusion pump",
        "ventilator",
        "patient monitor",
        "defibrillator",
        "pacemaker",
        "PACS",
        "DICOM",
        "MRI",
        "x-ray",
        "ultrasound",
        "surgical robot",
        "insulin pump",
        "blood gas analyzer",
        "pulse oximeter",
        "EHR",
        "EMR",
        "HL7",
        "FHIR",
        "medical device",
        "clinical",
        "biomedical",
        "telehealth",
        "point of care",
        "bedside",
        "wearable medical",
    ])
    def test_device_keyword_in_title(self, keyword):
        assert is_healthcare_relevant(_issue(title=f"Vuln in {keyword} firmware")) is True

    def test_keyword_in_summary(self):
        issue = _issue(summary="Remote code execution affecting infusion pump controller")
        assert is_healthcare_relevant(issue) is True

    @pytest.mark.parametrize("keyword", [
        "FDA",
        "IEC 62443",
        "HIPAA",
        "510(k)",
        "premarket",
        "postmarket",
        "medical device regulation",
    ])
    def test_regulatory_keyword(self, keyword):
        assert is_healthcare_relevant(_issue(title=f"Advisory related to {keyword}")) is True

    @pytest.mark.parametrize("vendor_name", [
        "GE Healthcare",
        "Philips",
        "Siemens Healthineers",
        "Medtronic",
        "Baxter",
        "BD",
        "B. Braun",
        "Epic Systems",
        "Roche Diagnostics",
        "Contec Health",
        "WHILL",
    ])
    def test_vendor_in_text(self, vendor_name):
        assert is_healthcare_relevant(_issue(title=f"{vendor_name} advisory")) is True

    def test_vendor_in_vendor_field(self):
        assert is_healthcare_relevant(_issue(vendor="GE Healthcare")) is True

    def test_case_insensitive(self):
        assert is_healthcare_relevant(_issue(title="INFUSION PUMP overflow")) is True


# -- (c) healthcare_category -----------------------------------------------

class TestHealthcareCategory:
    def test_non_empty_category(self):
        assert is_healthcare_relevant(_issue(healthcare_category="infusion pump")) is True

    def test_empty_category_not_sufficient(self):
        assert is_healthcare_relevant(_issue(healthcare_category="")) is False


# -- (d) KEV + medical vendor ----------------------------------------------

class TestKevVendor:
    def test_kev_with_medical_vendor(self):
        issue = _issue(sources=["cisa-kev-csv"], vendor="Philips")
        assert is_healthcare_relevant(issue) is True

    def test_kev_with_generic_vendor(self):
        issue = _issue(sources=["cisa-kev-json"], vendor="Microsoft")
        assert is_healthcare_relevant(issue) is False

    def test_kev_vendor_case_insensitive(self):
        issue = _issue(sources=["cisa-kev-csv"], vendor="medtronic")
        assert is_healthcare_relevant(issue) is True


# -- negatives (should NOT match) ------------------------------------------

class TestNotRelevant:
    def test_generic_it_vuln(self):
        issue = _issue(
            title="Chrome V8 type confusion",
            summary="Use-after-free in V8 JavaScript engine",
            vendor="Google",
            sources=["cisa-kev-csv"],
        )
        assert is_healthcare_relevant(issue) is False

    def test_sharepoint_vuln(self):
        issue = _issue(
            title="SharePoint Server remote code execution",
            vendor="Microsoft",
            sources=["cisa-ncas-alerts"],
        )
        assert is_healthcare_relevant(issue) is False

    def test_laravel_vuln(self):
        issue = _issue(
            title="Laravel framework SQL injection",
            vendor="Laravel",
            sources=["github-advisories"],
        )
        assert is_healthcare_relevant(issue) is False

    def test_empty_issue(self):
        assert is_healthcare_relevant({}) is False

    def test_kev_without_medical_vendor(self):
        issue = _issue(sources=["cisa-kev-csv"], vendor="Cisco")
        assert is_healthcare_relevant(issue) is False


class TestFalsePositiveExclusion:
    """Negative patterns should exclude cosmetics, food, and generic threat reports."""

    def test_ombrelle_sunscreen_excluded(self):
        """Ombrelle is a sunscreen product recalled by Health Canada, not a medical device."""
        issue = _issue(
            title="Ombrelle product recall (2021-10-13)",
            summary="Ombrelle sunscreen recall due to labeling issue",
            sources=["health-canada-recalls"],
        )
        cat = classify_healthcare_category(issue)
        assert cat != "medical_device", f"Ombrelle sunscreen should not be medical_device, got {cat}"

    def test_brickstorm_malware_excluded(self):
        """BRICKSTORM is a backdoor malware report, not about a specific device."""
        issue = _issue(
            title="BRICKSTORM Backdoor",
            summary="Malware Analysis: BRICKSTORM backdoor targets healthcare and medical device networks.",
            sources=["cisa-ncas-analysis"],
        )
        cat = classify_healthcare_category(issue)
        assert cat != "medical_device", f"BRICKSTORM backdoor should not be medical_device, got {cat}"

    def test_real_medical_device_not_excluded(self):
        """A real medical device advisory should NOT be excluded."""
        issue = _issue(
            title="CVE-2025-1234: Philips IntelliSpace PACS vulnerability",
            summary="A critical vulnerability in Philips IntelliSpace PACS allows remote code execution.",
            sources=["cisa-icsma"],
        )
        cat = classify_healthcare_category(issue)
        assert cat == "medical_device"

    def test_device_in_threat_report_not_excluded(self):
        """A threat report that mentions a SPECIFIC device should not be excluded."""
        issue = _issue(
            title="Ransomware campaign targeting infusion pumps",
            summary="A ransomware campaign has been observed targeting infusion pump controllers via backdoor implant.",
            sources=["mandiant-blog"],
        )
        cat = classify_healthcare_category(issue)
        assert cat == "medical_device"
