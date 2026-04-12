"""Feature D — healthcare_category classification tests."""
from __future__ import annotations

from advisoryops.healthcare_filter import classify_healthcare_category


class TestClassifyHealthcareCategory:
    def test_cisa_icsma_source_is_medical_device(self):
        issue = {"sources": ["cisa-icsma"], "title": "", "summary": "", "vendor": ""}
        assert classify_healthcare_category(issue) == "medical_device"

    def test_philips_psirt_alone_no_longer_medical_device(self):
        """Regression guard for the Chrome-via-Philips-PSIRT noise bug.

        philips-psirt alone is not Rule 1 (cisa-icsma) nor any other rule,
        so a bare PSIRT co-occurrence must not promote to medical_device.
        """
        issue = {"sources": ["philips-psirt"], "title": "", "summary": "", "vendor": ""}
        assert classify_healthcare_category(issue) != "medical_device"

    def test_vendor_field_match_is_medical_device(self):
        """Rule 2 — curated vendor substring match in the vendor field."""
        issue = {"sources": [], "title": "", "summary": "", "vendor": "Medtronic"}
        assert classify_healthcare_category(issue) == "medical_device"

    def test_vendor_in_title_only_is_not_medical_device(self):
        """Rule 2 checks the vendor field, not title/summary text."""
        issue = {"sources": [], "title": "Medtronic pump vulnerability", "summary": "", "vendor": ""}
        assert classify_healthcare_category(issue) != "medical_device"

    def test_fda_risk_class_is_medical_device(self):
        issue = {"sources": [], "title": "Some recall", "summary": "", "vendor": "", "fda_risk_class": "2"}
        assert classify_healthcare_category(issue) == "medical_device"

    def test_affected_product_keyword_is_medical_device(self):
        """Rule 4 — product keyword substring match in affected_products."""
        issue = {
            "sources": [], "title": "", "summary": "", "vendor": "",
            "affected_products": ["Medtronic MiniMed 780G Insulin Pump"],
        }
        assert classify_healthcare_category(issue) == "medical_device"

    def test_keyword_in_title_is_not_medical_device(self):
        """Keyword-in-title is no longer a medical_device rule (strict 4-rule)."""
        issue = {"sources": [], "title": "Infusion pump firmware update", "summary": "", "vendor": ""}
        assert classify_healthcare_category(issue) != "medical_device"

    def test_ehr_keyword_is_healthcare_it(self):
        issue = {"sources": [], "title": "EHR data breach", "summary": "", "vendor": ""}
        assert classify_healthcare_category(issue) == "healthcare_it"

    def test_fhir_keyword_is_healthcare_it(self):
        issue = {"sources": [], "title": "FHIR API vulnerability", "summary": "", "vendor": ""}
        assert classify_healthcare_category(issue) == "healthcare_it"

    def test_hospital_keyword_is_infrastructure(self):
        issue = {"sources": [], "title": "Hospital network compromise", "summary": "", "vendor": ""}
        assert classify_healthcare_category(issue) == "healthcare_infrastructure"

    def test_hipaa_keyword_is_infrastructure(self):
        issue = {"sources": [], "title": "HIPAA violation risk", "summary": "", "vendor": ""}
        assert classify_healthcare_category(issue) == "healthcare_infrastructure"

    def test_unknown_defaults_to_adjacent(self):
        issue = {"sources": [], "title": "Generic vulnerability", "summary": "", "vendor": ""}
        assert classify_healthcare_category(issue) == "healthcare_adjacent"

    def test_ehr_connected_to_pump_falls_through_to_it(self):
        """With strict rules, EHR text → healthcare_it; pump keyword is ignored."""
        issue = {"sources": [], "title": "EHR connected to infusion pump", "summary": "", "vendor": ""}
        assert classify_healthcare_category(issue) == "healthcare_it"
