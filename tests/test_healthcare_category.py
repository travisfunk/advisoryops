"""Feature D — healthcare_category classification tests."""
from __future__ import annotations

from advisoryops.healthcare_filter import classify_healthcare_category


class TestClassifyHealthcareCategory:
    def test_cisa_icsma_source_is_medical_device(self):
        issue = {"sources": ["cisa-icsma"], "title": "", "summary": "", "vendor": ""}
        assert classify_healthcare_category(issue) == "medical_device"

    def test_openfda_source_is_medical_device(self):
        issue = {"sources": ["openfda-recalls-historical"], "title": "", "summary": "", "vendor": ""}
        assert classify_healthcare_category(issue) == "medical_device"

    def test_philips_psirt_source_is_medical_device(self):
        issue = {"sources": ["philips-psirt"], "title": "", "summary": "", "vendor": ""}
        assert classify_healthcare_category(issue) == "medical_device"

    def test_medical_vendor_in_text_is_medical_device(self):
        issue = {"sources": [], "title": "Medtronic pump vulnerability", "summary": "", "vendor": ""}
        assert classify_healthcare_category(issue) == "medical_device"

    def test_fda_risk_class_is_medical_device(self):
        issue = {"sources": [], "title": "Some recall", "summary": "", "vendor": "", "fda_risk_class": "2"}
        assert classify_healthcare_category(issue) == "medical_device"

    def test_device_keyword_is_medical_device(self):
        issue = {"sources": [], "title": "Infusion pump firmware update", "summary": "", "vendor": ""}
        assert classify_healthcare_category(issue) == "medical_device"

    def test_defibrillator_keyword_is_medical_device(self):
        issue = {"sources": [], "title": "Defibrillator recall", "summary": "", "vendor": ""}
        assert classify_healthcare_category(issue) == "medical_device"

    def test_ehr_keyword_is_healthcare_it(self):
        issue = {"sources": [], "title": "EHR data breach", "summary": "", "vendor": ""}
        assert classify_healthcare_category(issue) == "healthcare_it"

    def test_fhir_keyword_is_healthcare_it(self):
        issue = {"sources": [], "title": "FHIR API vulnerability", "summary": "", "vendor": ""}
        assert classify_healthcare_category(issue) == "healthcare_it"

    def test_epic_systems_is_medical_device(self):
        """Epic Systems is in MEDICAL_DEVICE_VENDORS, so vendor match wins."""
        issue = {"sources": [], "title": "Epic Systems update", "summary": "", "vendor": ""}
        assert classify_healthcare_category(issue) == "medical_device"

    def test_hospital_keyword_is_infrastructure(self):
        issue = {"sources": [], "title": "Hospital network compromise", "summary": "", "vendor": ""}
        assert classify_healthcare_category(issue) == "healthcare_infrastructure"

    def test_hipaa_keyword_is_infrastructure(self):
        issue = {"sources": [], "title": "HIPAA violation risk", "summary": "", "vendor": ""}
        assert classify_healthcare_category(issue) == "healthcare_infrastructure"

    def test_unknown_defaults_to_adjacent(self):
        issue = {"sources": [], "title": "Generic vulnerability", "summary": "", "vendor": ""}
        assert classify_healthcare_category(issue) == "healthcare_adjacent"

    def test_medical_device_takes_precedence_over_it(self):
        """If both device and IT keywords match, medical_device wins."""
        issue = {"sources": [], "title": "EHR connected to infusion pump", "summary": "", "vendor": ""}
        assert classify_healthcare_category(issue) == "medical_device"
