from __future__ import annotations

from advisoryops.feed_parsers import parse_json_feed, parse_csv_feed


def test_parse_kev_json_minimal():
    obj = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-9999",
                "dateAdded": "2024-01-02",
                "shortDescription": "Test desc",
                "vendorProject": "Vendor",
                "product": "Product",
            }
        ]
    }
    items = parse_json_feed(obj, source_id="cisa-kev-json", fetched_at="2026-01-01T00:00:00+00:00")
    assert len(items) == 1
    it = items[0]
    assert it["guid"] == "CVE-2024-9999"
    assert "nvd.nist.gov" in it["link"]
    assert "Vendor" in it["summary"]


def test_parse_kev_csv_minimal():
    csv_text = """cveID,dateAdded,shortDescription,vendorProject,product
CVE-2023-1111,2023-02-03,Hello,ACME,Thing
"""
    items = parse_csv_feed(csv_text, source_id="cisa-kev-csv", fetched_at="2026-01-01T00:00:00+00:00")
    assert len(items) == 1
    it = items[0]
    assert it["guid"] == "CVE-2023-1111"
    assert "nvd.nist.gov" in it["link"]
    assert "ACME" in it["summary"]


def test_parse_openfda_results_minimal():
    obj = {
        "meta": {"results": {"skip": 0, "limit": 1, "total": 1}},
        "results": [
            {
                "recall_number": "Z-1234-2026",
                "reason_for_recall": "Cybersecurity vulnerability in bedside monitor",
                "product_description": "Acme Bedside Monitor",
                "recalling_firm": "Acme Medical",
                "recall_initiation_date": "20260301",
            }
        ],
    }
    items = parse_json_feed(obj, source_id="openfda-device-recalls", fetched_at="2026-03-17T00:00:00+00:00")
    assert len(items) == 1
    it = items[0]
    assert it["guid"] == "Z-1234-2026"
    assert it["title"] == "Z-1234-2026"
    assert "Acme Medical" in it["summary"]
    assert "Acme Bedside Monitor" in it["summary"]


def test_parse_generic_cve_csv_includes_epss_fields():
    csv_text = """cve,epss,percentile,date
CVE-2026-0001,0.9123,0.991,2026-03-15
"""
    items = parse_csv_feed(csv_text, source_id="epss-data", fetched_at="2026-03-17T00:00:00+00:00")
    assert len(items) == 1
    it = items[0]
    assert it["guid"] == "CVE-2026-0001"
    assert "nvd.nist.gov" in it["link"]
    assert "EPSS=0.9123" in it["summary"]


def test_parse_openfda_results_builds_api_link_when_direct_link_missing():
    obj = {
        "results": [
            {
                "res_event_number": "12345",
                "reason_for_recall": "Cybersecurity vulnerability in bedside monitor",
                "product_description": "Acme Bedside Monitor",
                "recalling_firm": "Acme Medical",
            }
        ]
    }
    items = parse_json_feed(obj, source_id="openfda-device-recalls", fetched_at="2026-03-17T00:00:00+00:00")
    assert len(items) == 1
    it = items[0]
    assert 'https://api.fda.gov/device/recall.json?search=res_event_number:"12345"' == it["link"]


def test_parse_openfda_results_prefers_direct_link_when_present():
    obj = {
        "results": [
            {
                "event_id": "99999",
                "link": "https://example.com/recall/99999",
                "reason_for_recall": "Cybersecurity vulnerability in infusion pump",
            }
        ]
    }
    items = parse_json_feed(obj, source_id="openfda-device-recalls", fetched_at="2026-03-17T00:00:00+00:00")
    assert len(items) == 1
    assert items[0]["link"] == "https://example.com/recall/99999"
