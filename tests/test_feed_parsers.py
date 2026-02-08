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
    csv_text = "cveID,dateAdded,shortDescription,vendorProject,product\nCVE-2023-1111,2023-02-03,Hello,ACME,Thing\n"
    items = parse_csv_feed(csv_text, source_id="cisa-kev-csv", fetched_at="2026-01-01T00:00:00+00:00")
    assert len(items) == 1
    it = items[0]
    assert it["guid"] == "CVE-2023-1111"
    assert "nvd.nist.gov" in it["link"]
    assert "ACME" in it["summary"]