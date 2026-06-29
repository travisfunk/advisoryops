"""Tests for IOC export formats (CSV and STIX 2.1)."""
from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from advisoryops.packet_export import export_iocs_csv, export_iocs_stix


@pytest.fixture
def sample_iocs():
    return [
        {"type": "cve", "value": "CVE-2024-1234", "source": "cisa-icsma"},
        {"type": "ip", "value": "10.0.0.1", "source": "mandiant-blog"},
        {"type": "hash_sha256", "value": "a" * 64, "source": "tenable-newest"},
        {"type": "domain", "value": "evil.example.org", "source": "threatfox-iocs"},
        {"type": "url", "value": "https://malware.example.org/payload", "source": "urlhaus-recent"},
    ]


class TestExportIOCsCSV:

    def test_creates_file(self, sample_iocs, tmp_path):
        out = tmp_path / "iocs.csv"
        result = export_iocs_csv(sample_iocs, out)
        assert result.exists()

    def test_valid_csv(self, sample_iocs, tmp_path):
        out = tmp_path / "iocs.csv"
        export_iocs_csv(sample_iocs, out)
        with open(out, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 5
        assert set(reader.fieldnames) == {"type", "value", "source"}

    def test_csv_content_correct(self, sample_iocs, tmp_path):
        out = tmp_path / "iocs.csv"
        export_iocs_csv(sample_iocs, out)
        with open(out, encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        assert rows[0]["type"] == "cve"
        assert rows[0]["value"] == "CVE-2024-1234"
        assert rows[0]["source"] == "cisa-icsma"

    def test_empty_iocs(self, tmp_path):
        out = tmp_path / "empty.csv"
        export_iocs_csv([], out)
        with open(out, encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 0


class TestExportIOCsSTIX:

    def test_creates_file(self, sample_iocs, tmp_path):
        out = tmp_path / "iocs.stix.json"
        result = export_iocs_stix(sample_iocs, out)
        assert result.exists()

    def test_valid_json(self, sample_iocs, tmp_path):
        out = tmp_path / "iocs.stix.json"
        export_iocs_stix(sample_iocs, out)
        data = json.loads(out.read_text(encoding="utf-8"))
        assert isinstance(data, dict)

    def test_stix_bundle_structure(self, sample_iocs, tmp_path):
        out = tmp_path / "iocs.stix.json"
        export_iocs_stix(sample_iocs, out)
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["type"] == "bundle"
        assert data["id"].startswith("bundle--")
        assert isinstance(data["objects"], list)

    def test_stix_indicator_structure(self, sample_iocs, tmp_path):
        out = tmp_path / "iocs.stix.json"
        export_iocs_stix(sample_iocs, out)
        data = json.loads(out.read_text(encoding="utf-8"))
        for obj in data["objects"]:
            assert obj["type"] == "indicator"
            assert obj["spec_version"] == "2.1"
            assert obj["id"].startswith("indicator--")
            assert "pattern" in obj
            assert obj["pattern_type"] == "stix"
            assert "created" in obj
            assert "modified" in obj

    def test_stix_patterns_correct(self, sample_iocs, tmp_path):
        out = tmp_path / "iocs.stix.json"
        export_iocs_stix(sample_iocs, out)
        data = json.loads(out.read_text(encoding="utf-8"))
        patterns = {obj["name"]: obj["pattern"] for obj in data["objects"]}
        assert "ipv4-addr:value" in patterns["ip: 10.0.0.1"]
        assert "domain-name:value" in patterns["domain: evil.example.org"]
        assert "vulnerability:name" in patterns["cve: CVE-2024-1234"]

    def test_empty_iocs(self, tmp_path):
        out = tmp_path / "empty.stix.json"
        export_iocs_stix([], out)
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["type"] == "bundle"
        assert len(data["objects"]) == 0
