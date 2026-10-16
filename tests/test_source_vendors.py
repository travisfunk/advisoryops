"""Vendor extraction must survive real publication, not just matcher fixtures."""

import json
from pathlib import Path

import pytest

from advisoryops.source_vendors import (
    cpe_vendors,
    load_vendor_sources,
    populate_source_vendors,
    refresh_vendor_sources,
)

ROOT = Path(__file__).resolve().parents[1]


def configurations(vendor="smiths_medical"):
    return [
        {
            "nodes": [
                {
                    "cpeMatch": [
                        {
                            "vulnerable": True,
                            "criteria": f"cpe:2.3:a:{vendor}:pump:1:*:*:*:*:*:*:*",
                        },
                        {
                            "vulnerable": False,
                            "criteria": "cpe:2.3:o:platform:os:1:*:*:*:*:*:*:*",
                        },
                    ]
                }
            ]
        }
    ]


def test_nvd_vendor_comes_from_vulnerable_cpe_not_platform_or_product_prose():
    assert cpe_vendors(configurations()) == ["smiths medical"]
    for vendor in ("*", "-", "smiths*", "smiths?"):
        assert cpe_vendors(configurations(vendor)) == []
    nested = [{"nodes": [{"children": configurations()[0]["nodes"]}]}]
    assert cpe_vendors(nested) == ["smiths medical"]


@pytest.mark.parametrize(
    "module", ["advisoryops.nvd_enrich", "advisoryops.sources.nvd_backfill"]
)
def test_nvd_parsers_retain_cpe_vendor(module):
    import importlib

    parser_module = importlib.import_module(module)
    parser = getattr(parser_module, "_extract_nvd_fields", None) or getattr(
        parser_module, "_extract_fields_for_cache"
    )
    fields = parser({"id": "CVE-2017-12718", "configurations": configurations()})
    assert fields["vendor"] == "smiths medical"
    fields = parser(
        {
            "id": "CVE-2017-12718",
            "configurations": configurations() + configurations("other"),
        }
    )
    assert "vendor" not in fields


def test_vendor_resolution_preserves_explicit_values_and_rejects_conflicts():
    evidence = [
        {"url": "https://source/one", "cves": ["CVE-1"], "vendor": "Smiths Medical"},
        {"url": "https://source/two", "cves": ["CVE-1"], "vendor": "Other"},
    ]
    rows = [
        {"vendor": "Declared", "canonical_link": "https://source/one"},
        {"canonical_link": "https://source/one/", "cves": ["CVE-1"]},
        {"cves": ["CVE-1"]},
        {"signals": [{"vendor": "Source Vendor"}]},
        {"signals": [{"vendor": "One"}, {"vendor": "Two"}]},
    ]
    result = populate_source_vendors(rows, evidence)
    assert [r.get("vendor") for r in result] == [
        "Declared",
        "Smiths Medical",
        None,
        "Source Vendor",
        None,
    ]
    assert "vendor" not in rows[1]


def test_refresh_uses_csv_csaf_cache_and_nvd_cpe_evidence(tmp_path):
    path = tmp_path / "sources.json"
    cisa = tmp_path / "cisa_icsma_cache"
    nvd = tmp_path / "nvd_cache"
    cisa.mkdir()
    nvd.mkdir()
    (cisa / "ICSMA-17-250-02.json").write_text(
        json.dumps({"vendor": "Smiths Medical ASD Inc.", "cves": ["CVE-2017-12718"]})
    )
    (nvd / "CVE-2026-1234.json").write_text(
        json.dumps({"configurations": configurations()})
    )
    csv = "ICS-CERT_Number,Vendor,CVE_Number\nICSMA-17-250-02,Smiths Medical,CVE-2017-12718\n"
    refresh_vendor_sources(csv_text=csv, cache_root=tmp_path, path=path)
    evidence = load_vendor_sources(path)
    assert len(evidence) == 2
    assert {r["vendor"] for r in evidence} == {
        "smiths medical",
        "Smiths Medical ASD Inc.",
    }
    before = path.read_bytes()
    refresh_vendor_sources(csv_text=csv, cache_root=tmp_path, path=path)
    assert path.read_bytes() == before


def test_published_catalog_reproduces_from_archive_and_source_evidence(tmp_path):
    from advisoryops.sbom_catalog import write_sbom_catalog

    published = json.loads((ROOT / "docs/sbom_advisories.json").read_text())
    rows = [
        json.loads(line)
        for path in (ROOT / "docs/feed_archive").glob("*.jsonl")
        for line in path.open()
    ]
    generated = write_sbom_catalog(
        rows, tmp_path / "catalog.json", generated_at=published["generated_at"]
    )
    assert generated == published


def test_cisa_csaf_vendor_survives_merge_signal_and_publication(tmp_path):
    from advisoryops.sources.cisa_icsma_backfill import (
        _merge_advisory,
        generate_signals_from_cache,
    )
    from advisoryops.sbom_catalog import write_sbom_catalog

    merged = _merge_advisory(
        {
            "advisory_id": "ICSMA-26-001-01",
            "vendor": "CSV Vendor",
            "cves": ["CVE-2026-99999"],
        },
        {"vendor": "CSAF Vendor Inc."},
    )
    (tmp_path / "ICSMA-26-001-01.json").write_text(json.dumps(merged))
    signals = generate_signals_from_cache(cache_dir=tmp_path)
    assert signals[0]["vendor"] == "CSAF Vendor Inc."
    catalog = write_sbom_catalog(
        [{"issue_id": "test", "signals": signals, "vendor": ""}],
        tmp_path / "catalog.json",
        generated_at="2026-10-16T00:00:00Z",
    )
    assert catalog["issues"][0]["vendor"] == "CSAF Vendor Inc."
    assert "signals" not in catalog["issues"][0]


def test_nvd_vendor_applies_without_overwriting_explicit_manufacturer():
    from advisoryops.nvd_enrich import _apply_nvd_fields

    issue = {"vendor": ""}
    _apply_nvd_fields(issue, {"vendor": "smiths medical"})
    assert issue["vendor"] == "smiths medical"
    _apply_nvd_fields(issue, {"vendor": "other"})
    assert issue["vendor"] == "smiths medical"


def test_duplicate_source_rows_retain_all_cves(tmp_path):
    path = tmp_path / "sources.json"
    csv = "ICS-CERT_Number,Vendor,CVE_Number\nICSMA-26-001-01,Vendor,CVE-2026-10000\nICSMA-26-001-01,Vendor,CVE-2026-10001\n"
    refresh_vendor_sources(csv_text=csv, cache_root=tmp_path, path=path)
    records = load_vendor_sources(path)
    assert len(records) == 1
    assert records[0]["cves"] == ["CVE-2026-10000", "CVE-2026-10001"]
