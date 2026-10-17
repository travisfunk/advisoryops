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


def test_product_vendors_never_cross_between_products_in_the_same_cve():
    from advisoryops.source_vendors import populate_source_vendors

    rows = [
        {
            "issue_id": "CVE-2026-1234",
            "cves": ["CVE-2026-1234"],
            "affected_products": [
                "Alpha Station Pro",
                "Beta Station Pro",
                "Unknown Station Pro",
            ],
        }
    ]
    sources = [
        {
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-1234",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2026-1234",
            "kind": "nvd",
            "cves": ["CVE-2026-1234"],
            "vendor": "",
            "product_identities": [
                {"vendor": "Alpha", "product": "Station Pro"},
                {"vendor": "Beta", "product": "Station Pro"},
            ],
        }
    ]
    result = populate_source_vendors(rows, sources)[0]
    assert {(b["vendor"], b["product"]) for b in result["product_vendors"]} == {
        ("Alpha", "Alpha Station Pro"),
        ("Beta", "Beta Station Pro"),
    }
    assert "vendor" not in result  # Ambiguous issue summary does not choose one.


def test_csaf_ancestry_and_categories_keep_multiple_vendors_separate():
    from advisoryops.source_vendors import csaf_identities

    tree = {
        "branches": [
            {
                "category": "vendor",
                "name": "Alpha",
                "branches": [
                    {
                        "category": "product_family",
                        "name": "Pumps",
                        "branches": [
                            {
                                "category": "product_name",
                                "name": "Station Pro",
                                "branches": [
                                    {"category": "product_version", "name": "1.0"}
                                ],
                            }
                        ],
                    }
                ],
            },
            {
                "category": "vendor",
                "name": "Beta",
                "branches": [{"category": "product_name", "name": "Other Pump"}],
            },
            {"category": "product_name", "name": "Orphan Product"},
        ]
    }
    assert csaf_identities(tree) == [
        {"vendor": "Alpha", "product": "Station Pro"},
        {"vendor": "Beta", "product": "Other Pump"},
    ]


def test_negated_and_non_vulnerable_cpe_pairs_cannot_be_manufacturers():
    from advisoryops.source_vendors import cpe_identities

    data = configurations()
    data[0]["negate"] = True
    assert cpe_identities(data) == []
    assert cpe_identities(configurations("real")) == [
        {"vendor": "real", "product": "pump"}
    ]


def test_csaf_snapshot_survives_csv_only_refresh_without_local_csaf_cache(tmp_path):
    path = tmp_path / "vendors.json"
    url = "https://www.cisa.gov/news-events/ics-medical-advisories/icsma-17-250-02"
    record = {
        "url": url,
        "source": url,
        "kind": "csaf",
        "vendor": "CSAF Vendor",
        "cves": ["CVE-2017-12718"],
        "product_identities": [{"vendor": "CSAF Vendor", "product": "Pump"}],
    }
    path.write_text(json.dumps({"version": 2, "records": [record]}))
    refresh_vendor_sources(
        csv_text="ICS-CERT_Number,Vendor,Product,CVE_Number\nICSMA-17-250-02,Old CSV Vendor,Pump,CVE-2017-12718\n",
        cache_root=tmp_path,
        path=path,
    )
    assert load_vendor_sources(path) == [record]


def test_legacy_nvd_cache_refetches_once_and_retains_product_pairs(tmp_path):
    from advisoryops.nvd_enrich import enrich_issue, _load_cache
    from advisoryops.sources.nvd_backfill import _extract_fields_for_cache

    path = tmp_path / "CVE-2026-1234.json"
    path.write_text(json.dumps({"affected_products": ["Smiths Medical Pump"]}))
    assert _load_cache("CVE-2026-1234", tmp_path) is None
    calls = []

    def fetch(cve):
        calls.append(cve)
        return _extract_fields_for_cache({"configurations": configurations()})

    for _ in range(2):
        issue = {"issue_id": "CVE-2026-1234", "cves": ["CVE-2026-1234"]}
        enrich_issue(issue, cache_dir=tmp_path, _fetch_fn=fetch)
    assert calls == ["CVE-2026-1234"]
    assert _load_cache("CVE-2026-1234", tmp_path)["product_identities"] == [
        {"vendor": "smiths medical", "product": "pump"}
    ]


def test_nvd_recovery_checks_all_cves_checkpoints_and_resumes(tmp_path):
    from advisoryops.vendor_recovery import recover_nvd
    from datetime import datetime, timezone

    path = tmp_path / "vendors.json"
    catalog = {
        "issues": [
            {"cves": [f"CVE-2026-{i:04d}"], "affected_products": ["Pump"]}
            for i in range(1000, 1101)
        ]
    }
    calls = []

    def fetch(url):
        from urllib.parse import urlparse, parse_qs

        ids = parse_qs(urlparse(url).query)["cveIds"][0].split(",")
        calls.append(ids)
        return {
            "totalResults": len(ids),
            "vulnerabilities": [
                {"cve": {"id": c, "configurations": configurations()}} for c in ids
            ],
        }

    waits = []
    now = datetime(2026, 10, 16, tzinfo=timezone.utc)
    stats = recover_nvd(
        catalog=catalog,
        cache_root=tmp_path,
        path=path,
        limit=0,
        fetch=fetch,
        wait=waits.append,
        now=now,
    )
    assert stats == {"requested": 101, "total_cves": 101}
    assert [len(c) for c in calls] == [100, 1]
    assert waits == [6.2]
    assert len(load_vendor_sources(path)) == 101
    assert (
        recover_nvd(
            catalog=catalog,
            cache_root=tmp_path,
            path=path,
            limit=0,
            fetch=fetch,
            now=now,
        )["requested"]
        == 0
    )
    assert len(calls) == 2


def test_failed_nvd_batch_does_not_mark_records_as_checked(tmp_path):
    from advisoryops.vendor_recovery import recover_nvd

    path = tmp_path / "vendors.json"
    catalog = {"issues": [{"cves": ["CVE-2026-1234"], "affected_products": ["Pump"]}]}
    with pytest.raises(ValueError, match="Incomplete"):
        recover_nvd(
            catalog=catalog,
            cache_root=tmp_path,
            path=path,
            fetch=lambda _: {"totalResults": 1, "vulnerabilities": []},
        )
    assert not path.exists()


def test_actual_source_to_correlate_to_feed_to_catalog_keeps_vendor_evidence(
    tmp_path, monkeypatch
):
    from advisoryops.correlate import _IssueBuilder
    from advisoryops.community_build import _feed_entry
    from advisoryops.sbom_catalog import write_sbom_catalog
    import advisoryops.source_vendors as sources

    builder = _IssueBuilder("CVE-2026-1234", "cve", cves={"CVE-2026-1234"})
    builder.add_signal(
        {
            "source": "cisa-icsma-historical",
            "link": "https://www.cisa.gov/news-events/ics-medical-advisories/new",
            "vendor": "New Manufacturer",
            "vendor_source_kind": "csaf",
            "product_identities": [
                {"vendor": "New Manufacturer", "product": "New Pump"}
            ],
        }
    )
    issue = builder.to_obj()
    issue["affected_products"] = ["New Manufacturer New Pump"]
    assert issue["vendor"] == "New Manufacturer"
    feed = _feed_entry(issue)
    assert "signals" not in feed
    assert feed["source_product_identities"]
    monkeypatch.setattr(sources, "load_vendor_sources", lambda: [])
    catalog = write_sbom_catalog(
        [feed], tmp_path / "catalog.json", generated_at="2026-10-16T00:00:00Z"
    )
    published = catalog["issues"][0]
    assert published["vendor"] == "New Manufacturer"
    assert published["product_vendors"] == [
        {
            "product": "New Manufacturer New Pump",
            "vendor": "New Manufacturer",
            "source": "https://www.cisa.gov/news-events/ics-medical-advisories/new",
        }
    ]


def test_baseline_merge_retains_other_source_identities_and_replaces_corrections():
    from advisoryops.community_build import merge_baseline_feed

    def identity(vendor, source):
        return {"vendor": vendor, "product": "Pump", "source": source, "kind": "csaf"}

    base = {
        "issue_id": "test",
        "source_product_identities": [
            identity("CISA", "https://cisa"),
            identity("Old NVD", "https://nvd"),
        ],
    }
    new = {
        "issue_id": "test",
        "source_product_identities": [identity("New NVD", "https://nvd")],
    }
    result = merge_baseline_feed([new], [base])
    assert result[0]["source_product_identities"] == [
        identity("CISA", "https://cisa"),
        identity("New NVD", "https://nvd"),
    ]


def test_older_nvd_cache_does_not_replace_fresher_persisted_evidence(tmp_path):
    path = tmp_path / "vendors.json"
    source = "https://nvd.nist.gov/vuln/detail/CVE-2026-1234"
    record = {
        "url": source,
        "source": source,
        "kind": "nvd",
        "cves": ["CVE-2026-1234"],
        "vendor": "Fresh",
        "product_identities": [{"vendor": "Fresh", "product": "Pump"}],
        "identity_schema": 2,
        "checked_at": "2026-10-16T00:00:00+00:00",
    }
    path.write_text(json.dumps({"version": 2, "records": [record]}))
    cache = tmp_path / "nvd_cache"
    cache.mkdir()
    (cache / "CVE-2026-1234.json").write_text(
        json.dumps(
            {
                "vendor": "Stale",
                "product_identities": [{"vendor": "Stale", "product": "Pump"}],
                "identity_schema": 2,
                "vendor_checked_at": "2026-01-01T00:00:00+00:00",
            }
        )
    )
    refresh_vendor_sources(csv_text="", cache_root=tmp_path, path=path)
    assert load_vendor_sources(path) == [record]


def test_csaf_known_affected_status_scopes_pairs_to_each_cve():
    from advisoryops.source_vendors import csaf_cve_identities, populate_source_vendors
    from advisoryops.correlate import _IssueBuilder

    tree = {
        "branches": [
            {
                "category": "vendor",
                "name": "Alpha",
                "branches": [
                    {
                        "category": "product_name",
                        "name": "Pump",
                        "branches": [
                            {
                                "category": "product_version",
                                "name": "1",
                                "product": {
                                    "product_id": "alpha-1",
                                    "name": "Alpha Pump 1",
                                },
                            }
                        ],
                    }
                ],
            },
            {
                "category": "vendor",
                "name": "Beta",
                "branches": [
                    {
                        "category": "product_name",
                        "name": "Pump",
                        "product": {"product_id": "beta", "name": "Beta Pump"},
                    }
                ],
            },
        ]
    }
    csaf = {
        "product_tree": tree,
        "vulnerabilities": [
            {
                "cve": "CVE-2026-10000",
                "product_status": {
                    "known_affected": ["alpha-1"],
                    "known_not_affected": ["beta"],
                },
            },
            {"cve": "CVE-2026-10001", "product_status": {"known_affected": ["beta"]}},
        ],
    }
    identities = csaf_cve_identities(csaf)
    assert identities == [
        {"vendor": "Alpha", "product": "Pump", "cves": ["CVE-2026-10000"]},
        {"vendor": "Beta", "product": "Pump", "cves": ["CVE-2026-10001"]},
    ]
    builder = _IssueBuilder("CVE-2026-10000", "cve", cves={"CVE-2026-10000"})
    builder.add_signal(
        {
            "source": "cisa-icsma",
            "link": "https://cisa.example/advisory",
            "product_identities": identities,
        }
    )
    issue = builder.to_obj()
    assert {x["vendor"] for x in issue["source_product_identities"]} == {"Alpha"}
    assert {
        b["vendor"] for b in populate_source_vendors([issue], [])[0]["product_vendors"]
    } == {"Alpha"}


def test_nvd_modified_source_updates_current_schema_cache(tmp_path):
    from advisoryops.sources.nvd_backfill import _save_cve_raw

    old = {
        "cve": {
            "id": "CVE-2026-1234",
            "lastModified": "2026-01-01",
            "configurations": configurations("old"),
        }
    }
    new = {
        "cve": {
            "id": "CVE-2026-1234",
            "lastModified": "2026-10-16",
            "configurations": configurations("new"),
        }
    }
    _save_cve_raw(old, tmp_path)
    _save_cve_raw(new, tmp_path)
    assert json.loads((tmp_path / "CVE-2026-1234.json").read_text())["vendor"] == "new"


def test_recovery_prioritizes_missing_before_stale_and_oldest_first(tmp_path):
    from advisoryops.vendor_recovery import recover_nvd
    from datetime import datetime, timezone

    path = tmp_path / "vendors.json"
    records = [
        {
            "url": f"https://nvd.nist.gov/vuln/detail/CVE-2026-{n}",
            "cves": [f"CVE-2026-{n}"],
            "source": "https://nvd.nist.gov",
            "kind": "nvd",
            "identity_schema": 2,
            "checked_at": checked,
        }
        for n, checked in [(1000, "2026-06-01"), (1001, "2026-01-01")]
    ]
    path.write_text(json.dumps({"version": 2, "records": records}))
    catalog = {
        "issues": [
            {"cves": [f"CVE-2026-{n}"], "affected_products": ["Pump"]}
            for n in (1000, 1001, 1002)
        ]
    }
    urls = []

    def fetch(url):
        urls.append(url)
        return {"totalResults": 0, "vulnerabilities": []}

    recover_nvd(
        catalog=catalog,
        cache_root=tmp_path,
        path=path,
        limit=2,
        fetch=fetch,
        now=datetime(2026, 10, 16, tzinfo=timezone.utc),
    )
    from urllib.parse import parse_qs, urlparse

    assert parse_qs(urlparse(urls[0]).query)["cveIds"] == [
        "CVE-2026-1002,CVE-2026-1001"
    ]


def test_same_advisory_url_cannot_borrow_products_from_another_cve():
    row = {
        "issue_id": "CVE-2026-10000",
        "cves": ["CVE-2026-10000"],
        "canonical_link": "https://advisory",
        "affected_products": ["Alpha Pump"],
    }
    sources = [
        {
            "url": "https://advisory",
            "source": "https://advisory",
            "kind": "csaf",
            "cves": ["CVE-2026-10001"],
            "product_identities": [{"vendor": "Beta", "product": "Pump"}],
        }
    ]
    result = populate_source_vendors([row], sources)[0]
    assert result["affected_products"] == ["Alpha Pump"]
    assert result["product_vendors"] == []
