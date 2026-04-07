"""Tests for CISA ICSMA historical backfill: CSV parsing, CSAF enrichment, caching."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from advisoryops.sources.cisa_icsma_backfill import (
    _load_progress,
    _save_progress,
    _load_advisory_cache,
    _save_advisory_cache,
    _merge_advisory,
    discover_csaf_files,
    generate_signals_from_cache,
    incremental_update,
    parse_csaf_advisory,
    parse_icsma_csv,
    run_backfill,
)


# ---------------------------------------------------------------------------
# Fixtures: realistic CSV and CSAF data
# ---------------------------------------------------------------------------

_SAMPLE_CSV = """\
icsad_ID,Original_Release_Date,Last_Updated,Year,ICS-CERT_Number,ICS-CERT_Advisory_Title,Vendor,Product,Products_Affected,CVE_Number,Cumulative_CVSS,CVSS_Severity,CWE_Number,Critical_Infrastructure_Sector,Product_Distribution,Company_Headquarters,License
1,04/21/2020,04/21/2020,2020,ICSMA-20-112-01,Baxter ExactaMix,Baxter,ExactaMix EM2400 & EM1200,ExactaMix EM2400 versions prior to 1.14,CVE-2020-12016,8.1,High,CWE-319,Healthcare and Public Health,Worldwide,United States,ICS Advisory Project
2,03/17/2022,03/17/2022,2022,ICSMA-22-076-01,Philips e-Alert Unit,Philips,e-Alert Unit,e-Alert Unit versions 2.7 and prior,CVE-2022-0922,6.5,Medium,CWE-20,Healthcare and Public Health,Worldwide,Netherlands,ICS Advisory Project
3,01/15/2019,01/15/2019,2019,ICSA-19-015-01,Non-ICSMA Advisory,SomeVendor,SomeProduct,v1.0,,5.0,Medium,,Critical Manufacturing,Worldwide,Germany,ICS Advisory Project
"""

_SAMPLE_CSAF = {
    "document": {
        "tracking": {
            "id": "ICSMA-20-112-01",
            "initial_release_date": "2020-04-21T00:00:00.000Z",
            "current_release_date": "2020-04-21T00:00:00.000Z",
        },
        "title": "Baxter ExactaMix",
        "notes": [
            {"category": "summary", "text": "Baxter ExactaMix contains cleartext transmission vulnerability."},
            {"category": "risk_evaluation", "text": "Successful exploitation could allow access to sensitive data."},
        ],
        "references": [
            {"url": "https://www.cisa.gov/news-events/ics-medical-advisories/icsma-20-112-01"},
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2020-12016"},
        ],
    },
    "product_tree": {
        "branches": [
            {
                "name": "Baxter",
                "branches": [
                    {"name": "ExactaMix EM2400"},
                    {"name": "ExactaMix EM1200"},
                ],
            }
        ]
    },
    "vulnerabilities": [
        {
            "cve": "CVE-2020-12016",
            "cwe": {"id": "CWE-319", "name": "Cleartext Transmission"},
            "scores": [
                {
                    "cvss_v3": {
                        "baseScore": 8.1,
                        "baseSeverity": "HIGH",
                        "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    }
                }
            ],
            "remediations": [
                {"category": "vendor_fix", "details": "Baxter recommends upgrading to version 1.14 or later."},
            ],
        },
        {
            "cve": "CVE-2020-12017",
            "cwe": {"id": "CWE-798", "name": "Hard-coded Credentials"},
            "scores": [
                {
                    "cvss_v3": {
                        "baseScore": 6.1,
                        "baseSeverity": "MEDIUM",
                        "vectorString": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                    }
                }
            ],
            "remediations": [],
        },
    ],
}

_SAMPLE_TREE = {
    "tree": [
        {"path": "csaf_files/OT/white/2020/icsma-20-112-01.json", "type": "blob"},
        {"path": "csaf_files/OT/white/2022/icsma-22-076-01.json", "type": "blob"},
        {"path": "csaf_files/OT/white/2022/icsa-22-100-01.json", "type": "blob"},  # Not ICSMA
        {"path": "csaf_files/OT/white/README.md", "type": "blob"},  # Not JSON
    ]
}


# ---------------------------------------------------------------------------
# CSV Parsing
# ---------------------------------------------------------------------------

class TestParseIcsmaCsv:

    def test_parses_icsma_rows_only(self):
        advisories = parse_icsma_csv(_SAMPLE_CSV)
        assert len(advisories) == 2  # Skips ICSA row
        assert advisories[0]["advisory_id"] == "ICSMA-20-112-01"
        assert advisories[1]["advisory_id"] == "ICSMA-22-076-01"

    def test_parses_fields_correctly(self):
        advisories = parse_icsma_csv(_SAMPLE_CSV)
        adv = advisories[0]
        assert adv["title"] == "Baxter ExactaMix"
        assert adv["vendor"] == "Baxter"
        assert adv["product"] == "ExactaMix EM2400 & EM1200"
        assert adv["cves"] == ["CVE-2020-12016"]
        assert adv["cwes"] == ["CWE-319"]
        assert adv["cvss_score"] == 8.1
        assert adv["cvss_severity"] == "High"
        assert adv["original_release_date"] == "04/21/2020"
        assert adv["sector"] == "Healthcare and Public Health"

    def test_handles_empty_cves(self):
        advisories = parse_icsma_csv(_SAMPLE_CSV)
        # ICSA row is filtered out, but if it weren't, it has no CVE
        # Check the Philips row which does have a CVE
        assert advisories[1]["cves"] == ["CVE-2022-0922"]

    def test_empty_csv_returns_empty(self):
        assert parse_icsma_csv("") == []
        assert parse_icsma_csv("header1,header2\n") == []

    def test_handles_invalid_cvss(self):
        csv_text = (
            "icsad_ID,Original_Release_Date,Last_Updated,Year,ICS-CERT_Number,"
            "ICS-CERT_Advisory_Title,Vendor,Product,Products_Affected,CVE_Number,"
            "Cumulative_CVSS,CVSS_Severity,CWE_Number,Critical_Infrastructure_Sector,"
            "Product_Distribution,Company_Headquarters,License\n"
            "1,01/01/2020,01/01/2020,2020,ICSMA-20-001-01,Test,V,P,v1,,N/A,,"
            ",Healthcare,,US,\n"
        )
        advisories = parse_icsma_csv(csv_text)
        assert len(advisories) == 1
        assert advisories[0]["cvss_score"] is None


# ---------------------------------------------------------------------------
# CSAF Discovery
# ---------------------------------------------------------------------------

class TestDiscoverCsafFiles:

    def test_filters_icsma_json_only(self):
        files = discover_csaf_files(_SAMPLE_TREE)
        assert len(files) == 2  # Only the two ICSMA .json files
        paths = [f["path"] for f in files]
        assert "csaf_files/OT/white/2020/icsma-20-112-01.json" in paths
        assert "csaf_files/OT/white/2022/icsma-22-076-01.json" in paths

    def test_builds_raw_urls(self):
        files = discover_csaf_files(_SAMPLE_TREE)
        urls = [f["url"] for f in files]
        assert any("2020/icsma-20-112-01.json" in u for u in urls)

    def test_empty_tree(self):
        assert discover_csaf_files({"tree": []}) == []
        assert discover_csaf_files({}) == []


# ---------------------------------------------------------------------------
# CSAF Parsing
# ---------------------------------------------------------------------------

class TestParseCsafAdvisory:

    def test_extracts_basic_fields(self):
        result = parse_csaf_advisory(_SAMPLE_CSAF)
        assert result["advisory_id"] == "ICSMA-20-112-01"
        assert result["title"] == "Baxter ExactaMix"
        assert "cleartext" in result["description"].lower()
        assert "Successful exploitation" in result["risk_evaluation"]

    def test_extracts_cves(self):
        result = parse_csaf_advisory(_SAMPLE_CSAF)
        assert "CVE-2020-12016" in result["cves"]
        assert "CVE-2020-12017" in result["cves"]

    def test_extracts_cwes(self):
        result = parse_csaf_advisory(_SAMPLE_CSAF)
        assert "CWE-319" in result["cwes"]
        assert "CWE-798" in result["cwes"]

    def test_extracts_cvss(self):
        result = parse_csaf_advisory(_SAMPLE_CSAF)
        assert result["cvss_score"] == 8.1  # max of 8.1 and 6.1
        assert result["cvss_severity"] == "HIGH"
        assert "CVSS:3.1" in result["cvss_vector"]

    def test_extracts_remediations(self):
        result = parse_csaf_advisory(_SAMPLE_CSAF)
        assert len(result["remediations"]) == 1
        assert "version 1.14" in result["remediations"][0]

    def test_extracts_vendor_products(self):
        result = parse_csaf_advisory(_SAMPLE_CSAF)
        assert result["vendor"] == "Baxter"
        assert "ExactaMix EM2400" in result["products"]

    def test_extracts_references(self):
        result = parse_csaf_advisory(_SAMPLE_CSAF)
        assert len(result["references"]) == 2

    def test_empty_csaf(self):
        result = parse_csaf_advisory({})
        assert result["advisory_id"] == ""
        assert result["cves"] == []


# ---------------------------------------------------------------------------
# Merge CSV + CSAF
# ---------------------------------------------------------------------------

class TestMergeAdvisory:

    def test_csaf_enriches_csv(self):
        csv_row = parse_icsma_csv(_SAMPLE_CSV)[0]
        csaf_data = parse_csaf_advisory(_SAMPLE_CSAF)
        merged = _merge_advisory(csv_row, csaf_data)

        assert merged["advisory_id"] == "ICSMA-20-112-01"
        assert "cleartext" in merged["description"].lower()
        assert "CVE-2020-12016" in merged["cves"]
        assert "CVE-2020-12017" in merged["cves"]  # Added by CSAF
        assert "CWE-319" in merged["cwes"]
        assert "CWE-798" in merged["cwes"]  # Added by CSAF
        assert len(merged["remediations"]) == 1
        assert merged["vendor"] == "Baxter"

    def test_csv_only_when_no_csaf(self):
        csv_row = parse_icsma_csv(_SAMPLE_CSV)[0]
        merged = _merge_advisory(csv_row, None)
        assert merged["advisory_id"] == "ICSMA-20-112-01"
        assert merged["cves"] == ["CVE-2020-12016"]
        assert "description" not in merged  # No CSAF enrichment


# ---------------------------------------------------------------------------
# Cache operations
# ---------------------------------------------------------------------------

class TestCacheOps:

    def test_save_and_load(self, tmp_path):
        data = {"advisory_id": "ICSMA-20-112-01", "title": "Test"}
        _save_advisory_cache("ICSMA-20-112-01", data, tmp_path)
        loaded = _load_advisory_cache("ICSMA-20-112-01", tmp_path)
        assert loaded == data

    def test_load_missing_returns_none(self, tmp_path):
        assert _load_advisory_cache("ICSMA-99-999-01", tmp_path) is None

    def test_load_corrupted_returns_none(self, tmp_path):
        (tmp_path / "ICSMA-20-112-01.json").write_text("NOT JSON")
        assert _load_advisory_cache("ICSMA-20-112-01", tmp_path) is None


# ---------------------------------------------------------------------------
# Progress tracking
# ---------------------------------------------------------------------------

class TestProgress:

    def test_load_missing_returns_defaults(self, tmp_path):
        progress = _load_progress(tmp_path)
        assert progress["csv_fetched"] is False
        assert progress["completed"] is False

    def test_save_and_load_roundtrip(self, tmp_path):
        progress = {
            "csv_fetched": True,
            "csaf_files_fetched": 50,
            "csaf_files_total": 175,
            "advisories_total": 182,
            "completed": False,
            "last_updated": None,
        }
        _save_progress(tmp_path, progress)
        loaded = _load_progress(tmp_path)
        assert loaded["csv_fetched"] is True
        assert loaded["csaf_files_fetched"] == 50
        assert loaded["last_updated"] is not None


# ---------------------------------------------------------------------------
# Full backfill
# ---------------------------------------------------------------------------

class TestRunBackfill:

    def _make_fetch_fn(self, csv_text, tree_json, csaf_map):
        """Create a mock fetch function that returns different data per URL."""
        def fetch(url):
            if "CISA_ICS_ADV_Master.csv" in url:
                return csv_text.encode("utf-8")
            if "git/trees" in url:
                return json.dumps(tree_json).encode("utf-8")
            # Check for CSAF file requests
            for advisory_id, csaf_data in csaf_map.items():
                if advisory_id.lower() in url.lower():
                    return json.dumps(csaf_data).encode("utf-8")
            raise ValueError(f"Unexpected URL: {url}")
        return fetch

    def test_full_backfill(self, tmp_path):
        fetch_fn = self._make_fetch_fn(
            _SAMPLE_CSV, _SAMPLE_TREE,
            {"icsma-20-112-01": _SAMPLE_CSAF},
        )
        stats = run_backfill(cache_dir=tmp_path, _fetch_fn=fetch_fn)

        assert stats["status"] == "completed"
        assert stats["csv_advisories"] == 2
        assert stats["csaf_enriched"] == 1  # Only one has CSAF data
        assert stats["advisories_total"] == 2

        # Verify cached files
        assert (tmp_path / "ICSMA-20-112-01.json").exists()
        assert (tmp_path / "ICSMA-22-076-01.json").exists()

        # Verify enriched advisory has CSAF data
        data = json.loads((tmp_path / "ICSMA-20-112-01.json").read_text())
        assert "CVE-2020-12017" in data["cves"]  # From CSAF
        assert "description" in data

    def test_already_completed_returns_early(self, tmp_path):
        progress = {
            "csv_fetched": True,
            "csaf_files_fetched": 2,
            "csaf_files_total": 2,
            "advisories_total": 2,
            "completed": True,
            "last_updated": "2024-01-01T00:00:00",
        }
        _save_progress(tmp_path, progress)

        stats = run_backfill(
            cache_dir=tmp_path,
            _fetch_fn=lambda u: (_ for _ in ()).throw(AssertionError("Should not fetch")),
        )
        assert stats["status"] == "already_completed"

    def test_skips_cached_advisories(self, tmp_path):
        # Pre-cache one advisory
        _save_advisory_cache("ICSMA-20-112-01", {"advisory_id": "ICSMA-20-112-01", "cached": True}, tmp_path)

        fetch_fn = self._make_fetch_fn(
            _SAMPLE_CSV, _SAMPLE_TREE,
            {"icsma-22-076-01": {}},  # Only need CSAF for the non-cached one
        )
        stats = run_backfill(cache_dir=tmp_path, _fetch_fn=fetch_fn)

        assert stats["csaf_skipped_cached"] == 1
        # The cached version should NOT be overwritten
        data = json.loads((tmp_path / "ICSMA-20-112-01.json").read_text())
        assert data.get("cached") is True

    def test_handles_csaf_failure_gracefully(self, tmp_path):
        """If CSAF tree fetch fails, should still produce CSV-only results."""
        def fetch(url):
            if "CISA_ICS_ADV_Master.csv" in url:
                return _SAMPLE_CSV.encode("utf-8")
            if "git/trees" in url:
                raise ConnectionError("GitHub is down")
            raise ValueError(f"Unexpected URL: {url}")

        stats = run_backfill(cache_dir=tmp_path, _fetch_fn=fetch)

        assert stats["status"] == "completed"
        assert stats["csv_advisories"] == 2
        assert stats["csaf_enriched"] == 0
        assert len(stats["errors"]) == 1
        assert "GitHub" in stats["errors"][0]["error"]


# ---------------------------------------------------------------------------
# Signal generation
# ---------------------------------------------------------------------------

class TestGenerateSignals:

    def _populate_cache(self, cache_dir):
        for adv_id, title, vendor in [
            ("ICSMA-20-112-01", "Baxter ExactaMix", "Baxter"),
            ("ICSMA-22-076-01", "Philips e-Alert", "Philips"),
        ]:
            _save_advisory_cache(adv_id, {
                "advisory_id": adv_id,
                "title": title,
                "vendor": vendor,
                "product": "TestProduct",
                "cves": ["CVE-2020-12016"],
                "original_release_date": "04/21/2020",
                "description": f"Vulnerability in {vendor} product.",
            }, cache_dir)

    def test_generates_signals(self, tmp_path):
        self._populate_cache(tmp_path)
        signals = generate_signals_from_cache(cache_dir=tmp_path)
        assert len(signals) == 2
        assert all(s["source"] == "cisa-icsma-historical" for s in signals)
        assert signals[0]["guid"] == "ICSMA-20-112-01"
        assert "icsma-20-112-01" in signals[0]["link"]
        assert "Baxter" in signals[0]["summary"]
        assert signals[0]["published_date"] == "04/21/2020"

    def test_respects_limit(self, tmp_path):
        self._populate_cache(tmp_path)
        signals = generate_signals_from_cache(cache_dir=tmp_path, limit=1)
        assert len(signals) == 1

    def test_empty_cache(self, tmp_path):
        assert generate_signals_from_cache(cache_dir=tmp_path) == []

    def test_nonexistent_dir(self, tmp_path):
        assert generate_signals_from_cache(cache_dir=tmp_path / "nope") == []

    def test_custom_source_id(self, tmp_path):
        self._populate_cache(tmp_path)
        signals = generate_signals_from_cache(cache_dir=tmp_path, source_id="custom")
        assert signals[0]["source"] == "custom"

    def test_skips_progress_file(self, tmp_path):
        self._populate_cache(tmp_path)
        _save_progress(tmp_path, {"completed": True})
        signals = generate_signals_from_cache(cache_dir=tmp_path)
        assert len(signals) == 2  # Only the ICSMA files, not progress


# ---------------------------------------------------------------------------
# Incremental update
# ---------------------------------------------------------------------------

class TestIcsmaIncrementalUpdate:

    def _make_fetch_fn(self, csv_text, tree_json=None, csaf_map=None):
        """Create a mock fetch function."""
        if tree_json is None:
            tree_json = {"tree": []}
        if csaf_map is None:
            csaf_map = {}

        def fetch(url):
            if "CISA_ICS_ADV_Master.csv" in url:
                return csv_text.encode("utf-8")
            if "git/trees" in url:
                return json.dumps(tree_json).encode("utf-8")
            for advisory_id, csaf_data in csaf_map.items():
                if advisory_id.lower() in url.lower():
                    return json.dumps(csaf_data).encode("utf-8")
            raise ValueError(f"Unexpected URL: {url}")
        return fetch

    def test_detects_new_advisories(self, tmp_path):
        """Incremental should detect advisories not yet cached."""
        cache_dir = tmp_path / "cache"
        discover_root = tmp_path / "discover"

        # Pre-cache one advisory
        cache_dir.mkdir()
        _save_advisory_cache("ICSMA-20-112-01", {
            "advisory_id": "ICSMA-20-112-01",
            "title": "Baxter ExactaMix",
            "original_release_date": "04/21/2020",
        }, cache_dir)

        # CSV has 2 advisories (one cached, one new)
        fetch_fn = self._make_fetch_fn(_SAMPLE_CSV, _SAMPLE_TREE)

        stats = incremental_update(
            cache_dir=cache_dir,
            out_root=str(discover_root),
            _fetch_fn=fetch_fn,
        )

        assert stats["status"] == "completed"
        assert stats["new_advisories"] == 1  # Only ICSMA-22-076-01 is new
        assert stats["total_signals_published"] == 2  # Both in discover

    def test_no_new_advisories_still_publishes(self, tmp_path):
        """Even with no new advisories, should publish all cached signals."""
        cache_dir = tmp_path / "cache"
        discover_root = tmp_path / "discover"

        # Pre-cache both advisories
        cache_dir.mkdir()
        for adv_id, title in [
            ("ICSMA-20-112-01", "Baxter ExactaMix"),
            ("ICSMA-22-076-01", "Philips e-Alert"),
        ]:
            _save_advisory_cache(adv_id, {
                "advisory_id": adv_id,
                "title": title,
                "original_release_date": "01/01/2020",
            }, cache_dir)

        fetch_fn = self._make_fetch_fn(_SAMPLE_CSV)

        stats = incremental_update(
            cache_dir=cache_dir,
            out_root=str(discover_root),
            _fetch_fn=fetch_fn,
        )

        assert stats["new_advisories"] == 0
        assert stats["total_signals_published"] == 2

        # Verify discover artifacts
        items_path = discover_root / "cisa-icsma-historical" / "items.jsonl"
        assert items_path.exists()

    def test_new_signals_detected_across_runs(self, tmp_path):
        """Second run should mark previously-published signals as not new."""
        cache_dir = tmp_path / "cache"
        discover_root = tmp_path / "discover"
        cache_dir.mkdir()

        # Only 1 advisory in CSV on first run
        csv1 = _SAMPLE_CSV.split("\n")
        csv1_text = "\n".join(csv1[:2])  # Header + first ICSMA row

        fetch_fn1 = self._make_fetch_fn(csv1_text, _SAMPLE_TREE, {"icsma-20-112-01": _SAMPLE_CSAF})
        stats1 = incremental_update(
            cache_dir=cache_dir, out_root=str(discover_root), _fetch_fn=fetch_fn1,
        )
        assert stats1["new_signals_published"] == 1

        # Second run with same data — no new signals
        fetch_fn2 = self._make_fetch_fn(csv1_text)
        stats2 = incremental_update(
            cache_dir=cache_dir, out_root=str(discover_root), _fetch_fn=fetch_fn2,
        )
        assert stats2["new_signals_published"] == 0
        assert stats2["total_signals_published"] == 1

    def test_publishes_to_correct_discover_dir(self, tmp_path):
        cache_dir = tmp_path / "cache"
        discover_root = tmp_path / "discover"
        cache_dir.mkdir()

        fetch_fn = self._make_fetch_fn(_SAMPLE_CSV, _SAMPLE_TREE, {"icsma-20-112-01": _SAMPLE_CSAF})
        incremental_update(
            cache_dir=cache_dir,
            out_root=str(discover_root),
            source_id="cisa-icsma-historical",
            _fetch_fn=fetch_fn,
        )

        out_dir = discover_root / "cisa-icsma-historical"
        assert (out_dir / "items.jsonl").exists()
        assert (out_dir / "feed.json").exists()
        assert (out_dir / "state.json").exists()
        assert (out_dir / "meta.json").exists()
