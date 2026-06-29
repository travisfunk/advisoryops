"""Tests for Siemens ProductCERT CSAF feed backfill."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from advisoryops.sources.siemens_productcert_backfill import (
    _load_progress,
    _save_progress,
    _save_advisory_cache,
    _load_advisory_cache,
    generate_signals_from_cache,
    incremental_update,
    parse_csaf_advisory,
    parse_csaf_feed,
    run_backfill,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_SAMPLE_FEED = [
    {
        "id": "ssa-123456",
        "title": "SSA-123456: Vulnerability in SIMATIC S7-1200",
        "published": "2024-01-15T00:00:00Z",
        "url": "https://cert-portal.siemens.com/productcert/csaf/ssa-123456.json",
    },
    {
        "id": "ssa-789012",
        "title": "SSA-789012: Multiple Vulnerabilities in SCALANCE",
        "published": "2024-02-20T00:00:00Z",
        "url": "https://cert-portal.siemens.com/productcert/csaf/ssa-789012.json",
    },
]

_SAMPLE_CSAF = {
    "document": {
        "tracking": {
            "id": "SSA-123456",
            "initial_release_date": "2024-01-15T00:00:00Z",
            "current_release_date": "2024-01-20T00:00:00Z",
        },
        "title": "SSA-123456: Vulnerability in SIMATIC S7-1200",
        "notes": [
            {"category": "summary", "text": "A vulnerability in SIMATIC S7-1200 allows remote code execution."},
        ],
        "references": [
            {"url": "https://cert-portal.siemens.com/productcert/html/ssa-123456.html"},
        ],
    },
    "product_tree": {
        "branches": [
            {
                "name": "Siemens",
                "branches": [
                    {"name": "SIMATIC S7-1200"},
                    {"name": "SIMATIC S7-1500"},
                ],
            }
        ]
    },
    "vulnerabilities": [
        {
            "cve": "CVE-2024-1111",
            "cwe": {"id": "CWE-787", "name": "Out-of-bounds Write"},
            "scores": [
                {
                    "cvss_v3": {
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    }
                }
            ],
            "remediations": [
                {"details": "Update to firmware V4.6 or later."},
            ],
        },
    ],
}


# ---------------------------------------------------------------------------
# Feed parsing
# ---------------------------------------------------------------------------

class TestParseCsafFeed:

    def test_parses_list_feed(self):
        entries = parse_csaf_feed(_SAMPLE_FEED)
        assert len(entries) == 2
        assert entries[0]["advisory_id"] == "SSA-123456"
        assert entries[1]["advisory_id"] == "SSA-789012"

    def test_parses_dict_feed(self):
        entries = parse_csaf_feed({"advisories": _SAMPLE_FEED})
        assert len(entries) == 2

    def test_builds_urls(self):
        entries = parse_csaf_feed(_SAMPLE_FEED)
        assert "ssa-123456.json" in entries[0]["url"]

    def test_empty_feed(self):
        assert parse_csaf_feed([]) == []
        assert parse_csaf_feed({}) == []


# ---------------------------------------------------------------------------
# CSAF advisory parsing
# ---------------------------------------------------------------------------

class TestParseCsafAdvisory:

    def test_extracts_fields(self):
        result = parse_csaf_advisory(_SAMPLE_CSAF)
        assert result["advisory_id"] == "SSA-123456"
        assert "SIMATIC" in result["title"]
        assert "remote code execution" in result["description"]
        assert result["cves"] == ["CVE-2024-1111"]
        assert result["cwes"] == ["CWE-787"]
        assert result["cvss_score"] == 9.8
        assert result["cvss_severity"] == "CRITICAL"
        assert len(result["remediations"]) == 1
        assert "SIMATIC S7-1200" in result["products"]

    def test_empty_csaf(self):
        result = parse_csaf_advisory({})
        assert result["advisory_id"] == ""
        assert result["cves"] == []
        assert result["cwes"] == []


# ---------------------------------------------------------------------------
# Cache operations
# ---------------------------------------------------------------------------

class TestCacheOps:

    def test_save_and_load(self, tmp_path):
        data = {"advisory_id": "SSA-123456", "title": "Test"}
        _save_advisory_cache("SSA-123456", data, tmp_path)
        loaded = _load_advisory_cache("SSA-123456", tmp_path)
        assert loaded == data

    def test_save_skips_existing(self, tmp_path):
        data1 = {"advisory_id": "SSA-X", "v": 1}
        data2 = {"advisory_id": "SSA-X", "v": 2}
        _save_advisory_cache("SSA-X", data1, tmp_path)
        _save_advisory_cache("SSA-X", data2, tmp_path)
        loaded = _load_advisory_cache("SSA-X", tmp_path)
        assert loaded["v"] == 1

    def test_load_missing(self, tmp_path):
        assert _load_advisory_cache("SSA-NOPE", tmp_path) is None


# ---------------------------------------------------------------------------
# Progress
# ---------------------------------------------------------------------------

class TestProgress:

    def test_defaults(self, tmp_path):
        p = _load_progress(tmp_path)
        assert p["completed"] is False

    def test_roundtrip(self, tmp_path):
        p = {"feed_fetched": True, "advisories_in_feed": 80,
             "csaf_fetched": 75, "completed": True, "last_updated": None}
        _save_progress(tmp_path, p)
        loaded = _load_progress(tmp_path)
        assert loaded["csaf_fetched"] == 75
        assert loaded["last_updated"] is not None


# ---------------------------------------------------------------------------
# Full backfill
# ---------------------------------------------------------------------------

class TestRunBackfill:

    def _make_fetch_fn(self, feed, csaf_map):
        def fetch(url):
            if "feed" in url.lower():
                return json.dumps(feed).encode()
            for ssa_id, csaf_data in csaf_map.items():
                if ssa_id.lower() in url.lower():
                    return json.dumps(csaf_data).encode()
            return json.dumps({}).encode()
        return fetch

    def test_fetches_feed_and_csaf(self, tmp_path):
        fetch_fn = self._make_fetch_fn(
            _SAMPLE_FEED,
            {"ssa-123456": _SAMPLE_CSAF, "ssa-789012": _SAMPLE_CSAF},
        )
        stats = run_backfill(cache_dir=tmp_path, _fetch_fn=fetch_fn)

        assert stats["status"] == "completed"
        assert stats["advisories_in_feed"] == 2
        assert stats["csaf_fetched"] == 2
        assert (tmp_path / "SSA-123456.json").exists()

    def test_already_completed(self, tmp_path):
        _save_progress(tmp_path, {
            "feed_fetched": True, "advisories_in_feed": 2,
            "csaf_fetched": 2, "completed": True, "last_updated": "x",
        })
        stats = run_backfill(cache_dir=tmp_path, _fetch_fn=lambda u: b"error")
        assert stats["status"] == "already_completed"

    def test_skips_cached(self, tmp_path):
        _save_advisory_cache("SSA-123456", {"advisory_id": "SSA-123456"}, tmp_path)

        fetch_fn = self._make_fetch_fn(
            _SAMPLE_FEED,
            {"ssa-789012": _SAMPLE_CSAF},
        )
        stats = run_backfill(cache_dir=tmp_path, _fetch_fn=fetch_fn)

        assert stats["csaf_cached"] == 1
        assert stats["csaf_fetched"] == 1

    def test_handles_csaf_failure(self, tmp_path):
        def fetch(url):
            if "feed" in url.lower():
                return json.dumps(_SAMPLE_FEED).encode()
            raise ConnectionError("CSAF server down")

        stats = run_backfill(cache_dir=tmp_path, _fetch_fn=fetch)
        assert stats["status"] == "completed"
        assert stats["csaf_failed"] == 2


# ---------------------------------------------------------------------------
# Signal generation
# ---------------------------------------------------------------------------

class TestGenerateSignals:

    def _populate_cache(self, cache_dir, n=2):
        for i in range(n):
            _save_advisory_cache(f"SSA-{i:06d}", {
                "advisory_id": f"SSA-{i:06d}",
                "title": f"SSA-{i:06d}: Test Vulnerability {i}",
                "url": f"https://cert-portal.siemens.com/productcert/csaf/ssa-{i:06d}.json",
                "published": "2024-01-15",
                "cves": [f"CVE-2024-{i:04d}"],
                "vendor": "Siemens",
                "description": f"Test vulnerability {i}.",
            }, cache_dir)

    def test_generates_signals(self, tmp_path):
        self._populate_cache(tmp_path)
        signals = generate_signals_from_cache(cache_dir=tmp_path)
        assert len(signals) == 2
        assert all(s["source"] == "siemens-productcert-psirt" for s in signals)

    def test_signal_format(self, tmp_path):
        self._populate_cache(tmp_path, 1)
        signals = generate_signals_from_cache(cache_dir=tmp_path)
        s = signals[0]
        assert s["guid"].startswith("SSA-")
        assert "cert-portal.siemens.com" in s["link"]
        assert "CVE-2024-0000" in s["summary"]

    def test_respects_limit(self, tmp_path):
        self._populate_cache(tmp_path, 10)
        signals = generate_signals_from_cache(cache_dir=tmp_path, limit=3)
        assert len(signals) == 3

    def test_empty_cache(self, tmp_path):
        assert generate_signals_from_cache(cache_dir=tmp_path) == []

    def test_skips_progress_file(self, tmp_path):
        self._populate_cache(tmp_path, 1)
        _save_progress(tmp_path, {"completed": True})
        signals = generate_signals_from_cache(cache_dir=tmp_path)
        assert len(signals) == 1


# ---------------------------------------------------------------------------
# Incremental update
# ---------------------------------------------------------------------------

class TestIncrementalUpdate:

    def test_fetches_new_and_publishes(self, tmp_path):
        cache_dir = tmp_path / "cache"
        discover_root = tmp_path / "discover"
        cache_dir.mkdir()

        # Pre-cache one advisory
        _save_advisory_cache("SSA-123456", {
            "advisory_id": "SSA-123456",
            "title": "Old advisory",
            "url": "https://example.com",
            "published": "2024-01-15",
            "vendor": "Siemens",
        }, cache_dir)

        def fetch(url):
            if "feed" in url.lower():
                return json.dumps(_SAMPLE_FEED).encode()
            return json.dumps(_SAMPLE_CSAF).encode()

        stats = incremental_update(
            cache_dir=cache_dir,
            out_root=str(discover_root),
            _fetch_fn=fetch,
        )

        assert stats["status"] == "completed"
        assert stats["new_advisories"] == 1  # SSA-789012 is new
        assert stats["total_signals_published"] == 2

        items_path = discover_root / "siemens-productcert-psirt" / "items.jsonl"
        assert items_path.exists()

    def test_handles_feed_error(self, tmp_path):
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        stats = incremental_update(
            cache_dir=cache_dir,
            out_root=str(tmp_path / "discover"),
            _fetch_fn=lambda url: (_ for _ in ()).throw(ConnectionError("down")),
        )

        assert stats["status"] == "completed"
        assert len(stats["errors"]) == 1
