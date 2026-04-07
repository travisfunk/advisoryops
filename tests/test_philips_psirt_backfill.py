"""Tests for Philips PSIRT advisory backfill."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from advisoryops.sources.philips_psirt_backfill import (
    _load_progress,
    _save_progress,
    _save_advisory_cache,
    _load_advisory_cache,
    generate_signals_from_cache,
    incremental_update,
    parse_advisory_page,
    run_backfill,
)


# ---------------------------------------------------------------------------
# Fixtures: sample Philips advisory HTML
# ---------------------------------------------------------------------------

_SAMPLE_HTML = """
<html>
<head><title>Philips Security Advisories</title></head>
<body>
<div class="advisory-list">
  <div class="advisory-item">
    <a href="/a-w/security/security-advisories/philips-patient-monitoring-2024.html">
      Philips Patient Monitoring Network Vulnerability Advisory
    </a>
    <span class="date">January 15, 2024</span>
    <p>Addresses CVE-2024-1234 and CVE-2024-1235 in patient monitoring firmware.</p>
  </div>
  <div class="advisory-item">
    <a href="/a-w/security/security-advisories/philips-intellispace-portal-2024.html">
      Philips IntelliSpace Portal Security Update Advisory
    </a>
    <span class="date">March 20, 2024</span>
    <p>Security update for IntelliSpace Portal addressing CVE-2024-5678.</p>
  </div>
  <div class="advisory-item">
    <a href="https://www.example.com/unrelated">Not an advisory link</a>
  </div>
</div>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# HTML parsing
# ---------------------------------------------------------------------------

class TestParseAdvisoryPage:

    def test_extracts_advisory_links(self):
        advisories = parse_advisory_page(_SAMPLE_HTML, year=2024)
        # Should find the two advisory links (not the unrelated one)
        assert len(advisories) >= 2

    def test_extracts_titles(self):
        advisories = parse_advisory_page(_SAMPLE_HTML, year=2024)
        titles = [a["title"] for a in advisories]
        assert any("Patient Monitoring" in t for t in titles)
        assert any("IntelliSpace" in t for t in titles)

    def test_extracts_cves(self):
        advisories = parse_advisory_page(_SAMPLE_HTML, year=2024)
        all_cves = []
        for a in advisories:
            all_cves.extend(a.get("cves", []))
        assert "CVE-2024-1234" in all_cves

    def test_builds_full_urls(self):
        advisories = parse_advisory_page(_SAMPLE_HTML, year=2024)
        for a in advisories:
            assert a["link"].startswith("https://")

    def test_sets_vendor(self):
        advisories = parse_advisory_page(_SAMPLE_HTML, year=2024)
        for a in advisories:
            assert a["vendor"] == "Philips"

    def test_advisory_ids_prefixed(self):
        advisories = parse_advisory_page(_SAMPLE_HTML, year=2024)
        for a in advisories:
            assert a["advisory_id"].startswith("PHILIPS-")

    def test_empty_html(self):
        assert parse_advisory_page("", year=2024) == []
        assert parse_advisory_page("<html></html>", year=2024) == []


# ---------------------------------------------------------------------------
# Cache operations
# ---------------------------------------------------------------------------

class TestCacheOps:

    def test_save_and_load(self, tmp_path):
        data = {"advisory_id": "PHILIPS-test-123", "title": "Test Advisory"}
        _save_advisory_cache("PHILIPS-test-123", data, tmp_path)
        loaded = _load_advisory_cache("PHILIPS-test-123", tmp_path)
        assert loaded == data

    def test_save_skips_existing(self, tmp_path):
        data1 = {"advisory_id": "PHILIPS-x", "version": 1}
        data2 = {"advisory_id": "PHILIPS-x", "version": 2}
        _save_advisory_cache("PHILIPS-x", data1, tmp_path)
        _save_advisory_cache("PHILIPS-x", data2, tmp_path)
        loaded = _load_advisory_cache("PHILIPS-x", tmp_path)
        assert loaded["version"] == 1  # Not overwritten

    def test_load_missing(self, tmp_path):
        assert _load_advisory_cache("PHILIPS-nonexistent", tmp_path) is None


# ---------------------------------------------------------------------------
# Progress
# ---------------------------------------------------------------------------

class TestProgress:

    def test_defaults(self, tmp_path):
        p = _load_progress(tmp_path)
        assert p["completed"] is False
        assert p["years_completed"] == []

    def test_roundtrip(self, tmp_path):
        p = {"years_completed": [2023, 2024], "advisories_total": 10,
             "completed": True, "last_updated": None}
        _save_progress(tmp_path, p)
        loaded = _load_progress(tmp_path)
        assert loaded["years_completed"] == [2023, 2024]
        assert loaded["last_updated"] is not None


# ---------------------------------------------------------------------------
# Full backfill
# ---------------------------------------------------------------------------

class TestRunBackfill:

    def test_fetches_pages_and_caches(self, tmp_path):
        pages_served = []

        def mock_fetch(url):
            pages_served.append(url)
            return _SAMPLE_HTML.encode("utf-8")

        stats = run_backfill(cache_dir=tmp_path, _fetch_fn=mock_fetch)

        assert stats["status"] == "completed"
        assert stats["pages_fetched"] > 0
        assert stats["advisories_found"] > 0
        assert stats["advisories_new"] > 0

    def test_already_completed(self, tmp_path):
        _save_progress(tmp_path, {
            "years_completed": [2024], "advisories_total": 5,
            "completed": True, "last_updated": "2024-01-01",
        })
        stats = run_backfill(cache_dir=tmp_path, _fetch_fn=lambda u: b"error")
        assert stats["status"] == "already_completed"

    def test_handles_fetch_failure(self, tmp_path):
        call_count = [0]

        def failing_fetch(url):
            call_count[0] += 1
            raise ConnectionError("Philips is down")

        stats = run_backfill(cache_dir=tmp_path, _fetch_fn=failing_fetch)

        assert stats["status"] == "completed"
        assert stats["pages_failed"] > 0
        assert len(stats["errors"]) > 0


# ---------------------------------------------------------------------------
# Signal generation
# ---------------------------------------------------------------------------

class TestGenerateSignals:

    def _populate_cache(self, cache_dir, n=3):
        for i in range(n):
            _save_advisory_cache(f"PHILIPS-test-{i:03d}", {
                "advisory_id": f"PHILIPS-test-{i:03d}",
                "title": f"Test Advisory {i}",
                "link": f"https://philips.com/advisory/{i}",
                "date": "2024-01-15",
                "cves": [f"CVE-2024-{i:04d}"],
                "vendor": "Philips",
                "summary": f"Test advisory {i} description.",
            }, cache_dir)

    def test_generates_signals(self, tmp_path):
        self._populate_cache(tmp_path)
        signals = generate_signals_from_cache(cache_dir=tmp_path)
        assert len(signals) == 3
        assert all(s["source"] == "philips-psirt" for s in signals)

    def test_signal_format(self, tmp_path):
        self._populate_cache(tmp_path, 1)
        signals = generate_signals_from_cache(cache_dir=tmp_path)
        s = signals[0]
        assert "PHILIPS-" in s["guid"]
        assert s["published_date"] == "2024-01-15"
        assert "CVE-2024-0000" in s["summary"]
        assert s["link"].startswith("https://")

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

    def test_fetches_current_and_publishes(self, tmp_path):
        cache_dir = tmp_path / "cache"
        discover_root = tmp_path / "discover"
        cache_dir.mkdir()

        # Pre-cache one advisory
        _save_advisory_cache("PHILIPS-old", {
            "advisory_id": "PHILIPS-old",
            "title": "Old Advisory",
            "link": "https://philips.com/old",
            "date": "2023-01-01",
            "cves": [],
            "vendor": "Philips",
            "summary": "Old advisory.",
        }, cache_dir)

        stats = incremental_update(
            cache_dir=cache_dir,
            out_root=str(discover_root),
            _fetch_fn=lambda url: _SAMPLE_HTML.encode("utf-8"),
        )

        assert stats["status"] == "completed"
        assert stats["total_signals_published"] >= 1

        items_path = discover_root / "philips-psirt" / "items.jsonl"
        assert items_path.exists()

    def test_handles_fetch_error(self, tmp_path):
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        stats = incremental_update(
            cache_dir=cache_dir,
            out_root=str(tmp_path / "discover"),
            _fetch_fn=lambda url: (_ for _ in ()).throw(ConnectionError("down")),
        )

        assert stats["status"] == "completed"
        assert len(stats["errors"]) == 1
