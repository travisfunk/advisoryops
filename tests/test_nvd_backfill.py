"""Tests for NVD historical backfill: pagination, rate limiting, resumability, caching."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from advisoryops.sources.nvd_backfill import (
    RateLimiter,
    _extract_fields_for_cache,
    _load_progress,
    _save_progress,
    _save_cve_raw,
    generate_signals_from_cache,
    incremental_update,
    run_backfill,
)


# ---------------------------------------------------------------------------
# Fixtures: realistic NVD API response pages
# ---------------------------------------------------------------------------

def _nvd_page(
    *,
    start_index: int = 0,
    total_results: int = 5000,
    cves: list[dict] | None = None,
) -> dict:
    """Build a realistic NVD CVE 2.0 API page response."""
    if cves is None:
        cves = [_nvd_vuln(f"CVE-2024-{i:04d}") for i in range(start_index, start_index + 3)]
    return {
        "resultsPerPage": len(cves),
        "startIndex": start_index,
        "totalResults": total_results,
        "format": "NVD_CVE",
        "version": "2.0",
        "vulnerabilities": cves,
    }


def _nvd_vuln(
    cve_id: str = "CVE-2024-0001",
    description: str = "Test vulnerability description.",
    base_score: float = 7.5,
    severity: str = "HIGH",
    cwe: str = "CWE-79",
    published: str = "2024-01-15T10:00:00.000",
) -> dict:
    """Build a single NVD vulnerability wrapper."""
    return {
        "cve": {
            "id": cve_id,
            "published": published,
            "lastModified": published,
            "descriptions": [
                {"lang": "en", "value": description},
            ],
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {
                        "baseScore": base_score,
                        "baseSeverity": severity,
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    }
                }]
            },
            "weaknesses": [
                {"description": [{"lang": "en", "value": cwe}]},
            ],
            "configurations": [
                {
                    "nodes": [{
                        "cpeMatch": [{
                            "criteria": "cpe:2.3:a:test_vendor:test_product:1.0:*:*:*:*:*:*:*",
                            "vulnerable": True,
                        }]
                    }]
                }
            ],
            "references": [
                {"url": "https://example.com/advisory/1", "source": "vendor"},
            ],
        }
    }


# ---------------------------------------------------------------------------
# Field extraction
# ---------------------------------------------------------------------------

class TestExtractFieldsForCache:

    def test_extracts_all_fields(self):
        vuln = _nvd_vuln()
        fields = _extract_fields_for_cache(vuln["cve"])
        assert fields["nvd_description"] == "Test vulnerability description."
        assert fields["cvss_score"] == 7.5
        assert fields["cvss_severity"] == "HIGH"
        assert "CVSS:3.1" in fields["cvss_vector"]
        assert fields["cwe_ids"] == ["CWE-79"]
        assert "Test Vendor Test Product" in fields["affected_products"]
        assert fields["published_date"] == "2024-01-15T10:00:00.000"
        assert "https://example.com/advisory/1" in fields["references"]

    def test_empty_cve_returns_minimal(self):
        fields = _extract_fields_for_cache({})
        assert fields.get("cwe_ids") == []
        assert fields.get("affected_products") == []

    def test_v2_severity_derivation(self):
        cve_obj = {
            "descriptions": [{"lang": "en", "value": "Test"}],
            "metrics": {
                "cvssMetricV2": [{
                    "cvssData": {
                        "baseScore": 9.5,
                        "vectorString": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
                    }
                }]
            },
        }
        fields = _extract_fields_for_cache(cve_obj)
        assert fields["cvss_severity"] == "CRITICAL"
        assert fields["cvss_score"] == 9.5


# ---------------------------------------------------------------------------
# Cache operations
# ---------------------------------------------------------------------------

class TestSaveCveRaw:

    def test_saves_new_cve(self, tmp_path):
        vuln = _nvd_vuln("CVE-2024-9999")
        cve_id = _save_cve_raw(vuln, tmp_path)
        assert cve_id == "CVE-2024-9999"
        assert (tmp_path / "CVE-2024-9999.json").exists()

        data = json.loads((tmp_path / "CVE-2024-9999.json").read_text())
        assert data["nvd_description"] == "Test vulnerability description."

    def test_skips_existing_cve(self, tmp_path):
        # Pre-populate cache
        (tmp_path / "CVE-2024-0001.json").write_text('{"old": true}')
        vuln = _nvd_vuln("CVE-2024-0001")
        cve_id = _save_cve_raw(vuln, tmp_path)
        assert cve_id == "CVE-2024-0001"
        # Should NOT overwrite
        data = json.loads((tmp_path / "CVE-2024-0001.json").read_text())
        assert data == {"old": True}

    def test_returns_none_for_missing_id(self, tmp_path):
        assert _save_cve_raw({"cve": {}}, tmp_path) is None
        assert _save_cve_raw({}, tmp_path) is None


# ---------------------------------------------------------------------------
# Progress tracking
# ---------------------------------------------------------------------------

class TestProgress:

    def test_load_missing_returns_defaults(self, tmp_path):
        progress = _load_progress(tmp_path)
        assert progress["last_start_index"] == 0
        assert progress["total_results"] is None
        assert progress["completed"] is False

    def test_save_and_load_roundtrip(self, tmp_path):
        progress = {"last_start_index": 4000, "total_results": 10000,
                     "cves_fetched": 4000, "pages_fetched": 2,
                     "completed": False, "last_updated": None}
        _save_progress(tmp_path, progress)
        loaded = _load_progress(tmp_path)
        assert loaded["last_start_index"] == 4000
        assert loaded["total_results"] == 10000
        assert loaded["last_updated"] is not None

    def test_load_corrupted_returns_defaults(self, tmp_path):
        (tmp_path / "_backfill_progress.json").write_text("NOT JSON")
        progress = _load_progress(tmp_path)
        assert progress["last_start_index"] == 0


# ---------------------------------------------------------------------------
# Paginated backfill
# ---------------------------------------------------------------------------

class TestRunBackfill:

    def test_fetches_all_pages(self, tmp_path):
        """Simulate a 6-CVE database with page_size=3 → 2 pages."""
        pages = {
            0: _nvd_page(
                start_index=0, total_results=6,
                cves=[_nvd_vuln(f"CVE-2024-{i:04d}") for i in range(3)],
            ),
            3: _nvd_page(
                start_index=3, total_results=6,
                cves=[_nvd_vuln(f"CVE-2024-{i:04d}") for i in range(3, 6)],
            ),
        }

        def mock_fetch(url: str) -> bytes:
            for idx in pages:
                if f"startIndex={idx}" in url:
                    return json.dumps(pages[idx]).encode()
            return json.dumps(_nvd_page(total_results=6, cves=[])).encode()

        stats = run_backfill(
            cache_dir=tmp_path, page_size=3, _fetch_fn=mock_fetch,
        )
        assert stats["status"] == "completed"
        assert stats["cves_fetched"] == 6
        assert stats["cves_new"] == 6
        assert stats["pages_fetched"] == 2

        # Verify cache files exist
        for i in range(6):
            assert (tmp_path / f"CVE-2024-{i:04d}.json").exists()

        # Verify progress file
        progress = _load_progress(tmp_path)
        assert progress["completed"] is True

    def test_respects_max_results(self, tmp_path):
        """Stop after max_results even if more are available."""
        page = _nvd_page(
            start_index=0, total_results=100000,
            cves=[_nvd_vuln(f"CVE-2024-{i:04d}") for i in range(5)],
        )

        def mock_fetch(url: str) -> bytes:
            return json.dumps(page).encode()

        stats = run_backfill(
            cache_dir=tmp_path, max_results=5, page_size=5, _fetch_fn=mock_fetch,
        )
        assert stats["cves_fetched"] == 5
        assert stats["pages_fetched"] == 1

    def test_resumes_from_progress(self, tmp_path):
        """If progress says we left off at startIndex=3, skip page 0."""
        # Pre-populate progress
        progress = {
            "last_start_index": 3,
            "total_results": 6,
            "cves_fetched": 3,
            "pages_fetched": 1,
            "completed": False,
            "last_updated": None,
        }
        _save_progress(tmp_path, progress)

        # Also pre-populate cache for first 3 CVEs
        for i in range(3):
            vuln = _nvd_vuln(f"CVE-2024-{i:04d}")
            _save_cve_raw(vuln, tmp_path)

        page2 = _nvd_page(
            start_index=3, total_results=6,
            cves=[_nvd_vuln(f"CVE-2024-{i:04d}") for i in range(3, 6)],
        )

        fetched_urls = []

        def mock_fetch(url: str) -> bytes:
            fetched_urls.append(url)
            if "startIndex=3" in url:
                return json.dumps(page2).encode()
            return json.dumps(_nvd_page(total_results=6, cves=[])).encode()

        stats = run_backfill(
            cache_dir=tmp_path, page_size=3, _fetch_fn=mock_fetch,
        )

        assert stats["status"] == "completed"
        # Should have only fetched page 2
        assert any("startIndex=3" in u for u in fetched_urls)
        assert not any("startIndex=0" in u for u in fetched_urls)

    def test_already_completed_returns_early(self, tmp_path):
        progress = {
            "last_start_index": 6,
            "total_results": 6,
            "cves_fetched": 6,
            "pages_fetched": 2,
            "completed": True,
            "last_updated": "2024-01-01T00:00:00",
        }
        _save_progress(tmp_path, progress)

        stats = run_backfill(
            cache_dir=tmp_path, _fetch_fn=lambda u: b"should not be called",
        )
        assert stats["status"] == "already_completed"

    def test_skips_already_cached_cves(self, tmp_path):
        """Pre-cached CVEs should be counted as skipped, not new."""
        # Pre-populate one CVE
        vuln = _nvd_vuln("CVE-2024-0001")
        _save_cve_raw(vuln, tmp_path)

        page = _nvd_page(
            start_index=0, total_results=2,
            cves=[
                _nvd_vuln("CVE-2024-0001"),  # already cached
                _nvd_vuln("CVE-2024-0002"),  # new
            ],
        )

        def mock_fetch(url: str) -> bytes:
            return json.dumps(page).encode()

        stats = run_backfill(
            cache_dir=tmp_path, page_size=2, _fetch_fn=mock_fetch,
        )
        assert stats["cves_new"] == 1
        assert stats["cves_skipped"] == 1


# ---------------------------------------------------------------------------
# Signal generation from cache
# ---------------------------------------------------------------------------

class TestGenerateSignalsFromCache:

    def test_generates_signals_from_cached_files(self, tmp_path):
        # Create a couple of cached CVEs
        for i in range(3):
            vuln = _nvd_vuln(f"CVE-2024-{i:04d}")
            _save_cve_raw(vuln, tmp_path)

        signals = generate_signals_from_cache(cache_dir=tmp_path)
        assert len(signals) == 3
        assert all(s["source"] == "nvd-historical" for s in signals)
        assert signals[0]["guid"] == "CVE-2024-0000"
        assert signals[0]["title"] == "CVE-2024-0000"
        assert "nvd.nist.gov" in signals[0]["link"] or "example.com" in signals[0]["link"]
        assert signals[0]["published_date"] == "2024-01-15T10:00:00.000"

    def test_respects_limit(self, tmp_path):
        for i in range(10):
            vuln = _nvd_vuln(f"CVE-2024-{i:04d}")
            _save_cve_raw(vuln, tmp_path)

        signals = generate_signals_from_cache(cache_dir=tmp_path, limit=3)
        assert len(signals) == 3

    def test_empty_cache_returns_empty(self, tmp_path):
        signals = generate_signals_from_cache(cache_dir=tmp_path)
        assert signals == []

    def test_nonexistent_dir_returns_empty(self, tmp_path):
        signals = generate_signals_from_cache(cache_dir=tmp_path / "nope")
        assert signals == []

    def test_custom_source_id(self, tmp_path):
        vuln = _nvd_vuln("CVE-2024-0001")
        _save_cve_raw(vuln, tmp_path)
        signals = generate_signals_from_cache(
            cache_dir=tmp_path, source_id="custom-source"
        )
        assert signals[0]["source"] == "custom-source"

    def test_skips_progress_file(self, tmp_path):
        """The _backfill_progress.json file should not generate a signal."""
        vuln = _nvd_vuln("CVE-2024-0001")
        _save_cve_raw(vuln, tmp_path)
        _save_progress(tmp_path, {"completed": True})
        signals = generate_signals_from_cache(cache_dir=tmp_path)
        assert len(signals) == 1  # Only the CVE, not the progress file


# ---------------------------------------------------------------------------
# Incremental update
# ---------------------------------------------------------------------------

class TestNvdIncrementalUpdate:

    def test_fetches_recent_cves_and_publishes(self, tmp_path):
        """Incremental update should query with lastModStartDate and publish signals."""
        cache_dir = tmp_path / "cache"
        discover_root = tmp_path / "discover"

        # Pre-populate 2 cached CVEs
        cache_dir.mkdir()
        for i in range(2):
            vuln = _nvd_vuln(f"CVE-2024-{i:04d}")
            _save_cve_raw(vuln, cache_dir)

        # Mock: return 1 new CVE from the "recent" query
        page = _nvd_page(
            start_index=0, total_results=1,
            cves=[_nvd_vuln("CVE-2024-9999")],
        )

        def mock_fetch(url: str) -> bytes:
            return json.dumps(page).encode()

        stats = incremental_update(
            cache_dir=cache_dir,
            out_root=str(discover_root),
            _fetch_fn=mock_fetch,
        )

        assert stats["status"] == "completed"
        assert stats["new_cves_fetched"] == 1
        assert stats["new_cves_cached"] == 1
        # Should publish all 3 signals (2 old + 1 new)
        assert stats["total_signals_published"] == 3

        # Verify discover artifacts exist
        items_path = discover_root / "nvd-historical" / "items.jsonl"
        assert items_path.exists()
        lines = items_path.read_text().strip().split("\n")
        assert len(lines) == 3

    def test_publishes_existing_cache_even_with_no_new_cves(self, tmp_path):
        """Even if no new CVEs, should still publish cached signals."""
        cache_dir = tmp_path / "cache"
        discover_root = tmp_path / "discover"

        cache_dir.mkdir()
        vuln = _nvd_vuln("CVE-2024-0001")
        _save_cve_raw(vuln, cache_dir)

        page = _nvd_page(start_index=0, total_results=0, cves=[])

        stats = incremental_update(
            cache_dir=cache_dir,
            out_root=str(discover_root),
            _fetch_fn=lambda url: json.dumps(page).encode(),
        )

        assert stats["status"] == "completed"
        assert stats["new_cves_cached"] == 0
        assert stats["total_signals_published"] == 1

    def test_uses_lastmod_date_in_url(self, tmp_path):
        """Incremental should use lastModStartDate parameter."""
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        fetched_urls = []
        page = _nvd_page(start_index=0, total_results=0, cves=[])

        def mock_fetch(url: str) -> bytes:
            fetched_urls.append(url)
            return json.dumps(page).encode()

        incremental_update(
            cache_dir=cache_dir,
            out_root=str(tmp_path / "discover"),
            _fetch_fn=mock_fetch,
        )

        assert len(fetched_urls) == 1
        assert "lastModStartDate=" in fetched_urls[0]
        assert "lastModEndDate=" in fetched_urls[0]

    def test_new_items_detected_on_second_run(self, tmp_path):
        """Second incremental run should detect previously published as not-new."""
        cache_dir = tmp_path / "cache"
        discover_root = tmp_path / "discover"
        cache_dir.mkdir()

        vuln = _nvd_vuln("CVE-2024-0001")
        _save_cve_raw(vuln, cache_dir)

        page = _nvd_page(start_index=0, total_results=0, cves=[])
        fetch_fn = lambda url: json.dumps(page).encode()

        # First run
        stats1 = incremental_update(
            cache_dir=cache_dir, out_root=str(discover_root), _fetch_fn=fetch_fn,
        )
        assert stats1["new_signals_published"] == 1

        # Second run (same cache, no new CVEs)
        stats2 = incremental_update(
            cache_dir=cache_dir, out_root=str(discover_root), _fetch_fn=fetch_fn,
        )
        assert stats2["new_signals_published"] == 0


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

class TestRateLimiter:

    def test_allows_initial_requests(self):
        rl = RateLimiter(max_requests=5, window_seconds=30)
        # Should not block for first 5 calls
        for _ in range(5):
            rl.wait()  # Should return immediately (or near-immediately)

    def test_rate_limiter_creation_with_key(self, monkeypatch):
        monkeypatch.setenv("NVD_API_KEY", "test-key")
        from advisoryops.sources.nvd_backfill import _get_rate_limiter
        rl = _get_rate_limiter()
        assert rl._max == 45

    def test_rate_limiter_creation_without_key(self, monkeypatch):
        monkeypatch.delenv("NVD_API_KEY", raising=False)
        from advisoryops.sources.nvd_backfill import _get_rate_limiter
        rl = _get_rate_limiter()
        assert rl._max == 4
