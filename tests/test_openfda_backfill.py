"""Tests for openFDA device recalls backfill: pagination, filtering, caching, incremental."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from advisoryops.sources.openfda_backfill import (
    _RateLimiter,
    _load_progress,
    _recall_cache_id,
    _save_progress,
    _save_recall_cache,
    generate_signals_from_cache,
    incremental_update,
    is_cyber_relevant,
    run_backfill,
    run_backfill_date_ranges,
)


# ---------------------------------------------------------------------------
# Fixtures: realistic openFDA API responses
# ---------------------------------------------------------------------------

def _fda_page(
    *,
    skip: int = 0,
    total: int = 200,
    recalls: list[dict] | None = None,
) -> dict:
    """Build a realistic openFDA device recall API page."""
    if recalls is None:
        recalls = [_fda_recall(f"RES-{skip + i:05d}") for i in range(3)]
    return {
        "meta": {
            "results": {"skip": skip, "limit": len(recalls), "total": total},
        },
        "results": recalls,
    }


def _fda_recall(
    res_event_number: str = "RES-00001",
    recall_number: str = "",
    reason: str = "Device malfunction due to component failure.",
    product_description: str = "Patient monitoring system model X.",
    recalling_firm: str = "MedDevice Corp",
    recall_initiation_date: str = "20240115",
    cyber: bool = False,
) -> dict:
    """Build a single openFDA recall record."""
    if cyber:
        reason = "Cybersecurity vulnerability in firmware allows unauthorized remote access."
    recall = {
        "res_event_number": res_event_number,
        "product_description": product_description,
        "reason_for_recall": reason,
        "recalling_firm": recalling_firm,
        "recall_initiation_date": recall_initiation_date,
        "root_cause_description": "",
        "event_id": f"EVT-{res_event_number.split('-')[-1]}",
    }
    if recall_number:
        recall["recall_number"] = recall_number
    return recall


# ---------------------------------------------------------------------------
# Cybersecurity relevance filter
# ---------------------------------------------------------------------------

class TestIsCyberRelevant:

    def test_positive_cybersecurity(self):
        r = _fda_recall(reason="Cybersecurity vulnerability allows remote access")
        assert is_cyber_relevant(r) is True

    def test_positive_firmware(self):
        r = _fda_recall(reason="Firmware update required to address security flaw")
        assert is_cyber_relevant(r) is True

    def test_positive_authentication(self):
        r = _fda_recall(product_description="Network-connected device with authentication bypass")
        assert is_cyber_relevant(r) is True

    def test_positive_cve(self):
        r = _fda_recall(reason="Addresses CVE-2024-1234 in device software")
        assert is_cyber_relevant(r) is True

    def test_positive_malware(self):
        r = _fda_recall(reason="Device susceptible to ransomware attack")
        assert is_cyber_relevant(r) is True

    def test_positive_patch(self):
        r = _fda_recall(reason="Software patch required for security update")
        assert is_cyber_relevant(r) is True

    def test_negative_mechanical(self):
        r = _fda_recall(reason="Mechanical spring failure in pump assembly")
        assert is_cyber_relevant(r) is False

    def test_negative_labeling(self):
        r = _fda_recall(reason="Incorrect labeling of dosage instructions")
        assert is_cyber_relevant(r) is False

    def test_case_insensitive(self):
        r = _fda_recall(reason="CYBERSECURITY VULNERABILITY in FIRMWARE")
        assert is_cyber_relevant(r) is True

    def test_empty_fields(self):
        r = {"reason_for_recall": "", "product_description": ""}
        assert is_cyber_relevant(r) is False


# ---------------------------------------------------------------------------
# Cache operations
# ---------------------------------------------------------------------------

class TestCacheOps:

    def test_recall_cache_id_prefers_res_event(self):
        r = {"res_event_number": "RES-001", "recall_number": "Z-123"}
        assert _recall_cache_id(r) == "RES-001"

    def test_recall_cache_id_fallback_recall_number(self):
        r = {"recall_number": "Z-123-2024"}
        assert _recall_cache_id(r) == "Z-123-2024"

    def test_recall_cache_id_none_for_empty(self):
        assert _recall_cache_id({}) is None
        assert _recall_cache_id({"res_event_number": ""}) is None

    def test_save_and_load(self, tmp_path):
        r = _fda_recall("RES-12345", cyber=True)
        cache_id = _save_recall_cache(r, tmp_path)
        assert cache_id == "RES-12345"
        assert (tmp_path / "recall_RES-12345.json").exists()

        data = json.loads((tmp_path / "recall_RES-12345.json").read_text())
        assert data["_cyber_relevant"] is True
        assert data["recalling_firm"] == "MedDevice Corp"

    def test_save_skips_existing(self, tmp_path):
        (tmp_path / "recall_RES-00001.json").write_text('{"old": true}')
        r = _fda_recall("RES-00001")
        _save_recall_cache(r, tmp_path)
        data = json.loads((tmp_path / "recall_RES-00001.json").read_text())
        assert data == {"old": True}

    def test_save_marks_non_cyber(self, tmp_path):
        r = _fda_recall("RES-99999", reason="Mechanical failure")
        _save_recall_cache(r, tmp_path)
        data = json.loads((tmp_path / "recall_RES-99999.json").read_text())
        assert data["_cyber_relevant"] is False


# ---------------------------------------------------------------------------
# Progress
# ---------------------------------------------------------------------------

class TestProgress:

    def test_defaults(self, tmp_path):
        p = _load_progress(tmp_path)
        assert p["last_skip"] == 0
        assert p["completed"] is False

    def test_roundtrip(self, tmp_path):
        p = {"last_skip": 500, "total_results": 60000,
             "recalls_fetched": 500, "pages_fetched": 5,
             "completed": False, "last_updated": None}
        _save_progress(tmp_path, p)
        loaded = _load_progress(tmp_path)
        assert loaded["last_skip"] == 500
        assert loaded["last_updated"] is not None


# ---------------------------------------------------------------------------
# Full backfill
# ---------------------------------------------------------------------------

class TestRunBackfill:

    def test_fetches_all_pages(self, tmp_path):
        """Simulate 6 recalls across 2 pages (page_size=3)."""
        pages = {
            0: _fda_page(skip=0, total=6,
                         recalls=[_fda_recall(f"RES-{i:05d}") for i in range(3)]),
            3: _fda_page(skip=3, total=6,
                         recalls=[_fda_recall(f"RES-{i:05d}") for i in range(3, 6)]),
        }

        def mock_fetch(url):
            for s in pages:
                if f"skip={s}" in url:
                    return json.dumps(pages[s]).encode()
            return json.dumps(_fda_page(total=6, recalls=[])).encode()

        stats = run_backfill(cache_dir=tmp_path, page_size=3, _fetch_fn=mock_fetch)

        assert stats["status"] == "completed"
        assert stats["recalls_fetched"] == 6
        assert stats["pages_fetched"] == 2
        for i in range(6):
            assert (tmp_path / f"recall_RES-{i:05d}.json").exists()

    def test_respects_max_results(self, tmp_path):
        page = _fda_page(skip=0, total=10000,
                         recalls=[_fda_recall(f"RES-{i:05d}") for i in range(5)])

        stats = run_backfill(
            cache_dir=tmp_path, max_results=5, page_size=5,
            _fetch_fn=lambda url: json.dumps(page).encode(),
        )
        assert stats["recalls_fetched"] == 5
        assert stats["pages_fetched"] == 1

    def test_resumes_from_progress(self, tmp_path):
        _save_progress(tmp_path, {
            "last_skip": 3, "total_results": 6,
            "recalls_fetched": 3, "pages_fetched": 1,
            "completed": False, "last_updated": None,
        })
        for i in range(3):
            _save_recall_cache(_fda_recall(f"RES-{i:05d}"), tmp_path)

        page2 = _fda_page(skip=3, total=6,
                          recalls=[_fda_recall(f"RES-{i:05d}") for i in range(3, 6)])

        fetched_urls = []

        def mock_fetch(url):
            fetched_urls.append(url)
            if "skip=3" in url:
                return json.dumps(page2).encode()
            return json.dumps(_fda_page(total=6, recalls=[])).encode()

        stats = run_backfill(cache_dir=tmp_path, page_size=3, _fetch_fn=mock_fetch)
        assert stats["status"] == "completed"
        assert any("skip=3" in u for u in fetched_urls)
        assert not any("skip=0" in u for u in fetched_urls)

    def test_already_completed(self, tmp_path):
        _save_progress(tmp_path, {
            "last_skip": 100, "total_results": 100,
            "recalls_fetched": 100, "pages_fetched": 1,
            "completed": True, "last_updated": "2024-01-01",
        })
        stats = run_backfill(cache_dir=tmp_path, _fetch_fn=lambda u: b"error")
        assert stats["status"] == "already_completed"

    def test_counts_cyber_relevant(self, tmp_path):
        recalls = [
            _fda_recall("RES-00001", cyber=True),
            _fda_recall("RES-00002", cyber=False),
            _fda_recall("RES-00003", cyber=True),
        ]
        page = _fda_page(skip=0, total=3, recalls=recalls)

        stats = run_backfill(
            cache_dir=tmp_path, page_size=3,
            _fetch_fn=lambda url: json.dumps(page).encode(),
        )
        assert stats["cyber_relevant"] == 2

    def test_skips_cached_recalls(self, tmp_path):
        _save_recall_cache(_fda_recall("RES-00001"), tmp_path)
        page = _fda_page(skip=0, total=2, recalls=[
            _fda_recall("RES-00001"),
            _fda_recall("RES-00002"),
        ])
        stats = run_backfill(
            cache_dir=tmp_path, page_size=2,
            _fetch_fn=lambda url: json.dumps(page).encode(),
        )
        assert stats["recalls_new"] == 1
        assert stats["recalls_skipped"] == 1


# ---------------------------------------------------------------------------
# Signal generation
# ---------------------------------------------------------------------------

class TestGenerateSignals:

    def _populate_cache(self, cache_dir, n_cyber=2, n_non_cyber=3):
        for i in range(n_cyber):
            _save_recall_cache(
                _fda_recall(f"RES-C{i:04d}", cyber=True, recalling_firm=f"CyberFirm{i}"),
                cache_dir,
            )
        for i in range(n_non_cyber):
            _save_recall_cache(
                _fda_recall(f"RES-N{i:04d}", cyber=False, recalling_firm=f"RegularFirm{i}"),
                cache_dir,
            )

    def test_cyber_only_default(self, tmp_path):
        self._populate_cache(tmp_path)
        signals = generate_signals_from_cache(cache_dir=tmp_path)
        assert len(signals) == 2  # Only cyber-relevant
        assert all(s["source"] == "openfda-recalls-historical" for s in signals)

    def test_all_recalls(self, tmp_path):
        self._populate_cache(tmp_path)
        signals = generate_signals_from_cache(cache_dir=tmp_path, cyber_only=False)
        assert len(signals) == 5  # All recalls

    def test_signal_format(self, tmp_path):
        _save_recall_cache(
            _fda_recall("RES-99999", recall_number="Z-1234-2024",
                        cyber=True, recalling_firm="AcmeMed",
                        reason="Cybersecurity vulnerability in firmware",
                        recall_initiation_date="20240301"),
            tmp_path,
        )
        signals = generate_signals_from_cache(cache_dir=tmp_path)
        assert len(signals) == 1
        s = signals[0]
        assert s["guid"] == "Z-1234-2024"
        assert "AcmeMed" in s["title"]
        assert "Cybersecurity" in s["summary"]
        assert s["published_date"] == "20240301"
        assert "fetched_at" in s

    def test_respects_limit(self, tmp_path):
        self._populate_cache(tmp_path, n_cyber=10, n_non_cyber=0)
        signals = generate_signals_from_cache(cache_dir=tmp_path, limit=3)
        assert len(signals) == 3

    def test_empty_cache(self, tmp_path):
        assert generate_signals_from_cache(cache_dir=tmp_path) == []

    def test_nonexistent_dir(self, tmp_path):
        assert generate_signals_from_cache(cache_dir=tmp_path / "nope") == []

    def test_skips_progress_file(self, tmp_path):
        _save_recall_cache(_fda_recall("RES-00001", cyber=True), tmp_path)
        _save_progress(tmp_path, {"completed": True})
        signals = generate_signals_from_cache(cache_dir=tmp_path)
        assert len(signals) == 1


# ---------------------------------------------------------------------------
# Incremental update
# ---------------------------------------------------------------------------

class TestIncrementalUpdate:

    def test_fetches_recent_and_publishes(self, tmp_path):
        cache_dir = tmp_path / "cache"
        discover_root = tmp_path / "discover"

        # Pre-cache one cyber-relevant recall
        cache_dir.mkdir()
        _save_recall_cache(_fda_recall("RES-OLD01", cyber=True), cache_dir)

        # Mock: return 1 new cyber recall from recent query
        page = _fda_page(skip=0, total=1,
                         recalls=[_fda_recall("RES-NEW01", cyber=True)])

        stats = incremental_update(
            cache_dir=cache_dir,
            out_root=str(discover_root),
            _fetch_fn=lambda url: json.dumps(page).encode(),
        )

        assert stats["status"] == "completed"
        assert stats["new_recalls_fetched"] == 1
        assert stats["new_recalls_cached"] == 1
        assert stats["total_signals_published"] == 2  # old + new

        items_path = discover_root / "openfda-recalls-historical" / "items.jsonl"
        assert items_path.exists()

    def test_publishes_cached_with_no_new(self, tmp_path):
        cache_dir = tmp_path / "cache"
        discover_root = tmp_path / "discover"
        cache_dir.mkdir()
        _save_recall_cache(_fda_recall("RES-00001", cyber=True), cache_dir)

        page = _fda_page(skip=0, total=0, recalls=[])

        stats = incremental_update(
            cache_dir=cache_dir,
            out_root=str(discover_root),
            _fetch_fn=lambda url: json.dumps(page).encode(),
        )

        assert stats["status"] == "completed"
        assert stats["new_recalls_cached"] == 0
        assert stats["total_signals_published"] == 1

    def test_uses_date_search(self, tmp_path):
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        fetched_urls = []
        page = _fda_page(skip=0, total=0, recalls=[])

        def mock_fetch(url):
            fetched_urls.append(url)
            return json.dumps(page).encode()

        incremental_update(
            cache_dir=cache_dir,
            out_root=str(tmp_path / "discover"),
            _fetch_fn=mock_fetch,
        )

        assert len(fetched_urls) == 1
        assert "date_received" in fetched_urls[0]

    def test_new_signals_detected_across_runs(self, tmp_path):
        cache_dir = tmp_path / "cache"
        discover_root = tmp_path / "discover"
        cache_dir.mkdir()
        _save_recall_cache(_fda_recall("RES-00001", cyber=True), cache_dir)

        page = _fda_page(skip=0, total=0, recalls=[])
        fetch_fn = lambda url: json.dumps(page).encode()

        stats1 = incremental_update(
            cache_dir=cache_dir, out_root=str(discover_root), _fetch_fn=fetch_fn,
        )
        assert stats1["new_signals_published"] == 1

        stats2 = incremental_update(
            cache_dir=cache_dir, out_root=str(discover_root), _fetch_fn=fetch_fn,
        )
        assert stats2["new_signals_published"] == 0


# ---------------------------------------------------------------------------
# Date-range backfill
# ---------------------------------------------------------------------------

class TestDateRangeBackfill:

    def test_fetches_across_ranges(self, tmp_path):
        """Two date ranges, 3 records each."""
        def mock_fetch(url):
            if "20100101" in url:
                return json.dumps(_fda_page(
                    skip=0, total=3,
                    recalls=[_fda_recall(f"RES-A{i}", recall_initiation_date="20100601") for i in range(3)],
                )).encode()
            if "20150101" in url:
                return json.dumps(_fda_page(
                    skip=0, total=2,
                    recalls=[_fda_recall(f"RES-B{i}", recall_initiation_date="20150601") for i in range(2)],
                )).encode()
            return json.dumps(_fda_page(total=0, recalls=[])).encode()

        stats = run_backfill_date_ranges(
            cache_dir=tmp_path,
            date_ranges=[("20100101", "20141231"), ("20150101", "20191231")],
            _fetch_fn=mock_fetch,
        )

        assert stats["status"] == "completed"
        assert stats["ranges_completed"] == 2
        assert stats["recalls_new"] == 5

    def test_resumes_completed_ranges(self, tmp_path):
        """Skips already-completed ranges."""
        progress = {
            "completed_date_ranges": [["20100101", "20141231"]],
            "last_updated": None,
        }
        _save_progress(tmp_path, progress)

        fetch_calls = []
        def mock_fetch(url):
            fetch_calls.append(url)
            return json.dumps(_fda_page(
                skip=0, total=2,
                recalls=[_fda_recall(f"RES-X{i}") for i in range(2)],
            )).encode()

        stats = run_backfill_date_ranges(
            cache_dir=tmp_path,
            date_ranges=[("20100101", "20141231"), ("20150101", "20191231")],
            _fetch_fn=mock_fetch,
        )

        assert stats["ranges_completed"] == 2
        # Should NOT have fetched the first range
        assert not any("20100101" in u for u in fetch_calls)
        assert any("20150101" in u for u in fetch_calls)

    def test_uses_date_field_in_search(self, tmp_path):
        urls = []
        def mock_fetch(url):
            urls.append(url)
            return json.dumps(_fda_page(total=0, recalls=[])).encode()

        run_backfill_date_ranges(
            cache_dir=tmp_path,
            date_ranges=[("20200101", "20201231")],
            date_field="event_date_initiated",
            _fetch_fn=mock_fetch,
        )

        assert any("event_date_initiated" in u for u in urls)

    def test_skips_already_cached_records(self, tmp_path):
        _save_recall_cache(_fda_recall("RES-EXIST"), tmp_path)

        def mock_fetch(url):
            if "skip=0" in url or "skip" not in url:
                return json.dumps(_fda_page(
                    skip=0, total=2,
                    recalls=[_fda_recall("RES-EXIST"), _fda_recall("RES-NEW01")],
                )).encode()
            return json.dumps(_fda_page(total=2, recalls=[])).encode()

        stats = run_backfill_date_ranges(
            cache_dir=tmp_path,
            date_ranges=[("20200101", "20201231")],
            _fetch_fn=mock_fetch,
        )

        assert stats["recalls_new"] == 1
        assert stats["recalls_skipped"] == 1


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

class TestRateLimiter:

    def test_allows_initial_requests(self):
        rl = _RateLimiter(max_requests=4, window_seconds=1.0)
        for _ in range(4):
            rl.wait()
