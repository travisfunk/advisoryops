"""Tests for MHRA UK medical device alerts backfill."""
from __future__ import annotations

import json
from pathlib import Path

from advisoryops.sources.mhra_uk_backfill import (
    _alert_cache_id,
    _load_progress,
    _save_alert_cache,
    _save_progress,
    generate_signals_from_cache,
    incremental_update,
    run_backfill,
)


def _govuk_page(*, start=0, total=50, records=None):
    if records is None:
        records = [_govuk_alert(i) for i in range(start, start + 3)]
    return {"results": records, "total": total, "start": start, "count": len(records)}


def _govuk_alert(idx=0):
    return {
        "title": f"Medical Device Alert: Test device issue {idx}",
        "description": f"Description of safety alert {idx} affecting patient monitors.",
        "link": f"/drug-device-alerts/mda-2024-{idx:03d}",
        "public_timestamp": "2024-03-15T10:00:00Z",
        "document_type": "medical_safety_alert",
        "format": "medical_safety_alert",
    }


class TestCacheId:
    def test_from_link(self):
        assert _alert_cache_id({"link": "/drug-device-alerts/mda-2024-001"}) == "mda-2024-001"

    def test_from_title(self):
        assert _alert_cache_id({"title": "Test Alert"}) is not None

    def test_empty(self):
        assert _alert_cache_id({}) is None


class TestRunBackfill:
    def test_fetches_all_pages(self, tmp_path):
        pages = {
            0: _govuk_page(start=0, total=6, records=[_govuk_alert(i) for i in range(3)]),
            3: _govuk_page(start=3, total=6, records=[_govuk_alert(i) for i in range(3, 6)]),
        }

        def mock_fetch(url):
            for s in pages:
                if f"start={s}" in url:
                    return json.dumps(pages[s]).encode()
            return json.dumps(_govuk_page(total=6, records=[])).encode()

        stats = run_backfill(cache_dir=tmp_path, page_size=3, _fetch_fn=mock_fetch)
        assert stats["status"] == "completed"
        assert stats["records_fetched"] == 6
        assert stats["records_new"] == 6

    def test_respects_max_results(self, tmp_path):
        page = _govuk_page(start=0, total=1000, records=[_govuk_alert(i) for i in range(5)])
        stats = run_backfill(
            cache_dir=tmp_path, max_results=5, page_size=5,
            _fetch_fn=lambda url: json.dumps(page).encode(),
        )
        assert stats["records_fetched"] == 5

    def test_already_completed(self, tmp_path):
        _save_progress(tmp_path, {"last_start": 50, "total_results": 50,
                                   "records_fetched": 50, "pages_fetched": 1,
                                   "completed": True, "last_updated": "x"})
        stats = run_backfill(cache_dir=tmp_path, _fetch_fn=lambda u: b"err")
        assert stats["status"] == "already_completed"

    def test_skips_cached(self, tmp_path):
        _save_alert_cache(_govuk_alert(0), tmp_path)
        page = _govuk_page(start=0, total=2, records=[_govuk_alert(0), _govuk_alert(1)])
        stats = run_backfill(
            cache_dir=tmp_path, page_size=2,
            _fetch_fn=lambda url: json.dumps(page).encode(),
        )
        assert stats["records_new"] == 1
        assert stats["records_skipped"] == 1


class TestGenerateSignals:
    def _populate(self, cache_dir, n=3):
        for i in range(n):
            _save_alert_cache(_govuk_alert(i), cache_dir)

    def test_generates_signals(self, tmp_path):
        self._populate(tmp_path)
        signals = generate_signals_from_cache(cache_dir=tmp_path)
        assert len(signals) == 3
        assert all(s["source"] == "mhra-uk-alerts" for s in signals)

    def test_signal_format(self, tmp_path):
        self._populate(tmp_path, 1)
        signals = generate_signals_from_cache(cache_dir=tmp_path)
        s = signals[0]
        assert "gov.uk" in s["link"]
        assert s["published_date"] == "2024-03-15T10:00:00Z"
        assert "patient monitors" in s["summary"]

    def test_limit(self, tmp_path):
        self._populate(tmp_path, 10)
        assert len(generate_signals_from_cache(cache_dir=tmp_path, limit=3)) == 3

    def test_empty(self, tmp_path):
        assert generate_signals_from_cache(cache_dir=tmp_path) == []

    def test_skips_progress(self, tmp_path):
        self._populate(tmp_path, 1)
        _save_progress(tmp_path, {"completed": True})
        assert len(generate_signals_from_cache(cache_dir=tmp_path)) == 1


class TestIncrementalUpdate:
    def test_fetches_and_publishes(self, tmp_path):
        cache_dir = tmp_path / "cache"
        discover_root = tmp_path / "discover"
        cache_dir.mkdir()
        _save_alert_cache(_govuk_alert(0), cache_dir)

        page = _govuk_page(start=0, total=2, records=[_govuk_alert(0), _govuk_alert(1)])
        stats = incremental_update(
            cache_dir=cache_dir, out_root=str(discover_root),
            _fetch_fn=lambda url: json.dumps(page).encode(),
        )
        assert stats["status"] == "completed"
        assert stats["new_alerts"] == 1
        assert stats["total_signals_published"] == 2
        assert (discover_root / "mhra-uk-alerts" / "items.jsonl").exists()

    def test_new_detection_across_runs(self, tmp_path):
        cache_dir = tmp_path / "cache"
        discover_root = tmp_path / "discover"
        cache_dir.mkdir()
        _save_alert_cache(_govuk_alert(0), cache_dir)

        page = _govuk_page(start=0, total=1, records=[_govuk_alert(0)])
        fn = lambda url: json.dumps(page).encode()

        s1 = incremental_update(cache_dir=cache_dir, out_root=str(discover_root), _fetch_fn=fn)
        assert s1["new_signals_published"] == 1
        s2 = incremental_update(cache_dir=cache_dir, out_root=str(discover_root), _fetch_fn=fn)
        assert s2["new_signals_published"] == 0
