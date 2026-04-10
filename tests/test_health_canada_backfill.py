"""Tests for Health Canada medical device recalls backfill."""
from __future__ import annotations

import json
from pathlib import Path

from advisoryops.sources.health_canada_backfill import (
    _load_progress,
    _load_recall_cache,
    _save_progress,
    _save_recall_cache,
    generate_signals_from_cache,
    incremental_update,
    parse_recent_api,
    parse_recall_detail,
    run_backfill,
)


def _hc_recent_response(recalls=None):
    if recalls is None:
        recalls = [_hc_recall_entry(i) for i in range(3)]
    return {"results": {"HEALTH": recalls}}


def _hc_recall_entry(idx=1):
    return {
        "recallId": str(70000 + idx),
        "title": f"Health Canada recall: Test medical device {idx}",
        "date_published": 1705334400000,  # 2024-01-15 in ms
        "category": [3],  # 3 = Health
        "url": f"/recall-alert-rappel-avis/api/{70000 + idx}/en",
    }


def _hc_recall_detail(idx=1):
    return {
        "recallId": str(70000 + idx),
        "title": f"Detailed recall: Test device {idx}",
        "date_published": 1705334400000,
        "panels": {"issue": "Device may malfunction", "what_you_should_do": "Stop using device"},
        "url": f"/recall-alert-rappel-avis/api/{70000 + idx}/en",
    }


class TestParseRecentApi:
    def test_parses_health_category(self):
        recalls = parse_recent_api(_hc_recent_response())
        assert len(recalls) == 3
        assert recalls[0]["recall_id"] == "70000"

    def test_filters_non_health(self):
        entries = [
            {"recallId": "1", "title": "Food recall", "category": [1], "date_published": 0},
            {"recallId": "2", "title": "Medical device", "category": [3], "date_published": 0},
        ]
        recalls = parse_recent_api({"results": {"ALL": entries}})
        assert len(recalls) == 1
        assert recalls[0]["recall_id"] == "2"

    def test_converts_unix_timestamp(self):
        recalls = parse_recent_api(_hc_recent_response([_hc_recall_entry(1)]))
        assert "2024" in recalls[0]["date_published"]

    def test_empty_response(self):
        assert parse_recent_api({}) == []
        assert parse_recent_api({"results": {}}) == []


class TestParseRecallDetail:
    def test_parses_detail(self):
        result = parse_recall_detail(_hc_recall_detail(1))
        assert result["recall_id"] == "70001"
        assert result["title"] == "Detailed recall: Test device 1"
        assert "malfunction" in result.get("issue", "")


class TestCacheOps:
    def test_save_and_load(self, tmp_path):
        _save_recall_cache("70001", {"recall_id": "70001", "title": "T"}, tmp_path)
        loaded = _load_recall_cache("70001", tmp_path)
        assert loaded["recall_id"] == "70001"

    def test_save_skips_existing(self, tmp_path):
        _save_recall_cache("70001", {"v": 1}, tmp_path)
        _save_recall_cache("70001", {"v": 2}, tmp_path)
        assert _load_recall_cache("70001", tmp_path)["v"] == 1

    def test_load_missing(self, tmp_path):
        assert _load_recall_cache("99999", tmp_path) is None


class TestProgress:
    def test_defaults(self, tmp_path):
        p = _load_progress(tmp_path)
        assert p["completed"] is False

    def test_roundtrip(self, tmp_path):
        p = {"recall_ids_fetched": ["1", "2"], "records_total": 10,
             "completed": True, "last_updated": None}
        _save_progress(tmp_path, p)
        loaded = _load_progress(tmp_path)
        assert loaded["records_total"] == 10
        assert loaded["last_updated"] is not None


class TestRunBackfill:
    def _make_fetch_fn(self, recent_resp, detail_resp):
        def fetch(url):
            if "recent" in url:
                return json.dumps(recent_resp).encode()
            # Detail page
            return json.dumps(detail_resp).encode()
        return fetch

    def test_fetches_and_caches(self, tmp_path):
        fetch = self._make_fetch_fn(_hc_recent_response([_hc_recall_entry(1)]), _hc_recall_detail(1))
        stats = run_backfill(cache_dir=tmp_path, _fetch_fn=fetch)
        assert stats["status"] == "completed"
        assert stats["recalls_discovered"] == 1
        assert stats["details_fetched"] == 1

    def test_skips_cached(self, tmp_path):
        _save_recall_cache("70001", {"recall_id": "70001"}, tmp_path)
        fetch = self._make_fetch_fn(
            _hc_recent_response([_hc_recall_entry(1), _hc_recall_entry(2)]),
            _hc_recall_detail(2),
        )
        stats = run_backfill(cache_dir=tmp_path, _fetch_fn=fetch)
        assert stats["details_cached"] == 1
        assert stats["details_fetched"] == 1

    def test_handles_detail_failure(self, tmp_path):
        def fetch(url):
            if "recent" in url:
                return json.dumps(_hc_recent_response([_hc_recall_entry(1)])).encode()
            raise ConnectionError("detail server down")

        stats = run_backfill(cache_dir=tmp_path, _fetch_fn=fetch)
        assert stats["status"] == "completed"
        assert stats["details_failed"] == 1


class TestGenerateSignals:
    def _populate(self, cache_dir, n=3):
        for i in range(1, n + 1):
            _save_recall_cache(str(70000 + i), {
                "recall_id": str(70000 + i),
                "title": f"Test recall {i}",
                "date_published": "2024-01-15T00:00:00+00:00",
                "url": f"/api/{70000 + i}/en",
            }, cache_dir)

    def test_generates_signals(self, tmp_path):
        self._populate(tmp_path)
        signals = generate_signals_from_cache(cache_dir=tmp_path)
        assert len(signals) == 3
        assert all(s["source"] == "health-canada-recalls-historical" for s in signals)

    def test_signal_format(self, tmp_path):
        self._populate(tmp_path, 1)
        signals = generate_signals_from_cache(cache_dir=tmp_path)
        s = signals[0]
        assert s["guid"] == "70001"
        assert "healthycanadians" in s["link"]
        assert "2024" in s["published_date"]

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
        _save_recall_cache("70001", {"recall_id": "70001", "title": "Old",
                                      "date_published": "2024-01-01", "url": "/api/70001/en"}, cache_dir)

        def fetch(url):
            if "recent" in url:
                return json.dumps(_hc_recent_response([_hc_recall_entry(1), _hc_recall_entry(2)])).encode()
            return json.dumps(_hc_recall_detail(2)).encode()

        stats = incremental_update(
            cache_dir=cache_dir, out_root=str(discover_root), _fetch_fn=fetch,
        )
        assert stats["status"] == "completed"
        assert stats["new_recalls"] == 1
        assert stats["total_signals_published"] == 2
        assert (discover_root / "health-canada-recalls-historical" / "items.jsonl").exists()

    def test_handles_fetch_error(self, tmp_path):
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        stats = incremental_update(
            cache_dir=cache_dir, out_root=str(tmp_path / "discover"),
            _fetch_fn=lambda url: (_ for _ in ()).throw(ConnectionError("down")),
        )
        assert stats["status"] == "completed"
        assert len(stats["errors"]) == 1
