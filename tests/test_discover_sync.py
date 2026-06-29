"""Tests for discover_sync: publishing backfill signals to discover output."""
from __future__ import annotations

import json
from pathlib import Path

from advisoryops.sources.discover_sync import (
    _ensure_signal_id,
    publish_to_discover,
)


class TestEnsureSignalId:

    def test_adds_signal_id(self):
        item = {"guid": "CVE-2024-0001", "source": "test"}
        _ensure_signal_id(item, source_id="test")
        assert "signal_id" in item
        assert len(item["signal_id"]) == 64  # SHA-256 hex

    def test_preserves_existing_signal_id(self):
        item = {"guid": "CVE-2024-0001", "signal_id": "existing"}
        _ensure_signal_id(item, source_id="test")
        assert item["signal_id"] == "existing"

    def test_deterministic(self):
        item1 = {"guid": "CVE-2024-0001"}
        item2 = {"guid": "CVE-2024-0001"}
        _ensure_signal_id(item1, source_id="test")
        _ensure_signal_id(item2, source_id="test")
        assert item1["signal_id"] == item2["signal_id"]

    def test_different_sources_different_ids(self):
        item1 = {"guid": "CVE-2024-0001"}
        item2 = {"guid": "CVE-2024-0001"}
        _ensure_signal_id(item1, source_id="source-a")
        _ensure_signal_id(item2, source_id="source-b")
        assert item1["signal_id"] != item2["signal_id"]


class TestPublishToDiscover:

    def _make_signals(self, n=3, source_id="test-source"):
        return [
            {
                "source": source_id,
                "guid": f"CVE-2024-{i:04d}",
                "title": f"CVE-2024-{i:04d}",
                "link": f"https://example.com/{i}",
                "published_date": "2024-01-01",
                "summary": f"Test vulnerability {i}",
                "fetched_at": "2024-01-01T00:00:00+00:00",
            }
            for i in range(n)
        ]

    def test_writes_all_artifacts(self, tmp_path):
        signals = self._make_signals()
        out_root = str(tmp_path / "discover")

        stats = publish_to_discover(
            signals, source_id="test-source", out_root=out_root,
        )

        out_dir = tmp_path / "discover" / "test-source"
        assert (out_dir / "items.jsonl").exists()
        assert (out_dir / "new_items.jsonl").exists()
        assert (out_dir / "feed.json").exists()
        assert (out_dir / "new_items.json").exists()
        assert (out_dir / "state.json").exists()
        assert (out_dir / "meta.json").exists()

    def test_items_jsonl_has_correct_count(self, tmp_path):
        signals = self._make_signals(5)
        out_root = str(tmp_path / "discover")

        publish_to_discover(signals, source_id="test", out_root=out_root)

        lines = (tmp_path / "discover" / "test" / "items.jsonl").read_text().strip().split("\n")
        assert len(lines) == 5

    def test_signals_have_signal_ids(self, tmp_path):
        signals = self._make_signals(2)
        out_root = str(tmp_path / "discover")

        publish_to_discover(signals, source_id="test", out_root=out_root)

        lines = (tmp_path / "discover" / "test" / "items.jsonl").read_text().strip().split("\n")
        for line in lines:
            item = json.loads(line)
            assert "signal_id" in item

    def test_first_run_all_items_are_new(self, tmp_path):
        signals = self._make_signals(3)
        out_root = str(tmp_path / "discover")

        stats = publish_to_discover(signals, source_id="test", out_root=out_root)

        assert stats["total_signals"] == 3
        assert stats["new_signals"] == 3

    def test_second_run_detects_seen_items(self, tmp_path):
        signals = self._make_signals(3)
        out_root = str(tmp_path / "discover")

        # First run
        publish_to_discover(signals, source_id="test", out_root=out_root)

        # Second run with same signals
        stats = publish_to_discover(signals, source_id="test", out_root=out_root)

        assert stats["total_signals"] == 3
        assert stats["new_signals"] == 0

    def test_second_run_detects_only_new_items(self, tmp_path):
        out_root = str(tmp_path / "discover")

        # First run with 2 signals
        publish_to_discover(
            self._make_signals(2), source_id="test", out_root=out_root,
        )

        # Second run with 4 signals (2 old + 2 new)
        stats = publish_to_discover(
            self._make_signals(4), source_id="test", out_root=out_root,
        )

        assert stats["total_signals"] == 4
        assert stats["new_signals"] == 2

    def test_meta_json_has_counts(self, tmp_path):
        signals = self._make_signals(3)
        out_root = str(tmp_path / "discover")

        publish_to_discover(signals, source_id="test", out_root=out_root)

        meta = json.loads(
            (tmp_path / "discover" / "test" / "meta.json").read_text()
        )
        assert meta["counts"]["parsed"] == 3
        assert meta["counts"]["new"] == 3
        assert meta["source_id"] == "test"

    def test_feed_json_structure(self, tmp_path):
        signals = self._make_signals(2)
        out_root = str(tmp_path / "discover")

        publish_to_discover(signals, source_id="test", out_root=out_root)

        feed = json.loads(
            (tmp_path / "discover" / "test" / "feed.json").read_text()
        )
        assert feed["source"] == "test"
        assert len(feed["items"]) == 2
        assert "fetched_at" in feed

    def test_state_json_tracks_guids(self, tmp_path):
        signals = self._make_signals(2)
        out_root = str(tmp_path / "discover")

        publish_to_discover(signals, source_id="test", out_root=out_root)

        state = json.loads(
            (tmp_path / "discover" / "test" / "state.json").read_text()
        )
        assert "CVE-2024-0000" in state["seen"]
        assert "CVE-2024-0001" in state["seen"]
