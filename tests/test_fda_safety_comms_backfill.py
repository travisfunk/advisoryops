"""Tests for FDA device enforcement / safety communications backfill."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from advisoryops.sources.fda_safety_comms_backfill import (
    _load_progress,
    _record_cache_id,
    _save_progress,
    _save_record_cache,
    generate_signals_from_cache,
    incremental_update,
    is_cyber_relevant,
    run_backfill,
    run_backfill_date_ranges,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _enforcement_page(
    *,
    skip: int = 0,
    total: int = 200,
    records: list[dict] | None = None,
) -> dict:
    if records is None:
        records = [_enforcement_record(f"Z-{skip + i:04d}-2024") for i in range(3)]
    return {
        "meta": {
            "results": {"skip": skip, "limit": len(records), "total": total},
        },
        "results": records,
    }


def _enforcement_record(
    recall_number: str = "Z-0001-2024",
    reason: str = "Device component failure causing intermittent readings.",
    product_description: str = "Patient monitor model ABC.",
    recalling_firm: str = "MedCo Inc",
    report_date: str = "20240301",
    classification: str = "II",
    cyber: bool = False,
) -> dict:
    if cyber:
        reason = "Cybersecurity vulnerability in device firmware allows unauthorized remote access to patient data."
    return {
        "recall_number": recall_number,
        "event_id": f"EVT-{recall_number.replace('Z-', '').replace('-2024', '')}",
        "reason_for_recall": reason,
        "product_description": product_description,
        "recalling_firm": recalling_firm,
        "report_date": report_date,
        "classification": classification,
        "code_info": "",
        "product_type": "Devices",
    }


# ---------------------------------------------------------------------------
# Cyber relevance
# ---------------------------------------------------------------------------

class TestIsCyberRelevant:

    def test_positive_cybersecurity(self):
        assert is_cyber_relevant(_enforcement_record(cyber=True)) is True

    def test_positive_firmware(self):
        r = _enforcement_record(reason="Firmware update required for security patch")
        assert is_cyber_relevant(r) is True

    def test_positive_software_vulnerability(self):
        r = _enforcement_record(reason="Software vulnerability allows data breach")
        assert is_cyber_relevant(r) is True

    def test_negative_mechanical(self):
        r = _enforcement_record(reason="Mechanical failure in pump assembly")
        assert is_cyber_relevant(r) is False

    def test_negative_labeling(self):
        r = _enforcement_record(reason="Incorrect labeling of device parameters")
        assert is_cyber_relevant(r) is False

    def test_empty(self):
        assert is_cyber_relevant({}) is False


# ---------------------------------------------------------------------------
# Cache operations
# ---------------------------------------------------------------------------

class TestCacheOps:

    def test_cache_id_from_recall_number(self):
        r = {"recall_number": "Z-1234-2024", "event_id": "EVT-123"}
        assert _record_cache_id(r) == "Z-1234-2024"

    def test_cache_id_fallback_event_id(self):
        r = {"event_id": "EVT-5678"}
        assert _record_cache_id(r) == "EVT-5678"

    def test_cache_id_none_for_empty(self):
        assert _record_cache_id({}) is None

    def test_save_and_check(self, tmp_path):
        r = _enforcement_record("Z-9999-2024", cyber=True)
        cache_id = _save_record_cache(r, tmp_path)
        assert cache_id == "Z-9999-2024"
        assert (tmp_path / "enf_Z-9999-2024.json").exists()
        data = json.loads((tmp_path / "enf_Z-9999-2024.json").read_text())
        assert data["_cyber_relevant"] is True

    def test_save_skips_existing(self, tmp_path):
        (tmp_path / "enf_Z-0001-2024.json").write_text('{"old": true}')
        r = _enforcement_record("Z-0001-2024")
        _save_record_cache(r, tmp_path)
        data = json.loads((tmp_path / "enf_Z-0001-2024.json").read_text())
        assert data == {"old": True}

    def test_save_marks_non_cyber(self, tmp_path):
        r = _enforcement_record("Z-0002-2024", reason="Labeling error")
        _save_record_cache(r, tmp_path)
        data = json.loads((tmp_path / "enf_Z-0002-2024.json").read_text())
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
        p = {"last_skip": 500, "total_results": 38000,
             "records_fetched": 500, "pages_fetched": 5,
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
        pages = {
            0: _enforcement_page(skip=0, total=6,
                                 records=[_enforcement_record(f"Z-{i:04d}-2024") for i in range(3)]),
            3: _enforcement_page(skip=3, total=6,
                                 records=[_enforcement_record(f"Z-{i:04d}-2024") for i in range(3, 6)]),
        }

        def mock_fetch(url):
            for s in pages:
                if f"skip={s}" in url:
                    return json.dumps(pages[s]).encode()
            return json.dumps(_enforcement_page(total=6, records=[])).encode()

        stats = run_backfill(cache_dir=tmp_path, page_size=3, _fetch_fn=mock_fetch)
        assert stats["status"] == "completed"
        assert stats["records_fetched"] == 6
        assert stats["pages_fetched"] == 2

    def test_respects_max_results(self, tmp_path):
        page = _enforcement_page(skip=0, total=10000,
                                 records=[_enforcement_record(f"Z-{i:04d}-2024") for i in range(5)])
        stats = run_backfill(
            cache_dir=tmp_path, max_results=5, page_size=5,
            _fetch_fn=lambda url: json.dumps(page).encode(),
        )
        assert stats["records_fetched"] == 5

    def test_resumes_from_progress(self, tmp_path):
        _save_progress(tmp_path, {
            "last_skip": 3, "total_results": 6,
            "records_fetched": 3, "pages_fetched": 1,
            "completed": False, "last_updated": None,
        })
        for i in range(3):
            _save_record_cache(_enforcement_record(f"Z-{i:04d}-2024"), tmp_path)

        page2 = _enforcement_page(skip=3, total=6,
                                   records=[_enforcement_record(f"Z-{i:04d}-2024") for i in range(3, 6)])
        fetched_urls = []

        def mock_fetch(url):
            fetched_urls.append(url)
            if "skip=3" in url:
                return json.dumps(page2).encode()
            return json.dumps(_enforcement_page(total=6, records=[])).encode()

        stats = run_backfill(cache_dir=tmp_path, page_size=3, _fetch_fn=mock_fetch)
        assert stats["status"] == "completed"
        assert any("skip=3" in u for u in fetched_urls)
        assert not any("skip=0" in u for u in fetched_urls)

    def test_already_completed(self, tmp_path):
        _save_progress(tmp_path, {
            "last_skip": 100, "total_results": 100,
            "records_fetched": 100, "pages_fetched": 1,
            "completed": True, "last_updated": "2024-01-01",
        })
        stats = run_backfill(cache_dir=tmp_path, _fetch_fn=lambda u: b"error")
        assert stats["status"] == "already_completed"

    def test_counts_cyber_relevant(self, tmp_path):
        records = [
            _enforcement_record("Z-0001-2024", cyber=True),
            _enforcement_record("Z-0002-2024", cyber=False),
            _enforcement_record("Z-0003-2024", cyber=True),
        ]
        page = _enforcement_page(skip=0, total=3, records=records)
        stats = run_backfill(
            cache_dir=tmp_path, page_size=3,
            _fetch_fn=lambda url: json.dumps(page).encode(),
        )
        assert stats["cyber_relevant"] == 2


# ---------------------------------------------------------------------------
# Signal generation
# ---------------------------------------------------------------------------

class TestGenerateSignals:

    def _populate_cache(self, cache_dir, n_cyber=2, n_non_cyber=3):
        for i in range(n_cyber):
            _save_record_cache(
                _enforcement_record(f"Z-C{i:03d}-2024", cyber=True, recalling_firm=f"CyberFirm{i}"),
                cache_dir,
            )
        for i in range(n_non_cyber):
            _save_record_cache(
                _enforcement_record(f"Z-N{i:03d}-2024", cyber=False, recalling_firm=f"RegFirm{i}"),
                cache_dir,
            )

    def test_cyber_only_default(self, tmp_path):
        self._populate_cache(tmp_path)
        signals = generate_signals_from_cache(cache_dir=tmp_path)
        assert len(signals) == 2

    def test_all_records(self, tmp_path):
        self._populate_cache(tmp_path)
        signals = generate_signals_from_cache(cache_dir=tmp_path, cyber_only=False)
        assert len(signals) == 5

    def test_signal_format(self, tmp_path):
        _save_record_cache(
            _enforcement_record("Z-9999-2024", cyber=True,
                                recalling_firm="AcmeMed",
                                reason="Cybersecurity vulnerability in firmware",
                                report_date="20240301",
                                classification="I"),
            tmp_path,
        )
        signals = generate_signals_from_cache(cache_dir=tmp_path)
        assert len(signals) == 1
        s = signals[0]
        assert s["guid"] == "Z-9999-2024"
        assert "AcmeMed" in s["title"]
        assert "Cybersecurity" in s["summary"]
        assert "Class I" in s["summary"]
        assert s["published_date"] == "20240301"
        assert s["source"] == "fda-safety-comms-historical"

    def test_respects_limit(self, tmp_path):
        self._populate_cache(tmp_path, n_cyber=10, n_non_cyber=0)
        signals = generate_signals_from_cache(cache_dir=tmp_path, limit=3)
        assert len(signals) == 3

    def test_empty_cache(self, tmp_path):
        assert generate_signals_from_cache(cache_dir=tmp_path) == []

    def test_skips_progress_file(self, tmp_path):
        _save_record_cache(_enforcement_record("Z-0001-2024", cyber=True), tmp_path)
        _save_progress(tmp_path, {"completed": True})
        signals = generate_signals_from_cache(cache_dir=tmp_path)
        assert len(signals) == 1


# ---------------------------------------------------------------------------
# Incremental update
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Date-range backfill
# ---------------------------------------------------------------------------

class TestDateRangeBackfill:

    def test_fetches_across_ranges(self, tmp_path):
        def mock_fetch(url):
            if "20120101" in url:
                return json.dumps(_enforcement_page(
                    skip=0, total=2,
                    records=[_enforcement_record(f"Z-A{i}-2012") for i in range(2)],
                )).encode()
            if "20150101" in url:
                return json.dumps(_enforcement_page(
                    skip=0, total=1,
                    records=[_enforcement_record("Z-B0-2015")],
                )).encode()
            return json.dumps(_enforcement_page(total=0, records=[])).encode()

        stats = run_backfill_date_ranges(
            cache_dir=tmp_path,
            date_ranges=[("20120101", "20141231"), ("20150101", "20171231")],
            _fetch_fn=mock_fetch,
        )
        assert stats["status"] == "completed"
        assert stats["ranges_completed"] == 2
        assert stats["records_new"] == 3

    def test_resumes_completed_ranges(self, tmp_path):
        _save_progress(tmp_path, {
            "completed_date_ranges": [["20120101", "20141231"]],
            "last_updated": None,
        })

        fetch_calls = []
        def mock_fetch(url):
            fetch_calls.append(url)
            return json.dumps(_enforcement_page(
                skip=0, total=1,
                records=[_enforcement_record("Z-X0-2015")],
            )).encode()

        stats = run_backfill_date_ranges(
            cache_dir=tmp_path,
            date_ranges=[("20120101", "20141231"), ("20150101", "20171231")],
            _fetch_fn=mock_fetch,
        )
        assert stats["ranges_completed"] == 2
        assert not any("20120101" in u for u in fetch_calls)

    def test_uses_date_field_in_search(self, tmp_path):
        urls = []
        def mock_fetch(url):
            urls.append(url)
            return json.dumps(_enforcement_page(total=0, records=[])).encode()

        run_backfill_date_ranges(
            cache_dir=tmp_path,
            date_ranges=[("20200101", "20201231")],
            date_field="report_date",
            _fetch_fn=mock_fetch,
        )
        assert any("report_date" in u for u in urls)


# ---------------------------------------------------------------------------
# Incremental update
# ---------------------------------------------------------------------------

class TestIncrementalUpdate:

    def test_fetches_recent_and_publishes(self, tmp_path):
        cache_dir = tmp_path / "cache"
        discover_root = tmp_path / "discover"
        cache_dir.mkdir()
        _save_record_cache(_enforcement_record("Z-OLD1-2024", cyber=True), cache_dir)

        page = _enforcement_page(skip=0, total=1,
                                  records=[_enforcement_record("Z-NEW1-2024", cyber=True)])

        stats = incremental_update(
            cache_dir=cache_dir,
            out_root=str(discover_root),
            _fetch_fn=lambda url: json.dumps(page).encode(),
        )

        assert stats["status"] == "completed"
        assert stats["new_records_fetched"] == 1
        assert stats["new_records_cached"] == 1
        assert stats["total_signals_published"] == 2

        items_path = discover_root / "fda-safety-comms-historical" / "items.jsonl"
        assert items_path.exists()

    def test_publishes_cached_with_no_new(self, tmp_path):
        cache_dir = tmp_path / "cache"
        discover_root = tmp_path / "discover"
        cache_dir.mkdir()
        _save_record_cache(_enforcement_record("Z-0001-2024", cyber=True), cache_dir)

        page = _enforcement_page(skip=0, total=0, records=[])

        stats = incremental_update(
            cache_dir=cache_dir,
            out_root=str(discover_root),
            _fetch_fn=lambda url: json.dumps(page).encode(),
        )

        assert stats["status"] == "completed"
        assert stats["new_records_cached"] == 0
        assert stats["total_signals_published"] == 1

    def test_uses_date_search(self, tmp_path):
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        fetched_urls = []
        page = _enforcement_page(skip=0, total=0, records=[])

        def mock_fetch(url):
            fetched_urls.append(url)
            return json.dumps(page).encode()

        incremental_update(
            cache_dir=cache_dir,
            out_root=str(tmp_path / "discover"),
            _fetch_fn=mock_fetch,
        )

        assert len(fetched_urls) == 1
        assert "report_date" in fetched_urls[0]

    def test_new_signals_detected_across_runs(self, tmp_path):
        cache_dir = tmp_path / "cache"
        discover_root = tmp_path / "discover"
        cache_dir.mkdir()
        _save_record_cache(_enforcement_record("Z-0001-2024", cyber=True), cache_dir)

        page = _enforcement_page(skip=0, total=0, records=[])
        fetch_fn = lambda url: json.dumps(page).encode()

        stats1 = incremental_update(
            cache_dir=cache_dir, out_root=str(discover_root), _fetch_fn=fetch_fn,
        )
        assert stats1["new_signals_published"] == 1

        stats2 = incremental_update(
            cache_dir=cache_dir, out_root=str(discover_root), _fetch_fn=fetch_fn,
        )
        assert stats2["new_signals_published"] == 0
