import json
from pathlib import Path

import pytest

from advisoryops.feed_archive import prepare_baseline, publish_archive


def _rows(count: int):
    return [
        {
            "issue_id": f"issue-{i:04d}",
            "title": f"Issue {i}",
            "priority": "P2",
            "score": 60 + (i % 20),
            "healthcare_category": (
                "medical_device" if i % 7 == 0 else "healthcare_it"
            ),
        }
        for i in range(count)
    ]


def test_publish_archive_bounds_latest_and_preserves_full_history(tmp_path: Path):
    docs = tmp_path / "docs"
    docs.mkdir()
    source = tmp_path / "full.json"
    source.write_text(json.dumps(_rows(120)), encoding="utf-8")
    (docs / "meta.json").write_text(
        json.dumps({"counts": {"issues_public": 120}}), encoding="utf-8"
    )

    result = publish_archive(
        source_path=source,
        docs_dir=docs,
        latest_count=25,
        shard_count=8,
    )

    latest = json.loads((docs / "feed_latest.json").read_text(encoding="utf-8"))
    manifest = json.loads(
        (docs / "feed_archive" / "manifest.json").read_text(encoding="utf-8")
    )
    meta = json.loads((docs / "meta.json").read_text(encoding="utf-8"))

    assert len(latest) == 25
    assert result["total_records"] == 120
    assert manifest["total_records"] == 120
    assert sum(s["count"] for s in manifest["shards"]) == 120
    assert meta["publication"]["strategy"] == "bounded_latest_plus_stable_hash_jsonl"
    assert meta["publication"]["total_records"] == 120
    assert meta["publication"]["latest_records"] == 25


def test_prepare_baseline_round_trips_all_archive_rows(tmp_path: Path):
    docs = tmp_path / "docs"
    docs.mkdir()
    rows = _rows(137)
    source = tmp_path / "full.json"
    source.write_text(json.dumps(rows), encoding="utf-8")

    publish_archive(
        source_path=source,
        docs_dir=docs,
        latest_count=20,
        shard_count=8,
    )

    baseline = tmp_path / "baseline.json"
    result = prepare_baseline(
        manifest_path=docs / "feed_archive" / "manifest.json",
        legacy_path=docs / "feed_latest.json",
        out_path=baseline,
    )

    restored = json.loads(baseline.read_text(encoding="utf-8"))
    assert result["source"] == "sharded_archive"
    assert result["records"] == 137
    assert {row["issue_id"] for row in restored} == {
        row["issue_id"] for row in rows
    }


def test_prepare_baseline_bootstraps_from_legacy_monolith(tmp_path: Path):
    docs = tmp_path / "docs"
    docs.mkdir()
    legacy = docs / "feed_latest.json"
    legacy.write_text(json.dumps(_rows(15)), encoding="utf-8")
    baseline = tmp_path / "baseline.json"

    result = prepare_baseline(
        manifest_path=docs / "feed_archive" / "manifest.json",
        legacy_path=legacy,
        out_path=baseline,
    )

    assert result["source"] == "legacy_monolith"
    assert result["records"] == 15
    assert len(json.loads(baseline.read_text(encoding="utf-8"))) == 15


def test_publish_archive_rejects_duplicate_issue_ids(tmp_path: Path):
    docs = tmp_path / "docs"
    docs.mkdir()
    rows = _rows(4)
    rows.append(dict(rows[0]))
    source = tmp_path / "full.json"
    source.write_text(json.dumps(rows), encoding="utf-8")

    with pytest.raises(ValueError, match="Duplicate issue_id"):
        publish_archive(
            source_path=source,
            docs_dir=docs,
            latest_count=2,
            shard_count=4,
        )


def test_publish_archive_enforces_monotonic_history(tmp_path: Path):
    docs = tmp_path / "docs"
    docs.mkdir()
    source = tmp_path / "full.json"
    source.write_text(json.dumps(_rows(20)), encoding="utf-8")
    publish_archive(source_path=source, docs_dir=docs, latest_count=5, shard_count=4)

    source.write_text(json.dumps(_rows(19)), encoding="utf-8")
    with pytest.raises(RuntimeError, match="would shrink"):
        publish_archive(
            source_path=source,
            docs_dir=docs,
            latest_count=5,
            shard_count=4,
        )


def test_publish_archive_enforces_file_size_budget(tmp_path: Path):
    docs = tmp_path / "docs"
    docs.mkdir()
    source = tmp_path / "full.json"
    source.write_text(json.dumps(_rows(10)), encoding="utf-8")

    with pytest.raises(RuntimeError, match="publication guard"):
        publish_archive(
            source_path=source,
            docs_dir=docs,
            latest_count=10,
            shard_count=4,
            max_latest_bytes=10,
        )
