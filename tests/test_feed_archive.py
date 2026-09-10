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


def test_projection_matches_dashboard_inventory_and_preserves_values():
    import re
    from advisoryops.feed_archive import DASHBOARD_FIELDS, dashboard_record
    root = Path(__file__).resolve().parents[1]
    html = (root / "dashboard/index.html").read_text(encoding="utf-8")
    # Include aliases, array-indexed issues, sorting and methodology loops.
    reads = set(re.findall(r'\b(?:issue|i|it)\.([a-z_][a-z0-9_]*)', html))
    reads.update(re.findall(r'\b(?:issues|list|mdList|kevList)\[[^\]]+\]\.([a-z_][a-z0-9_]*)', html))
    reads.update({"priority", "published_dates", "first_seen_at"})  # sort helpers a/b
    contract = json.loads((root / "docs/dashboard_feed_contract.json").read_text())
    assert reads == DASHBOARD_FIELDS == set(contract["fields"])
    row = {key: ["unchanged", {"unicode": "\u2713"}] for key in DASHBOARD_FIELDS}
    row.update(source_summary="large source evidence" * 10000, private_future_field={"raw": True})
    projected = dashboard_record(row)
    assert projected == {key: row[key] for key in DASHBOARD_FIELDS}
    projected["recommended_patterns"].append("mutation")
    assert projected["recommended_patterns"] != row["recommended_patterns"]
    assert dashboard_record({"issue_id": "x", "is_kev_medical_device": False,
                             "remotely_exploitable_no_auth": None}) == {
        "issue_id": "x", "is_kev_medical_device": False, "remotely_exploitable_no_auth": None}


def test_multiple_nights_preserve_full_fidelity_and_new_ids(tmp_path):
    from advisoryops.community_build import merge_baseline_feed, _sort_feed_entries
    docs = tmp_path / "docs"
    source = tmp_path / "source.json"
    baseline = tmp_path / "baseline.json"
    rows = _rows(20)
    rows[0]["source_summary"] = "Full evidence" * 10000
    rows[0]["extracted_facts"] = {"nested": [1, 2, 3]}
    source.write_text(json.dumps(rows))
    for new in [[dict(_rows(21)[-1], source_summary="new evidence")], []]:
        publish_archive(source_path=source, docs_dir=docs, latest_count=2, shard_count=4)
        (docs / "feed_latest.json").unlink()  # history cannot rely on it
        prepare_baseline(manifest_path=docs / "feed_archive/manifest.json",
                         legacy_path=docs / "feed_latest.json", out_path=baseline)
        restored = json.loads(baseline.read_text())
        assert sorted(restored, key=lambda r:r["issue_id"]) == sorted(rows, key=lambda r:r["issue_id"])
        again = tmp_path / "again.json"
        prepare_baseline(manifest_path=docs / "feed_archive/manifest.json",
                         legacy_path=docs / "missing.json", out_path=again)
        assert again.read_bytes() == baseline.read_bytes()
        merged = _sort_feed_entries(merge_baseline_feed(new, restored, run_timestamp="2026-09-10"))
        assert {r["issue_id"] for r in merged} == {r["issue_id"] for r in rows + new}
        rows = merged
        source.write_text(json.dumps(rows))
    assert len(rows) == 21
    assert next(r for r in rows if r["issue_id"] == "issue-0020")["source_summary"] == "new evidence"


@pytest.mark.parametrize("failure", ["latest", "shard", "replacement"])
def test_failed_publication_leaves_all_files_unchanged(tmp_path, failure):
    docs = tmp_path / "docs"
    source = tmp_path / "source.json"
    rows = _rows(20)
    source.write_text(json.dumps(rows))
    publish_archive(source_path=source, docs_dir=docs, latest_count=5, shard_count=4)
    before = {str(p.relative_to(docs)): p.read_bytes() for p in docs.rglob("*") if p.is_file()}
    kwargs = {}
    if failure == "latest":
        kwargs["max_latest_bytes"] = 10
    elif failure == "shard":
        kwargs["max_shard_bytes"] = 10
    else:
        rows[-1]["issue_id"] = "replacement"
        source.write_text(json.dumps(rows))
    with pytest.raises(RuntimeError, match="publication guard|missing issue IDs"):
        publish_archive(source_path=source, docs_dir=docs, latest_count=5, shard_count=4, **kwargs)
    assert before == {str(p.relative_to(docs)): p.read_bytes() for p in docs.rglob("*") if p.is_file()}


def test_missing_archive_cannot_fall_back_to_compact_feed(tmp_path):
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "feed_latest.json").write_text(json.dumps(_rows(2)))
    (docs / "meta.json").write_text(json.dumps({"publication": {"total_records": 100}}))
    with pytest.raises(RuntimeError, match="Missing durable archive"):
        prepare_baseline(manifest_path=docs / "feed_archive/manifest.json",
                         legacy_path=docs / "feed_latest.json", out_path=tmp_path / "baseline.json")


def test_kev_verification_uses_full_archive_not_dashboard_window(tmp_path):
    from advisoryops.kev_medical_device_reconcile import reconcile_rows
    from advisoryops.kev_full_catalog import run
    rows = _rows(10)
    rows[-1].update(issue_id="CVE-2026-12345", cves=["CVE-2026-12345"], healthcare_category="medical_device")
    stats = reconcile_rows(rows, {"CVE-2026-12345"})
    assert stats["strict_kev_medical_device"] == 1
    source = tmp_path / "source.json"
    source.write_text(json.dumps(rows))
    docs = tmp_path / "docs"
    publish_archive(source_path=source, docs_dir=docs, latest_count=1, shard_count=4)
    assert not json.loads((docs / "feed_latest.json").read_text())[0]["is_kev_medical_device"]
    prepare_baseline(manifest_path=docs / "feed_archive/manifest.json",
                     legacy_path=docs / "feed_latest.json", out_path=source)
    kev = tmp_path / "kev.jsonl"
    kev.write_text(json.dumps({"guid": "CVE-2026-12345"}) + "\n")
    report = run(feed_path=source, kev_path=kev, out_path=tmp_path / "report.json", min_kev_cves=1)
    assert report["cve_overlap_ids"] == ["CVE-2026-12345"]
    assert report["medical_device_records"] == 3
    restored = json.loads(source.read_text())
    assert next(r for r in restored if r["issue_id"] == "CVE-2026-12345")["is_kev_medical_device"]


@pytest.mark.parametrize("damage", ["missing", "hash", "bytes", "count"])
def test_corrupt_archive_fails_closed(tmp_path, damage):
    source = tmp_path / "full.json"
    source.write_text(json.dumps(_rows(10)))
    docs = tmp_path / "docs"
    publish_archive(source_path=source, docs_dir=docs, latest_count=2, shard_count=4)
    manifest = docs / "feed_archive/manifest.json"
    data = json.loads(manifest.read_text())
    shard = manifest.parent / data["shards"][0]["file"]
    if damage == "missing":
        shard.unlink()
    elif damage == "hash":
        shard.write_text("corrupt")
    else:
        key = "bytes" if damage == "bytes" else "count"
        data["shards"][0][key] += 1
        manifest.write_text(json.dumps(data))
    with pytest.raises((ValueError, FileNotFoundError)):
        prepare_baseline(manifest_path=manifest, legacy_path=docs / "feed_latest.json",
                         out_path=tmp_path / "baseline.json")
    assert not (tmp_path / "baseline.json").exists()


def test_shard_bytes_are_independent_of_source_order(tmp_path):
    source = tmp_path / "full.json"
    rows = _rows(20)
    source.write_text(json.dumps(rows))
    docs = tmp_path / "docs"
    publish_archive(source_path=source, docs_dir=docs, latest_count=2, shard_count=4)
    before = {p.name: p.read_bytes() for p in (docs / "feed_archive").glob("*.jsonl")}
    source.write_text(json.dumps(rows[::-1]))
    publish_archive(source_path=source, docs_dir=docs, latest_count=2, shard_count=4)
    assert before == {p.name: p.read_bytes() for p in (docs / "feed_archive").glob("*.jsonl")}


def test_verifier_cli_defaults_to_full_archive(tmp_path, monkeypatch):
    from advisoryops.kev_full_catalog import main
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "full.json"
    rows = _rows(10)
    rows[-1].update(issue_id="CVE-2026-12345", healthcare_category="medical_device")
    source.write_text(json.dumps(rows))
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "meta.json").write_text("{}")
    publish_archive(source_path=source, docs_dir=docs, latest_count=1, shard_count=4)
    kev = tmp_path / "kev.jsonl"
    kev.write_text(json.dumps({"guid": "CVE-2026-12345"}) + "\n")
    monkeypatch.setattr("sys.argv", ["kev_full_catalog", "--kev-jsonl", str(kev), "--min-kev-cves", "1"])
    assert main() == 0
    report = json.loads((docs / "kev_full_catalog_overlap.json").read_text())
    assert report["cve_overlap_ids"] == ["CVE-2026-12345"]


def test_quiet_publication_preserves_shard_bytes_mtimes_and_manifest_entries(tmp_path, monkeypatch):
    import os
    from advisoryops import feed_archive
    source = tmp_path / "full.json"
    source.write_text(json.dumps(_rows(200)))
    docs = tmp_path / "docs"
    timestamps = iter(["2026-09-10T00:00:00+00:00", "2026-09-11T00:00:00+00:00"])
    monkeypatch.setattr(feed_archive, "_utc_now", lambda: next(timestamps))
    publish_archive(source_path=source, docs_dir=docs)
    archive = docs / "feed_archive"
    shards = sorted(archive.glob("shard-*.jsonl"))
    assert len(shards) == 32
    # A fixed old mtime makes replacement detectable without timing/sleep races.
    for shard in shards:
        os.utime(shard, ns=(1_600_000_000_000_000_000, 1_600_000_000_000_000_000))
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in shards}
    manifest_before = json.loads((archive / "manifest.json").read_text())
    publish_archive(source_path=source, docs_dir=docs)
    assert before == {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in shards}
    manifest_after = json.loads((archive / "manifest.json").read_text())
    assert {key for key in manifest_before if manifest_before[key] != manifest_after[key]} == {"generated_at"}
    assert manifest_after["generated_at"] == "2026-09-11T00:00:00+00:00"


@pytest.mark.parametrize("change_kind", ["update", "insert"])
def test_small_changes_only_replace_affected_shards(tmp_path, change_kind):
    import os
    from advisoryops.feed_archive import _shard_index
    source = tmp_path / "full.json"
    rows = _rows(200)
    source.write_text(json.dumps(rows))
    docs = tmp_path / "docs"
    publish_archive(source_path=source, docs_dir=docs)
    shards = sorted((docs / "feed_archive").glob("shard-*.jsonl"))
    for shard in shards:
        os.utime(shard, ns=(1_600_000_000_000_000_000, 1_600_000_000_000_000_000))
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in shards}
    if change_kind == "update":
        changed = rows[:3]
        for row in changed:
            row["title"] = row["title"].replace("Issue", "ISSUE")  # same byte length
    else:
        changed = _rows(203)[200:]
        rows.extend(changed)
    expected = {f"shard-{_shard_index(row['issue_id'], 32):02d}.jsonl" for row in changed}
    source.write_text(json.dumps(rows))
    publish_archive(source_path=source, docs_dir=docs)
    assert {p.name for p in shards if p.read_bytes() != before[p.name][0]} == expected
    assert {p.name for p in shards if p.stat().st_mtime_ns != before[p.name][1]} == expected
