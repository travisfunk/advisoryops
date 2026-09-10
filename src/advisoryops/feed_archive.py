"""Durable publication helpers for the public AdvisoryOps feed.

The dashboard should stay fast and GitHub-friendly even as the historical
corpus grows. The public contract is split into:

* ``docs/feed_latest.json``: a bounded rolling window used by the dashboard.
* ``docs/feed_archive/manifest.json``: a manifest describing the complete
  historical corpus.
* ``docs/feed_archive/shard-XX.jsonl``: stable hash-partitioned JSONL shards
  containing the full-fidelity historical feed.

The stable hash partition keeps individual files well below GitHub's 100 MiB
single-file limit and avoids rewriting every shard when new records arrive.

For backward compatibility, ``prepare_baseline`` can bootstrap from the legacy
monolithic ``docs/feed_latest.json`` on the first migration run.
"""

from __future__ import annotations

import argparse
import filecmp
import hashlib
import json
import shutil
import tempfile
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence

MANIFEST_VERSION = 1
DEFAULT_LATEST_COUNT = 750
DEFAULT_SHARD_COUNT = 32
DEFAULT_MAX_LATEST_BYTES = 25 * 1024 * 1024
DEFAULT_MAX_SHARD_BYTES = 50 * 1024 * 1024


# Audited against dashboard/index.html; docs/dashboard_feed_contract.json is
# the public inventory. Keep optional values (including null/false) unchanged.
DASHBOARD_FIELDS = frozenset("""
issue_id title priority score summary cves cvss_score cvss_severity cwe_ids
fda_risk_class kev_required_action kev_due_date kev_vendor kev_product
kev_vulnerability_name is_kev_medical_device vendor affected_products
affected_versions handling_warnings remediation_steps actions sources
canonical_link published_dates first_seen_at last_seen_at healthcare_relevant
healthcare_category nvd_description recommended_patterns tasks_by_role reasoning
epss_score first_published_to_feed remotely_exploitable_no_auth
""".split())


def dashboard_record(row: Dict[str, Any]) -> Dict[str, Any]:
    """Lossless projection of UI fields; never summarize or truncate facts."""
    return {key: deepcopy(row[key]) for key in sorted(DASHBOARD_FIELDS) if key in row}


def assert_history_retained(
    prior: Sequence[Dict[str, Any]], current: Sequence[Dict[str, Any]],
) -> None:
    """A count floor alone misses replacement of old IDs by new IDs."""
    _validate_unique_issue_ids(current)
    missing = {_issue_key(row) for row in prior} - {_issue_key(row) for row in current}
    if missing:
        raise RuntimeError(
            f"Publication would shrink or lose full history: {len(missing)} missing "
            f"issue IDs (sample: {', '.join(sorted(missing)[:5])}). "
            "Reconstruct the full archive baseline and merge before publishing."
        )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_json_array(path: Path) -> List[Dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list) or not all(isinstance(row, dict) for row in data):
        raise ValueError(f"{path} must contain a JSON array of objects")
    return data


def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line:
                continue
            obj = json.loads(line)
            if not isinstance(obj, dict):
                raise ValueError(f"{path}:{lineno} is not a JSON object")
            rows.append(obj)
    return rows


def _write_json_array(path: Path, rows: Sequence[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(list(rows), ensure_ascii=False, separators=(",", ":")) + "\n"
    path.write_text(payload, encoding="utf-8", newline="\n")


def _write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        for row in rows:
            fh.write(
                json.dumps(
                    row,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            )


def _issue_key(row: Dict[str, Any]) -> str:
    key = str(row.get("issue_id") or "").strip()
    if not key:
        raise ValueError("Every archived feed row must have a non-empty issue_id")
    return key


def _validate_unique_issue_ids(rows: Sequence[Dict[str, Any]]) -> None:
    seen: set[str] = set()
    duplicates: List[str] = []
    for row in rows:
        key = _issue_key(row)
        if key in seen:
            duplicates.append(key)
        seen.add(key)
    if duplicates:
        sample = ", ".join(sorted(set(duplicates))[:5])
        raise ValueError(f"Duplicate issue_id values in feed: {sample}")


def _shard_index(issue_id: str, shard_count: int) -> int:
    digest = hashlib.sha256(issue_id.encode("utf-8")).digest()
    return int.from_bytes(digest[:4], "big") % shard_count


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _manifest_rows(manifest_path: Path) -> List[Dict[str, Any]]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError(f"{manifest_path} must contain a JSON object")
    if int(manifest.get("version", 0) or 0) != MANIFEST_VERSION:
        raise ValueError(
            f"Unsupported feed archive manifest version: {manifest.get('version')!r}"
        )
    shards = manifest.get("shards")
    if not isinstance(shards, list) or not shards:
        raise ValueError(f"{manifest_path} has no archive shards")

    if len(shards) != manifest.get("shard_count"):
        raise ValueError("Feed archive shard_count mismatch")
    names = [entry.get("file") for entry in shards if isinstance(entry, dict)]
    if len(set(names)) != len(shards):
        raise ValueError("Duplicate or invalid archive shard entries")
    rows: List[Dict[str, Any]] = []
    root = manifest_path.parent
    for entry in shards:
        if not isinstance(entry, dict) or not entry.get("file"):
            raise ValueError(f"Invalid shard entry in {manifest_path}: {entry!r}")
        name = str(entry["file"])
        if Path(name).name != name or not name.startswith("shard-") or not name.endswith(".jsonl"):
            raise ValueError(f"Invalid archive shard filename: {name}")
        shard_path = root / name
        if not shard_path.exists():
            raise FileNotFoundError(f"Missing feed archive shard: {shard_path}")
        expected_hash = str(entry.get("sha256") or "")
        if not expected_hash or _sha256_file(shard_path) != expected_hash:
            raise ValueError(f"Feed archive shard hash mismatch: {shard_path}")
        if shard_path.stat().st_size != entry.get("bytes"):
            raise ValueError(f"Feed archive shard byte size mismatch: {shard_path}")
        shard_rows = _read_jsonl(shard_path)
        expected_count = int(entry.get("count", len(shard_rows)) or 0)
        if len(shard_rows) != expected_count:
            raise ValueError(
                f"Feed archive shard count mismatch for {shard_path}: "
                f"{len(shard_rows)} != {expected_count}"
            )
        rows.extend(shard_rows)

    expected_total = int(manifest.get("total_records", len(rows)) or 0)
    if len(rows) != expected_total:
        raise ValueError(
            f"Feed archive total mismatch: {len(rows)} != {expected_total}"
        )
    _validate_unique_issue_ids(rows)
    return rows


def prepare_baseline(
    *,
    manifest_path: Path,
    legacy_path: Path,
    out_path: Path,
) -> Dict[str, Any]:
    """Build the full-fidelity baseline used by ``community-build``.

    Prefer the sharded archive when present. On the first migration run,
    bootstrap from the legacy monolithic ``feed_latest.json``.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if not manifest_path.exists():
        if manifest_path.parent.exists():
            raise RuntimeError("Archive directory exists without manifest; restore the durable archive")
        meta_path = legacy_path.parent / "meta.json"
        if meta_path.exists() and json.loads(meta_path.read_text(encoding="utf-8")).get("publication"):
            raise RuntimeError("Missing durable archive; refusing compact feed as a historical baseline")

    if manifest_path.exists():
        rows = _manifest_rows(manifest_path)
        _write_json_array(out_path, rows)
        source = "sharded_archive"
    elif legacy_path.exists():
        rows = _read_json_array(legacy_path)
        _validate_unique_issue_ids(rows)
        shutil.copyfile(legacy_path, out_path)
        source = "legacy_monolith"
    else:
        _write_json_array(out_path, [])
        rows = []
        source = "empty"

    return {
        "source": source,
        "records": len(rows),
        "path": str(out_path),
    }


def _publish_archive_staged(
    *,
    source_path: Path,
    docs_dir: Path,
    latest_count: int = DEFAULT_LATEST_COUNT,
    shard_count: int = DEFAULT_SHARD_COUNT,
    max_latest_bytes: int = DEFAULT_MAX_LATEST_BYTES,
    max_shard_bytes: int = DEFAULT_MAX_SHARD_BYTES,
) -> Dict[str, Any]:
    """Publish a bounded dashboard feed plus the complete sharded archive."""
    if latest_count <= 0:
        raise ValueError("latest_count must be greater than zero")
    if shard_count <= 1:
        raise ValueError("shard_count must be greater than one")

    rows = _read_json_array(source_path)
    _validate_unique_issue_ids(rows)
    docs_dir.mkdir(parents=True, exist_ok=True)

    latest_rows = [dashboard_record(row) for row in rows[:latest_count]]
    latest_path = docs_dir / "feed_latest.json"
    _write_json_array(latest_path, latest_rows)
    latest_bytes = latest_path.stat().st_size
    if latest_bytes > max_latest_bytes:
        raise RuntimeError(
            f"Bounded feed_latest.json is {latest_bytes} bytes, above the "
            f"{max_latest_bytes}-byte publication guard. Inspect dashboard field sizes "
            "and outlier issue IDs; preserve full facts in the archive. "
            "Do not lower latest_count to conceal oversized records."
        )

    archive_dir = docs_dir / "feed_archive"
    archive_dir.mkdir(parents=True, exist_ok=True)

    prior_manifest_path = archive_dir / "manifest.json"
    if archive_dir.exists() and any(archive_dir.iterdir()) and not prior_manifest_path.exists():
        raise RuntimeError("Archive directory exists without manifest; restore the durable archive")
    if prior_manifest_path.exists():
        assert_history_retained(_manifest_rows(prior_manifest_path), rows)

    buckets: List[List[Dict[str, Any]]] = [[] for _ in range(shard_count)]
    for row in rows:
        idx = _shard_index(_issue_key(row), shard_count)
        buckets[idx].append(row)

    shard_entries: List[Dict[str, Any]] = []
    expected_names: set[str] = set()
    width = max(2, len(str(shard_count - 1)))
    for idx, bucket in enumerate(buckets):
        bucket.sort(key=_issue_key)
        name = f"shard-{idx:0{width}d}.jsonl"
        expected_names.add(name)
        shard_path = archive_dir / name
        _write_jsonl(shard_path, bucket)
        size_bytes = shard_path.stat().st_size
        if size_bytes > max_shard_bytes:
            raise RuntimeError(
                f"{name} is {size_bytes} bytes, above the {max_shard_bytes}-byte "
                "publication guard. Increase shard_count before publishing."
            )
        shard_entries.append(
            {
                "file": name,
                "count": len(bucket),
                "bytes": size_bytes,
                "sha256": _sha256_file(shard_path),
            }
        )

    for stale in archive_dir.glob("shard-*.jsonl"):
        if stale.name not in expected_names:
            stale.unlink()

    manifest = {
        "version": MANIFEST_VERSION,
        "generated_at": _utc_now(),
        "strategy": "bounded_latest_plus_stable_hash_jsonl",
        "total_records": len(rows),
        "latest_records": len(latest_rows),
        "latest_file": "../feed_latest.json",
        "dashboard_contract": "../dashboard_feed_contract.json",
        "dashboard_projection_version": 1,
        "shard_count": shard_count,
        "shard_function": "uint32_be(sha256(issue_id)[:4]) mod shard_count",
        "shards": shard_entries,
    }
    manifest_path = archive_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    readme_path = archive_dir / "README.md"
    readme_path.write_text(
        "# AdvisoryOps full feed archive\n\n"
        "`feed_latest.json` is intentionally bounded for fast GitHub Pages "
        "dashboard loading. The complete full-fidelity corpus is preserved in "
        "the JSONL shards in this directory. `manifest.json` records the shard "
        "count, record counts, byte sizes, SHA-256 hashes, and partition "
        "strategy. Shard membership is deterministic: `uint32_be(sha256(issue_id)[:4]) mod "
        "shard_count`.\n\n"
        "This design keeps every published file well below GitHub's single-file "
        "limit while preserving an auditable, reconstructable historical "
        "baseline.\n",
        encoding="utf-8",
        newline="\n",
    )

    meta_path = docs_dir / "meta.json"
    if meta_path.exists():
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if isinstance(meta, dict):
            meta["publication"] = {
                "strategy": manifest["strategy"],
                "total_records": len(rows),
                "latest_records": len(latest_rows),
                "archive_shards": shard_count,
                "archive_manifest": "feed_archive/manifest.json",
                "largest_shard_bytes": max(
                    (e["bytes"] for e in shard_entries), default=0
                ),
                "latest_bytes": latest_bytes,
                "generated_at": manifest["generated_at"],
            }
            meta_path.write_text(
                json.dumps(meta, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
                newline="\n",
            )

    return {
        "total_records": len(rows),
        "latest_records": len(latest_rows),
        "latest_bytes": latest_bytes,
        "shard_count": shard_count,
        "archive_bytes": sum(e["bytes"] for e in shard_entries),
        "largest_shard_bytes": max(
            (e["bytes"] for e in shard_entries), default=0
        ),
        "manifest": str(manifest_path),
    }


def publish_archive(
    *, source_path: Path, docs_dir: Path,
    latest_count: int = DEFAULT_LATEST_COUNT,
    shard_count: int = DEFAULT_SHARD_COUNT,
    max_latest_bytes: int = DEFAULT_MAX_LATEST_BYTES,
    max_shard_bytes: int = DEFAULT_MAX_SHARD_BYTES,
) -> Dict[str, Any]:
    """Validate all archive/projection files before replacing published files.

    Failed guards leave the existing publication intact. GitHub Pages receives
    the completed set through one git commit, not through these local renames.
    """
    docs_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".publication-", dir=docs_dir.parent) as temp:
        staged = Path(temp)
        archive = docs_dir / "feed_archive"
        if archive.exists():
            shutil.copytree(archive, staged / "feed_archive")
        if (docs_dir / "meta.json").exists():
            shutil.copy2(docs_dir / "meta.json", staged / "meta.json")
        result = _publish_archive_staged(
            source_path=source_path, docs_dir=staged, latest_count=latest_count,
            shard_count=shard_count, max_latest_bytes=max_latest_bytes,
            max_shard_bytes=max_shard_bytes,
        )
        for source in sorted(staged.rglob("*")):
            if source.is_file():
                target = docs_dir / source.relative_to(staged)
                target.parent.mkdir(parents=True, exist_ok=True)
                # Compare contents, never just stat metadata: unchanged files
                # keep their mtimes and existing Git blob identities. Staged
                # serialization/validation still runs for every shard.
                if target.is_file() and filecmp.cmp(source, target, shallow=False):
                    continue
                source.replace(target)
        expected = {entry["file"] for entry in json.loads(
            (archive / "manifest.json").read_text(encoding="utf-8"))["shards"]}
        for stale in archive.glob("shard-*.jsonl"):
            if stale.name not in expected:
                stale.unlink()
        result["manifest"] = str(archive / "manifest.json")
        return result


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    baseline = sub.add_parser(
        "prepare-baseline",
        help="Reconstruct full baseline from archive shards, with legacy fallback.",
    )
    baseline.add_argument("--manifest", type=Path, required=True)
    baseline.add_argument("--legacy", type=Path, required=True)
    baseline.add_argument("--out", type=Path, required=True)

    publish = sub.add_parser(
        "publish",
        help="Publish bounded feed_latest.json plus stable sharded full history.",
    )
    publish.add_argument("--source", type=Path, required=True)
    publish.add_argument("--docs", type=Path, required=True)
    publish.add_argument("--latest-count", type=int, default=DEFAULT_LATEST_COUNT)
    publish.add_argument("--shards", type=int, default=DEFAULT_SHARD_COUNT)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "prepare-baseline":
        result = prepare_baseline(
            manifest_path=args.manifest,
            legacy_path=args.legacy,
            out_path=args.out,
        )
        print(
            "Prepared AdvisoryOps baseline: "
            f"{result['records']} records from {result['source']} -> "
            f"{result['path']}"
        )
        return 0

    result = publish_archive(
        source_path=args.source,
        docs_dir=args.docs,
        latest_count=args.latest_count,
        shard_count=args.shards,
    )
    print("Published AdvisoryOps scalable feed:")
    print(f"  Full archive records: {result['total_records']}")
    print(
        f"  Dashboard latest:     {result['latest_records']} "
        f"({result['latest_bytes']} bytes)"
    )
    print(f"  Archive shards:       {result['shard_count']}")
    print(f"  Largest shard:        {result['largest_shard_bytes']} bytes")
    print(f"  Manifest:             {result['manifest']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
