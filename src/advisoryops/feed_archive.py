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
import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence

MANIFEST_VERSION = 1
DEFAULT_LATEST_COUNT = 750
DEFAULT_SHARD_COUNT = 32
DEFAULT_MAX_LATEST_BYTES = 25 * 1024 * 1024
DEFAULT_MAX_SHARD_BYTES = 50 * 1024 * 1024


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

    rows: List[Dict[str, Any]] = []
    root = manifest_path.parent
    for entry in shards:
        if not isinstance(entry, dict) or not entry.get("file"):
            raise ValueError(f"Invalid shard entry in {manifest_path}: {entry!r}")
        shard_path = root / str(entry["file"])
        if not shard_path.exists():
            raise FileNotFoundError(f"Missing feed archive shard: {shard_path}")
        expected_hash = str(entry.get("sha256") or "")
        if expected_hash and _sha256_file(shard_path) != expected_hash:
            raise ValueError(f"Feed archive shard hash mismatch: {shard_path}")
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


def publish_archive(
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

    latest_rows = rows[:latest_count]
    latest_path = docs_dir / "feed_latest.json"
    _write_json_array(latest_path, latest_rows)
    latest_bytes = latest_path.stat().st_size
    if latest_bytes > max_latest_bytes:
        raise RuntimeError(
            f"Bounded feed_latest.json is {latest_bytes} bytes, above the "
            f"{max_latest_bytes}-byte publication guard. Reduce latest_count "
            "or investigate unexpectedly large records."
        )

    archive_dir = docs_dir / "feed_archive"
    archive_dir.mkdir(parents=True, exist_ok=True)

    prior_manifest_path = archive_dir / "manifest.json"
    if prior_manifest_path.exists():
        prior_manifest = json.loads(prior_manifest_path.read_text(encoding="utf-8"))
        prior_total = (
            int(prior_manifest.get("total_records", 0) or 0)
            if isinstance(prior_manifest, dict)
            else 0
        )
        if len(rows) < prior_total:
            raise RuntimeError(
                f"Publication would shrink full history from {prior_total} "
                f"to {len(rows)} records"
            )

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
        "shard_count": shard_count,
        "shard_function": "sha256(issue_id) mod shard_count",
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
        "strategy. Shard membership is deterministic: `sha256(issue_id) mod "
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
        "largest_shard_bytes": max(
            (e["bytes"] for e in shard_entries), default=0
        ),
        "manifest": str(manifest_path),
    }


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
