from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from .community_manifest import load_community_manifest
from .correlate import correlate
from .score import score_issues
from .source_run import source_run
from .sources_config import load_sources_config


def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not path.exists():
        raise FileNotFoundError(f"Missing JSONL file: {path}")
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        if isinstance(obj, dict):
            rows.append(obj)
    return rows


def _write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def _feed_entry(issue: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "issue_id": issue.get("issue_id", ""),
        "issue_type": issue.get("issue_type", ""),
        "title": issue.get("title", ""),
        "summary": issue.get("summary", ""),
        "canonical_link": issue.get("canonical_link", ""),
        "cves": issue.get("cves", []) or [],
        "sources": issue.get("sources", []) or [],
        "published_dates": issue.get("published_dates", []) or [],
        "first_seen_at": issue.get("first_seen_at", ""),
        "last_seen_at": issue.get("last_seen_at", ""),
        "score": int(issue.get("score", 0) or 0),
        "priority": issue.get("priority", ""),
        "actions": issue.get("actions", []) or [],
    }


def _sort_feed_entries(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(
        rows,
        key=lambda r: (
            -int(r.get("score", 0) or 0),
            str(r.get("last_seen_at", "") or ""),
            str(r.get("issue_id", "") or ""),
        ),
    )


def _write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "issue_id",
        "issue_type",
        "priority",
        "score",
        "title",
        "canonical_link",
        "cves",
        "sources",
        "published_dates",
        "first_seen_at",
        "last_seen_at",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "issue_id": row.get("issue_id", ""),
                    "issue_type": row.get("issue_type", ""),
                    "priority": row.get("priority", ""),
                    "score": row.get("score", 0),
                    "title": row.get("title", ""),
                    "canonical_link": row.get("canonical_link", ""),
                    "cves": ";".join(row.get("cves", []) or []),
                    "sources": ";".join(row.get("sources", []) or []),
                    "published_dates": ";".join(row.get("published_dates", []) or []),
                    "first_seen_at": row.get("first_seen_at", ""),
                    "last_seen_at": row.get("last_seen_at", ""),
                }
            )


def build_community_feed(
    *,
    set_id: str = "gold_pass1",
    refresh: bool = False,
    refresh_limit: int = 10,
    out_root_discover: str = "outputs/discover",
    out_root_runs: str = "outputs/source_runs",
    out_root_community: str = "outputs/community_public",
    only_new: bool = False,
    limit_per_source: int = 200,
    limit_issues: int = 0,
    min_priority: str = "P2",
    top: int = 100,
    latest: int = 50,
) -> Tuple[Path, Path, Path]:
    if latest <= 0:
        raise ValueError("--latest must be > 0")

    manifest = load_community_manifest()
    selected_set = manifest.get_set(set_id)
    cfg = load_sources_config()
    cfg_by_id = {s.source_id: s for s in cfg.sources}

    if refresh:
        for source_id in selected_set.source_ids:
            print("")
            print(f"Refreshing source: {source_id}")
            source_run(
                source_id,
                limit=refresh_limit,
                ingest=False,
                dry_run=False,
                ingest_mode="new",
                out_root_discover=out_root_discover,
                out_root_runs=out_root_runs,
                show_links=False,
                reset_state=False,
            )

    community_root = Path(out_root_community)
    community_root.mkdir(parents=True, exist_ok=True)

    correlate_root = community_root / "correlate"
    scored_root = community_root / "scored"

    issues_path, _ = correlate(
        out_root_discover=out_root_discover,
        out_root_issues=str(correlate_root),
        sources=selected_set.source_ids,
        only_new=only_new,
        limit_per_source=limit_per_source,
        limit_issues=limit_issues,
        dry_run=False,
    )
    if issues_path is None:
        raise RuntimeError("Correlate did not produce issues output")

    _, alerts_path, _ = score_issues(
        in_issues=str(issues_path),
        out_root_scored=str(scored_root),
        min_priority=min_priority,
        top=top,
    )

    scored_rows = _read_jsonl(scored_root / "issues_scored.jsonl")
    alert_rows = _read_jsonl(alerts_path)
    feed_rows = _sort_feed_entries([_feed_entry(r) for r in scored_rows])
    latest_rows = feed_rows[:latest]
    alert_feed_rows = _sort_feed_entries([_feed_entry(r) for r in alert_rows])

    out_issues_public = community_root / "issues_public.jsonl"
    out_alerts_public = community_root / "alerts_public.jsonl"
    out_latest = community_root / "feed_latest.json"
    out_csv = community_root / "feed.csv"
    out_sources = community_root / "validated_sources.json"
    out_meta = community_root / "meta.json"

    _write_jsonl(out_issues_public, feed_rows)
    _write_jsonl(out_alerts_public, alert_feed_rows)
    out_latest.write_text(json.dumps(latest_rows, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    _write_csv(out_csv, feed_rows)

    validated_sources = []
    for source_id in selected_set.source_ids:
        src = cfg_by_id[source_id]
        validated_sources.append(
            {
                "source_id": src.source_id,
                "name": src.name,
                "scope": src.scope,
                "page_type": src.page_type,
                "entry_url": src.entry_url,
                "enabled": src.enabled,
                "status": "validated",
            }
        )
    for source_id in manifest.candidate_sources:
        src = cfg_by_id[source_id]
        validated_sources.append(
            {
                "source_id": src.source_id,
                "name": src.name,
                "scope": src.scope,
                "page_type": src.page_type,
                "entry_url": src.entry_url,
                "enabled": src.enabled,
                "status": "candidate",
            }
        )
    out_sources.write_text(json.dumps(validated_sources, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    meta = {
        "set_id": selected_set.set_id,
        "set_name": selected_set.name,
        "description": selected_set.description,
        "out_root_discover": out_root_discover,
        "out_root_runs": out_root_runs,
        "out_root_community": str(community_root),
        "params": {
            "refresh": bool(refresh),
            "refresh_limit": int(refresh_limit),
            "only_new": bool(only_new),
            "limit_per_source": int(limit_per_source),
            "limit_issues": int(limit_issues),
            "min_priority": min_priority,
            "top": int(top),
            "latest": int(latest),
        },
        "counts": {
            "validated_sources": len(selected_set.source_ids),
            "candidate_sources": len(manifest.candidate_sources),
            "issues_public": len(feed_rows),
            "alerts_public": len(alert_feed_rows),
            "latest": len(latest_rows),
        },
        "outputs": {
            "issues_public_jsonl": str(out_issues_public),
            "alerts_public_jsonl": str(out_alerts_public),
            "feed_latest_json": str(out_latest),
            "feed_csv": str(out_csv),
            "validated_sources_json": str(out_sources),
            "meta_json": str(out_meta),
        },
    }
    out_meta.write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print("")
    print("Community build summary:")
    print(f"  Set:              {selected_set.set_id} ({selected_set.name})")
    print(f"  Validated:        {len(selected_set.source_ids)}")
    print(f"  Candidates:       {len(manifest.candidate_sources)}")
    print(f"  Issues public:    {len(feed_rows)}")
    print(f"  Alerts public:    {len(alert_feed_rows)}")
    print(f"  Latest entries:   {len(latest_rows)}")
    print(f"  Wrote:            {out_issues_public}")
    print(f"  Wrote:            {out_alerts_public}")
    print(f"  Wrote:            {out_latest}")
    print(f"  Wrote:            {out_csv}")
    print(f"  Wrote:            {out_sources}")
    print(f"  Wrote:            {out_meta}")

    return out_issues_public, out_alerts_public, out_meta
