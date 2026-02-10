from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple

from .discover import discover
from .ingest import ingest_url
from .sources_config import load_sources_config


IngestMode = Literal["new", "all"]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_items(path: Path) -> List[Dict[str, Any]]:
    obj = json.loads(path.read_text(encoding="utf8"))
    items = obj.get("items", [])
    if not isinstance(items, list):
        raise ValueError(f"{path}: expected list at .items")
    out: List[Dict[str, Any]] = []
    for it in items:
        if isinstance(it, dict):
            out.append(it)
    return out


def source_run(
    source_id: str,
    *,
    limit: int,
    ingest: bool,
    dry_run: bool,
    ingest_mode: IngestMode = "new",
    out_root_discover: str = "outputs/discover",
    out_root_runs: str = "outputs/source_runs",
    show_links: bool = False,
    reset_state: bool = False,
) -> Optional[Path]:
    """
    Orchestrate: discover -> (optional) ingest

    - limit is required to prevent surprise spend.
    - ingest_mode:
        - "new": ingest only new items (based on discover state)
        - "all": ingest top N items from feed.json regardless of state
    - dry_run:
        - when true and ingest is requested, prints planned ingest but does not fetch item pages.
    """
    if limit <= 0:
        raise ValueError("--limit must be > 0")

    cfg = load_sources_config()
    src = cfg.get(source_id)

    if not src.enabled:
        raise ValueError(f"Source '{source_id}' is disabled (enabled=false)")

    # Optional: reset discovery state (force all items treated as new)
    if reset_state:
        state_file = Path(out_root_discover) / source_id / "state.json"
        try:
            if state_file.exists():
                state_file.unlink()
        except Exception:
            # Best-effort; discovery will proceed either way
            pass

    # Run discovery (writes outputs/discover/<source_id>/feed.json and new_items.json)
    raw_path, feed_path, new_path, state_path = discover(
        source_id,
        limit=limit,
        out_root=out_root_discover,
        show_links=show_links,
    )

    # Select items to ingest
    if ingest_mode == "new":
        items = _read_items(new_path)
    elif ingest_mode == "all":
        items = _read_items(feed_path)
    else:
        raise ValueError(f"Unknown ingest_mode: {ingest_mode}")

    # Enforce limit (discover already applied, but keep deterministic guardrail)
    items = items[:limit]

    print("")
    print("Source run summary:")
    print(f"  Source:      {source_id} ({src.name})")
    print(f"  Scope:       {src.scope}")
    print(f"  Page type:   {src.page_type}")
    print(f"  Ingest:      {bool(ingest)}")
    print(f"  Dry-run:     {bool(dry_run)}")
    print(f"  Ingest mode: {ingest_mode}")
    print(f"  Selected:    {len(items)}")
    if items:
        print("  Sample:")
        for row in items[:3]:
            print("   - " + str(row.get("link", "")))

    if not ingest:
        return None

    # If discovery selected nothing, ingest is a no-op (exit cleanly)
    if not items:
        print("")
        print("No items selected; nothing to ingest.")
        return None

    # Scope guardrail: only advisory sources can ingest in v1
    if src.scope != "advisory":
        print("")
        print(f"Ingest skipped: scope='{src.scope}' is not ingestable in v1 (use advisory sources).")
        if dry_run:
            print("")
            print("DRY RUN: planned ingest URLs (no fetching):")
            for row in items:
                print(" - " + str(row.get("link", "")))
        return None


    if dry_run:
        print("")
        print("DRY RUN: planned ingest URLs (no fetching):")
        for row in items:
            print(" - " + str(row.get("link", "")))
        return None

    # Rate limit between per-item ingests (default from config: 1 req/sec)
    delay_s = 0.0
    if src.rate_limit_rps and src.rate_limit_rps > 0:
        delay_s = 1.0 / float(src.rate_limit_rps)

    started = utc_now_iso()
    ingested: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []

    for idx, row in enumerate(items, start=1):
        url = str(row.get("link", "") or "").strip()
        title = str(row.get("title", "") or "").strip()
        guid = str(row.get("guid", "") or "").strip()
        if not url:
            errors.append({"index": idx, "error": "missing link", "title": title, "guid": guid})
            continue

        print("")
        print(f"[{idx}/{len(items)}] Ingesting: {url}")
        try:
            advisory_id, out_dir = ingest_url(url)
            ingested.append(
                {
                    "index": idx,
                    "advisory_id": advisory_id,
                    "output_dir": str(out_dir),
                    "url": url,
                    "title": title,
                    "guid": guid,
                }
            )
            print(f"  advisory_id: {advisory_id}")
            print(f"  output_dir:  {out_dir}")
        except Exception as e:
            errors.append({"index": idx, "url": url, "title": title, "guid": guid, "error": str(e)})
            print(f"  ERROR: {e}")

        if delay_s > 0 and idx < len(items):
            time.sleep(delay_s)

    finished = utc_now_iso()

    # Write a run report (gitignored under outputs/)
    out_dir = Path(out_root_runs)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_path = out_dir / f"{ts}_{source_id}.json"

    report = {
        "source_id": source_id,
        "source_name": src.name,
        "scope": src.scope,
        "page_type": src.page_type,
        "entry_url": src.entry_url,
        "ingest_mode": ingest_mode,
        "limit": limit,
        "started_at": started,
        "finished_at": finished,
        "discover_outputs": {
            "raw_feed": str(raw_path),
            "feed_json": str(feed_path),
            "new_items_json": str(new_path),
            "state_json": str(state_path),
        },
        "ingested": ingested,
        "errors": errors,
    }
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf8")
    print("")
    print(f"Wrote run report: {report_path}")
    print(f"Ingested: {len(ingested)}  Errors: {len(errors)}")

    return report_path
