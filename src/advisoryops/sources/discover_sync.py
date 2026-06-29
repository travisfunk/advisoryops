"""Shared utility: publish backfill signals into the discover output directory.

The pipeline's correlate stage reads from ``outputs/discover/<source_id>/items.jsonl``.
This module bridges backfill caches into that format so backfill data flows through
the standard pipeline without modification.

Used by both ``nvd_backfill`` and ``cisa_icsma_backfill`` (and future backfill modules).
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()


def _ensure_signal_id(item: Dict[str, Any], *, source_id: str) -> None:
    """Add a deterministic signal_id if not present (matches discover.py logic)."""
    if item.get("signal_id"):
        return
    guid = str(item.get("guid") or item.get("link") or item.get("title") or "").strip()
    if not guid:
        return
    item["signal_id"] = _sha256_hex(f"{source_id}|{guid}")


def publish_to_discover(
    signals: List[Dict[str, Any]],
    *,
    source_id: str,
    out_root: str = "outputs/discover",
) -> Dict[str, Any]:
    """Write signals into the discover output directory for pipeline consumption.

    Creates/updates the same artifact set that ``discover.py`` produces:
      - items.jsonl, new_items.jsonl
      - feed.json, new_items.json
      - state.json, meta.json

    New-item detection uses state.json (same as discover.py).

    Args:
        signals: List of normalized signal dicts.
        source_id: The source ID for the discover output directory.
        out_root: Root discover output directory.

    Returns:
        Stats dict with counts.
    """
    out_dir = Path(out_root) / source_id
    out_dir.mkdir(parents=True, exist_ok=True)

    fetched_at = datetime.now(timezone.utc).isoformat()

    # Ensure signal_ids
    for sig in signals:
        _ensure_signal_id(sig, source_id=source_id)

    # Load existing state for new-item detection
    state_path = out_dir / "state.json"
    state: Dict[str, Any] = {"source": source_id, "seen": {}}
    if state_path.exists():
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
        except Exception:
            state = {"source": source_id, "seen": {}}

    seen = state.get("seen", {}) if isinstance(state.get("seen"), dict) else {}

    new_items: List[Dict[str, Any]] = []
    for sig in signals:
        guid = str(sig.get("guid") or "").strip()
        sid = str(sig.get("signal_id") or "").strip()

        seen_guid = bool(guid) and (guid in seen)
        seen_sid = bool(sid) and (sid in seen)

        if not (seen_guid or seen_sid):
            new_items.append(sig)

        if guid:
            seen[guid] = fetched_at
        if sid:
            seen[sid] = fetched_at

    state["seen"] = seen

    # Write all artifacts
    _write_jsonl(out_dir / "items.jsonl", signals)
    _write_jsonl(out_dir / "new_items.jsonl", new_items)

    feed_obj = {"source": source_id, "fetched_at": fetched_at, "items": signals}
    new_obj = {"source": source_id, "fetched_at": fetched_at, "items": new_items}

    (out_dir / "feed.json").write_text(
        json.dumps(feed_obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (out_dir / "new_items.json").write_text(
        json.dumps(new_obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    state_path.write_text(
        json.dumps(state, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    # Write meta.json
    meta = {
        "source_id": source_id,
        "source_name": f"{source_id} (backfill)",
        "scope": "dataset",
        "page_type": "backfill_cache",
        "entry_url": "",
        "started_at": fetched_at,
        "fetched_at": fetched_at,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "limit": len(signals),
        "counts": {
            "parsed": len(signals),
            "limited": len(signals),
            "filtered": len(signals),
            "new": len(new_items),
        },
        "outputs": {
            "feed_json": str(out_dir / "feed.json"),
            "new_items_json": str(out_dir / "new_items.json"),
            "items_jsonl": str(out_dir / "items.jsonl"),
            "new_items_jsonl": str(out_dir / "new_items.jsonl"),
            "state_json": str(state_path),
            "meta_json": str(out_dir / "meta.json"),
        },
        "errors": [],
    }
    (out_dir / "meta.json").write_text(
        json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    return {
        "total_signals": len(signals),
        "new_signals": len(new_items),
        "out_dir": str(out_dir),
    }


def _write_jsonl(path: Path, items: List[Dict[str, Any]]) -> None:
    lines = [json.dumps(it, ensure_ascii=False, sort_keys=True) for it in items]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
