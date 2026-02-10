from __future__ import annotations

import json
import hashlib
import re
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import xml.etree.ElementTree as ET

from .sources_config import load_sources_config, SourceDef
from .feed_parsers import parse_json_feed, parse_csv_feed


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()


def _ensure_signal_id(item: dict, *, source_id: str) -> None:
    # Deterministic per-source signal id (used later for correlation/dedup).
    if item.get("signal_id"):
        return
    guid = _text(item.get("guid")) or _text(item.get("link")) or _text(item.get("title"))
    if not guid:
        return
    item["signal_id"] = _sha256_hex(f"{source_id}|{guid}")


def _write_jsonl(path: Path, items: list) -> None:
    lines = []
    for it in items:
        lines.append(json.dumps(it, ensure_ascii=False, sort_keys=True))
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def _http_get_bytes(url: str, *, timeout_s: int, retries: int) -> bytes:
    last_err: Optional[Exception] = None
    headers = {
        "User-Agent": "advisoryops/1.1 (+https://github.com/travisfunk/advisoryops)",
        "Accept": "*/*",
    }
    for attempt in range(1, retries + 2):
        try:
            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                return resp.read()
        except Exception as e:
            last_err = e
            if attempt >= retries + 1:
                break
            # simple backoff
            time.sleep(min(2.0 * attempt, 10.0))
    raise RuntimeError(f"GET failed: {url} ({last_err})")


def _compile_regex(pat: Optional[str]) -> Optional[re.Pattern]:
    if not pat:
        return None
    return re.compile(pat, re.IGNORECASE)


def _text(v: Any) -> str:
    return str(v or "").strip()


def _apply_filters(item: Dict[str, Any], *, src: SourceDef) -> bool:
    f = src.filters
    fields = set([x.lower() for x in (f.apply_to or [])])

    hay = ""
    if "title" in fields:
        hay += " " + _text(item.get("title"))
    if "summary" in fields:
        hay += " " + _text(item.get("summary"))
    if "description" in fields:
        hay += " " + _text(item.get("summary"))

    hay_l = hay.lower()

    if f.keywords_all:
        for kw in f.keywords_all:
            if kw.lower() not in hay_l:
                return False

    if f.keywords_any:
        ok = False
        for kw in f.keywords_any:
            if kw.lower() in hay_l:
                ok = True
                break
        if not ok:
            return False

    link = _text(item.get("link"))
    allow_re = _compile_regex(f.url_allow_regex)
    deny_re = _compile_regex(f.url_deny_regex)
    if allow_re and link and not allow_re.search(link):
        return False
    if deny_re and link and deny_re.search(link):
        return False

    return True


def _parse_rss_atom(xml_bytes: bytes, *, source_id: str, fetched_at: str) -> List[Dict[str, Any]]:
    """
    stdlib RSS/Atom parse (good enough for CISA, CERT/CC, most feeds)
    returns normalized items with keys: source,guid,title,link,published_date,summary,fetched_at
    """
    items: List[Dict[str, Any]] = []
    try:
        root = ET.fromstring(xml_bytes)
    except Exception as e:
        raise RuntimeError(f"Invalid XML in feed: {e}")

    # namespace helpers
    def _find_text(elem: ET.Element, tags: List[str]) -> str:
        for t in tags:
            x = elem.find(t)
            if x is not None and x.text:
                return x.text.strip()
        return ""

    # RSS: channel/item
    channel = root.find("./channel")
    if channel is not None:
        for it in channel.findall("./item"):
            title = _find_text(it, ["title"])
            link = _find_text(it, ["link"])
            guid = _find_text(it, ["guid"]) or link or title
            pub = _find_text(it, ["pubDate", "date"])
            desc = _find_text(it, ["description"])
            items.append(
                {
                    "source": source_id,
                    "guid": guid,
                    "title": title or "item",
                    "link": link,
                    "published_date": pub,
                    "summary": desc,
                    "fetched_at": fetched_at,
                }
            )
        return items

    # Atom: entry
    # Atom feeds often use default namespace; handle generically by searching tag suffix
    for entry in root.findall(".//{*}entry"):
        title = ""
        link = ""
        guid = ""
        pub = ""
        summary = ""

        for child in list(entry):
            tag = child.tag.split("}")[-1]
            if tag == "title" and child.text:
                title = child.text.strip()
            elif tag in ("id",) and child.text:
                guid = child.text.strip()
            elif tag in ("updated", "published") and child.text:
                if not pub:
                    pub = child.text.strip()
            elif tag in ("summary", "content") and child.text:
                if not summary:
                    summary = child.text.strip()
            elif tag == "link":
                href = child.attrib.get("href")
                rel = child.attrib.get("rel", "alternate")
                if href and (not link) and rel in ("alternate", ""):
                    link = href.strip()

        if not guid:
            guid = link or title
        items.append(
            {
                "source": source_id,
                "guid": guid,
                "title": title or "entry",
                "link": link,
                "published_date": pub,
                "summary": summary,
                "fetched_at": fetched_at,
            }
        )

    return items


def discover(
    source_id: str,
    *,
    limit: int = 50,
    out_root: str = "outputs/discover",
    show_links: bool = False,
) -> Tuple[Path, Path, Path, Path]:
    if limit <= 0:
        raise ValueError("--limit must be > 0")

    cfg = load_sources_config()
    src = cfg.get(source_id)
    if not src.enabled:
        raise ValueError(f"Source '{source_id}' is disabled (enabled=false)")

    out_dir = Path(out_root) / source_id
    out_dir.mkdir(parents=True, exist_ok=True)

    started_at = utc_now_iso()
    fetched_at = utc_now_iso()

    meta = {
        "source_id": source_id,
        "source_name": src.name,
        "scope": src.scope,
        "page_type": src.page_type,
        "entry_url": src.entry_url,
        "started_at": started_at,
        "fetched_at": fetched_at,
        "finished_at": None,
        "limit": limit,
        "counts": {},
        "outputs": {},
        "errors": [],
    }

    raw_ext = "bin"
    raw_bytes = b""
    items = []

    raw_path = None
    feed_path = None
    new_path = None
    state_path = None
    items_jsonl_path = None
    new_items_jsonl_path = None

    try:
        if src.page_type == "rss_atom":
            raw_ext = "xml"
            raw_bytes = _http_get_bytes(src.entry_url, timeout_s=src.timeout_s, retries=src.retries)
            items = _parse_rss_atom(raw_bytes, source_id=source_id, fetched_at=fetched_at)

        elif src.page_type == "json_feed":
            raw_ext = "json"
            raw_bytes = _http_get_bytes(src.entry_url, timeout_s=src.timeout_s, retries=src.retries)
            text = raw_bytes.decode("utf-8", errors="replace")
            obj = json.loads(text)
            items = parse_json_feed(obj, source_id=source_id, fetched_at=fetched_at)

        elif src.page_type == "csv_feed":
            raw_ext = "csv"
            raw_bytes = _http_get_bytes(src.entry_url, timeout_s=src.timeout_s, retries=src.retries)
            text = raw_bytes.decode("utf-8", errors="replace")
            items = parse_csv_feed(text, source_id=source_id, fetched_at=fetched_at)

        else:
            raise ValueError(f"Unsupported page_type implemented in v1.1: {src.page_type}")

        parsed_count = len(items)

        # Enforce limit early (pre-filter still writes raw feed)
        items = items[:limit]
        limited_count = len(items)

        # Apply cheap filters
        filtered = []
        for it in items:
            if _apply_filters(it, src=src):
                filtered.append(it)
        items = filtered[:limit]
        filtered_count = len(items)

        # Ensure stable signal_id (later correlation/dedup)
        for it in items:
            _ensure_signal_id(it, source_id=source_id)

        # Load / update state for new-items detection
        state_path = out_dir / "state.json"
        state = {"source": source_id, "seen": {}}
        if state_path.exists():
            try:
                state = json.loads(state_path.read_text(encoding="utf-8"))
            except Exception:
                state = {"source": source_id, "seen": {}}

        seen = state.get("seen", {}) if isinstance(state.get("seen", {}), dict) else {}
        new_items = []
        for it in items:
            guid = _text(it.get("guid"))
            if not guid:
                continue
            if guid not in seen:
                new_items.append(it)
            seen[guid] = fetched_at
        state["seen"] = seen

        # Existing JSON artifacts
        raw_path = out_dir / f"raw_feed.{raw_ext}"
        raw_path.write_bytes(raw_bytes)

        feed_path = out_dir / "feed.json"
        new_path = out_dir / "new_items.json"

        feed_obj = {"source": source_id, "fetched_at": fetched_at, "items": items}
        new_obj = {"source": source_id, "fetched_at": fetched_at, "items": new_items}

        feed_path.write_text(json.dumps(feed_obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        new_path.write_text(json.dumps(new_obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        state_path.write_text(json.dumps(state, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

        # New JSONL artifacts (stable for diffs + pipelines)
        items_jsonl_path = out_dir / "items.jsonl"
        new_items_jsonl_path = out_dir / "new_items.jsonl"
        _write_jsonl(items_jsonl_path, items)
        _write_jsonl(new_items_jsonl_path, new_items)

        meta["counts"] = {
            "parsed": parsed_count,
            "limited": limited_count,
            "filtered": filtered_count,
            "new": len(new_items),
        }
        meta["outputs"] = {
            "raw_feed": str(raw_path),
            "feed_json": str(feed_path),
            "new_items_json": str(new_path),
            "state_json": str(state_path),
            "items_jsonl": str(items_jsonl_path),
            "new_items_jsonl": str(new_items_jsonl_path),
            "meta_json": str(out_dir / "meta.json"),
        }

        print("Done.")
        print(f"  Source: {source_id}")
        print(f"  URL:    {src.entry_url}")
        print(f"  Items:  {len(items)}")
        print(f"  New:    {len(new_items)}")
        print(f"  Wrote:  {out_dir}")
        print(f"  Raw:    {raw_path}")
        print(f"  JSONL:  {items_jsonl_path}")
        print(f"  Meta:   {out_dir / 'meta.json'}")

        if show_links and new_items:
            print("")
            print("New links:")
            for it in new_items[: min(50, len(new_items))]:
                link = _text(it.get("link"))
                if link:
                    print(f" - {link}")

        return raw_path, feed_path, new_path, state_path

    except Exception as e:
        meta["errors"].append({"type": type(e).__name__, "message": str(e)})
        raise

    finally:
        meta["finished_at"] = utc_now_iso()
        # Always write meta.json for diagnosability (even on errors).
        try:
            meta_path = out_dir / "meta.json"
            meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        except Exception:
            pass
