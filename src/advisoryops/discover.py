from __future__ import annotations

import hashlib
import json
import re
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import xml.etree.ElementTree as ET

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .sources_config import load_sources_config


DEFAULT_UA = "AdvisoryOpsRSS/0.1.0 (+https://github.com/travisfunk/advisoryops)"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_text(text: str) -> str:
    h = hashlib.sha256()
    h.update(text.encode("utf-8", errors="ignore"))
    return h.hexdigest()


def _strip_ns(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _child(parent: ET.Element, name: str) -> Optional[ET.Element]:
    for c in list(parent):
        if _strip_ns(c.tag) == name:
            return c
    return None


def _children(parent: ET.Element, name: str) -> List[ET.Element]:
    out: List[ET.Element] = []
    for c in list(parent):
        if _strip_ns(c.tag) == name:
            out.append(c)
    return out


def _text(el: Optional[ET.Element]) -> str:
    if el is None:
        return ""
    return (el.text or "").strip()


def _parse_date(raw: str) -> Optional[datetime]:
    if not raw:
        return None
    raw = raw.strip()
    # RSS pubDate often parses via email.utils
    try:
        dt = parsedate_to_datetime(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        pass
    # Atom is often ISO-ish
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _pick_atom_link(entry: ET.Element) -> str:
    # Atom: <link href="..." rel="alternate" />
    links = _children(entry, "link")
    if not links:
        return ""
    # Prefer rel=alternate or missing
    for l in links:
        rel = (l.attrib.get("rel") or "").strip().lower()
        href = (l.attrib.get("href") or "").strip()
        if not href:
            continue
        if rel in ("", "alternate"):
            return href
    # Fallback first href
    for l in links:
        href = (l.attrib.get("href") or "").strip()
        if href:
            return href
    return ""


def _parse_rss_items(root: ET.Element) -> List[Dict[str, str]]:
    channel = _child(root, "channel")
    if channel is None:
        return []
    items = _children(channel, "item")
    out: List[Dict[str, str]] = []
    for it in items:
        title = _text(_child(it, "title"))
        link = _text(_child(it, "link"))
        desc = _text(_child(it, "description")) or _text(_child(it, "summary"))
        guid = _text(_child(it, "guid"))
        pub = _text(_child(it, "pubDate"))
        out.append({"title": title, "link": link, "summary": desc, "guid": guid, "published_raw": pub})
    return out


def _parse_atom_entries(root: ET.Element) -> List[Dict[str, str]]:
    entries = _children(root, "entry")
    out: List[Dict[str, str]] = []
    for e in entries:
        title = _text(_child(e, "title"))
        link = _pick_atom_link(e)
        desc = _text(_child(e, "summary")) or _text(_child(e, "content"))
        guid = _text(_child(e, "id"))
        pub = _text(_child(e, "published")) or _text(_child(e, "updated"))
        out.append({"title": title, "link": link, "summary": desc, "guid": guid, "published_raw": pub})
    return out


def _load_seen(state_path: Path) -> set[str]:
    if not state_path.exists():
        return set()
    try:
        obj = json.loads(state_path.read_text(encoding="utf8"))
        seen = obj.get("seen", [])
        return set(str(x) for x in seen)
    except Exception:
        return set()


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf8")


def _build_session(retries: int) -> requests.Session:
    retry = Retry(
        total=retries,
        connect=retries,
        read=retries,
        status=retries,
        backoff_factor=0.75,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "HEAD"]),
        raise_on_status=False,
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
    s = requests.Session()
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    s.headers.update({"User-Agent": DEFAULT_UA, "Accept": "application/rss+xml, application/atom+xml, application/xml;q=0.9, */*;q=0.8"})
    return s


def _passes_filters(title: str, summary: str, link: str, filters: Dict[str, Any]) -> bool:
    if not filters:
        return True

    apply_to = filters.get("apply_to") or ["title", "summary", "description"]
    parts: List[str] = []
    if "title" in apply_to:
        parts.append(title or "")
    if "summary" in apply_to or "description" in apply_to:
        parts.append(summary or "")
    blob = "\n".join(parts).lower()

    kws_any = filters.get("keywords_any") or []
    if kws_any:
        if not any(str(k).lower() in blob for k in kws_any):
            return False

    kws_all = filters.get("keywords_all") or []
    if kws_all:
        if not all(str(k).lower() in blob for k in kws_all):
            return False

    allow_pat = filters.get("url_allow_regex")
    if allow_pat:
        if not re.search(allow_pat, link or ""):
            return False

    deny_pat = filters.get("url_deny_regex")
    if deny_pat:
        if re.search(deny_pat, link or ""):
            return False

    return True


def discover(
    source: str,
    *,
    limit: int = 50,
    out_root: str = "outputs/discover",
    show_links: bool = False,
) -> Tuple[Path, Path, Path, Path]:
    cfg = load_sources_config()
    try:
        src = cfg.get(source)
    except KeyError:
        known = ", ".join([s.source_id for s in cfg.sources])
        raise ValueError(f"Unknown source: {source}. Known sources in configs/sources.json: {known}")

    if not src.enabled:
        raise ValueError(f"Source '{source}' is disabled in configs/sources.json (enabled=false).")

    if src.page_type != "rss_atom":
        raise NotImplementedError(f"discover currently supports page_type='rss_atom' only. Source '{source}' has page_type='{src.page_type}'")

    url = src.entry_url

    out_dir = Path(out_root) / source
    out_dir.mkdir(parents=True, exist_ok=True)
    raw_path = out_dir / "raw_feed.xml"
    feed_path = out_dir / "feed.json"
    new_path = out_dir / "new_items.json"
    state_path = out_dir / "state.json"

    seen = _load_seen(state_path)

    session = _build_session(retries=src.retries)
    t0 = time.monotonic()
    resp = session.get(url, timeout=(10, src.timeout_s), allow_redirects=True)
    elapsed_ms = int((time.monotonic() - t0) * 1000)

    resp.raise_for_status()
    xml_text = resp.text or ""
    if not xml_text.strip():
        raise RuntimeError(f"Empty response from {url}")

    raw_path.write_text(xml_text + "\n", encoding="utf8")

    try:
        root = ET.fromstring(xml_text)
    except Exception as e:
        snippet = xml_text[:300]
        raise RuntimeError(f"Response was not valid XML. First 300 chars:\n{snippet}") from e

    root_name = _strip_ns(root.tag).lower()
    items_raw: List[Dict[str, str]]
    if root_name == "rss":
        items_raw = _parse_rss_items(root)
    elif root_name == "feed":
        items_raw = _parse_atom_entries(root)
    else:
        # Some feeds may wrap; try to locate rss/feed below
        rss = None
        feed = None
        for el in root.iter():
            n = _strip_ns(el.tag).lower()
            if n == "rss":
                rss = el
                break
            if n == "feed":
                feed = el
                break
        if rss is not None:
            items_raw = _parse_rss_items(rss)
        elif feed is not None:
            items_raw = _parse_atom_entries(feed)
        else:
            raise RuntimeError(f"Unexpected feed root element: <{root_name}>. See {raw_path}")

    # Sort newest-first before applying limit (important: some feeds are oldest-first)
    def sort_key(x: Dict[str, str]) -> datetime:
        dt = _parse_date(x.get("published_raw", ""))
        return dt or datetime(1970, 1, 1, tzinfo=timezone.utc)

    items_raw = sorted(items_raw, key=sort_key, reverse=True)
    if limit > 0:
        items_raw = items_raw[:limit]

    all_items: List[Dict[str, Any]] = []
    new_items: List[Dict[str, Any]] = []

    for it in items_raw:
        title = (it.get("title", "") or "").strip()
        link = (it.get("link", "") or "").strip()
        summary = (it.get("summary", "") or "").strip()
        guid = (it.get("guid", "") or "").strip()
        pub_raw = (it.get("published_raw", "") or "").strip()

        dt = _parse_date(pub_raw)
        published_date = dt.date().isoformat() if dt else ""

        if not guid:
            guid = link
        if not guid:
            guid = "sha256:" + sha256_text(f"{title}|{summary}")

        if not _passes_filters(title=title, summary=summary, link=link, filters=src.filters):
            continue

        obj = {
            "source": source,
            "guid": guid,
            "title": title,
            "link": link,
            "published_date": published_date,
            "summary": summary,
            "fetched_at": utc_now_iso(),
        }

        all_items.append(obj)
        if guid not in seen:
            new_items.append(obj)
            seen.add(guid)

    feed_out = {
        "source": source,
        "url": url,
        "http_elapsed_ms": elapsed_ms,
        "fetched_at": utc_now_iso(),
        "count": len(all_items),
        "items": all_items,
    }
    new_out = {
        "source": source,
        "url": url,
        "http_elapsed_ms": elapsed_ms,
        "fetched_at": utc_now_iso(),
        "count": len(new_items),
        "items": new_items,
    }
    state_out = {"source": source, "seen": sorted(list(seen))}

    _write_json(feed_path, feed_out)
    _write_json(new_path, new_out)
    _write_json(state_path, state_out)

    print("Done.")
    print(f"  Source: {source}")
    print(f"  URL:    {url}")
    print(f"  Items:  {len(all_items)}")
    print(f"  New:    {len(new_items)}")
    print(f"  Wrote:  {out_dir}")
    print(f"  Raw:    {raw_path}")
    if show_links and new_items:
        print("\nNew links:")
        for row in new_items[:15]:
            print(" - " + (row.get("link") or ""))
        if len(new_items) > 15:
            print(f" ... ({len(new_items) - 15} more)")

    return raw_path, feed_path, new_path, state_path