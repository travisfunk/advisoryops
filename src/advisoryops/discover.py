from __future__ import annotations
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import requests
import xml.etree.ElementTree as ET
SOURCES: Dict[str, str] = {
    "cisa-icsma": "https://www.cisa.gov/cybersecurity-advisories/ics-medical-advisories.xml",
    "cisa-icsa": "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml",
    "fda-medwatch": "https://www.fda.gov/about-fda/contact-fda/stay-informed/rss-feeds/medwatch/rss.xml",
}
FDA_KEYWORDS = [
    "cyber", "cybersecurity", "vulnerability", "vulnerabilities", "cve",
    "ransomware", "exploit", "unauthorized", "malware", "remote",
]
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
def _keyword_hit(text: str) -> bool:
    t = (text or "").lower()
    return any(k in t for k in FDA_KEYWORDS)
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
        out.append({"title": title, "link": link, "description": desc, "guid": guid, "published_raw": pub})
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
        out.append({"title": title, "link": link, "description": desc, "guid": guid, "published_raw": pub})
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
def discover(
    source: str,
    *,
    limit: int = 50,
    out_root: str = "outputs/discover",
    show_links: bool = False,
    timeout_s: int = 30,
) -> Tuple[Path, Path, Path, Path]:
    if source not in SOURCES:
        raise ValueError(f"Unknown source: {source}. Expected one of: {', '.join(SOURCES.keys())}")
    url = SOURCES[source]
    out_dir = Path(out_root) / source
    out_dir.mkdir(parents=True, exist_ok=True)
    raw_path = out_dir / "raw_feed.xml"
    feed_path = out_dir / "feed.json"
    new_path = out_dir / "new_items.json"
    state_path = out_dir / "state.json"
    seen = _load_seen(state_path)
    headers = {"User-Agent": "AdvisoryOpsRSS/0.1.0 (+https://github.com/travisfunk/advisoryops)"}
    resp = requests.get(url, headers=headers, timeout=timeout_s)
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
        title = it.get("title", "").strip()
        link = it.get("link", "").strip()
        desc = it.get("description", "").strip()
        guid = it.get("guid", "").strip()
        pub_raw = it.get("published_raw", "").strip()
        if not guid:
            guid = link
        if not guid:
            guid = "sha256:" + sha256_text(f"{title}|{desc}")
        # FDA feed is broad -> filter to cyber-ish entries
        if source == "fda-medwatch":
            blob = f"{title}\n{desc}\n{link}"
            if not _keyword_hit(blob):
                continue
        obj = {
            "source": source,
            "guid": guid,
            "title": title,
            "link": link,
            "published_raw": pub_raw,
            "description": desc,
            "fetched_utc": utc_now_iso(),
        }
        all_items.append(obj)
        if guid not in seen:
            new_items.append(obj)
            seen.add(guid)
    feed_out = {
        "source": source,
        "url": url,
        "fetched_utc": utc_now_iso(),
        "count": len(all_items),
        "items": all_items,
    }
    new_out = {
        "source": source,
        "url": url,
        "fetched_utc": utc_now_iso(),
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
