from __future__ import annotations

import csv
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha1(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()


def _nvd_link(cve: str) -> str:
    cve = cve.strip()
    if not cve:
        return ""
    return f"https://nvd.nist.gov/vuln/detail/{cve}"


def parse_json_feed(obj: Any, *, source_id: str, fetched_at: str) -> List[Dict[str, Any]]:
    """
    Normalize JSON feed into items with keys:
      source, guid, title, link, published_date, summary, fetched_at
    Supports:
      - CISA KEV JSON shape: { "vulnerabilities": [ ... ] }
      - { "items": [ ... ] }
      - root list: [ ... ]
    """
    items: List[Dict[str, Any]] = []

    if isinstance(obj, dict) and isinstance(obj.get("vulnerabilities"), list):
        # CISA KEV JSON
        for row in obj["vulnerabilities"]:
            if not isinstance(row, dict):
                continue
            cve = str(row.get("cveID", "") or "").strip()
            title = cve or str(row.get("vulnerabilityName", "") or "").strip() or "KEV item"
            guid = cve or str(row.get("cveID", "") or "").strip() or _sha1(json.dumps(row, sort_keys=True))
            published = str(row.get("dateAdded", "") or "").strip()
            summary = str(row.get("shortDescription", "") or "").strip()
            vendor = str(row.get("vendorProject", "") or "").strip()
            product = str(row.get("product", "") or "").strip()
            if vendor or product:
                summary = (summary + " | " if summary else "") + f"{vendor} {product}".strip()

            items.append(
                {
                    "source": source_id,
                    "guid": guid,
                    "title": title,
                    "link": _nvd_link(cve) if cve else "",
                    "published_date": published,
                    "summary": summary,
                    "fetched_at": fetched_at,
                }
            )
        return items

    # Generic JSON feed shapes
    if isinstance(obj, dict) and isinstance(obj.get("items"), list):
        raw_list = obj["items"]
    elif isinstance(obj, list):
        raw_list = obj
    else:
        raw_list = []

    for row in raw_list:
        if not isinstance(row, dict):
            continue
        title = str(row.get("title", "") or row.get("name", "") or "").strip() or "item"
        link = str(row.get("link", "") or row.get("url", "") or "").strip()
        guid = str(row.get("guid", "") or row.get("id", "") or "").strip()
        if not guid:
            guid = link or _sha1(json.dumps(row, sort_keys=True))
        published = str(row.get("published_date", "") or row.get("pubDate", "") or row.get("date", "") or "").strip()
        summary = str(row.get("summary", "") or row.get("description", "") or "").strip()

        items.append(
            {
                "source": source_id,
                "guid": guid,
                "title": title,
                "link": link,
                "published_date": published,
                "summary": summary,
                "fetched_at": fetched_at,
            }
        )

    return items


def parse_csv_feed(csv_text: str, *, source_id: str, fetched_at: str) -> List[Dict[str, Any]]:
    """
    Normalize CSV feed into items with keys:
      source, guid, title, link, published_date, summary, fetched_at

    Special-cases CISA KEV CSV column set.
    """
    items: List[Dict[str, Any]] = []
    reader = csv.DictReader(csv_text.splitlines())
    for row in reader:
        if not isinstance(row, dict):
            continue

        # CISA KEV CSV uses cveID/dateAdded/shortDescription/vendorProject/product/...
        cve = str(row.get("cveID", "") or "").strip()
        if cve:
            title = cve
            guid = cve
            link = _nvd_link(cve)
            published = str(row.get("dateAdded", "") or "").strip()
            summary = str(row.get("shortDescription", "") or "").strip()
            vendor = str(row.get("vendorProject", "") or "").strip()
            product = str(row.get("product", "") or "").strip()
            if vendor or product:
                summary = (summary + " | " if summary else "") + f"{vendor} {product}".strip()
        else:
            title = str(row.get("title", "") or row.get("name", "") or "item").strip()
            link = str(row.get("link", "") or row.get("url", "") or "").strip()
            guid = str(row.get("guid", "") or row.get("id", "") or "").strip() or link or _sha1(json.dumps(row, sort_keys=True))
            published = str(row.get("published_date", "") or row.get("date", "") or "").strip()
            summary = str(row.get("summary", "") or row.get("description", "") or "").strip()

        items.append(
            {
                "source": source_id,
                "guid": guid,
                "title": title,
                "link": link,
                "published_date": published,
                "summary": summary,
                "fetched_at": fetched_at,
            }
        )

    return items