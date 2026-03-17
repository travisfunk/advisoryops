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


def _openfda_device_recall_link(row: Dict[str, Any]) -> str:
    """Build a stable per-record openFDA query URL when no direct record URL exists."""
    searches = [
        ("res_event_number", _pick_str(row, "res_event_number")),
        ("event_id", _pick_str(row, "event_id")),
        ("cfres_id", _pick_str(row, "cfres_id")),
        ("recall_number", _pick_str(row, "recall_number")),
    ]
    for field, value in searches:
        if value:
            return f'https://api.fda.gov/device/recall.json?search={field}:"{value}"'
    return ""


def _pick_str(row: Dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = row.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def parse_json_feed(obj: Any, *, source_id: str, fetched_at: str) -> List[Dict[str, Any]]:
    """
    Normalize JSON feed into items with keys:
      source, guid, title, link, published_date, summary, fetched_at

    Supports:
      - CISA KEV JSON shape: { "vulnerabilities": [ ... ] }
      - openFDA-like shape: { "results": [ ... ] }
      - generic feed shape: { "items": [ ... ] }
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
    if isinstance(obj, dict) and isinstance(obj.get("results"), list):
        raw_list = obj["results"]
    elif isinstance(obj, dict) and isinstance(obj.get("items"), list):
        raw_list = obj["items"]
    elif isinstance(obj, list):
        raw_list = obj
    else:
        raw_list = []

    for row in raw_list:
        if not isinstance(row, dict):
            continue

        cve = _pick_str(row, "cve", "CVE", "cveID")
        title = _pick_str(
            row,
            "title",
            "name",
            "event_id",
            "recall_number",
            "report_number",
            "mdr_report_key",
            "id",
        ) or (cve or "item")
        link = _pick_str(row, "link", "url")
        if not link and source_id.startswith("openfda-device-recalls"):
            link = _openfda_device_recall_link(row)
        guid = _pick_str(row, "guid", "id", "event_id", "recall_number", "report_number", "mdr_report_key")
        if not guid:
            guid = cve or link or _sha1(json.dumps(row, sort_keys=True))
        published = _pick_str(
            row,
            "published_date",
            "pubDate",
            "date",
            "report_date",
            "event_date",
            "recall_initiation_date",
            "date_created",
        )
        summary = _pick_str(
            row,
            "summary",
            "description",
            "reason_for_recall",
            "product_description",
            "event_text",
            "event_type",
        )

        firm = _pick_str(row, "recalling_firm", "manufacturer_d_name", "manufacturer_name")
        product = _pick_str(row, "product_description", "brand_name", "device_name", "generic_name")
        if firm or product:
            extra = " | ".join([part for part in [firm, product] if part])
            if extra and extra not in summary:
                summary = (summary + " | " if summary else "") + extra

        if not link and cve:
            link = _nvd_link(cve)

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

    Special-cases:
      - CISA KEV CSV columns
      - generic CVE-centric CSVs (for example EPSS-style exports)
    """
    items: List[Dict[str, Any]] = []
    reader = csv.DictReader(csv_text.splitlines())
    for row in reader:
        if not isinstance(row, dict):
            continue

        # CISA KEV CSV uses cveID/dateAdded/shortDescription/vendorProject/product/...
        cve = str(row.get("cveID", "") or row.get("cve", "") or row.get("CVE", "") or "").strip()
        if cve:
            title = cve
            guid = cve
            link = _nvd_link(cve)
            published = str(row.get("dateAdded", "") or row.get("published_date", "") or row.get("date", "") or "").strip()
            summary = str(row.get("shortDescription", "") or row.get("summary", "") or row.get("description", "") or "").strip()
            vendor = str(row.get("vendorProject", "") or row.get("vendor", "") or "").strip()
            product = str(row.get("product", "") or row.get("product_name", "") or "").strip()
            epss = str(row.get("epss", "") or "").strip()
            percentile = str(row.get("percentile", "") or "").strip()
            extras = []
            if vendor or product:
                extras.append(f"{vendor} {product}".strip())
            if epss:
                extras.append(f"EPSS={epss}")
            if percentile:
                extras.append(f"percentile={percentile}")
            if extras:
                summary = (summary + " | " if summary else "") + " | ".join(extras)
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
