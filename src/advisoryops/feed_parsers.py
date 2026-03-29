"""JSON and CSV feed normalizers for AdvisoryOps discovery.

Called by ``discover.py`` for non-RSS/Atom feed types.  Both parsers return the
same normalized signal shape used throughout the pipeline:

    source, guid, title, link, published_date, summary, fetched_at

Functions
---------
parse_json_feed(obj, *, source_id, fetched_at)
    Handles four JSON structures:
    - CISA KEV JSON ({"vulnerabilities": [...]})  — special-cased for cveID/dateAdded fields
    - openFDA device events/recalls ({"results": [...]})
    - Generic JSON Feed spec ({"items": [...]})
    - Root list ([...])

parse_csv_feed(csv_text, *, source_id, fetched_at)
    Handles two CSV structures:
    - CISA KEV CSV (cveID/dateAdded/shortDescription columns)
    - EPSS percentile exports (cve/epss/percentile columns)
    - Generic advisory CSVs (title/link/date/summary columns)
    Comment lines (starting with #) are stripped before parsing — required
    for abuse.ch and some SANS feeds.

Both parsers are pure functions: same input always produces the same output.
"""
from __future__ import annotations

import csv
import hashlib
import json
import re
from datetime import datetime, timezone
from html import unescape
from typing import Any, Dict, List, Optional


_html_script_style_re = re.compile(r"(?is)<(script|style).*?>.*?</\1>")
_html_tag_re = re.compile(r"(?s)<[^>]+>")
_html_ws_re = re.compile(r"[ \t\f\v]+")


def _strip_html(html: str) -> str:
    """Strip HTML tags from a string, returning plain text."""
    if not html or "<" not in html:
        return html
    text = _html_script_style_re.sub(" ", html)
    text = re.sub(r"(?is)<br\s*/?>", " ", text)
    text = re.sub(r"(?is)</(p|div|li|h[1-6])\s*>", " ", text)
    text = _html_tag_re.sub(" ", text)
    text = unescape(text)
    lines = []
    for line in text.splitlines():
        line = _html_ws_re.sub(" ", line).strip()
        if line:
            lines.append(line)
    return " ".join(lines).strip()


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

    # NVD CVE API 2.0: {"format": "NVD_CVE", "vulnerabilities": [{"cve": {"id": ...}}]}
    if (isinstance(obj, dict) and obj.get("format") == "NVD_CVE"
            and isinstance(obj.get("vulnerabilities"), list)):
        for row in obj["vulnerabilities"]:
            if not isinstance(row, dict):
                continue
            cve_obj = row.get("cve") or {}
            if not isinstance(cve_obj, dict):
                continue
            cve_id = str(cve_obj.get("id", "") or "").strip()
            published = str(cve_obj.get("published", "") or cve_obj.get("lastModified", "") or "").strip()
            descs = cve_obj.get("descriptions") or []
            summary = ""
            for d in descs:
                if isinstance(d, dict) and d.get("lang") == "en":
                    summary = str(d.get("value", "") or "").strip()
                    break
            refs = cve_obj.get("references") or []
            link = _nvd_link(cve_id) if cve_id else ""
            for r in refs:
                if isinstance(r, dict) and r.get("url"):
                    link = r["url"]
                    break
            items.append({
                "source": source_id,
                "guid": cve_id or _sha1(json.dumps(row, sort_keys=True)),
                "title": cve_id or "NVD CVE",
                "link": link,
                "published_date": published,
                "summary": summary,
                "fetched_at": fetched_at,
            })
        return items

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

            item: Dict[str, Any] = {
                    "source": source_id,
                    "guid": guid,
                    "title": title,
                    "link": _nvd_link(cve) if cve else "",
                    "published_date": published,
                    "summary": summary,
                    "fetched_at": fetched_at,
                }
            # Preserve KEV-specific fields for downstream enrichment
            required_action = str(row.get("requiredAction", "") or "").strip()
            due_date = str(row.get("dueDate", "") or "").strip()
            vuln_name = str(row.get("vulnerabilityName", "") or "").strip()
            if required_action:
                item["kev_required_action"] = required_action
            if due_date:
                item["kev_due_date"] = due_date
            if vendor:
                item["kev_vendor"] = vendor
            if product:
                item["kev_product"] = product
            if vuln_name:
                item["kev_vulnerability_name"] = vuln_name
            items.append(item)
        return items

    # VulDB CTI API: {"response": {..., "status": "200"}, "result": [{"entry": {...}}]}
    if (isinstance(obj, dict) and isinstance(obj.get("response"), dict)
            and isinstance(obj.get("result"), list)):
        status = str(obj["response"].get("status", ""))
        if status != "200":
            # Auth failure or API error — return empty rather than crashing
            return items
        for row in obj["result"]:
            if not isinstance(row, dict):
                continue
            entry = row.get("entry") or row
            if not isinstance(entry, dict):
                continue
            entry_id = str(entry.get("id", "") or row.get("id", "") or "").strip()
            title = str(entry.get("title", "") or entry_id or "VulDB entry").strip()
            summary = str(entry.get("summary", "") or entry.get("description", "") or "").strip()
            cve_block = entry.get("cve") or {}
            cve_id = str(cve_block.get("cve_id", "") or "").strip() if isinstance(cve_block, dict) else ""
            published = str(entry.get("timestamp", "") or entry.get("date", "") or "").strip()
            link = str(entry.get("href", "") or entry.get("url", "") or "").strip()
            if not link and cve_id:
                link = _nvd_link(cve_id)
            guid = entry_id or cve_id or _sha1(json.dumps(row, sort_keys=True))
            items.append({
                "source": source_id,
                "guid": guid,
                "title": title,
                "link": link,
                "published_date": published,
                "summary": summary,
                "fetched_at": fetched_at,
            })
        return items

    # Generic JSON feed shapes
    if isinstance(obj, dict) and isinstance(obj.get("results"), list):
        raw_list = obj["results"]
    elif isinstance(obj, dict) and isinstance(obj.get("items"), list):
        raw_list = obj["items"]
    elif isinstance(obj, dict) and isinstance(obj.get("data"), list):
        raw_list = obj["data"]
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
        summary = _strip_html(_pick_str(
            row,
            "summary",
            "description",
            "reason_for_recall",
            "product_description",
            "event_text",
            "event_type",
        ))

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
    # Strip comment lines (lines starting with '#') — used by abuse.ch, SANS, etc.
    clean_lines = [l for l in csv_text.splitlines() if not l.lstrip().startswith("#")]
    reader = csv.DictReader(clean_lines)
    for row in reader:
        if not isinstance(row, dict):
            continue
        # Skip rows where all values are None (malformed comment lines absorbed by DictReader)
        if all(v is None for v in row.values()):
            continue

        # CISA KEV CSV uses cveID/dateAdded/shortDescription/vendorProject/product/...
        cve = str(row.get("cveID", "") or row.get("cve", "") or row.get("CVE", "") or "").strip()
        if cve:
            title = cve
            guid = cve
            link = _nvd_link(cve)
            published = str(row.get("dateAdded", "") or row.get("published_date", "") or row.get("date", "") or "").strip()
            summary = _strip_html(str(row.get("shortDescription", "") or row.get("summary", "") or row.get("description", "") or "").strip())
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
            summary = _strip_html(str(row.get("summary", "") or row.get("description", "") or "").strip())

        item_csv: Dict[str, Any] = {
                "source": source_id,
                "guid": guid,
                "title": title,
                "link": link,
                "published_date": published,
                "summary": summary,
                "fetched_at": fetched_at,
            }
        # Preserve KEV-specific fields for downstream enrichment (CSV variant)
        if cve:
            required_action = str(row.get("requiredAction", "") or "").strip()
            due_date = str(row.get("dueDate", "") or "").strip()
            if required_action:
                item_csv["kev_required_action"] = required_action
            if due_date:
                item_csv["kev_due_date"] = due_date
            if vendor:
                item_csv["kev_vendor"] = vendor
            if product:
                item_csv["kev_product"] = product
        items.append(item_csv)

    return items
