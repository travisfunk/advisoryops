"""FDA device risk classification extraction and lookup.

Extracts FDA risk class (1, 2, or 3) from cached openFDA recall records
and provides a fallback lookup via the openFDA device classification
database.

Data sources:
  - Primary: outputs/openfda_cache/recall_*.json (device_class field)
  - Secondary: openFDA Device Classification API, cached locally at
    outputs/fda_classification_cache/classifications.json
"""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional

import httpx

logger = logging.getLogger(__name__)

_VALID_CLASSES = frozenset({"1", "2", "3"})

# 90 days in seconds for cache staleness check
_CACHE_MAX_AGE_SECONDS = 90 * 24 * 60 * 60

_DEFAULT_CACHE_DIR = Path("outputs/fda_classification_cache")
_CLASSIFICATION_API = "https://api.fda.gov/device/classification.json"
_PAGE_SIZE = 1000


def extract_risk_class_from_recall(recall: dict) -> str | None:
    """Extract FDA risk class from a cached recall record.

    Returns '1', '2', or '3' for valid classes, None for missing or invalid.
    Handles both top-level and openfda-nested device_class fields.
    Rejects 'N', 'U', and other non-standard values.
    """
    raw = recall.get("device_class")
    if raw is None:
        raw = recall.get("openfda", {}).get("device_class")

    if raw is None:
        return None

    # If the value is a list, take the first element
    if isinstance(raw, list):
        if not raw:
            return None
        raw = raw[0]

    # Coerce to string
    val = str(raw).strip()

    if val in _VALID_CLASSES:
        return val

    return None


def fetch_classification_database(
    cache_dir: Path | None = None,
    *,
    _fetch_fn: Callable | None = None,
) -> dict:
    """Fetch the full openFDA device classification database.

    Returns a dict indexed by product_code for fast lookup.
    Caches the result to outputs/fda_classification_cache/classifications.json.
    Refreshes automatically if cache is older than 90 days.
    """
    cache_dir = cache_dir or _DEFAULT_CACHE_DIR
    cache_file = cache_dir / "classifications.json"

    # Check existing cache
    if cache_file.exists():
        try:
            data = json.loads(cache_file.read_text(encoding="utf-8"))
            fetched_at = data.get("_fetched_at", "")
            if fetched_at:
                fetched_dt = datetime.fromisoformat(fetched_at)
                age = (datetime.now(timezone.utc) - fetched_dt).total_seconds()
                if age < _CACHE_MAX_AGE_SECONDS:
                    logger.info("Using cached classification database (%d entries).", len(data) - 1)
                    return data
                logger.info("Classification cache is %.1f days old, refreshing.", age / 86400)
        except Exception as exc:
            logger.warning("Failed to read classification cache: %s", exc)

    # Fetch from API
    classifications: Dict[str, Any] = {}
    skip = 0

    fetch = _fetch_fn or _default_fetch

    while True:
        try:
            url = f"{_CLASSIFICATION_API}?search=_exists_:product_code&limit={_PAGE_SIZE}&skip={skip}"
            result = fetch(url)
            if result is None:
                break

            results_list = result.get("results", [])
            if not results_list:
                break

            for rec in results_list:
                pc = rec.get("product_code", "").strip()
                if not pc:
                    continue
                # Keep first occurrence if duplicate product codes
                if pc not in classifications:
                    classifications[pc] = {
                        "device_class": rec.get("device_class", ""),
                        "device_name": rec.get("device_name", ""),
                        "definition": rec.get("definition", ""),
                        "medical_specialty": rec.get("medical_specialty_description", ""),
                        "regulation_number": rec.get("regulation_number", ""),
                        "product_code": pc,
                    }

            logger.info("Fetched %d classifications (skip=%d).", len(results_list), skip)

            total = result.get("meta", {}).get("results", {}).get("total", 0)
            skip += _PAGE_SIZE
            if skip >= total or skip >= 25000:
                break

            # Be polite to the API
            time.sleep(0.3)

        except Exception as exc:
            logger.warning("Classification fetch failed at skip=%d: %s", skip, exc)
            break

    if not classifications:
        logger.warning("No classifications fetched; returning empty database.")
        return {"_fetched_at": datetime.now(timezone.utc).isoformat()}

    classifications["_fetched_at"] = datetime.now(timezone.utc).isoformat()

    # Write cache
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file.write_text(
            json.dumps(classifications, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        logger.info("Cached %d classifications to %s.", len(classifications) - 1, cache_file)
    except Exception as exc:
        logger.warning("Failed to write classification cache: %s", exc)

    return classifications


def _default_fetch(url: str) -> dict | None:
    """Fetch a URL and return parsed JSON, or None on failure."""
    try:
        resp = httpx.get(url, timeout=30.0, follow_redirects=True)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.warning("HTTP fetch failed for %s: %s", url, exc)
        return None


def lookup_risk_class(
    product_code: str | None = None,
    device_name: str | None = None,
    classifications: dict | None = None,
) -> str | None:
    """Look up FDA risk class for a device.

    Lookup order:
    1. Exact product_code match (highest confidence)
    2. Case-insensitive substring match on device_name (medium confidence)
    3. Return None if no match
    """
    if classifications is None:
        return None

    # 1. Exact product_code match
    if product_code:
        pc = product_code.strip()
        rec = classifications.get(pc)
        if rec and isinstance(rec, dict):
            dc = str(rec.get("device_class", "")).strip()
            if dc in _VALID_CLASSES:
                return dc

    # 2. Case-insensitive substring match on device_name
    if device_name:
        name_lower = device_name.strip().lower()
        if len(name_lower) >= 4:  # Avoid matching very short strings
            for key, rec in classifications.items():
                if key.startswith("_"):
                    continue
                if not isinstance(rec, dict):
                    continue
                rec_name = (rec.get("device_name") or "").lower()
                if name_lower in rec_name or rec_name in name_lower:
                    dc = str(rec.get("device_class", "")).strip()
                    if dc in _VALID_CLASSES:
                        return dc

    return None
