"""CISA Vulnrichment enrichment — per-CVE enrichment from cisagov/vulnrichment.

Fetches CISA-enriched CVE records from the GitHub-hosted vulnrichment repo.
Each CVE file contains ADP (Authorized Data Publisher) enrichment with:
  - CISA CVSS scores (may differ from NVD)
  - SSVC decision points (Exploitation, Automatable, Technical Impact)
  - Additional CWE mappings
  - KEV cross-references

Per-CVE on-demand fetch with local cache:
  https://raw.githubusercontent.com/cisagov/vulnrichment/develop/{year}/{Nxxx}/CVE-{id}.json

Cache: outputs/vulnrichment_cache/CVE-YYYY-NNNN.json
"""
from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

_RAW_BASE = "https://raw.githubusercontent.com/cisagov/vulnrichment/develop"
_DEFAULT_CACHE_DIR = Path("outputs/vulnrichment_cache")
_USER_AGENT = "AdvisoryOps/1.0 (security advisory aggregator; CISA Vulnrichment)"
_TIMEOUT = 15
_CVE_RE = re.compile(r"CVE-(\d{4})-(\d+)")


def _cve_to_path(cve_id: str) -> Optional[str]:
    """Convert CVE-YYYY-NNNN to the vulnrichment repo path: YYYY/NNNNxxx/CVE-YYYY-NNNN.json."""
    m = _CVE_RE.match(cve_id)
    if not m:
        return None
    year = m.group(1)
    num = int(m.group(2))
    # Bucket: 0xxx, 1xxx, 2xxx, ... based on thousands digit
    bucket = f"{num // 1000}xxx"
    return f"{year}/{bucket}/{cve_id}.json"


def _http_get(
    url: str,
    *,
    timeout: int = _TIMEOUT,
    _fetch_fn: Optional[Callable[[str], bytes]] = None,
) -> bytes:
    if _fetch_fn is not None:
        return _fetch_fn(url)
    headers = {"User-Agent": _USER_AGENT}
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def fetch_cve(
    cve_id: str,
    *,
    cache_dir: Optional[Path] = None,
    _fetch_fn: Optional[Callable[[str], bytes]] = None,
) -> Optional[Dict[str, Any]]:
    """Fetch CISA vulnrichment data for a single CVE. Returns parsed JSON or None."""
    if cache_dir is None:
        cache_dir = _DEFAULT_CACHE_DIR

    # Check cache first
    cache_file = cache_dir / f"{cve_id}.json"
    if cache_file.exists():
        try:
            return json.loads(cache_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass

    # Fetch from GitHub
    path = _cve_to_path(cve_id)
    if not path:
        return None

    url = f"{_RAW_BASE}/{path}"
    try:
        raw = _http_get(url, _fetch_fn=_fetch_fn)
        data = json.loads(raw.decode("utf-8"))

        # Cache it
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file.write_text(
            json.dumps(data, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

        return data
    except (urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError) as exc:
        logger.debug("Vulnrichment not available for %s: %s", cve_id, exc)
        return None
    except Exception as exc:
        logger.debug("Vulnrichment fetch error for %s: %s", cve_id, exc)
        return None


def extract_adp_fields(cve_record: Dict[str, Any]) -> Dict[str, Any]:
    """Extract CISA ADP enrichment fields from a vulnrichment CVE record.

    Returns dict with: cisa_cvss_score, cisa_cvss_severity, ssvc_exploitation,
    ssvc_automatable, ssvc_technical_impact, additional_cwe_ids.
    """
    result: Dict[str, Any] = {}

    containers = cve_record.get("containers") or {}
    adp_list = containers.get("adp") or []
    if isinstance(adp_list, dict):
        adp_list = [adp_list]

    for adp in adp_list:
        if not isinstance(adp, dict):
            continue

        # CVSS from ADP metrics
        metrics = adp.get("metrics") or []
        for metric in metrics:
            if not isinstance(metric, dict):
                continue
            for key in ("cvssV3_1", "cvssV3_0", "cvssV31"):
                cvss = metric.get(key) or {}
                if cvss.get("baseScore"):
                    result["cisa_cvss_score"] = float(cvss["baseScore"])
                    result["cisa_cvss_severity"] = cvss.get("baseSeverity", "")
                    break

            # SSVC
            other = metric.get("other") or {}
            content = other.get("content") or {}
            if isinstance(content, dict):
                options = content.get("options") or []
                for opt in options:
                    if isinstance(opt, dict):
                        if "Exploitation" in opt:
                            result["ssvc_exploitation"] = opt["Exploitation"]
                        if "Automatable" in opt:
                            result["ssvc_automatable"] = opt["Automatable"]
                        if "Technical Impact" in opt:
                            result["ssvc_technical_impact"] = opt["Technical Impact"]

        # Additional CWEs from ADP
        problem_types = adp.get("problemTypes") or []
        cwe_ids = []
        for pt in problem_types:
            for desc in pt.get("descriptions") or []:
                val = desc.get("cweId", "")
                if val.startswith("CWE-"):
                    cwe_ids.append(val)
        if cwe_ids:
            result["cisa_cwe_ids"] = sorted(set(cwe_ids))

    return result


def enrich_issue(
    issue: Dict[str, Any],
    *,
    cache_dir: Optional[Path] = None,
    _fetch_fn: Optional[Callable[[str], bytes]] = None,
) -> bool:
    """Enrich a single issue with CISA vulnrichment data. Returns True if enriched."""
    cves = issue.get("cves") or []
    issue_id = issue.get("issue_id", "")

    candidates = []
    if issue_id and issue_id.startswith("CVE-"):
        candidates.append(issue_id)
    candidates.extend(c for c in cves if c != issue_id)

    for cve_id in candidates:
        record = fetch_cve(cve_id, cache_dir=cache_dir, _fetch_fn=_fetch_fn)
        if not record:
            continue

        fields = extract_adp_fields(record)
        if fields:
            issue.update(fields)
            return True

    return False
