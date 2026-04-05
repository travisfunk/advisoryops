"""NVD enrichment — query NIST NVD 2.0 API for per-CVE structured data.

For each issue with CVEs, fetches:
  - nvd_description: English description text
  - cvss_score: base score (prefer v3.1, fall back to v2)
  - cvss_severity: LOW/MEDIUM/HIGH/CRITICAL
  - cvss_vector: the vector string
  - cwe_ids: list of CWE IDs
  - affected_products: human-readable vendor/product names from CPE data

Rate limiting:
  - Without NVD_API_KEY: 5 requests per 30 seconds
  - With NVD_API_KEY: 50 requests per 30 seconds

Caching:
  - Results cached to outputs/nvd_cache/<CVE-ID>.json
  - Cached CVEs are never re-fetched
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

_NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_DEFAULT_CACHE_DIR = Path("outputs/nvd_cache")
_USER_AGENT = "AdvisoryOps/1.0 (security advisory aggregator)"
_TIMEOUT = 30
_429_CONSECUTIVE_ABORT = 3  # Abort NVD fetching after this many consecutive 429s

# CVE pattern
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")

# Track whether the API key has been validated this session
_api_key_valid: Optional[bool] = None
_consecutive_429s = 0


class _RateLimiter:
    """Simple sliding-window rate limiter."""

    def __init__(self, max_requests: int, window_seconds: float):
        self._max = max_requests
        self._window = window_seconds
        self._timestamps: List[float] = []

    def downgrade(self, max_requests: int, window_seconds: float) -> None:
        """Reduce the rate limit (e.g., after API key invalidation)."""
        self._max = max_requests
        self._window = window_seconds

    def wait(self) -> None:
        now = time.monotonic()
        # Purge timestamps outside the window
        self._timestamps = [t for t in self._timestamps if now - t < self._window]
        if len(self._timestamps) >= self._max:
            sleep_time = self._window - (now - self._timestamps[0]) + 0.1
            if sleep_time > 0:
                logger.debug("Rate limit: sleeping %.1fs", sleep_time)
                time.sleep(sleep_time)
        self._timestamps.append(time.monotonic())


def _get_rate_limiter() -> _RateLimiter:
    """Return a rate limiter tuned to whether an API key is available."""
    if os.environ.get("NVD_API_KEY"):
        return _RateLimiter(max_requests=45, window_seconds=30)
    return _RateLimiter(max_requests=4, window_seconds=30)


def _parse_cpe_product(cpe_string: str) -> str:
    """Extract human-readable 'vendor product' from a CPE 2.3 URI.

    CPE format: cpe:2.3:part:vendor:product:version:...
    """
    parts = cpe_string.split(":")
    if len(parts) >= 5:
        vendor = parts[3].replace("_", " ").title()
        product = parts[4].replace("_", " ").title()
        if vendor == "*" or vendor == "-":
            return product
        if product == "*" or product == "-":
            return vendor
        return f"{vendor} {product}"
    return cpe_string


def _extract_nvd_fields(cve_item: Dict[str, Any]) -> Dict[str, Any]:
    """Extract structured fields from an NVD CVE 2.0 response item."""
    result: Dict[str, Any] = {}

    # Description — prefer English
    descriptions = cve_item.get("descriptions") or []
    for desc in descriptions:
        if desc.get("lang", "").startswith("en"):
            result["nvd_description"] = desc.get("value", "")
            break
    if "nvd_description" not in result and descriptions:
        result["nvd_description"] = descriptions[0].get("value", "")

    # CVSS — prefer v3.1, fall back to v3.0, then v2
    metrics = cve_item.get("metrics") or {}
    cvss_data = None

    for key in ("cvssMetricV31", "cvssMetricV30"):
        metric_list = metrics.get(key) or []
        if metric_list:
            cvss_data = metric_list[0].get("cvssData") or {}
            break

    if cvss_data is None:
        v2_list = metrics.get("cvssMetricV2") or []
        if v2_list:
            cvss_data = v2_list[0].get("cvssData") or {}

    if cvss_data:
        result["cvss_score"] = cvss_data.get("baseScore", 0)
        result["cvss_vector"] = cvss_data.get("vectorString", "")
        # Severity: v3 has baseSeverity in cvssData, v2 might not
        severity = cvss_data.get("baseSeverity", "")
        if not severity:
            # Derive from v2 score
            score = result["cvss_score"]
            if score >= 9.0:
                severity = "CRITICAL"
            elif score >= 7.0:
                severity = "HIGH"
            elif score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"
        result["cvss_severity"] = severity.upper()

    # CWE IDs
    cwe_ids: List[str] = []
    weaknesses = cve_item.get("weaknesses") or []
    for w in weaknesses:
        for desc in w.get("description") or []:
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                cwe_ids.append(val)
    result["cwe_ids"] = sorted(set(cwe_ids))

    # Affected products from CPE configurations
    products: List[str] = []
    seen_products: set = set()
    configurations = cve_item.get("configurations") or []
    for config in configurations:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                cpe = match.get("criteria", "")
                if cpe:
                    readable = _parse_cpe_product(cpe)
                    if readable and readable not in seen_products:
                        seen_products.add(readable)
                        products.append(readable)
    result["affected_products"] = products

    return result


def _fetch_cve(
    cve_id: str,
    *,
    rate_limiter: _RateLimiter,
    _fetch_fn: Optional[Callable[[str], Dict[str, Any]]] = None,
) -> Optional[Dict[str, Any]]:
    """Fetch a single CVE from the NVD API. Returns extracted fields or None."""
    if _fetch_fn is not None:
        return _fetch_fn(cve_id)

    global _api_key_valid, _consecutive_429s

    # Abort if NVD is persistently rate-limiting us
    if _consecutive_429s >= _429_CONSECUTIVE_ABORT:
        return None

    rate_limiter.wait()

    url = f"{_NVD_API_BASE}?cveId={cve_id}"
    headers = {"User-Agent": _USER_AGENT}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key and _api_key_valid is not False:
        headers["apiKey"] = api_key

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        vulns = data.get("vulnerabilities") or []
        if not vulns:
            logger.warning("NVD returned no vulnerabilities for %s", cve_id)
            return None

        if api_key and _api_key_valid is None:
            _api_key_valid = True
            logger.info("NVD API key validated successfully")

        _consecutive_429s = 0  # Reset on success
        cve_item = vulns[0].get("cve") or {}
        return _extract_nvd_fields(cve_item)

    except urllib.error.HTTPError as exc:
        # NVD returns 404 with "Invalid apiKey." header when key is bad
        if api_key and _api_key_valid is not False:
            msg = exc.headers.get("message", "") if hasattr(exc, "headers") else ""
            if "invalid apikey" in msg.lower() or (exc.code in (403, 404) and api_key):
                logger.warning(
                    "NVD API key is invalid — falling back to unauthenticated mode "
                    "(rate limit: 5 req/30s). Unset NVD_API_KEY or provide a valid key."
                )
                _api_key_valid = False
                # Downgrade rate limiter to unauthenticated limits
                rate_limiter.downgrade(max_requests=4, window_seconds=30)
                # Retry this CVE without the key
                return _fetch_cve(cve_id, rate_limiter=rate_limiter)

        if exc.code == 429:
            _consecutive_429s += 1
            if _consecutive_429s >= _429_CONSECUTIVE_ABORT:
                logger.warning(
                    "NVD rate limit: %d consecutive 429s — aborting remaining NVD "
                    "fetches. Cached entries (%d) will still be used.",
                    _consecutive_429s, 0,
                )
            else:
                # Back off before next attempt
                backoff = min(10 * _consecutive_429s, 30)
                logger.warning(
                    "NVD rate limited for %s (429 #%d) — backing off %ds",
                    cve_id, _consecutive_429s, backoff,
                )
                time.sleep(backoff)
            return None

        logger.warning("NVD fetch failed for %s: %s", cve_id, exc)
        return None
    except (urllib.error.URLError, json.JSONDecodeError) as exc:
        logger.warning("NVD fetch failed for %s: %s", cve_id, exc)
        return None
    except Exception as exc:
        logger.warning("NVD fetch unexpected error for %s: %s", cve_id, exc)
        return None


def _load_cache(cve_id: str, cache_dir: Path) -> Optional[Dict[str, Any]]:
    """Load cached NVD data for a CVE, or None if not cached."""
    cache_file = cache_dir / f"{cve_id}.json"
    if cache_file.exists():
        try:
            return json.loads(cache_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
    return None


def _save_cache(cve_id: str, data: Dict[str, Any], cache_dir: Path) -> None:
    """Save NVD data to cache."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file = cache_dir / f"{cve_id}.json"
    cache_file.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def enrich_issue(
    issue: Dict[str, Any],
    *,
    cache_dir: Optional[Path] = None,
    rate_limiter: Optional[_RateLimiter] = None,
    _fetch_fn: Optional[Callable[[str], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Enrich a single issue with NVD data for its CVEs.

    Modifies the issue dict in-place and returns it.
    For issues with multiple CVEs, data from the first successfully fetched
    CVE is used (typically the primary CVE = issue_id).
    """
    if cache_dir is None:
        cache_dir = _DEFAULT_CACHE_DIR
    if rate_limiter is None:
        rate_limiter = _get_rate_limiter()

    cves = issue.get("cves") or []
    if not cves:
        return issue

    # Try the issue_id CVE first (most likely to be the primary one)
    issue_id = issue.get("issue_id", "")
    if _CVE_RE.fullmatch(issue_id) and issue_id in cves:
        ordered_cves = [issue_id] + [c for c in cves if c != issue_id]
    else:
        ordered_cves = list(cves)

    for cve_id in ordered_cves:
        if not _CVE_RE.fullmatch(cve_id):
            continue

        # Check cache first
        cached = _load_cache(cve_id, cache_dir)
        if cached is not None:
            _apply_nvd_fields(issue, cached)
            return issue

        # Fetch from API
        fields = _fetch_cve(cve_id, rate_limiter=rate_limiter, _fetch_fn=_fetch_fn)
        if fields:
            _save_cache(cve_id, fields, cache_dir)
            _apply_nvd_fields(issue, fields)
            return issue

    return issue


def _apply_nvd_fields(issue: Dict[str, Any], nvd: Dict[str, Any]) -> None:
    """Apply NVD-extracted fields onto an issue dict."""
    if nvd.get("nvd_description"):
        issue["nvd_description"] = nvd["nvd_description"]
    if nvd.get("cvss_score"):
        issue["cvss_score"] = nvd["cvss_score"]
    if nvd.get("cvss_severity"):
        issue["cvss_severity"] = nvd["cvss_severity"]
    if nvd.get("cvss_vector"):
        issue["cvss_vector"] = nvd["cvss_vector"]
    if nvd.get("cwe_ids"):
        issue["cwe_ids"] = nvd["cwe_ids"]
    if nvd.get("affected_products"):
        issue["affected_products"] = nvd["affected_products"]


def enrich_issues(
    issues: List[Dict[str, Any]],
    *,
    cache_dir: Optional[Path] = None,
    _fetch_fn: Optional[Callable[[str], Dict[str, Any]]] = None,
) -> int:
    """Enrich a list of issues with NVD data. Returns count of enriched issues."""
    global _api_key_valid, _consecutive_429s
    _api_key_valid = None
    _consecutive_429s = 0

    if cache_dir is None:
        cache_dir = _DEFAULT_CACHE_DIR
    rate_limiter = _get_rate_limiter()

    enriched = 0
    for issue in issues:
        cves = issue.get("cves") or []
        if not cves:
            continue
        before_keys = set(issue.keys())
        enrich_issue(
            issue,
            cache_dir=cache_dir,
            rate_limiter=rate_limiter,
            _fetch_fn=_fetch_fn,
        )
        if set(issue.keys()) - before_keys:
            enriched += 1

    return enriched


# --- Summary deduplication ---

def deduplicate_summary(issue: Dict[str, Any]) -> None:
    """Replace blob summaries with per-CVE NVD descriptions.

    If nvd_description is available, it becomes the primary summary and the
    original summary is preserved as source_summary.

    If no NVD description, tries to extract the relevant sentence from a
    multi-CVE CISA blob by finding the sentence mentioning this CVE ID.
    """
    nvd_desc = issue.get("nvd_description", "")
    original_summary = issue.get("summary", "")

    if nvd_desc:
        # NVD description is authoritative and per-CVE
        issue["source_summary"] = original_summary
        issue["summary"] = nvd_desc
        return

    # No NVD description — try to extract relevant portion from blob
    issue_id = issue.get("issue_id", "")
    if not _CVE_RE.fullmatch(issue_id) or not original_summary:
        return

    # Split on sentence boundaries and find the one mentioning this CVE
    sentences = re.split(r'(?<=[.!?])\s+', original_summary)
    relevant = [s for s in sentences if issue_id in s]
    if relevant:
        issue["source_summary"] = original_summary
        issue["summary"] = " ".join(relevant)


# --- Action label translation ---

# Vuln-type keywords to match in summary/title/CWE
_VULN_TYPE_GUIDANCE = {
    "rce": [
        "Isolate affected systems. Block untrusted inbound connections.",
        "Apply vendor patch when available.",
    ],
    "remote code execution": [
        "Isolate affected systems. Block untrusted inbound connections.",
        "Apply vendor patch when available.",
    ],
    "code injection": [
        "Isolate affected systems. Block untrusted inbound connections.",
        "Apply vendor patch when available.",
    ],
    "deserialization": [
        "Isolate affected systems. Block untrusted inbound connections.",
        "Apply vendor patch when available.",
    ],
    "sql injection": [
        "Restrict database access to application accounts only.",
        "Enable query logging.",
        "Apply vendor patch.",
    ],
    "sqli": [
        "Restrict database access to application accounts only.",
        "Enable query logging.",
        "Apply vendor patch.",
    ],
    "cross-site scripting": [
        "Implement input validation and output encoding.",
        "Apply vendor patch.",
    ],
    "xss": [
        "Implement input validation and output encoding.",
        "Apply vendor patch.",
    ],
    "buffer overflow": [
        "Isolate affected systems from untrusted input sources.",
        "Apply vendor patch when available.",
    ],
    "privilege escalation": [
        "Restrict local access to trusted users only.",
        "Review account privileges.",
        "Apply vendor patch when available.",
    ],
    "authentication bypass": [
        "Restrict network access to affected service.",
        "Enable additional authentication factors where possible.",
        "Apply vendor patch when available.",
    ],
    "path traversal": [
        "Restrict file system access from application context.",
        "Apply vendor patch when available.",
    ],
}

_DEFAULT_GUIDANCE = [
    "Review vendor advisory for mitigation guidance.",
    "Monitor for exploitation indicators.",
]


def _detect_vuln_type(issue: Dict[str, Any]) -> Optional[str]:
    """Detect vulnerability type from issue fields."""
    text = " ".join([
        issue.get("summary", ""),
        issue.get("title", ""),
        issue.get("nvd_description", ""),
    ]).lower()

    cwe_ids = issue.get("cwe_ids") or []
    cwe_text = " ".join(cwe_ids).lower()
    combined = text + " " + cwe_text

    # Check in priority order (most specific first)
    for vuln_type in _VULN_TYPE_GUIDANCE:
        if vuln_type in combined:
            return vuln_type
    return None


def generate_remediation_steps(issue: Dict[str, Any]) -> List[str]:
    """Generate human-readable remediation steps from available context.

    Priority:
    1. kev_required_action (authoritative CISA guidance)
    2. source_mitigations (vendor guidance)
    3. Vulnerability-type-based guidance
    4. Default guidance
    """
    steps: List[str] = []

    # 1. KEV required action is authoritative
    kev_action = issue.get("kev_required_action", "")
    if kev_action:
        steps.append(kev_action)

    # 2. Source mitigations
    source_mits = issue.get("source_mitigations") or []
    for mit in source_mits:
        action = mit.get("action", "") if isinstance(mit, dict) else ""
        if action and action not in steps:
            steps.append(action)

    # 3. Vulnerability-type guidance (only if no authoritative guidance yet)
    if not steps:
        vuln_type = _detect_vuln_type(issue)
        if vuln_type and vuln_type in _VULN_TYPE_GUIDANCE:
            steps.extend(_VULN_TYPE_GUIDANCE[vuln_type])

    # 4. Default guidance
    if not steps:
        steps.extend(_DEFAULT_GUIDANCE)

    return steps
