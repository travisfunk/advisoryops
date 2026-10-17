"""Checkpointed historical NVD vendor/product recovery for the public catalog.

Use through ``python -m advisoryops.source_vendors --recover-nvd``. Network
failures leave completed batches intact; missing and stale records remain queued.
"""

from datetime import datetime, timezone, timedelta
import json
import re
import time
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .source_vendors import (
    SNAPSHOT,
    IDENTITY_SCHEMA,
    load_vendor_sources,
    nvd_record,
    _save_snapshot,
)


def recover_nvd(
    *,
    catalog,
    cache_root,
    path=SNAPSHOT,
    limit=200,
    fetch=None,
    wait=time.sleep,
    now=None,
):
    """Recover missing/stale historical CPE evidence, in resumable 100-CVE batches.

    Uses NVD's documented cveIds filter (up to 100 comma-separated IDs):
    https://nvd.nist.gov/developers/vulnerabilities#cveIds
    The singular cveId parameter is deprecated in current NVD documentation.
    Zero limit covers the entire catalog. Responses are validated before each
    checkpoint; failed requests remain retryable. No API key is needed or logged.
    """
    now = now or datetime.now(timezone.utc)
    records = {r["url"]: r for r in load_vendor_sources(path)}
    cutoff = (now - timedelta(days=30)).isoformat()
    ids = sorted(
        {
            c
            for r in catalog["issues"]
            if r.get("affected_products") or r.get("kev_product")
            for c in r.get("cves") or []
            if re.fullmatch(r"CVE-\d{4}-\d{4,}", c)
        }
    )
    pending = []
    for cve in ids:
        existing = records.get("https://nvd.nist.gov/vuln/detail/" + cve, {})
        if (
            existing.get("identity_schema") != IDENTITY_SCHEMA
            or existing.get("checked_at", "") < cutoff
        ):
            pending.append(cve)
    # Missing records first, then the least recently checked: no tail starvation.
    pending.sort(
        key=lambda c: (
            records.get("https://nvd.nist.gov/vuln/detail/" + c, {}).get(
                "checked_at", ""
            ),
            c,
        )
    )
    if limit:
        pending = pending[:limit]
    raw_dir = cache_root / "nvd_vendor_raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    for start in range(0, len(pending), 100):
        batch = pending[start : start + 100]
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urlencode(
            {"cveIds": ",".join(batch)}
        )
        if fetch:
            data = fetch(url)
        else:
            with urlopen(
                Request(
                    url,
                    headers={
                        "User-Agent": "AdvisoryOps/1.0 (public source vendor recovery)"
                    },
                ),
                timeout=45,
            ) as response:
                data = json.load(response)
        found = {v["cve"]["id"]: v["cve"] for v in data.get("vulnerabilities", [])}
        if data.get("totalResults") != len(found) or not set(found).issubset(batch):
            raise ValueError("Incomplete or unrelated NVD batch response")
        for cve in batch:
            raw = dict(
                found.get(cve, {"id": cve, "vendor_recovery_status": "not_found"})
            )
            raw["vendor_checked_at"] = now.isoformat()
            (raw_dir / (cve + ".json")).write_text(json.dumps(raw), encoding="utf-8")
            record = nvd_record(raw, checked_at=now.isoformat())
            records[record["url"]] = record
        _save_snapshot(records, path)
        print(
            f"NVD vendor recovery: {min(start+100, len(pending))}/{len(pending)} checked",
            flush=True,
        )
        if start + 100 < len(pending):
            wait(6.2)
    return {"requested": len(pending), "total_cves": len(ids)}
