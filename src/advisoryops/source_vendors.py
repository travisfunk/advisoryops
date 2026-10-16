"""Source-backed vendor identities for SBOM publication.

The checked-in snapshot repairs historical records without guessing vendors from
product labels or AI summaries. Refresh is an explicit network step; publication
and tests use the local snapshot and remain deterministic/offline. Ambiguous CVE
vendor associations are deliberately left unresolved.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

SNAPSHOT = Path(__file__).resolve().parents[2] / "configs/sbom_vendor_sources.json"


def cpe_vendors(configurations: list[dict[str, Any]]) -> list[str]:
    """Read concrete vendors from vulnerable NVD CPE 2.3 matches, recursively.

    Non-vulnerable platform prerequisites must not become product manufacturers.
    """
    vendors: set[str] = set()

    def visit(node: dict[str, Any]) -> None:
        for match in node.get("cpeMatch") or []:
            if match.get("vulnerable") is False:
                continue
            parts = re.findall(r"(?:\\.|[^:])+", match.get("criteria", ""))
            if len(parts) == 13 and parts[:2] == ["cpe", "2.3"]:
                vendor = parts[3]
                if vendor and not re.search(r"(?<!\\)[*?]", vendor) and vendor != "-":
                    vendors.add(re.sub(r"\\(.)", r"\1", vendor).replace("_", " "))
        for child in (node.get("nodes") or []) + (node.get("children") or []):
            visit(child)

    for config in configurations:
        visit(config)
    return sorted(vendors)


def load_vendor_sources(path: Path = SNAPSHOT) -> list[dict[str, Any]]:
    """Load audited evidence; absence is allowed in standalone installations."""
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("version") != 1 or not isinstance(data.get("records"), list):
        raise ValueError("Invalid SBOM vendor source snapshot")
    return data["records"]


def populate_source_vendors(
    rows: list[dict[str, Any]], sources: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Copy rows and fill only empty vendors from unambiguous source identities.

    Advisory URL associations take precedence over CVE associations. Existing
    explicit vendor values are never overwritten. No fuzzy or prose extraction.
    """
    by_url: dict[str, set[str]] = {}
    by_cve: dict[str, set[str]] = {}
    for source in sources:
        vendor = source.get("vendor", "").strip()
        if not vendor:
            continue
        if source.get("url"):
            by_url.setdefault(source["url"].rstrip("/"), set()).add(vendor)
        for cve in source.get("cves") or []:
            by_cve.setdefault(cve, set()).add(vendor)
    result = []
    for row in rows:
        item = dict(row)
        if not str(item.get("vendor") or "").strip():
            vendors = {
                s["vendor"].strip()
                for s in item.get("signals") or []
                if isinstance(s, dict)
                and isinstance(s.get("vendor"), str)
                and s["vendor"].strip()
            }
            if not vendors:
                vendors = by_url.get(
                    (item.get("canonical_link") or "").rstrip("/"), set()
                )
            if not vendors:
                vendors: set[str] = set().union(
                    *(by_cve.get(c, set()) for c in item.get("cves") or [])
                )
            if len(vendors) == 1:
                item["vendor"] = next(iter(vendors))
        result.append(item)
    return result


def refresh_vendor_sources(*, csv_text: str, cache_root: Path, path: Path = SNAPSHOT):
    """Refresh public CSV/CSAF and NVD cache evidence, retaining prior history."""
    from .sources.cisa_icsma_backfill import _CSV_URL, parse_icsma_csv

    records = {(r["url"], r["vendor"]): r for r in load_vendor_sources(path)}
    csv_records: dict[tuple[str, str], dict[str, Any]] = {}
    for advisory in parse_icsma_csv(csv_text):
        if advisory.get("vendor"):
            url = (
                "https://www.cisa.gov/news-events/ics-medical-advisories/"
                + advisory["advisory_id"].lower()
            )
            record = {
                "url": url,
                "cves": sorted(advisory["cves"]),
                "vendor": advisory["vendor"],
                "source": _CSV_URL,
            }
            key = (url, record["vendor"])
            previous = csv_records.get(key, {})
            record["cves"] = sorted(set(record["cves"]) | set(previous.get("cves", [])))
            csv_records[key] = record
    # Replace source corrections, but retain all CVEs across duplicate CSV rows.
    refreshed_urls = {url for url, _ in csv_records}
    records = {k: v for k, v in records.items() if k[0] not in refreshed_urls}
    records.update(csv_records)
    for folder in ("cisa_icsma_cache", "nvd_cache"):
        for cache in sorted((cache_root / folder).glob("*.json")):
            if cache.name.startswith("_"):
                continue
            data = json.loads(cache.read_text(encoding="utf-8"))
            if folder == "cisa_icsma_cache":
                vendor = data.get("vendor")
                url = (
                    "https://www.cisa.gov/news-events/ics-medical-advisories/"
                    + cache.stem.lower()
                )
                cves = data.get("cves") or []
            else:
                vendors = data.get("cpe_vendors") or cpe_vendors(
                    data.get("configurations") or []
                )
                vendor = vendors[0] if len(vendors) == 1 else None
                url = "https://nvd.nist.gov/vuln/detail/" + cache.stem
                cves = [cache.stem]
            if vendor:
                records = {k: v for k, v in records.items() if k[0] != url}
                records[(url, vendor)] = {
                    "url": url,
                    "cves": sorted(cves),
                    "vendor": vendor,
                    "source": url,
                }
    payload = {
        "version": 1,
        "records": sorted(records.values(), key=lambda r: (r["url"], r["vendor"])),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return payload


def main():
    from urllib.request import urlopen
    from .sources.cisa_icsma_backfill import _CSV_URL

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--csv", type=Path, help="Local source CSV (otherwise fetch the public feed)"
    )
    parser.add_argument("--cache-root", type=Path, default=Path("outputs"))
    parser.add_argument("--out", type=Path, default=SNAPSHOT)
    args = parser.parse_args()
    if args.csv:
        csv_text = args.csv.read_text(encoding="utf-8-sig")
    else:
        with urlopen(_CSV_URL, timeout=60) as response:
            csv_text = response.read().decode("utf-8-sig")
    refresh_vendor_sources(csv_text=csv_text, cache_root=args.cache_root, path=args.out)


if __name__ == "__main__":
    main()
