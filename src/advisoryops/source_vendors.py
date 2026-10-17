"""Reproducible, product-scoped public vendor evidence for SBOM publication.

Network recovery is explicit and checkpointed. Publication uses only the local
snapshot. A CVE association alone never binds a manufacturer to every product.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any
from urllib.request import urlopen

SNAPSHOT = Path(__file__).resolve().parents[2] / "configs/sbom_vendor_sources.json"
IDENTITY_SCHEMA = 2
SOURCE_RANK = {"nvd": 1, "cisa_csv": 2, "csaf": 3}


def _norm(value: str) -> str:
    # Historical CPE display labels retained escaped punctuation.
    value = re.sub(r"\\([^\w\s])", r"\1", value)
    return re.sub(r"\s+", " ", re.sub(r"[_\-./]+", " ", value.casefold())).strip()


def cpe_identities(configurations: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Retain concrete vendor/product pairs from vulnerable, non-negated CPEs.

    Platform prerequisites, wildcard identities and logical exclusions cannot
    establish a software manufacturer. Version ranges remain uninterpreted.
    """
    pairs: set[tuple[str, str]] = set()

    def visit(node: dict[str, Any]) -> None:
        if node.get("negate"):
            return
        for match in node.get("cpeMatch") or []:
            if match.get("vulnerable") is False:
                continue
            parts = re.findall(r"(?:\\.|[^:])+", match.get("criteria", ""))
            if (
                len(parts) != 13
                or parts[:2] != ["cpe", "2.3"]
                or parts[2] not in {"a", "h", "o"}
            ):
                continue
            vendor, product = parts[3:5]
            if any(
                not v or v == "-" or re.search(r"(?<!\\)[*?]", v)
                for v in (vendor, product)
            ):
                continue
            decode = lambda v: re.sub(r"\\(.)", r"\1", v).replace("_", " ")
            pairs.add((decode(vendor), decode(product)))
        for child in (node.get("nodes") or []) + (node.get("children") or []):
            visit(child)

    for config in configurations:
        visit(config)
    return [{"vendor": v, "product": p} for v, p in sorted(pairs)]


def cpe_vendors(configurations: list[dict[str, Any]]) -> list[str]:
    return sorted({p["vendor"] for p in cpe_identities(configurations)})


def csaf_identities(tree: dict[str, Any]) -> list[dict[str, str]]:
    """Follow CSAF branch categories, preserving each product's vendor ancestry.

    Never choose the first vendor in a multi-vendor tree. Version branches are
    not product names. Uncategorized legacy trees are not identity evidence.
    """
    pairs: set[tuple[str, str]] = set()

    def visit(branch, vendor="", product=""):
        category, name = branch.get("category"), branch.get("name", "")
        if category == "vendor":
            vendor, product = name, ""
        elif category == "product_name":
            product = name
            if vendor and product:
                pairs.add((vendor, product))
        for child in branch.get("branches") or []:
            visit(child, vendor, product)

    for branch in tree.get("branches") or []:
        visit(branch)
    return [{"vendor": v, "product": p} for v, p in sorted(pairs)]


def csaf_cve_identities(csaf: dict[str, Any]) -> list[dict[str, Any]]:
    """Bind CSAF known-affected product IDs to their own CVEs and vendors."""
    by_id = {}

    def visit(branch, vendor="", product=""):
        if branch.get("category") == "vendor":
            vendor, product = branch.get("name", ""), ""
        if branch.get("category") == "product_name":
            product = branch.get("name", "")
        full = branch.get("product") or {}
        if vendor and product and full.get("product_id"):
            by_id[full["product_id"]] = (vendor, product)
        for child in branch.get("branches") or []:
            visit(child, vendor, product)

    for branch in (csaf.get("product_tree") or {}).get("branches") or []:
        visit(branch)
    pairs = {}
    for vulnerability in csaf.get("vulnerabilities") or []:
        cve = vulnerability.get("cve")
        if not cve:
            continue
        status = vulnerability.get("product_status") or {}
        for product_id in status.get("known_affected") or []:
            if product_id in by_id:
                pairs.setdefault(by_id[product_id], set()).add(cve)
    return [
        {"vendor": v, "product": p, "cves": sorted(cves)}
        for (v, p), cves in sorted(pairs.items())
    ]


def load_vendor_sources(path: Path = SNAPSHOT) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("version") not in (1, 2) or not isinstance(data.get("records"), list):
        raise ValueError("Invalid SBOM vendor source snapshot")
    return data["records"]


def _kind(record):
    if record.get("kind") in SOURCE_RANK:
        return record["kind"]
    return (
        "cisa_csv"
        if record.get("source", "").endswith(".csv")
        else "nvd" if "nvd.nist.gov" in record.get("url", "") else "csaf"
    )


def populate_source_vendors(rows, sources):
    """Fill summary vendors and publish only explicit product/vendor bindings.

    Source product names must equal a label, or equal the label prefixed by that
    source's vendor. No substring or prose inference is used at publication.
    Higher-authority evidence wins for the same label; unrelated CVE products
    never borrow another product's manufacturer.
    """
    by_url, by_cve = {}, {}
    for source in sources:
        by_url.setdefault(source.get("url", "").rstrip("/"), []).append(source)
        for cve in source.get("cves") or []:
            by_cve.setdefault(cve, []).append(source)
    result = []
    for row in rows:
        item = dict(row)
        direct = by_url.get((item.get("canonical_link") or "").rstrip("/"), [])
        cves = (
            [item["issue_id"]]
            if item.get("issue_id") in (item.get("cves") or [])
            else item.get("cves") or []
        )
        direct = [
            s
            for s in direct
            if not cves or not s.get("cves") or set(s["cves"]).intersection(cves)
        ]
        evidence = direct + [s for c in cves for s in by_cve.get(c, [])]
        evidence += [
            {
                "source": identity["source"],
                "kind": identity.get("kind", "nvd"),
                "product_identities": [identity],
            }
            for identity in item.get("source_product_identities") or []
        ]
        evidence = [
            dict(
                source,
                product_identities=[
                    identity
                    for identity in source.get("product_identities") or []
                    if not identity.get("cves")
                    or set(identity["cves"]).intersection(cves)
                ],
            )
            for source in evidence
        ]
        labels = set(item.get("affected_products") or [])
        if item.get("kev_product"):
            labels.add(item["kev_product"])
        # Recover authoritative names that the old flattened CPE parser lost
        # (notably escaped colons), without replacing existing evidence labels.
        for source in evidence:
            for identity in source.get("product_identities") or []:
                vendor, product = identity["vendor"], identity["product"]
                if not any(
                    _norm(label) in {_norm(product), _norm(vendor + " " + product)}
                    for label in labels
                ):
                    labels.add(vendor + " " + product)
        item["affected_products"] = sorted(labels - {item.get("kev_product")})
        bindings = []
        for label in sorted(labels):
            candidates = []
            for source in evidence:
                for identity in source.get("product_identities") or []:
                    vendor, product = identity["vendor"], identity["product"]
                    if _norm(label) in {_norm(product), _norm(vendor + " " + product)}:
                        candidates.append(
                            (SOURCE_RANK[_kind(source)], vendor, source["source"])
                        )
            # KEV's vendor applies to KEV's product only.
            if label == item.get("kev_product") and item.get("kev_vendor"):
                candidates.append(
                    (
                        4,
                        item["kev_vendor"],
                        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                    )
                )
            if candidates:
                rank = max(c[0] for c in candidates)
                bindings.extend(
                    {"product": label, "vendor": v, "source": url}
                    for r, v, url in sorted(set(candidates))
                    if r == rank
                )
        item["product_vendors"] = bindings
        if not str(item.get("vendor") or "").strip():
            vendors = {b["vendor"] for b in bindings}
            if not vendors:
                # This is summary metadata only; never used to create bindings.
                signals = {
                    s["vendor"].strip()
                    for s in item.get("signals") or []
                    if isinstance(s, dict)
                    and isinstance(s.get("vendor"), str)
                    and s["vendor"].strip()
                }
                vendors = signals or {
                    s["vendor"] for s in (direct or evidence) if s.get("vendor")
                }
            if len(vendors) == 1:
                item["vendor"] = next(iter(vendors))
        result.append(item)
    return result


def nvd_record(data, *, checked_at):
    identities = cpe_identities(data.get("configurations") or [])
    vendors = {p["vendor"] for p in identities}
    url = "https://nvd.nist.gov/vuln/detail/" + data["id"]
    return {
        "url": url,
        "source": url,
        "kind": "nvd",
        "cves": [data["id"]],
        "vendor": next(iter(vendors)) if len(vendors) == 1 else "",
        "product_identities": identities,
        "identity_schema": IDENTITY_SCHEMA,
        "checked_at": checked_at,
        "last_modified": data.get("lastModified", ""),
        "status": data.get(
            "vendor_recovery_status", "available" if identities else "no_concrete_cpe"
        ),
    }


def _save_snapshot(records, path):
    payload = {
        "version": 2,
        "records": sorted(
            records.values(), key=lambda r: (r["url"], r.get("vendor", ""))
        ),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".tmp")
    temp.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    temp.replace(path)
    return payload


def refresh_vendor_sources(*, csv_text, cache_root: Path, path: Path = SNAPSHOT):
    """Refresh CSV/cache evidence without downgrading persisted CSAF evidence."""
    from .sources.cisa_icsma_backfill import _CSV_URL, parse_icsma_csv

    records = {r["url"]: r for r in load_vendor_sources(path)}
    csv_records = {}
    for advisory in parse_icsma_csv(csv_text):
        vendor, product = advisory.get("vendor"), advisory.get("product")
        if not vendor:
            continue
        url = (
            "https://www.cisa.gov/news-events/ics-medical-advisories/"
            + advisory["advisory_id"].lower()
        )
        record = csv_records.setdefault(
            url,
            {
                "url": url,
                "cves": [],
                "vendor": vendor,
                "source": _CSV_URL,
                "kind": "cisa_csv",
                "product_identities": [],
            },
        )
        record["cves"] = sorted(set(record["cves"]) | set(advisory["cves"]))
        if (
            product
            and {"vendor": vendor, "product": product}
            not in record["product_identities"]
        ):
            record["product_identities"].append({"vendor": vendor, "product": product})
        if record["vendor"] != vendor:
            record["vendor"] = ""
    for url, record in csv_records.items():
        if (
            url not in records
            or SOURCE_RANK[_kind(records[url])] <= SOURCE_RANK["cisa_csv"]
        ):
            records[url] = record
    for folder in ("cisa_icsma_cache", "nvd_cache", "nvd_vendor_raw"):
        for cache in sorted((cache_root / folder).glob("*.json")):
            if cache.name.startswith("_"):
                continue
            data = json.loads(cache.read_text(encoding="utf-8"))
            if folder == "cisa_icsma_cache":
                identities = data.get("product_identities") or csaf_cve_identities(data)
                vendor = data.get("vendor", "")
                if not vendor and not identities:
                    continue
                url = (
                    "https://www.cisa.gov/news-events/ics-medical-advisories/"
                    + cache.stem.lower()
                )
                record = {
                    "url": url,
                    "cves": sorted(data.get("cves") or []),
                    "vendor": vendor,
                    "source": data.get("vendor_source_url") or url,
                    "kind": data.get("vendor_source_kind", "csaf"),
                    "product_identities": identities,
                }
            elif "configurations" in data or folder == "nvd_vendor_raw":
                data.setdefault("id", cache.stem)
                checked = (
                    data.get("vendor_checked_at")
                    or datetime.fromtimestamp(
                        cache.stat().st_mtime, timezone.utc
                    ).isoformat()
                )
                record = nvd_record(data, checked_at=checked)
                url = record["url"]
            elif data.get("identity_schema") == IDENTITY_SCHEMA:
                url = "https://nvd.nist.gov/vuln/detail/" + cache.stem
                record = {
                    "url": url,
                    "cves": [cache.stem],
                    "vendor": data.get("vendor", ""),
                    "source": url,
                    "kind": "nvd",
                    "product_identities": data.get("product_identities", []),
                    "identity_schema": IDENTITY_SCHEMA,
                    "checked_at": data.get("vendor_checked_at", ""),
                }
            else:
                continue  # Old lossy caches cannot establish product bindings.
            older = records.get(url)
            replace = (
                older is None or SOURCE_RANK[_kind(record)] > SOURCE_RANK[_kind(older)]
            )
            if older and SOURCE_RANK[_kind(record)] == SOURCE_RANK[_kind(older)]:
                if _kind(record) == "nvd":
                    replace = record.get("checked_at", "") > older.get("checked_at", "")
                else:
                    replace = bool(record.get("product_identities")) or not older.get(
                        "product_identities"
                    )
            if replace:
                records[url] = record
    return _save_snapshot(records, path)


def main():
    from .sources.cisa_icsma_backfill import _CSV_URL

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path)
    parser.add_argument("--cache-root", type=Path, default=Path("outputs"))
    parser.add_argument("--out", type=Path, default=SNAPSHOT)
    parser.add_argument("--recover-nvd", action="store_true")
    parser.add_argument(
        "--nvd-limit", type=int, default=200, help="Maximum CVEs per run; 0 means all"
    )
    parser.add_argument(
        "--catalog", type=Path, default=Path("docs/sbom_advisories.json")
    )
    args = parser.parse_args()
    if args.nvd_limit < 0:
        parser.error("--nvd-limit must be nonnegative")
    if args.csv:
        csv_text = args.csv.read_text(encoding="utf-8-sig")
    else:
        with urlopen(_CSV_URL, timeout=60) as response:
            csv_text = response.read().decode("utf-8-sig")
    refresh_vendor_sources(csv_text=csv_text, cache_root=args.cache_root, path=args.out)
    if args.recover_nvd:
        from .vendor_recovery import recover_nvd

        recover_nvd(
            catalog=json.loads(args.catalog.read_text()),
            cache_root=args.cache_root,
            path=args.out,
            limit=args.nvd_limit,
        )


if __name__ == "__main__":
    main()
