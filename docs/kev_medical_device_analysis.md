# KEV / Medical Device Overlap Analysis

**Finding:** The current AdvisoryOps medical-device corpus has zero **exact structured CVE-ID overlap** with the **full CISA KEV catalog**.

## Current measured snapshot

Production comparison generated **2026-09-23T11:10:17.344475+00:00**, from
[the full-catalog report](kev_full_catalog_overlap.json) and [metadata](meta.json).
An independent reconstruction and fresh CISA discovery on 2026-09-23 reproduced these counts.

| Metric | Count |
| --- | ---: |
| Full canonical corpus | 10,880 |
| Medical-device records | 463 |
| Unique structured medical-device CVEs | 72 |
| Full KEV records / unique CVEs | 1,721 / 1,721 |
| Exact structured CVE-ID intersection | **0** |
| Normalized exact vendor matches (diagnostic only) | 0 |
| Partial vendor pairs (diagnostic only) | 2 |
| KEV-enriched issues in the corpus (not the full catalog) | 370 |

These values are a dated snapshot, not permanent statistics. The generated report
and metadata carry the authoritative counts and comparison timestamp for each build.
The public `feed_latest.json` has only 750 projected rows and is **never an input
for this analysis**. The full corpus is retained in 32 canonical archive shards.

## Methodology

The implementation is [`advisoryops.kev_full_catalog`](../src/advisoryops/kev_full_catalog.py).

1. Reconstruct every canonical row from `docs/feed_archive/manifest.json` and its
   shards. Reconstruction validates hashes, byte sizes, record counts and unique
   issue IDs. Select records with `healthcare_category == "medical_device"`.
2. Load all discovered CISA KEV JSON records, independently of the bounded
   correlation/enrichment subset. `cisa-kev-json` has no keyword filters and a
   configured limit of 9,999; confirm the parsed and retained counts agree with
   the downloaded catalog's `count`. The verifier's minimum of 1,000 unique CVEs
   detects obvious truncation but alone does not prove completeness.
3. Extract normalized uppercase CVE IDs from structured `cves`, `issue_id`, and
   `guid` fields. CISA discovery maps its `cveID` to `guid`; correlated issues
   can use CVE-keyed `issue_id` values. Ignore incidental CVE mentions in prose.
4. Intersect the unique CVE sets. This exact structured CVE-ID intersection is
   the authoritative overlap result. The strict per-record flag additionally
   requires the medical-device classification.
5. Separately normalize vendor names to lowercase alphanumeric words with
   collapsed whitespace. Report exact matches and non-identical substring pairs
   where both names have at least four characters. These are **diagnostics only**;
   never add them to the CVE intersection or use them to activate strict KEV badges.

The two current partial pairs are `siemens medical solutions usa inc` / `siemens`
and `sunquest information systems` / `quest`. A shared or contained vendor name
does not identify the same product or vulnerability and is not evidence of KEV
medical-device overlap.

## Correction of the historical claim

The old **203 KEV-enriched issues** described a historical enriched subset of the
AdvisoryOps corpus, **not all entries in CISA KEV**. Comparisons against that subset
could not support a full-catalog claim. The old zero-vendor-overlap statement and
claims that KEV universally lacks medical-device coverage are withdrawn.

The defensible result is limited to this corpus, its classifications, its
structured identifiers, and the catalog snapshot. Records without structured
CVEs cannot participate in the intersection. A zero intersection does not establish
that medical devices are never exploited, explain KEV inclusion decisions, or
rule out other medical-device CVEs outside this corpus. Specialized advisory and
recall sources remain useful alongside KEV.

## Reproduction from the full canonical archive

Run from the repository root after `pip install -e .`. The commands below use
scratch outputs and do not change published feeds or production metadata.
Use the repository commit for the desired corpus snapshot; a fresh CISA download
can change later results. For a byte-identical historical comparison, retain the
matching discovery input as well as the repository commit.

```sh
python -m advisoryops.cli discover --source cisa-kev-json --out-root tmp/closeout-discover --limit 9999
python -m advisoryops.feed_archive prepare-baseline --manifest docs/feed_archive/manifest.json --legacy tmp/absent-legacy.json --out tmp/closeout-full.json
python -c "import shutil; shutil.copyfile('docs/meta.json', 'tmp/closeout-meta.json')"
python -m advisoryops.kev_full_catalog --feed tmp/closeout-full.json --kev-jsonl tmp/closeout-discover/cisa-kev-json/items.jsonl --meta tmp/closeout-meta.json --out tmp/closeout-kev.json
```

Keep `tmp/absent-legacy.json` nonexistent: this deliberately prevents fallback to
the serving projection. If the archive is missing or corrupt, restore the manifest
and shards from the same known-good commit; do not substitute `docs/feed_latest.json`.
The verifier CLI also reconstructs the archive by default when `--feed` is omitted.
Any explicit `--feed` must be a **full canonical JSON array**.

Confirm the discovery cap did not omit records:

```sh
python -c "import json; from pathlib import Path; p=Path('tmp/closeout-discover/cisa-kev-json'); raw=json.loads((p/'raw_feed.json').read_text(encoding='utf-8')); rows=[json.loads(x) for x in (p/'items.jsonl').read_text(encoding='utf-8').splitlines() if x.strip()]; assert raw['count']==len(raw['vulnerabilities'])==len(rows); print('Complete KEV records:', len(rows))"
```

The 2026-09-23 run prints 1,721 complete KEV records, 463 medical-device records,
72 medical-device CVEs, zero exact CVE matches, zero exact vendor matches, and two
partial vendor pairs. Current values may differ; report the resulting timestamp
and counts rather than copying these numbers forward.

## Production and dashboard contract

The [scheduled workflow](../.github/workflows/update-feed.yml) reconciles strict
flags on the full canonical corpus, verifies that same corpus against the full
catalog, and only then publishes the bounded dashboard projection and full archive.
The dashboard reads scoped full-corpus metrics from `meta.json`; absent or unscoped
metrics remain unavailable, rather than being inferred from loaded rows.

Only a medical-device record with an exact structured CVE ID in the full KEV
catalog receives `is_kev_medical_device` and enters `feed_medical_device_kev.json`.
Vendor diagnostics do not change those flags, feeds, scores, or priorities.
See [publication architecture](publication.md) for the unchanged storage and serving contract.
