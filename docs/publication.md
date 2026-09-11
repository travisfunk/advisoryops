# Static publication and dashboard contract

The nightly build has two separate data products. Canonical records preserve all
issue fields for enrichment, reconstruction, research and reproducible analysis.
Serving records preserve only the fields read by the dashboard, without rewriting,
truncating or synthesizing any values.

## Artifacts and sequence

1. `feed_archive.prepare-baseline` validates manifest version, shard hashes, byte
   sizes, counts and unique issue IDs, then reconstructs the complete JSON baseline.
   Only the first migration may bootstrap from the legacy monolithic feed. A
   missing archive after migration fails closed; restore it from a prior commit.
2. `community-build --latest 0 --baseline-feed ...` merges new observations with
   that baseline. Its publication health guard compares against the full archive,
   including retention of every prior issue ID. Equality is valid on quiet days.
3. The workflow copies the full intermediate feed to a runner-temporary canonical
   file. Reconciliation explicitly takes that file through `--feed`, updates strict
   KEV flags/scores, and regenerates the existing CSV, RSS and medical-device
   outputs. `kev_full_catalog --feed ...` independently verifies the same complete
   corpus against the full CISA discovery catalog (minimum 1,000 unique CVEs).
4. `feed_archive.publish` writes full canonical rows into 32 deterministic JSONL
   shards, and projects the first 750 rows in the builder's existing order into
   `docs/feed_latest.json`. The order is the existing priority/date order, not a
   promise that these are the 750 newest dates. All fields on historical records
   remain in the archive, including unknown future fields.
5. The dashboard projection must be at most 25 MiB and each archive shard at most
   50 MiB. Archive and serving files are staged and validated before replacing
   existing publication files. A failed guard leaves those files unchanged.
   The workflow additionally checks **every** docs file against 50 MiB before a
   single commit publishes the complete set to Pages. Local file replacement is
   not a filesystem-wide transaction; deployment consistency comes from the git
   commit. A failed build never reaches that commit.

The hash bucket is `uint32_be(sha256(UTF8(issue_id))[:4]) mod shard_count`.
Rows within a shard are sorted by issue ID; JSON keys are sorted and UTF-8 JSONL
uses LF. With the same rows and shard count, shard bytes and hashes are identical.
Manifest generation timestamps intentionally vary. On identical runs, only the
manifest `generated_at` changes; the shard entries and shard bytes remain identical.
Publication still serializes and validates the staged shards, but compares full
file contents before replacement so unchanged destination files keep their mtimes.
Git reuses their existing content-addressed blobs. Changes to a small set of
canonical records affect only the hash buckets containing those issue IDs. Increasing the shard count
redistributes the corpus and requires a complete reconstruction and republication.
No record or field is dropped to meet a budget; an oversized record fails with
an actionable error. There is no Git LFS or application backend.

`docs/feed_healthcare.json` remains the complete, full-fidelity strict
`healthcare_category == "medical_device"` subset. The dashboard loads it initially;
its general-advisory mode loads the bounded `feed_latest.json`. Thus medical-device
filtering and historical medical-device access do not depend on the 750-row window.
Existing CSV, RSS, and strict KEV medical-device output formats are unchanged.
General-mode search and urgency counts cover the serving window; full-history
research uses the archive. Metadata methodology counts describe the full corpus.

Do not use the compact feed as an additive baseline or KEV verification input.
The verifier's CLI default reconstructs the archive; an explicit `--feed` must
point to a full canonical array. The reconciler CLI requires that explicit input.
The builder's `outputs/community_public/feed_latest.json` and intermediate docs
copy are still full-fidelity during the nightly build; only the final archive
publication produces the compact public artifact. Running `community-build` or
`scripts/republish_docs.py` alone is not a complete production publication.

## Every dashboard issue-field read

The machine-readable allowlist is [dashboard_feed_contract.json](dashboard_feed_contract.json).
[feed_contract.json](feed_contract.json) and [schema.md](schema.md) describe canonical
records. Optional fields retain their exact value and type when present, including
`false` and `null`; absent fields remain absent. Nested values are retained intact.
Tests compare the inventory to issue aliases and array-indexed reads in the UI,
and check projected values against their canonical originals.

| UI use | Fields |
|---|---|
| Identity, list, priority counts, local read state | `issue_id`, `title`, `priority`, `score` |
| Search, summary, title fallback | `summary`, `nvd_description`, `vendor`, `cves`, `affected_versions`, `affected_products`, `cwe_ids` |
| Dates, sorting, weekly digest, update fallback, new badge | `published_dates`, `first_seen_at`, `last_seen_at`, `first_published_to_feed` |
| Healthcare filters and badge | `healthcare_category`, `healthcare_relevant` |
| Exploitation, FDA, CVSS, EPSS badges/detail | `is_kev_medical_device`, `remotely_exploitable_no_auth`, `fda_risk_class`, `cvss_score`, `cvss_severity`, `epss_score` |
| KEV title/product fallback, required action and deadline | `kev_vulnerability_name`, `kev_vendor`, `kev_product`, `kev_required_action`, `kev_due_date` |
| Warnings, has-fix filter, complete remediation detail | `handling_warnings`, `remediation_steps`, `actions` |
| AI detail guidance | `reasoning`, `recommended_patterns`, `tasks_by_role` |
| Multi-source filter, attribution and links | `sources`, `canonical_link` |

Within `recommended_patterns`, the UI reads `priority_order`, `name`, `pattern_id`,
`why_selected`, `basis`, `friction_level`, and `side_effects`. Role task reads are
`infosec`, `netops`, `htm_ce`, `vendor`, `clinical_ops`, and `it_ops`.
`validated_sources.json` supplies source names/URLs/authority context; `meta.json`
supplies build metadata and full-corpus methodology metrics. These are separate
requests, not issue fields in `feed_latest.json`.

The detail pane remains self-contained. It does not require another network fetch.
Fields used only in that pane are small enough to retain completely. Unread fields
such as `source_summary`, `source_consensus`, `why`, raw evidence, IOCs, extraction
provenance and additional enrichment metadata remain available in archive shards.

## Measured migration replay

A local replay of production commit `fc5d98e507bafe38c5797a262d70aede664c6ee5`
(9,254 records), using the CISA catalog released 2026-09-10, produced:

| Measurement | Result |
|---|---:|
| Canonical records | 9,254 |
| Archive shards | 32 |
| Total JSONL shard bytes | 98,990,357 |
| Archive directory bytes (including manifest/README) | 98,996,829 |
| Largest shard bytes | 4,345,373 |
| Dashboard records | 750 |
| Dashboard bytes | 1,908,094 |
| Dashboard budget bytes | 26,214,400 |
| Complete medical-device records | 458 |
| Medical-device unique CVEs | 69 |
| Full CISA KEV unique CVEs | 1,705 |
| Exact CVE overlap | 0 |

The canonical 750-row window was 50,289,570 bytes before projection.
`source_summary` values alone contributed 47,493,149 bytes (94.4%). The largest
record, `CVE-2020-11023`, was 364,323 bytes, of which 357,215 bytes were its
preserved source summary. Multiple CVEs carry the same large CISA multi-CVE
advisory: `nvd_enrich.deduplicate_summary` preserves the original advisory in
`source_summary` while putting the per-CVE NVD description in `summary`. The UI
reads `summary` and `nvd_description`, never `source_summary`. Removing the unread
fields from the serving projection reduces this window by 96.2%; it does not
remove those fields from canonical storage.

The CISA JSON SHA-256 for this replay was
`30f1fbd6104b59507bbb6ad0ced75c39834fe7bb8962a8f2ef1027d81a996211`.
Two vendor-substring pairs were found as secondary diagnostics; neither establishes
exploitation or changes the strict exact-CVE medical-device definition.
These measurements are a dated replay, not permanent live statistics. The failed
Actions run's 9,533-record output had no retained artifact; it was not the input
for this replay. A fresh end-to-end scheduled run still needs observation.

## Recovery and verification

```sh
python -m advisoryops.feed_archive prepare-baseline \
  --manifest docs/feed_archive/manifest.json \
  --legacy docs/feed_latest.json --out /tmp/advisoryops-full.json
python -m advisoryops.kev_full_catalog --feed /tmp/advisoryops-full.json
python -m advisoryops.feed_archive publish \
  --source /tmp/advisoryops-full.json --docs docs --latest-count 750 --shards 32
```

Verification requires a current complete `outputs/discover/cisa-kev-json/items.jsonl`.
For an actual nightly build, run reconciliation before verification/publication as
shown in the workflow. Restore corrupt/missing shards and their matching manifest
from the same known-good git commit; do not substitute the serving window.

The README's April statistics and “203 entries in CISA KEV” language are stale.
That historical number describes an enriched feed subset, not the full catalog.
They should be corrected in a separately verified public-statistics update after
publication is restored. Existing dashboard legacy overlap prose/calculations also
mix vendor diagnostics with exact-CVE results; the independent full-catalog report
is authoritative, and that UI wording warrants a separate methodology correction.
