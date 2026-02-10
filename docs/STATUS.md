# STATUS (ground truth)

This file exists to prevent “drift” between what the docs claim and what the code snapshot actually does.

## Snapshot date

- 2026-02-10

## Working today

- `advisoryops ingest` produces `outputs/ingest/<advisory_id>/raw.txt`, `normalized.txt`, `source.json`
- `advisoryops extract` produces `outputs/extract/<advisory_id>/advisory_record.json` and `extract_meta.json`
- `scripts/verify_extract.ps1` validates the 13-key `AdvisoryRecord` contract
- `advisoryops discover` supports feed parsing for:
  - `rss_atom`
  - `json_feed`
  - `csv_feed`

## Known regression

- `advisoryops source-run --ingest` is currently a no-op because `src/advisoryops/source_run.py` is truncated and exits before the ingest loop.
- A complete implementation exists in `src/advisoryops/source_run.py.bak.*`.

## v1 decisions that matter

- `scope: dataset` sources (e.g., KEV) are **discovery-only** in v1.
- `configs/sources.json` contains a root `defaults` object, but it is **not currently applied** by the config loader.
- Declared-future page types (`html_*`, `json_api`, `pdf_bulletin`) must remain disabled until implemented.

