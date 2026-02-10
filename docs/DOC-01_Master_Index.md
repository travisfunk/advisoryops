# DOC-01: Master Index

This is the single entry point for the repo docs.

## Current status (as of 2026-02-10)

### Milestones

- **Milestone B (ingest + extract stable)** ✅  
  - `advisoryops ingest` → `outputs/ingest/<advisory_id>/...`  
  - `advisoryops extract` → `outputs/extract/<advisory_id>/advisory_record.json`  
  - `scripts/verify_extract.ps1` validates:
    - stable 13-key contract
    - no mojibake markers in JSON output

- **Discovery Framework (config-driven sources)** ✅  
  - Source registry: `configs/sources.json`  
  - Implemented feed parsers (`page_type`):
    - `rss_atom`
    - `json_feed`
    - `csv_feed`
  - Discovery artifacts: `outputs/discover/<source_id>/raw_feed.*`, `feed.json`, `new_items.json`, `state.json`
  - CLI:
    - `advisoryops discover`
    - `advisoryops source-run` (discovery portion)

- **Source Framework v1 “source-run ingest”** ⚠️ (regression in this snapshot)  
  - `src/advisoryops/source_run.py` is truncated and exits before the ingest loop.  
  - A complete implementation exists in `src/advisoryops/source_run.py.bak.*`.  
  - Workaround: use `advisoryops discover` (or `source-run` without `--ingest`) and then run `advisoryops ingest --url ...` manually.

### Repo hygiene

- `.gitattributes` enforces consistent line endings:
  - **LF** for repo text files (platform-agnostic)
  - **CRLF** for `.ps1/.cmd/.bat` (Windows-friendly)

### Key docs

- **DOC-02**: Data Contracts (`AdvisoryRecord` schema + verify script)
- **DOC-05**: Ingestion Sources & Parsers (MVP ingest and discovery parsers)
- **DOC-09**: Prototype Plan (milestones and immediate next steps)
- **DOC-10**: Stack & Deployment (Windows PowerShell conventions and hygiene)
- `docs/STATUS.md` — snapshot truth + known regressions

