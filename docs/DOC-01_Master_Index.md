# DOC-01: Master Index

This is the single entry point for the repo docs.

## Current status (as of 2026-02-08)

### Milestones
- **Milestone B (ingest + extract stable)** ✅
  - `advisoryops ingest` → `outputs/ingest/<advisory_id>/...`
  - `advisoryops extract` → `outputs/extract/<advisory_id>/advisory_record.json`
  - `scripts/verify_extract.ps1` validates:
    - 13-key contract
    - no mojibake markers in JSON output

- **Source Framework v1** ✅
  - Config-driven sources (`configs/sources.json`)
  - `advisoryops source-run` orchestration
  - RSS/Atom discovery (page type: `rss_atom`)

- **Source Framework v1.1** ✅
  - Additional discovery types:
    - `json_feed`
    - `csv_feed`

### Repo hygiene
- `.gitattributes` enforces consistent line endings:
  - **LF** for repo text files (platform-agnostic)
  - **CRLF** for Windows scripts (`*.ps1`, `*.cmd`, `*.bat`)
- If you see odd characters like `﻿` at the top of files, it’s usually a UTF‑8 BOM; docs have been normalized to avoid this.

## Document map

### Contracts + data model
- `DOC-02_Data_Contracts.md` — AdvisoryRecord (13-key contract) and normalization rules

### Pipeline
- `DOC-05_Ingestion.md` — discovery + ingestion design and guardrails
- `DOC-06_Matching.md` — matching strategy (inputs → normalized fields)
- `DOC-07_Evaluation.md` — evaluation approach and quality gates

### Integrations + deployment
- `DOC-04_Integrations.md` — external touchpoints + conventions
- `DOC-10_Stack_and_Deployment.md` — stack pinning + repo hygiene notes

### Planning artifacts
- `DOC-03_Mitigation_Playbook.md`
- `DOC-08_Grant_Draft.md`
- `DOC-09_Prototype_Plan.md`

## Working definitions

- **Discovery**: find candidate advisories/links cheaply (RSS, JSON feeds, CSV feeds).
- **Ingestion**: fetch + snapshot + normalize content into `outputs/ingest/...`.
- **Extraction**: produce a clean `AdvisoryRecord` JSON from normalized text.

## Quick verification checklist

From repo root:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\scriptserify_extract.ps1
```
