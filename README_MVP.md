# AdvisoryOps MVP

This MVP provides a minimal, **deterministic** CLI for:
1) **Discovery** (feeds → normalized items + “new” detection), and
2) **Ingest + Extract** (advisory page → normalized text → `AdvisoryRecord` JSON).

**Updated:** 2026-02-10

---

## Core commands

### Discovery
- `advisoryops discover` — fetch + parse a single source into `outputs/discover/<source_id>/…`
- `advisoryops source-run` — orchestrates discovery (+ optional ingest) and writes a run report JSON under `outputs/source_runs/…`

### Ingest + Extract (advisory pages)
- `advisoryops ingest` — URL/text/PDF → normalized snapshot + hashes under `outputs/ingest/<advisory_id>/`
- `advisoryops extract` — normalized text → `AdvisoryRecord` JSON under `outputs/extract/<advisory_id>/`

`AdvisoryRecord` is **13 top-level keys** (schema in `schemas/advisory_record_schema.json`). Verification is enforced by `scripts/verify_extract.ps1`.

---

## Quickstart (Windows PowerShell)

```powershell
# 1) Setup
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -U pip
.\.venv\Scripts\pip.exe install -e .

Copy-Item .env.example .env
# edit .env and set OPENAI_API_KEY
# optional: set OPENAI_MODEL (default is gpt-4o-mini)

# 2) Discovery example (writes outputs/discover/... and outputs/source_runs/...)
.\.venv\Scriptsdvisoryops.exe source-run --source cisa-icsma --limit 5

# Optional: treat all items as new (deletes state.json first)
.\.venv\Scriptsdvisoryops.exe source-run --source cisa-kev-json --limit 5 --reset-state
```

### Ingest + Extract example (from a URL)
```powershell
# Ingest an advisory URL (prints advisory_id)
.\.venv\Scriptsdvisoryops.exe ingest --url https://www.cisa.gov/news-events/ics-medical-advisories/icsma-16-089-01

# Extract into structured JSON
.\.venv\Scriptsdvisoryops.exe extract --advisory-id <advisory_id_from_ingest>

# Validate contract
.\.venv\Scripts\pwsh.exe -File .\scriptserify_extract.ps1
```

---

## Output locations (MVP)

### Discovery
`outputs/discover/<source_id>/`
- `raw_feed.<xml|json|csv>`
- `feed.json`, `new_items.json`
- `items.jsonl`, `new_items.jsonl`
- `state.json`
- `meta.json`

### Source run reports
`outputs/source_runs/<timestamp>_<source_id>.json`

### Ingest
`outputs/ingest/<advisory_id>/`
- `raw.txt`
- `normalized.txt`
- `source.json` (paths + metadata)

### Extract
`outputs/extract/<advisory_id>/`
- `advisory_record.json`
- `schema_check.json` (verification summary; if present)

---

## Next milestone (planned)
Correlation/deduplication across sources (merging multiple reports of the same vuln/issue into a single “Issue”) and enrichment. The design will be documented after the feature is implemented.
