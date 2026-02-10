# advisoryops

A small, config-driven pipeline for **discovering**, **ingesting**, and **extracting** security advisories into a consistent JSON contract.

This repo is intentionally pragmatic:
- Prefer **cheap discovery + filtering** before any LLM work
- Keep **raw snapshots** under `outputs/` (gitignored)
- Enforce a **stable 13-key `AdvisoryRecord` contract** (see `schemas/advisory_record_schema.json`)
- Provide a one-command verification check (`scripts/verify_extract.ps1`)

## Current status (as of 2026-02-10)

✅ **Milestone B (ingest + extract) is working**
- `advisoryops ingest` writes `outputs/ingest/<advisory_id>/...`
- `advisoryops extract` writes `outputs/extract/<advisory_id>/advisory_record.json`
- `scripts/verify_extract.ps1` validates the 13-key contract

✅ **Discovery framework is working**
- Config-driven sources in `configs/sources.json`
- Implemented `page_type` parsers:
  - `rss_atom`
  - `json_feed`
  - `csv_feed`
- Discovery artifacts written to `outputs/discover/<source_id>/`:
  - `raw_feed.*`, `feed.json`, `new_items.json`, `state.json`

⚠️ **Known regression: `source-run --ingest` is currently a no-op in this snapshot**
- The checked-in `src/advisoryops/source_run.py` is truncated (it prints a warning and exits before the ingest loop).
- A complete implementation exists in `src/advisoryops/source_run.py.bak.*` (to be restored/fixed in the next milestone).
- Workaround today: use `advisoryops discover` (or `source-run` without `--ingest`) to get links, then run `advisoryops ingest --url ...` manually.

✅ Repo hygiene
- `.gitattributes` keeps line endings consistent (LF in repo; CRLF for `.ps1/.cmd/.bat`)

## Quickstart (Windows PowerShell)

From repo root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
pip install -e .

# configure secrets
Copy-Item .env.example .env
# then edit .env (OPENAI_API_KEY, optional OPENAI_MODEL)

# quick contract + mojibake check (reads latest ingested advisory by default)
.\scripts\verify_extract.ps1
```

## Key commands

### 1) Discover from a configured source

Use `discover` to fetch and parse the source feed into JSON artifacts:

```powershell
# discover up to 5 items and write outputs/discover/<source_id>/...
.\.venv\Scripts\advisoryops.exe discover --source cisa-icsma --limit 5

# show the discovered links in the console
.\.venv\Scripts\advisoryops.exe discover --source cisa-icsma --limit 5 --show-links
```

`source-run` also performs discovery (and writes the same discovery artifacts):

```powershell
# discovery-only (recommended until source-run ingest is fixed)
.\.venv\Scripts\advisoryops.exe source-run --source cisa-icsma --limit 5
```

Dataset sources (like CISA KEV) are discoverable:

```powershell
.\.venv\Scripts\advisoryops.exe discover --source cisa-kev-json --limit 5
.\.venv\Scripts\advisoryops.exe discover --source cisa-kev-csv --limit 5
```

### 2) Ingest a single advisory (URL or text) and then extract

```powershell
# ingest a local text sample (writes outputs/ingest/<advisory_id>/...)
.\.venv\Scripts\advisoryops.exe ingest --text-file .\samples\advisories\sample_advisory.txt

# or ingest a live URL
.\.venv\Scripts\advisoryops.exe ingest --url https://www.cisa.gov/news-events/ics-medical-advisories/icsma-16-089-01

# extract into outputs/extract/<advisory_id>/advisory_record.json
.\.venv\Scripts\advisoryops.exe extract --advisory-id adv_<id_from_ingest>
```

### Scope and v1 decisions (important)

- `scope: advisory` sources are intended to support ingest/extract workflows.
- `scope: dataset` sources (e.g., KEV) are **discovery-only** in v1. Treat dataset-to-advisory ingestion as a separate future milestone with its own output contracts.
- `configs/sources.json` contains a root `defaults` object, but **it is not currently applied by the loader**. Only per-source `timeout_s`, `retries`, and `rate_limit_rps` values are honored.

## Repo layout

- `src/advisoryops/` — CLI + pipeline modules
- `configs/sources.json` — source registry (enabled sources, parsers, filters)
- `schemas/` — JSON schemas (contracts)
- `prompts/` — LLM prompts (extract prompt)
- `scripts/` — verification and helper scripts
- `docs/` — design docs and plans
- `samples/` — local sample advisories and fixtures
- `outputs/` — runtime artifacts (gitignored)

## Docs

Start with:
- `docs/DOC-01_Master_Index.md`
- `docs/DOC-05_Ingestion.md`

