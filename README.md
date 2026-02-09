# advisoryops

A small, config-driven pipeline for **discovering**, **ingesting**, and **extracting** security advisories into a consistent JSON contract.

This repo is intentionally pragmatic:
- Prefer **cheap discovery + filtering** before any LLM work
- Keep **raw snapshots** under `outputs/` (gitignored)
- Enforce a **stable 13-key `AdvisoryRecord` contract** (see `schemas/advisory_record_schema.json`)
- Provide a one-command verification check (`scripts/verify_extract.ps1`)

## What works today (current milestones)

- **Milestone B (ingest + extract stable)**: `advisoryops ingest` + `advisoryops extract` + `verify_extract.ps1`
- **Source Framework v1**: `source-run` orchestration (config-driven sources + RSS/Atom discovery)
- **Source Framework v1.1**: additional discovery types: `json_feed` and `csv_feed`
- Repo hygiene: `.gitattributes` added to keep line endings consistent (LF in repo; CRLF for `.ps1/.cmd/.bat`)

## Quickstart (Windows PowerShell)

From repo root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
pip install -e .

# configure secrets
Copy-Item .env.example .env
# then edit .env (OPENAI_API_KEY, etc)

# quick contract + mojibake check
.\scriptserify_extract.ps1
```

## Key commands

### 1) Discover + optionally ingest from a configured source

```powershell
# discover 5 items from a source, write outputs/discover/<source_id>/...
.\.venv\Scriptsdvisoryops.exe source-run --source cisa-icsma-rss --limit 5

# discover + ingest newly-seen items (advisory scopes only in v1)
.\.venv\Scriptsdvisoryops.exe source-run --source cisa-icsma-rss --limit 5 --ingest

# plan an ingest without fetching (prints candidate URLs)
.\.venv\Scriptsdvisoryops.exe source-run --source cisa-icsma-rss --limit 5 --ingest --dry-run
```

**Important v1 guardrail:** ingestion is intended for sources with `scope: advisory`.
If you try `--ingest` on `scope: dataset` sources (e.g., the CISA KEV JSON feed), v1 will refuse. Use discovery-only (no `--ingest`) or run a `--dry-run` to see the linked URLs you might ingest in a future iteration.

### 2) Ingest a single advisory (URL or text) and then extract

```powershell
# ingest a local text sample (writes outputs/ingest/<advisory_id>/...)
.\.venv\Scriptsdvisoryops.exe ingest --text-file .\samplesdvisories\sample_advisory.txt

# extract into outputs/extract/<advisory_id>/advisory_record.json
.\.venv\Scriptsdvisoryops.exe extract --advisory-id adv_<id_from_ingest>
```

## Repo layout

- `configs/` – source definitions (`sources.json`)
- `docs/` – design + contracts + runbooks
- `schemas/` – JSON schema for the 13-key `AdvisoryRecord`
- `scripts/` – PowerShell helpers (`discover_rss.ps1`, `verify_extract.ps1`)
- `src/advisoryops/` – CLI + pipeline code
- `samples/` – sample advisories + raw snapshots used for testing
- `outputs/` – runtime artifacts (gitignored)

## Docs entry points

- `docs/DOC-01_Master_Index.md` – master index + current status
- `docs/DOC-02_Data_Contracts.md` – AdvisoryRecord contract + normalization rules
- `docs/DOC-05_Ingestion.md` – discovery + ingestion pipeline details
- `docs/DOC-10_Stack_and_Deployment.md` – stack pinning + repo hygiene notes
