# DOC-10 — Stack and Deployment (MVP)
## Locked MVP Stack (Decision)
- Backend runtime: **Python**
- API framework: **FastAPI**
- Deployment shape: **Monolith container** (API + worker code in same repo; deploy as one or two processes)
- Hosting (MVP): **Railway**
- Scheduler: **Railway Cron Jobs**
- Job execution model: **Postgres-backed queue + worker**
- Database (prod MVP): **Postgres**
- Object storage: **Cloudflare R2** (S3-compatible API)
## Current repo state (as of 2026-02-08)

The repo is currently shipping the ingestion/extraction pipeline as a **local CLI** (writing to `outputs/ingest/…` and `outputs/extract/…`).  
FastAPI + Railway deployment remains the intended MVP hosting shape, but is not required to run or test the extraction pipeline today.

## Local dev setup (Windows / PowerShell)

~~~powershell
# from repo root
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -U pip
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m pip install -U pytest
~~~

## Run an end-to-end smoke test (real LLM extract)

~~~powershell
# Option A: Validate an existing ingested advisory (calls the LLM)
.\scripts\verify_extract.ps1 -AdvisoryId adv_...

# Option B: Source Framework v1 (discover + ingest) with spend guardrails (no LLM unless you run verify_extract)
.\.venv\Scripts\advisoryops.exe source-run --source cisa-icsma --limit 1 --ingest --ingest-mode all

# then validate the ingested advisory_id (calls the LLM)
# .\scripts\verify_extract.ps1 -AdvisoryId adv_...
~~~

## Offline unit tests

~~~powershell
python -m pytest -q
~~~

Notes:

- The extractor writes a **stable 13-key** `advisory_record.json` (see DOC-02).
- If you see `â€™` etc only in PowerShell output but not in Python, it’s almost always a **read/display encoding issue**, not a file issue.

## Why this stack
- Minimizes operational overhead during MVP
- Strong ecosystem for parsing/PDF/text normalization + LLM extraction
- Portable architecture: container + S3-compatible storage makes later migration straightforward
## Scale-up path (later)
- Queue: Postgres queue → managed queue (Cloud Tasks/PubSub/SQS/CF Queues)
- Hosting: Railway → Cloud Run/AWS (no architecture rewrite)
- Add UI separately (optional TS frontend)

## Repo hygiene (encoding + line endings)

To avoid “mystery diffs” and mojibake issues, this repo includes `.gitattributes`:

- Store text files with **LF** line endings in the repo
- Keep Windows scripts (`*.ps1`, `*.cmd`, `*.bat`) as **CRLF**
- Mark common binaries (`.png`, `.pdf`, `.zip`, etc.) as `binary`

If you ever see a leading `﻿` at the top of a file, that’s typically a UTF‑8 BOM.
The docs are kept BOM-free and LF-normalized to reduce churn in diffs.

Recommended workflow on Windows:
- Always run tools from the venv (`.\.venv\Scripts\python.exe`, `.\.venv\Scriptsdvisoryops.exe`)
- Let `.gitattributes` handle line endings; avoid manual editor conversions unless necessary
