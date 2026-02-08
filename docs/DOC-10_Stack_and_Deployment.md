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
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
python -m pip install -e .
# dev-only tests
python -m pip install -U pytest
~~~

## Run an end-to-end smoke test (real LLM extract)

~~~powershell
# End-to-end integration check (calls the LLM)
# - runs extract
# - enforces strict 13-key output contract (DOC-02)
# - deep scans JSON for mojibake markers
.\scripts\verify_extract.ps1

# Optional: validate a specific advisory id
# .\scripts\verify_extract.ps1 -AdvisoryId adv_...
__VERIFY_EXTRACT_SCRIPT_DOC10__
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
