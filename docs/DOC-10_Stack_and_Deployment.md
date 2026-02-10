# DOC-10 — Stack and Deployment (MVP)

## 1) Current repo reality (as of 2026-02-10)

Today the repo ships a **local CLI** pipeline:

- `advisoryops ingest` → writes `outputs/ingest/<advisory_id>/...`
- `advisoryops extract` → writes `outputs/extract/<advisory_id>/...`
- `advisoryops discover` → writes `outputs/discover/<source_id>/...`

A web/API deployment is a **future milestone**. Do not assume FastAPI/Railway/Postgres are already present in code.

⚠️ Known regression in this snapshot:
- `advisoryops source-run --ingest` is currently a no-op because `src/advisoryops/source_run.py` is truncated (see DOC-01 / DOC-05).

---

## 2) Target MVP stack (decision / roadmap)

These are the intended deployment choices once the CLI pipeline is locked:

- Backend runtime: **Python**
- API framework: **FastAPI**
- Deployment shape: **Monolith container** (API + worker code in same repo; deploy as one or two processes)
- Hosting (MVP): **Railway**
- Scheduler: **Railway Cron Jobs**
- Database (prod MVP): **Postgres**
- Object storage: **Cloudflare R2** (S3-compatible API)

---

## 3) Local dev setup (Windows PowerShell)

From repo root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
pip install -e .

Copy-Item .env.example .env
# edit .env and set OPENAI_API_KEY
```

Validation gates:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\scripts\verify_extract.ps1
```

---

## 4) Text/encoding hygiene (important)

The repo has hit real-world issues caused by text encoding and invisible control characters.

**Rules of thumb:**
- Prefer **UTF-8 (no BOM)** for `.json`, `.md`, and `.txt`
- Keep `.ps1` files in a Windows-friendly encoding, but avoid introducing hidden control characters
- Avoid copying text that introduces ASCII control chars like **BEL (0x07)** or **VT (0x0B)** (these break PowerShell copy/paste)

**Line endings:**
- `.gitattributes` is used to normalize line endings:
  - **LF** for repo text files
  - **CRLF** for `.ps1/.cmd/.bat`

If you see “broken” command paths in docs (characters missing or strange symbols in the middle of a path),
sanitize the file by removing control chars and re-saving as UTF-8.

---

## 5) Dependency policy (v1)

- Prefer stdlib-only implementations unless a new dependency is explicitly approved.
- Treat fetch behavior as “polite by default”:
  - timeouts
  - retry/backoff
  - rate limit ~1 req/sec per source (configurable per source)

