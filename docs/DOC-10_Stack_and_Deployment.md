# Stack and Deployment (DOC-10)

**Last updated:** 2026-02-10

This doc describes the development/runtime stack and how to run AdvisoryOps in a repeatable way.

---

## 1) Runtime stack (current)

- **Python**: 3.11+ (recommended)
- **Packaging**: `pip install -e .` (editable install during development)
- **CLI entrypoint**: `advisoryops` (console script)
- **Outputs**: written under `outputs/` (gitignored)

---

## 2) Local development (Windows PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -U pip
.\.venv\Scripts\pip.exe install -e .

.\.venv\Scripts\python.exe -m pytest -q
```

---

## 3) Headless operation

### 3.1 Recommended primitive: `source-run`
For automation, prefer `source-run` because it:
- runs discovery (and optional ingest)
- writes a JSON run report under `outputs/source_runs/…`

Example:
```powershell
.\.venv\Scriptsdvisoryops.exe source-run --source cisa-icsma --limit 25
```

### 3.2 Scheduling options
- Windows Task Scheduler (run PowerShell with repo root as working directory)
- GitHub Actions (runner clones repo and runs CLI)
- Cron (Linux)

### 3.3 Machine-readable status
Automation should read:
- `outputs/source_runs/<timestamp>_<source_id>.json` (what ran + artifact paths)
- `outputs/discover/<source_id>/new_items.jsonl` (stream of new signals)

Avoid scraping console output.

---

## 4) Output layout (conventions)

- Discovery: `outputs/discover/<source_id>/...`
- Source-run reports: `outputs/source_runs/<ts>_<source>.json`
- Ingest: `outputs/ingest/<advisory_id>/...`
- Extract: `outputs/extract/<advisory_id>/...`

---

## 5) CI notes (current)
- Unit tests are expected to pass in <1s (`pytest -q`)
- Contract validation is performed by scripts like `scripts/verify_extract.ps1`

---

## 6) Security notes
- Secrets (e.g., `OPENAI_API_KEY`) live in `.env` and must never be committed.
- Outputs may contain advisory text; treat `outputs/` as sensitive and keep it out of git.
