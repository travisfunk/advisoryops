# AdvisoryOps MVP (Ingest + Extract)

The MVP provides a minimal CLI:
- `advisoryops ingest` — URL/text/PDF → normalized snapshot + hashes under `outputs/ingest/<advisory_id>/`
- `advisoryops extract` — normalized text → `AdvisoryRecord` JSON under `outputs/extract/<advisory_id>/`

The `AdvisoryRecord` contract is **13 keys** (schema in `schemas/advisory_record_schema.json`).

## Quickstart (Windows PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
pip install -e .

Copy-Item .env.example .env
# edit .env (OPENAI_API_KEY, etc)

# Smoke test: runs extract + validates contract + scans for mojibake
.\scriptserify_extract.ps1
```

## Typical flow

```powershell
# ingest a sample advisory
.\.venv\Scriptsdvisoryops.exe ingest --text-file .\samplesdvisories\sample_advisory.txt

# then extract (use the printed advisory_id)
.\.venv\Scriptsdvisoryops.exe extract --advisory-id adv_<...>

# validate output contract + encoding
.\scriptserify_extract.ps1
```
