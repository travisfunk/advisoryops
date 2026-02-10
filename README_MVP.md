# AdvisoryOps MVP (Ingest + Extract)

The MVP provides a minimal CLI:

- `advisoryops ingest` — URL/text/PDF → normalized snapshot + hashes under `outputs/ingest/<advisory_id>/`
- `advisoryops extract` — normalized text → `AdvisoryRecord` JSON under `outputs/extract/<advisory_id>/`

The `AdvisoryRecord` contract is **13 keys** (schema in `schemas/advisory_record_schema.json`).
Verification is enforced by `scripts/verify_extract.ps1`.

> Note: The repo also includes a discovery framework (`discover`, `source-run`). In the current snapshot, `source-run --ingest` is a known regression (no-op) due to a truncated `source_run.py`. The MVP ingest/extract commands are unaffected.

## Quickstart (Windows PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
pip install -e .

Copy-Item .env.example .env
# edit .env and set OPENAI_API_KEY
# optional: set OPENAI_MODEL (default is gpt-4o-mini)

# ingest sample
.\.venv\Scripts\advisoryops.exe ingest --text-file .\samples\advisories\sample_advisory.txt

# extract (use advisory_id printed by ingest)
.\.venv\Scripts\advisoryops.exe extract --advisory-id adv_<id_from_ingest>

# validate output contract
.\scripts\verify_extract.ps1 -AdvisoryId adv_<id_from_ingest>
```

## Outputs

Ingest writes:

- `outputs/ingest/<advisory_id>/raw.txt`
- `outputs/ingest/<advisory_id>/normalized.txt`
- `outputs/ingest/<advisory_id>/source.json`

Extract writes:

- `outputs/extract/<advisory_id>/advisory_record.json`
- `outputs/extract/<advisory_id>/extract_meta.json`

