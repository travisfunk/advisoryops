# AdvisoryOps MVP (Ingest + Extract)

This adds a minimal CLI:
- `advisoryops ingest` (URL/text/PDF -> normalized snapshot + hashes)
- `advisoryops extract` (normalized text -> AdvisoryRecord.json using OpenAI Structured Outputs)

Quickstart (Windows PowerShell):
1) python -m venv .venv
2) .\.venv\Scripts\Activate.ps1
3) pip install -U pip
4) pip install -e .
5) copy .env.example .env   (then edit .env)
6) advisoryops ingest --text-file .\samples\advisories\sample_advisory.txt
7) advisoryops extract --advisory-id adv_<...>

Outputs are written under outputs/ingest/<advisory_id>/ (gitignored).
