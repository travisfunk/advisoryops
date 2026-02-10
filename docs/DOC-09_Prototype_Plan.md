# DOC-09 Prototype & Implementation Plan (v1)

## 0) Purpose

Define a solo-friendly, thin-vertical prototype plan for AdvisoryOps that is:

- grant-aligned (evaluation + public good)
- MVP-focused (minimum integrations)
- expandable (core vs pro)

This plan is intentionally biased toward building a working pipeline quickly.

---

## 1) Guiding principles

- Build the **thin vertical slice first**: ingest → extract → cluster → match → packet → export → (optional) ServiceNow ticket
- Prefer **config-driven** design over per-customer custom code
- Treat “vendor-managed / can’t patch” as first-class
- Avoid PHI and sensitive customer data by design
- Control LLM cost via **cheap discovery/filtering** first + hard `--limit` caps

---

## 2) Current status (as of 2026-02-10)

### ✅ Completed / working

- **Milestone B — Ingest + AdvisoryRecord extraction** ✅  
  - `advisoryops ingest` and `advisoryops extract` produce a stable 13-key `AdvisoryRecord`  
  - `scripts/verify_extract.ps1` is the gate for contract validity

- **Discovery framework** ✅  
  - Config-driven sources (`configs/sources.json`)
  - Implemented discovery parsers: `rss_atom`, `json_feed`, `csv_feed`
  - `advisoryops discover` writes `outputs/discover/<source_id>/...`

### ⚠️ Known regression (must fix next)

- **`source-run --ingest` no-op**  
  - In this snapshot, `src/advisoryops/source_run.py` is truncated and exits before ingesting selected items.  
  - A complete implementation exists in `src/advisoryops/source_run.py.bak.*`.  
  - Workaround: `discover` → manually `ingest --url` → `extract`.

---

## 3) Next milestones (recommended order)

### Milestone C — Restore `source-run` ingest + lock it with tests

Goal:
- `advisoryops source-run --source <advisory_source> --limit N --ingest --ingest-mode new|all` reliably ingests items and writes run reports.

Acceptance criteria:
- `pytest` includes a test that fails if `source-run` ingest logic is missing
- `source-run` does not error when Selected == 0 (clean no-op)
- `scope: dataset` sources remain discover-only in v1 (skip ingest cleanly)

### Milestone D — Matching + clustering (thin + deterministic)

- De-dupe across sources
- Cluster advisories by vendor/product/CVE
- Persist a minimal “match candidate” record for later enrichment

### Milestone E — Packet/export + integrations (optional)

- Generate a remediation packet (markdown/PDF) per advisory cluster
- Optional: ticket creation integration (ServiceNow / Jira) behind a feature flag

---

## 4) Engineering constraints (v1)

- PowerShell-safe scripts/commands
- Prefer explicit venv invocation: `.\.venv\Scripts\python.exe`
- Prefer stdlib; no new dependencies unless explicitly approved
- Polite fetching: timeout + retry/backoff; default rate limit 1 req/sec
- Store raw snapshots under `outputs/...` and gitignore them
- After measurable milestones: run `pytest` + `scripts/verify_extract.ps1` before commit/push + doc updates
