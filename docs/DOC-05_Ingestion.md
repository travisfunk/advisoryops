# DOC-05 Ingestion Sources & Parsers (v1)

## 0) Purpose

Define how AdvisoryOps ingests advisory content (URLs, PDFs, text), normalizes raw content, and produces clean inputs for the extraction model and downstream workflows.

This doc is the canonical spec for:

- supported ingestion inputs (URL / PDF / text)
- discovery feed parsers (rss/json/csv)
- snapshot + hashing strategy
- output artifact locations
- guardrails (scope, cost control, and parser safety)

---

## 1) Ingestion inputs (MVP)

MVP supports ingestion from:

1) **URL (HTML pages)**: vendor advisories, security bulletins, regulator pages  
2) **PDF**: vendor bulletins, FDA communications, offline artifacts  
3) **Raw text**: pasted email/advisory text  

Ingestion is “best effort” and intentionally uses **stdlib-only** parsing.

### 1.1 URL ingestion (HTML)

- Fetch URL with a standard user-agent
- Extract text:
  - strip `<script>`/`<style>` blocks
  - replace `<br>` and `</p>` with newlines
  - remove remaining tags
  - normalize whitespace
- Persist raw + normalized snapshots

### 1.2 PDF ingestion

- Extract text from PDF (current implementation relies on the configured PDF parsing approach in `ingest.py`)
- Normalize whitespace
- Persist raw + normalized snapshots

### 1.3 Raw text ingestion

- Read `.txt` file (or provided string)
- Normalize whitespace
- Persist raw + normalized snapshots

---

## 2) Normalization, hashing, and advisory_id

- Normalize text into a deterministic canonical form (`normalized.txt`)
- Compute SHA-256 on normalized text
- Derive `advisory_id` from the hash (`adv_<...>`) to ensure stable identity across re-ingests

---

## 3) Discovery (configured sources)

Discovery is separate from ingestion.

- Discovery reads a **source feed** (RSS/Atom, JSON feed, or CSV feed)
- It applies **cheap filters** (keywords/regex) and a hard `--limit`
- It writes discovery artifacts to `outputs/discover/<source_id>/...`
- Selected items can later be ingested via `advisoryops ingest --url ...`

### 3.1 Implemented discovery `page_type` parsers (v1.1)

Implemented in code today:

- `rss_atom` — RSS/Atom feeds
- `json_feed` — JSON feeds where entries map to a `link`
- `csv_feed` — CSV feeds where rows map to a `link`

Declared (future) page types exist in the config validator, but **must remain disabled** until implemented:

- `html_generic`, `html_list`, `html_table`, `json_api`, `pdf_bulletin`

### 3.2 Discovery outputs

Written to `outputs/discover/<source_id>/`:

- `raw_feed.<ext>` — raw bytes (xml/json/csv)
- `feed.json` — parsed items (all)
- `new_items.json` — parsed items not seen before (based on `state.json`)
- `state.json` — simple dedupe store (seen GUIDs)

---

## 4) `discover` vs `source-run`

### 4.1 `advisoryops discover`

`discover` fetches/parses/writes discovery artifacts:

```powershell
.\.venv\Scripts\advisoryops.exe discover --source cisa-icsma --limit 5
.\.venv\Scripts\advisoryops.exe discover --source cisa-icsma --limit 5 --show-links
```

### 4.2 `advisoryops source-run`

`source-run` is intended to orchestrate:

1) discovery  
2) selection (`--ingest-mode new|all`)  
3) optional ingest of selected links (`--ingest`)  
4) run reporting (`outputs/source_runs/...`)  

**Current snapshot note (2026-02-10):** `src/advisoryops/source_run.py` is truncated and exits before the ingest loop.  
So `source-run` currently performs discovery and printing, but **`--ingest` does not ingest anything**.

Workaround until the regression is fixed:
- run `discover` (or `source-run` without `--ingest`) to obtain links
- run `advisoryops ingest --url <link>` manually for the items you want

---

## 5) Scope and v1 guardrails

Each configured source declares a `scope`:

- `advisory` — intended to lead to ingest/extract pipelines
- `dataset` — structured datasets (e.g., KEV). **Discovery-only** in v1.

Decision for v1:
- `scope: dataset` sources are discoverable, but dataset-to-advisory ingestion is treated as a separate future milestone with its own output contracts.

Cost control guardrail:
- `source-run --limit` is required (hard cap) to prevent runaway fetch/ingest.

Config note:
- `configs/sources.json` has a root `defaults` object, but it is **not currently applied** by the loader. Only per-source `timeout_s`, `retries`, and `rate_limit_rps` are honored.

---

## 6) Output artifacts (ground truth)

### 6.1 Ingest outputs

`outputs/ingest/<advisory_id>/`:

- `raw.txt`
- `normalized.txt`
- `source.json` (paths + metadata)

### 6.2 Extract outputs

`outputs/extract/<advisory_id>/`:

- `advisory_record.json` (stable contract)
- `extract_meta.json` (model, timestamps, hashes, etc.)

### 6.3 Discovery outputs

`outputs/discover/<source_id>/`:

- `raw_feed.<ext>`
- `feed.json`
- `new_items.json`
- `state.json`

---

## 7) Validation

- `scripts/verify_extract.ps1` is the MVP “gate”:
  - checks the 13 required keys exist in `advisory_record.json`
  - checks no mojibake markers appear in values

