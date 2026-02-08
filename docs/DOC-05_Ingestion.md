# DOC-05 Ingestion Sources & Parsers (v1)

## 0) Purpose
Define how AdvisoryOps ingests advisory content (URLs, PDFs, text), normalizes raw content, and produces clean inputs for the extraction model and downstream clustering/matching.

This doc is the canonical spec for:
- supported source types (public and user-provided)
- ingestion steps and data captured
- hashing/snapshot strategy
- parser constraints and safety rules

---

## 1) Source types (MVP)
MVP supports ingestion from:
1) **URL (HTML pages)**: vendor advisories, security bulletins, regulator pages
2) **PDF**: vendor bulletins, FDA communications, offline artifacts
3) **Raw text**: pasted email/advisory text

We do not require web scraping beyond basic retrieval/parsing for MVP. If retrieval fails, user can paste text or upload PDF.

---

## 2) Ingestion pipeline (MVP)
### Step A — Acquire content
Input: (url | pdf file | raw text)

Capture:
- source_url (if provided)
- retrieved_at timestamp
- content_type (html/pdf/text)
- raw bytes or raw text

### Step B — Normalize content
- For HTML: extract main text and preserve a minimal representation
- For PDF: extract text (best-effort) and preserve PDF hash
- For raw text: preserve as-is

### Step C — Snapshot & hashing
We compute:
- content_hash (sha256 of normalized raw text or bytes)
- advisory_id (deterministic id: e.g., `adv_<sha256_prefix>`)

This enables:
- idempotent ingestion (same advisory won’t create duplicates)
- provenance tracking (what changed between versions)

---

## 3) Snapshot storage strategy
MVP storage (local filesystem) layout proposal:
- `outputs/ingest/<advisory_id>/raw.txt`
- `outputs/ingest/<advisory_id>/source.json` (url, timestamps, hashes)
- `outputs/ingest/<advisory_id>/normalized.txt`
- optional: `outputs/ingest/<advisory_id>/original.pdf`

These are **gitignored** and treated as run artifacts, not repo content.

---

## 4) What the extractor receives
The extraction model receives:
- normalized text
- minimal source metadata:
  - publisher guess (optional)
  - source URL
  - published date guess (optional)
  - content hash
- system prompt + schema definition for AdvisoryRecord

Extractor must return:
- a strongly typed AdvisoryRecord (DOC-02)
- plus warnings for ambiguity
- plus references to extracted key points for citations

## 5) Public source categories (defensive-only)

### 5.1 Vendor advisories (primary)
- Vendor security bulletins and “product security” pages
- Firmware/software release notes containing security content
- OEM “customer letters” if publicly hosted

### 5.2 Regulators / public agencies
- FDA safety communications where public
- CISA ICS advisories (when relevant)
- NVD references (for CVE detail enrichment) — optional

### 5.3 Other sources (MVP optional)
- CERT advisories
- Public mailing list posts by vendors

**Important:** We do not ingest private, stolen, or illicit content sources. All corpus building for “public good” uses public sources only.

---

## 6) Acquisition notes (URL fetching)
MVP should keep URL fetching simple and polite:
- standard GET with user agent string
- obey basic timeouts
- store retrieved bytes (optional) and extracted text
- if blocked/403: fall back to “paste text” workflow

We avoid fragile scraping (headless browsers) for MVP.

---

## 7) Safety & constraints
- Defensive focus only: ingestion supports remediation planning and governance.
- Avoid collecting PHI: advisory content is public, facility context is minimal.
- If users paste internal tickets/emails, we should warn them not to include PHI.

## 8) Parsing & cleanup rules (MVP)

### 8.1 HTML extraction
Goal: remove navigation and boilerplate while preserving meaningful advisory content.

Rules:
- prefer main/article elements where available
- remove menus, footers, repeated nav items
- preserve headings and bullet lists where possible
- keep tables as text (best-effort)
- preserve links separately if needed (optional)

### 8.2 PDF extraction
Goal: best-effort text extraction suitable for model input.

Rules:
- extract text in reading order (best-effort)
- preserve page breaks as delimiters (e.g., `\n\n--- page N ---\n\n`)
- if text extraction is garbage (scanned PDF):
  - fallback: user-provided text
  - OCR is optional later (higher cost, error-prone)

### 8.3 Normalization
- normalize whitespace
- keep section boundaries (headings)
- preserve version strings (e.g., “v3.2.1”)
- do not “rewrite” content during ingestion (extraction model will interpret)

---

## 9) Quality checks before extraction
Before calling extraction, run quick checks:
- minimum length threshold (avoid empty pages)
- detect duplicate content (hash-based)
- detect obvious non-advisory pages (login pages, generic marketing pages)
- if uncertain: flag warning and request human confirmation

---

## 10) Multi-version advisories (updates)
If a source URL changes over time:
- content_hash changes → new AdvisoryRecord version with link to prior versions
- clustering layer (IssueCluster) handles “update/supersedes” relationships

## 11) Ingestion output artifacts (MVP)
Each ingestion produces:
- `raw_text` (normalized)
- `content_hash` (sha256)
- `advisory_id` (deterministic)
- `source metadata` (URL, retrieved_at, content_type)

Then extraction produces:
- AdvisoryRecord.json
- key_points for citations (packet sources[])

Optional enrichment (later):
- CVE detail enrichment (NVD/other)
- exploit intel enrichment (paid feeds, e.g., Flashpoint) — PRO scope

---

## 12) Changelog
- 2026-02-08: Extraction output stabilized (strict 13-key `advisory_record.json`) + deterministic mojibake cleanup + offline unit tests. Note: PowerShell validation should use UTF-8 (`Get-Content -Raw -Encoding utf8`).
- 2026-02-06: Initial v1 ingestion pipeline spec, hashing/snapshot strategy, and parsing constraints.


## Discovery Feeds (RSS/API) — Updated 2026-02-08

Discovery is a separate step from ingestion:
- **Discovery** finds candidate advisories and stores stable metadata (title/link/published_date/guid/summary).
- **Ingestion** fetches canonical content (HTML/PDF/text) and normalizes it for extraction.

### Source Registry (repo-tracked)
Discovery/ingest sources are defined in:

- `configs/sources.json` (schema_version=1)

Each source entry includes (minimum):
- `source_id` (stable id, used in CLI)
- `enabled` (true/false)
- `scope` (`advisory` | `dataset` | `news` | `threatintel`)
- `page_type` (v1 implemented: `rss_atom`; placeholders exist for future types)
- `entry_url` (feed/list URL)
- `filters` (cheap keyword/url filtering to reduce ingest/extract volume)
- polite defaults/overrides: `timeout_s`, `retries`, `rate_limit_rps`

### Implemented page types (Source Framework v1)
- `rss_atom` ✅ (implemented)
- `html_generic`, `html_list`, `html_table`, `json_feed`, `pdf_bulletin` (declared but may be unimplemented; keep sources disabled until implemented)

### Cheap Filtering (cost control)
Discovery applies only deterministic, non-LLM filters (per source):
- `filters.keywords_any`: accept if ANY keyword is present
- `filters.keywords_all`: accept if ALL keywords are present
- `filters.apply_to`: fields to search (`title`, `summary`, `description`)
- `filters.url_allow_regex` / `filters.url_deny_regex`: URL allow/deny gates

This is the primary guardrail for “mixed-topic” sources to avoid ingesting/extracting irrelevant items.

### Discovery outputs (gitignored)
For a source `<source_id>`, discovery writes:

- `outputs/discover/<source_id>/raw_feed.xml`
- `outputs/discover/<source_id>/feed.json`
- `outputs/discover/<source_id>/new_items.json`
- `outputs/discover/<source_id>/state.json` (dedupe state; preserves “seen” GUIDs)

### Stored Feed Item Fields (minimum)
- `source`
- `guid` (or a deterministic fallback)
- `title`
- `link` (canonical URL)
- `published_date` (best-effort)
- `summary` (raw)
- `fetched_at` (UTC)

### Orchestration: Source Framework v1 (discover + optional ingest)
Use:

- `advisoryops discover --source <source_id> --limit <n>`
- `advisoryops source-run --source <source_id> --limit <n> [--ingest] [--dry-run] [--ingest-mode new|all]`

`source-run` does:
1) Discover (writes outputs/discover/*)
2) Optionally ingest selected links (writes outputs/ingest/*), honoring `rate_limit_rps` between items
3) Writes a run report (gitignored): `outputs/source_runs/<timestamp>_<source_id>.json`

Notes:
- `--limit` is required on `source-run` to control spend/scope.
- `--dry-run` prints planned ingest URLs without fetching.

### Dedupe Strategy
- Discovery dedupe uses `outputs/discover/<source_id>/state.json`:
  - Primary key: `(source_id, guid)`
  - Fallbacks: link, then deterministic hash if needed
