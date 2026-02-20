# Project Status

**Last updated:** 2026-02-10

This file is the single source of truth for “what is done” vs “what is next”.

---

## Current state (as of 2026-02-10)

### ✅ Working (verified in local runs)
- **Ingest**: `advisoryops ingest --url <advisory_url>` writes:
  - `outputs/ingest/<advisory_id>/raw.txt`
  - `outputs/ingest/<advisory_id>/normalized.txt`
  - `outputs/ingest/<advisory_id>/source.json` (paths + metadata)
- **Extract**: `advisoryops extract --advisory-id <advisory_id>` writes:
  - `outputs/extract/<advisory_id>/advisory_record.json` (13 top-level keys, schema-validated)
- **Discovery**: `advisoryops discover --source <id>` writes standardized artifacts including JSONL + meta.
- **Source runner**: `advisoryops source-run --source <id> --limit N` runs discovery (and optional ingest), prints a summary, and writes a **run report JSON** under `outputs/source_runs/…`.

### ✅ Discovery hardening (completed)
- Add `meta.json` under `outputs/discover/<source_id>/` (timings, counts, output paths, errors)
- Add `items.jsonl` + `new_items.jsonl` (stable, one-item-per-line artifacts for diffs/automation)
- Add deterministic per-source `signal_id` to each discovered item (SHA-256)
- Track “new” by `guid` **or** `signal_id` (backwards compatible; state stores both keys)
- Add `--reset-state` to `source-run` to delete `outputs/discover/<source>/state.json` before discovery
- Write run report JSON for discovery-only runs (so automation doesn’t parse console output)

---

## Known gaps / next milestones

### 🔜 Correlation + de-dup (high priority next)
Goal: if 5 sources report the same vuln/issue, we recognize and combine them (avoid multiple entries), and optionally merge “missing fields” across sources.

Deliverables (when implemented):
- Deterministic correlation keys and merge policy (CVE-based matching first; heuristics fallbacks)
- `Signals → Issues` mapping artifacts + dedup report
- Doc update: correlation/dedup design + merge policy (tracked as a single docs update after milestone completion)

### 🔜 Enrichment + matching (later)
- Link to NVD/CVE records; vendor/product normalization
- Match issues to local environment/inventory (future integration layer)

---

## Operational notes
- Prefer deterministic, copy/paste scripts (PowerShell-safe) and keep dependencies minimal (stdlib-first).
- Maintain commit messages with multi-line notes: **Why / How / Verified**.
