# Project Status

**Last updated:** 2026-03-17

This file is the single source of truth for “what is done” vs “what is next”.

---

## Current state (as of 2026-03-17)

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

### ✅ Pass 1 public-side expansion (completed)
- Expanded the low-friction public source set to **30+ enabled RSS/JSON/CSV feeds**
- Locked the public-side v0 contract in docs:
  - **SourceObservation v0** via discovery artifacts
  - **CanonicalIssue v0** via correlation artifacts
- Added parser support for:
  - openFDA-style `results` JSON feeds
  - generic CVE CSV feeds (for example EPSS-style data)

### ✅ Smoke-test cleanup round (completed)
- Verified a first wave of high-value public sources locally
- Fixed dead source definitions identified in smoke tests:
  - updated **NCSC** RSS URL
  - updated **Claroty Team82** RSS URL
  - switched **Health Canada** recall feed to HTTPS
- Improved **openFDA device recall** discovery links by generating stable API query links when records do not include a direct URL
- Broadened keyword coverage for partial-but-reachable feeds like **FDA MedWatch** and **Armis Labs**

### ✅ Validated source manifest + combined public feed (completed)
- Added `configs/community_public_sources.json` to capture the **Gold Pass 1** validated public source set
- Added `advisoryops community-build` to build the first combined community/public feed from the validated source set
- Community build now writes file-based public artifacts:
  - `issues_public.jsonl`
  - `alerts_public.jsonl`
  - `feed_latest.json`
  - `feed.csv`
  - `validated_sources.json`
  - `meta.json`

---

## Known gaps / next milestones

### 🔜 Public source hygiene round 3 (high priority next)
Goal: keep tightening the public-side signal quality after the first combined feed exists.

Deliverables:
- Demote or disable stale/noisy sources like `health-canada-recalls` if they remain low-value
- Decide whether `armis-labs` should remain candidate-only or get source-specific filter tuning
- Expand the validated set only after new sources pass smoke testing

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
