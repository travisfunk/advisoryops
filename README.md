# AdvisoryOps

AdvisoryOps is a **config-driven security advisory aggregator** that turns heterogeneous vendor/government feeds into a consistent set of local artifacts you can automate against (JSON/JSONL), then (later) correlates/deduplicates and enriches them.

**Updated:** 2026-02-10 (docs rewritten to match current CLI + outputs)

---

## What it does today (v1)

### 1) Discovery (feeds → normalized “signals”)
- Reads a configured source (RSS/Atom, JSON feed, CSV feed).
- Applies cheap keyword filters (no LLMs).
- Tracks “new” vs “seen” items in `state.json`.
- Writes machine-friendly artifacts:
  - `feed.json` / `new_items.json`
  - `items.jsonl` / `new_items.jsonl` (one item per line, stable for diffs)
  - `meta.json` (timing, counts, output paths, errors)
- Adds a stable per-source `signal_id` to every item (SHA-256 of `{source_id}|{guid|link|title}`) to enable future correlation/dedup.

### 2) Source run (orchestration)
`advisoryops source-run` runs discovery and (optionally) ingest, and writes a **run report JSON** to `outputs/source_runs/…` so automation does not have to scrape console output.

### 3) Ingest + Extract (advisory pages → structured record)
For advisory-style sources (e.g., CISA ICS advisories), ingest downloads the linked page and produces raw + normalized text snapshots; extract then produces a normalized `advisory_record.json` for downstream use.

> **Note:** Correlation/dedup across sources (merging “same issue” reported by multiple sources) is a planned milestone. We track that design/doc update after the correlation feature is implemented.

---

## Quickstart (Windows PowerShell)

```powershell
# from repo root
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -U pip
.\.venv\Scripts\pip.exe install -e .

# run discovery + run report
.\.venv\Scriptsdvisoryops.exe source-run --source cisa-icsma --limit 5

# force all items treated as new (deletes outputs/discover/<source>/state.json first)
.\.venv\Scriptsdvisoryops.exe source-run --source cisa-kev-json --limit 5 --reset-state
```

---

## Where outputs go

### Discovery artifacts
`outputs/discover/<source_id>/`
- `raw_feed.<xml|json|csv>` — raw fetched bytes
- `feed.json` — normalized items (post-filter, post-limit)
- `new_items.json` — subset deemed “new”
- `state.json` — `seen` map (keys include both `guid` and `signal_id`)
- `items.jsonl` — one JSON object per line (stable)
- `new_items.jsonl` — one JSON object per line (stable)
- `meta.json` — timings, counts, output paths, errors

### Source-run reports
`outputs/source_runs/<timestamp>_<source_id>.json`

---

## Docs

Start at: `docs/DOC-01_Master_Index.md`
