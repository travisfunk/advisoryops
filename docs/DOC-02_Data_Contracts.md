# Data Contracts (DOC-02)

**Last updated:** 2026-02-10

This document defines the on-disk artifacts AdvisoryOps writes today and the *stable contracts* consumers can rely on.

> Convention: paths shown are relative to repo root.

---

## 1) Discovery artifacts (feeds → “signals”)

Discovery writes to:

`outputs/discover/<source_id>/`

### 1.1 raw_feed.*
**Purpose:** Exact bytes fetched from the remote source.

- RSS/Atom: `raw_feed.xml`
- JSON feed: `raw_feed.json`
- CSV feed: `raw_feed.csv`

### 1.2 feed.json
**Purpose:** Normalized discovery result *after* limit + cheap filters.

Shape:
```json
{
  "source": "<source_id>",
  "fetched_at": "<utc_iso>",
  "items": [ /* DiscoverItem */ ]
}
```

### 1.3 new_items.json
**Purpose:** Subset of `feed.json.items` deemed “new” vs `state.json`.

Shape is identical to `feed.json`.

### 1.4 items.jsonl / new_items.jsonl
**Purpose:** One JSON object per line for:
- stable diffs in git-friendly pipelines
- cheap downstream transforms without parsing a giant array

Each line is a `DiscoverItem` serialized with:
- `sort_keys=true` (stable key ordering)
- `ensure_ascii=false` (readable text)

### 1.5 state.json
**Purpose:** “seen” cache for new-item detection.

Shape:
```json
{
  "source": "<source_id>",
  "seen": {
    "<guid>": "<utc_iso_last_seen>",
    "<signal_id>": "<utc_iso_last_seen>"
  }
}
```

Notes:
- Backwards compatible: discovery treats an item as “seen” if **either** its `guid` or its `signal_id` exists in `seen`.
- Going forward, both keys are stored.

### 1.6 meta.json
**Purpose:** Always-written diagnostics (even when discovery fails).

Shape:
```json
{
  "source_id": "<source_id>",
  "source_name": "<human name>",
  "scope": "<advisory|dataset|...>",
  "page_type": "<rss_atom|json_feed|csv_feed>",
  "entry_url": "<url>",
  "started_at": "<utc_iso>",
  "fetched_at": "<utc_iso>",
  "finished_at": "<utc_iso>",
  "limit": 50,
  "counts": {
    "parsed": 123,
    "limited": 50,
    "filtered": 17,
    "new": 4
  },
  "outputs": {
    "raw_feed": "outputs\\discover\\<source_id>\\raw_feed.xml",
    "feed_json": "outputs\\discover\\<source_id>\\feed.json",
    "new_items_json": "outputs\\discover\\<source_id>\\new_items.json",
    "state_json": "outputs\\discover\\<source_id>\\state.json",
    "items_jsonl": "outputs\\discover\\<source_id>\\items.jsonl",
    "new_items_jsonl": "outputs\\discover\\<source_id>\\new_items.jsonl"
  },
  "errors": [
    { "type": "ExceptionType", "message": "..." }
  ]
}
```

### 1.7 DiscoverItem (signal) contract
Discovery outputs normalize different feeds into a common minimal item:

Required-ish (present for most sources):
- `source` (string) — the `source_id`
- `fetched_at` (utc iso string)
- `title` (string)
- `link` (string url)
- `guid` (string) — feed GUID or equivalent stable id
- `published_date` (string `YYYY-MM-DD` where available)
- `summary` (string; may be empty)

Added by AdvisoryOps:
- `signal_id` (string) — hex SHA-256 of `{source_id}|{guid|link|title}`

Optional / source-specific fields may be added by feed parsers.

---

## 2) Source-run report (orchestration)

When you run:

`advisoryops source-run --source <id> --limit N [...]`

a report JSON is written to:

`outputs/source_runs/<timestamp>_<source_id>.json`

Minimum fields:
```json
{
  "source_id": "<source_id>",
  "source_name": "...",
  "scope": "...",
  "page_type": "...",
  "entry_url": "...",
  "ingest": false,
  "dry_run": false,
  "ingest_mode": "new",
  "limit": 5,
  "started_at": "<utc_iso>",
  "finished_at": "<utc_iso>",
  "counts": {
    "selected": 0
  },
  "discover_outputs": {
    "raw_feed": "outputs\\discover\\<source_id>\\raw_feed.xml",
    "feed_json": "outputs\\discover\\<source_id>\\feed.json",
    "new_items_json": "outputs\\discover\\<source_id>\\new_items.json",
    "state_json": "outputs\\discover\\<source_id>\\state.json",
    "items_jsonl": "outputs\\discover\\<source_id>\\items.jsonl",
    "new_items_jsonl": "outputs\\discover\\<source_id>\\new_items.jsonl",
    "meta_json": "outputs\\discover\\<source_id>\\meta.json"
  },
  "sample_links": []
}
```

If `--ingest` is used, the report may include additional ingest/extract result fields (implementation-dependent).

---

## 3) Ingest artifacts (advisory URL/text → normalized snapshot)

Ingest writes to:

`outputs/ingest/<advisory_id>/`

### 3.1 raw.txt
Raw extracted text from the source (HTML/PDF/text). UTF-8.

### 3.2 normalized.txt
Mojibake fixups + whitespace normalization + stable formatting. UTF-8.

### 3.3 source.json
Metadata about the ingest run and how to find artifacts.

Shape (minimum):
```json
{
  "advisory_id": "<id>",
  "url": "<original_url_or_null>",
  "raw_path": "outputs/ingest/<id>/raw.txt",
  "normalized_path": "outputs/ingest/<id>/normalized.txt"
}
```

---

## 4) Extract artifacts (normalized snapshot → AdvisoryRecord JSON)

Extract writes to:

`outputs/extract/<advisory_id>/`

### 4.1 advisory_record.json
Schema-validated JSON with **13 top-level keys** (see `schemas/advisory_record_schema.json`).

### 4.2 schema_check.json (optional)
When verification is run, a sidecar summary may be produced by tooling/scripts.

---

## 5) Future contracts (not implemented yet)

### 5.1 Signals → Issues (correlation/dedup)
Planned: a cross-source `issue_id` and merge policy so multiple sources can collapse into one Issue.

Documentation for correlation/dedup will be updated **after** the feature is implemented (tracked in STATUS.md).
