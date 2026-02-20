# Discovery and Ingestion (DOC-05)

**Last updated:** 2026-02-10

This doc describes the end-to-end **operational workflow** and the CLI surface area for:
- discovery (feeds → signals + “new” tracking),
- source-run orchestration (discovery + optional ingest),
- ingest + extract (advisory pages → `AdvisoryRecord`).

---

## 0) Mental model

### Terms
- **Source**: a configured feed/dataset/advisory stream in `configs/sources.json`.
- **Signal**: one discovered item from a source (normalized minimal contract).
- **Issue**: (future) a correlated/deduped object spanning multiple signals/sources.

### Stages
1. **Discovery**: fetch and parse a source feed → write `outputs/discover/<source_id>/…`
2. **Source-run**: run discovery (+ optional ingest), then write `outputs/source_runs/<ts>_<source>.json`
3. **Ingest** (advisory sources): fetch each selected advisory link → raw + normalized text
4. **Extract**: GPT-assisted extraction → `advisory_record.json`

---

## 1) Discovery

### 1.1 Command
Discovery is available via:
- `advisoryops discover --source <id> --limit N [...]` (direct), or
- `advisoryops source-run --source <id> --limit N [...]` (recommended; adds run report)

### 1.2 Outputs (authoritative)
Discovery writes:

`outputs/discover/<source_id>/`
- `raw_feed.<xml|json|csv>`
- `feed.json`
- `new_items.json`
- `state.json`
- `items.jsonl`
- `new_items.jsonl`
- `meta.json`

See `DOC-02_Data_Contracts.md` for exact shapes.

### 1.3 New-item detection (state.json)
- Items are considered “seen” if **either** `guid` **or** `signal_id` exists in `state.json:seen`.
- Discovery stores both keys going forward.

### 1.4 `signal_id`
A deterministic per-source identifier for a discovered item.
- Used for stable downstream joins and future correlation/dedup.
- Implemented as SHA-256 hex of `{source_id}|{guid|link|title}`.

---

## 2) Source-run (discovery orchestration)

### 2.1 Why `source-run` exists
Automation should not have to parse console output. `source-run` writes a single JSON report that includes:
- which source ran,
- what was selected (“new” count),
- where artifacts are on disk,
- sample links.

### 2.2 Command
```powershell
.\.venv\Scriptsdvisoryops.exe source-run --source <source_id> --limit <N> [options]
```

### 2.3 Flags (source-run)
Required:
- `--source <source_id>`
- `--limit <N>`

Optional:
- `--ingest` — run ingest (and extract where applicable) for selected items
- `--ingest-mode new|all` — selection strategy (default: `new`)
  - `new`: act only on `new_items.json`
  - `all`: act on all items in `feed.json`
- `--dry-run` — reserved; discovery still runs and writes artifacts, ingest stage is skipped
- `--show-links` — prints a small sample of selected links to console
- `--reset-state` — deletes `outputs/discover/<source_id>/state.json` before discovery (forces items treated as new)
- `--out-root-discover <path>` — override discovery output root (default: `outputs/discover`)
- `--out-root-runs <path>` — override run-report output root (default: `outputs/source_runs`)

### 2.4 Run report JSON
After each `source-run`, a report is written:

`outputs/source_runs/<timestamp>_<source_id>.json`

This is the primary contract for schedulers (n8n, Windows Task Scheduler, GitHub Actions, etc.).
See `DOC-02_Data_Contracts.md` for fields.

---

## 3) Ingest (advisory sources)

### 3.1 When to use ingest
Use `--ingest` when the selected items’ `link` points at an advisory page you want to snapshot and extract.

Notes:
- For **dataset sources** (e.g., KEV), links may point to CVE/NVD pages and ingest/extract may not produce a meaningful `AdvisoryRecord`. Dataset ingest is a future enhancement; discovery outputs are still valuable today.

### 3.2 Command
```powershell
.\.venv\Scriptsdvisoryops.exe ingest --url <advisory_url>
```

### 3.3 Outputs
`outputs/ingest/<advisory_id>/`
- `raw.txt`
- `normalized.txt`
- `source.json`

---

## 4) Extract (AdvisoryRecord)

### 4.1 Command
```powershell
.\.venv\Scriptsdvisoryops.exe extract --advisory-id <advisory_id>
```

### 4.2 Outputs
`outputs/extract/<advisory_id>/`
- `advisory_record.json` (13 top-level keys; schema validated)

Verification:
```powershell
.\.venv\Scripts\pwsh.exe -File .\scriptserify_extract.ps1
```

---

## 5) Troubleshooting checklist (fast)

1. **Run tests**
```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

2. **Confirm discovery artifacts exist**
```powershell
dir .\outputs\discover\<source_id>
```

3. **Force re-run as “new”**
```powershell
.\.venv\Scriptsdvisoryops.exe source-run --source <source_id> --limit 5 --reset-state
```

4. **Use run report for paths**
```powershell
Get-ChildItem .\outputs\source_runs\*.json | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Get-Content
```
