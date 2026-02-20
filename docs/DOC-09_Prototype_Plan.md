# Prototype Plan (DOC-09)

**Last updated:** 2026-02-10

This document outlines a practical demo/POC path for AdvisoryOps that shows value early (without requiring full correlation/dedup).

---

## 1) Prototype goals

### 1.1 “Day 1” value
- Pull multiple sources reliably.
- Produce deterministic artifacts (`outputs/discover/...`) suitable for automation.
- Provide a single **run report JSON** per source-run (`outputs/source_runs/...`) so schedulers can react without parsing stdout.

### 1.2 “Day 2” value
- Ingest + extract advisory pages into normalized `AdvisoryRecord` JSON.
- Basic reporting (counts, recency, “what’s new”) driven from artifacts.

### 1.3 “Day 3” value (next milestone)
- Correlation/dedup: collapse duplicate coverage across sources into a single Issue, merge missing fields.

---

## 2) Demo scenarios

### Scenario A — Discovery-only dashboard
Run:
```powershell
.\.venv\Scriptsdvisoryops.exe source-run --source cisa-kev-json --limit 25
```

Use:
- `outputs/discover/cisa-kev-json/new_items.jsonl` as the “what’s new” stream.
- `outputs/source_runs/<ts>_cisa-kev-json.json` as the authoritative pointer to artifacts.

### Scenario B — Advisory ingest + extract
Run:
```powershell
.\.venv\Scriptsdvisoryops.exe source-run --source cisa-icsma --limit 10 --ingest
```

Show:
- `outputs/ingest/<id>/normalized.txt` snapshots for auditability
- `outputs/extract/<id>/advisory_record.json` for structured consumption

---

## 3) Prototype deliverables (minimal)

- A scheduled job (Task Scheduler / cron / GitHub Actions) that runs `source-run` on a small set of sources.
- A simple “report builder” script (later) that reads:
  - `outputs/source_runs/*.json` (what ran, where to look)
  - `outputs/discover/*/new_items.jsonl` (new signals stream)
  - `outputs/extract/*/advisory_record.json` (structured advisories)
- A short “demo pack” folder with sample outputs checked into `examples/` (optional; sanitized).

---

## 4) Out of scope for the prototype (for now)
- Cross-source correlation/dedup merge policy (tracked as next milestone)
- Deep enrichment (NVD scraping, vendor parsing beyond MVP)
- Environment-specific matching (inventory integration)
