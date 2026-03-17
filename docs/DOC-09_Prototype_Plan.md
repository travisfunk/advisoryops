# Prototype Plan (DOC-09)

**Last updated:** 2026-03-17

This document outlines a practical demo/POC path for AdvisoryOps that shows value early without requiring the full commercial platform.

---

## 1) Prototype goals

### 1.1 “Day 1” value
- Pull multiple sources reliably.
- Produce deterministic artifacts (`outputs/discover/...`) suitable for automation.
- Provide a single **run report JSON** per source-run (`outputs/source_runs/...`) so schedulers can react without parsing stdout.

### 1.2 “Day 2” value
- Ingest + extract advisory pages into normalized `AdvisoryRecord` JSON.
- Basic reporting (counts, recency, “what’s new”) driven from artifacts.

### 1.3 “Day 3” value
- Correlate cross-source observations into a public `CanonicalIssue v0` record.
- Score issues into a thin public alert stream (`outputs/scored/alerts.jsonl`).

---

## 2) Prototype track split

### Track A — public/community side first
The fastest useful path is the public side:
- expand the number of enabled low-friction public sources
- keep to implemented parser types (`rss_atom`, `json_feed`, `csv_feed`)
- normalize into discovery artifacts + issue artifacts that already exist

### Track B — commercial side later
Delay until the public corpus is credible:
- customer inventory upload / matching
- tailored alerts
- environment-specific risk scoring
- workflow and integration depth

---

## 3) Demo scenarios

### Scenario A — discovery-only dashboard
Run:
```powershell
.\.venv\Scriptsdvisoryops.exe source-run --source cisa-kev-json --limit 25
```

Use:
- `outputs/discover/cisa-kev-json/new_items.jsonl` as the “what’s new” stream.
- `outputs/source_runs/<ts>_cisa-kev-json.json` as the authoritative pointer to artifacts.

### Scenario B — advisory ingest + extract
Run:
```powershell
.\.venv\Scriptsdvisoryops.exe source-run --source cisa-icsma --limit 10 --ingest
```

Show:
- `outputs/ingest/<id>/normalized.txt` snapshots for auditability
- `outputs/extract/<id>/advisory_record.json` for structured consumption

### Scenario C — public issue feed
Run discovery across a small pack of enabled sources, then correlate + score.

Show:
- `outputs/correlate/issues.jsonl`
- `outputs/scored/issues_scored.jsonl`
- `outputs/scored/alerts.jsonl`

This is the first credible public/community product surface even before a UI exists.

---

## 4) Prototype deliverables (minimal)

- A scheduled job (Task Scheduler / cron / GitHub Actions) that runs `source-run` on a growing public-source pack.
- A simple “report builder” script (later) that reads:
  - `outputs/source_runs/*.json` (what ran, where to look)
  - `outputs/discover/*/new_items.jsonl` (new observations stream)
  - `outputs/correlate/issues.jsonl` (canonical issue stream)
  - `outputs/scored/alerts.jsonl` (alert feed)
- A short “demo pack” folder with sample outputs checked into `examples/` (optional; sanitized).

---

## 5) Pass 1 definition

Pass 1 is complete when all of the following are true:
- 30+ enabled public sources are configured using implemented parser types only
- discovery artifacts are being produced cleanly from that source pack
- `SourceObservation v0` is treated as the stable public observation contract
- `CanonicalIssue v0` is treated as the stable public issue contract
- the repo can generate a simple public alert stream from scored issues

---

## 6) Out of scope for Pass 1
- 100+ claim (that is Pass 2)
- HTML/text/dashboard/manual-source plumbing
- environment-specific matching (inventory integration)
- tailored commercial alerting
- polished public UI / search product
