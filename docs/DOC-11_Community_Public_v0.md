# Community Public Side v0 (DOC-11)

**Last updated:** 2026-03-17

This document defines **Pass 1** for the public / free side of AdvisoryOps.

The goal is not to finish the whole product. The goal is to stand up a credible, high-signal public intelligence layer quickly using the plumbing that already exists today.

---

## 1) Pass 1 objective

Ship a public corpus that can honestly say it monitors **30+ low-friction public feeds/endpoints** using the current implemented parser types:

- `rss_atom`
- `json_feed`
- `csv_feed`

Pass 1 is intentionally biased toward:
- medical-device / healthcare-specific sources
- regulatory and PSIRT-style sources
- broad cyber sources only when filtered down to healthcare / device relevance

Pass 1 is **not** the full “100+” claim yet. It is the first clean, supportable step toward that claim.

---

## 2) Public-side contract for Pass 1

### 2.1 SourceObservation v0

Use existing discovery artifacts as the public-source observation contract.

Minimum fields:
- `source`
- `signal_id`
- `guid`
- `title`
- `link`
- `published_date`
- `summary`
- `fetched_at`

This is already close to the current `DiscoverItem` contract and requires no new storage system.

### 2.2 CanonicalIssue v0

Use the current correlation output as the first public Issue contract.

Minimum fields:
- `issue_id`
- `issue_type`
- `title`
- `summary`
- `canonical_link`
- `sources`
- `links`
- `cves`
- `first_seen_at`
- `last_seen_at`
- `published_dates`
- `counts`
- `signals`

This keeps Pass 1 grounded in artifacts the repo already writes today.

### 2.3 Public alert / feed artifacts

Pass 1 public artifacts should be file-based first:
- `outputs/discover/*/items.jsonl`
- `outputs/discover/*/new_items.jsonl`
- `outputs/correlate/issues.jsonl`
- `outputs/scored/alerts.jsonl`

A public API or polished UI can come later.

---

## 3) Pass 1 source strategy

### 3.1 What counts in Pass 1
A source counts toward the public-side total only if it is:
- present in `configs/sources.json`
- `enabled=true`
- using an implemented parser type
- capable of producing normalized discovery artifacts

### 3.2 What does **not** count yet
These stay out of the Pass 1 count until implemented:
- HTML/table scrapers
- TXT-only feeds
- PDF bulletin parsing from source discovery
- API-key gated sources
- manual GitHub lists / dashboards

---

## 4) Pass 1 deliverable definition

A good Pass 1 outcome is:
- 30+ enabled public sources using current parser types
- one stable discovery contract (`SourceObservation v0`)
- one stable correlated issue contract (`CanonicalIssue v0`)
- file-based public alert artifacts
- documented path to scale from 30+ to 100+

---

## 5) After Pass 1

### Pass 2
- push toward **101 live public feeds/endpoints**
- add more regulatory / PSIRT / healthcare sources
- add the first hard parser types only where they materially expand coverage

### Pass 3
- add a simple public search/feed surface
- publish a community corpus snapshot
- expose fix/workaround visibility from normalized issue records
