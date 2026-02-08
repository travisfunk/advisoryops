# DOC-01 Master Index (AdvisoryOps)

## Purpose
Keep project documentation **modular, navigable, and durable**. This index defines **which document owns what** and serves as the single place to find the latest “canonical” versions.

---

## Document governance

### Promotion rule
- **Chat = working discussion**
- **Docs in this repo = canonical** once we agree something is stable enough to build against.

### Ownership rule
Each topic has exactly **one home document**. If content belongs elsewhere, reference it rather than duplicating it.

### Versioning rule
- Contracts/playbooks use visible `v1 / v1.1 / v2` versioning.
- Breaking changes require: “What changed” + “Migration notes”.

---

## Canonical document set

These are the authoritative docs for the repo. If a file conflicts with these, these win.

### DOC-01 Master Index
This file. The map, status, and “where to start”.

### DOC-02 Data Contracts
Canonical schemas and file formats. Includes the **current stable extract output contract** (13 keys) plus the extended contract roadmap.

### DOC-03 Mitigation Playbook
Guidance for turning extracted advisories into mitigation actions (templates, checklists, prioritization).

### DOC-04 Integrations
How we ingest from sources (CISA, vendor advisories, etc.) and how we publish/notify downstream systems.

### DOC-05 Ingestion
Ingestion sources, caching, canonical raw text capture, and ingest folder layout.

### DOC-06 Matching
Future matching logic for tailoring advisories/mitigations to a facility’s inventory, products, versions, and controls.

### DOC-07 Evaluation
Scoring and test harnesses for extraction quality (includes offline unit tests and integration checks).

### DOC-08 Grant Draft
Grant/proposal narrative; aligned to the technical plan but may be edited separately.

### DOC-09 Prototype Plan
Step-by-step implementation roadmap and milestones.

### DOC-10 Stack & Deployment
Local dev setup, packaging conventions, and execution/test commands.

## Current status

**As of 2026-02-08: Milestone B (Ingest + Extract) is functionally complete.**

✅ Working now

- `advisoryops ingest` creates a deterministic ingest folder under `outputs/ingest/<advisory_id>/`
- `advisoryops extract` produces a **stable 13-key** `advisory_record.json` under `outputs/extract/<advisory_id>/`
- Deterministic output text normalization removes common mojibake artifacts (e.g., `â€™`, `Â`, `â€…`) before writing JSON
- Offline unit tests cover the mojibake cleaner (`tests/test_mojibake_cleaning.py`)

⚠️ Windows note (important for validation)

PowerShell 5.x can show mojibake if you read UTF-8 JSON without specifying encoding. Use:

- `Get-Content -Raw -Encoding utf8 <file>` or validate using the Python JSON-walk scan in DOC-10.

Next up

- Milestone C: Minimal matching “inventory profile” + evaluation harness (DOC-06, DOC-07)
- Add additional sources to ingestion (prioritize CISA ICS, CISA KEV mapping, vendor advisories) (DOC-05, DOC-04)

## Migration checklist (from legacy/canvas into repo docs)
- [x] Create repo + scaffold
- [x] Migrate DOC-08 Grant Proposal Draft into repo
- [x] Migrate DOC-02 Data Contracts & Schemas into repo
- [x] Migrate DOC-03 Mitigation Playbook into repo
- [x] Migrate DOC-04 Integrations & Connectors into repo
- [x] Migrate DOC-05 Ingestion Sources & Parsers into repo
- [x] Migrate DOC-06 Matching & Confidence Engine into repo
- [x] Migrate DOC-07 Evaluation Harness & Public Good into repo
- [x] Migrate DOC-09 Prototype & Implementation Plan into repo
- [x] Migrate DOC-10 Stack & Deployment into repo
- [x] Update docs to reflect current stable 13-key extract output + mojibake cleanup (2026-02-08)

---

## Open questions (short list)
- ServiceNow: incident vs SIR vs VR as default beyond MVP
- First enrichment connector to build (Forescout vs Armisis vs Claroty) for best ROI
- Minimal facility fields required to achieve high-confidence matching


### MVP Additions (Discovery Layer) — Added 2026-02-06
- [ ] Implement RSS discovery (advisoryops discover) for CISA ICSMA + FDA MedWatch
- [ ] Document dedupe rules (GUID/link/hash) and provenance recording
- [ ] Add corpus builder workflow using discovered links

- Which sources do we ingest first after the MVP (CISA ICS, KEV, vendor advisories, NVD CVEs)?
- What is the minimal “inventory profile” format for matching (vendors/products/versions + environment)?

## Stack & Deployment
## Stack & Deployment
- DOC-10: Stack and Deployment (MVP)

- `scripts/verify_extract.ps1` integration check (extract + 13-key contract + mojibake scan). __VERIFY_EXTRACT_SCRIPT_INDEX__
