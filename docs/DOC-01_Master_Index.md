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

### DOC-01: Master Index (this document)
**Owns:** navigation, doc governance, current project status, open questions.

### DOC-02: Data Contracts & Schemas
**Owns:**
- AdvisoryRecord JSON contract
- IssueCluster JSON contract
- RemediationPacket JSON contract
- Citation model
- Full examples + JSON Schema files (later)

### DOC-03: Mitigation Playbook
**Owns:**
- Mitigation patterns YAML
- Applicability rules + required inputs
- Role splits, verification & rollback guidance
- “Vendor-managed / can’t patch” playbooks

### DOC-04: Integrations & Connectors
**Owns:**
- ITSM adapter interface (capabilities model)
- ServiceNow mapping spec (incident-first + config)
- Remedy/Helix mapping spec (later)
- Asset inventory enrichment connector specs (Forescout/Armis/Claroty/etc.)
- Auth patterns, rate-limit/retry standards

### DOC-05: Ingestion Sources & Parsers
**Owns:**
- FDA / vendor / CISA ingestion approach
- Source normalization rules
- Dedupe heuristics at ingestion
- Snapshot storage and hashing strategy

### DOC-06: Matching & Confidence Engine
**Owns:**
- Inventory CSV template (v1)
- Matching rules + confidence scoring
- Alias/normalization strategy
- Human-in-the-loop triggers

### DOC-07: Evaluation Harness & Public Good Deliverables
**Owns:**
- Public advisory corpus plan (public sources only)
- Labeling guidelines
- Rubric + metrics
- Reproducible evaluation harness design
- Responsible-use boundaries

### DOC-08: Grant Proposal Draft
**Owns:**
- One-paragraph abstract
- Problem statement + proposed solution
- Why advanced cyber models help
- Methodology + evaluation plan
- Public benefit/sharing plan
- Risk management + safety
- Credits usage plan + timeline

### DOC-09: Prototype & Implementation Plan
**Owns:**
- Thin vertical prototype plan (acceptance criteria)
- Architecture overview (components, storage, config)
- Security model (no PHI posture, auditability)
- Deployment notes (later; v1 focuses on local CLI + artifacts)

---

## Current status
- Repo scaffold complete ✅
- DOC-01..DOC-09 migrated into repo ✅
- Next build milestone: **Milestone B** (Ingest + AdvisoryRecord extraction) per DOC-09
- Next housekeeping: optional polish (DOC-03 numbering) and later JSON Schema files under `schemas/`

---

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

---

## Open questions (short list)
- ServiceNow: incident vs SIR vs VR as default beyond MVP
- First enrichment connector to build (Forescout vs Armis vs Claroty) for best ROI
- Minimal facility fields required to achieve high-confidence matching
