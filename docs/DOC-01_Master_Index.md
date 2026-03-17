# Master Documentation Index (DOC-01)

**Last updated:** 2026-03-17

This index is the starting point for navigating AdvisoryOps documentation.

---

## Quick links
- **Project status:** [STATUS.md](STATUS.md)
- **MVP guide:** (repo root) `README_MVP.md`
- **Data contracts:** [DOC-02_Data_Contracts.md](DOC-02_Data_Contracts.md)
- **Community public-side plan:** [DOC-11_Community_Public_v0.md](DOC-11_Community_Public_v0.md)
- **Discovery + ingestion details:** [DOC-05_Ingestion.md](DOC-05_Ingestion.md)

---

## Document map

### Core (read these first)
1. [DOC-02_Data_Contracts.md](DOC-02_Data_Contracts.md) — JSON schemas, artifact formats, and file layout
2. [DOC-05_Ingestion.md](DOC-05_Ingestion.md) — discovery + source-run + ingest/extract workflows
3. [DOC-10_Stack_and_Deployment.md](DOC-10_Stack_and_Deployment.md) — local dev, CI, deployment notes
4. [DOC-11_Community_Public_v0.md](DOC-11_Community_Public_v0.md) — Pass 1 public-side scope, contracts, source-count rules, and validated source-set build

### Design (next)
5. [DOC-06_Matching.md](DOC-06_Matching.md) — planned: Signals → Issues → Matches (future)
6. [DOC-07_Evaluation.md](DOC-07_Evaluation.md) — planned: scoring/triage and quality gates

### Supporting
7. [DOC-03_Mitigation_Playbook.md](DOC-03_Mitigation_Playbook.md) — response guidance patterns (human-facing)
8. [DOC-04_Integrations.md](DOC-04_Integrations.md) — integration targets (n8n, SIEM, ticketing) and assumptions
9. [DOC-08_Grant_Draft.md](DOC-08_Grant_Draft.md) — draft notes for grant narrative
10. [DOC-09_Prototype_Plan.md](DOC-09_Prototype_Plan.md) — prototype roadmap and demo scenarios

---

## Naming conventions
- `DOC-XX_*.md` are stable docs intended to evolve over time.
- Outputs are written under `outputs/` and are treated as build artifacts (should be `.gitignore`d).
- `signal_id` is the deterministic ID for a single discovered “signal” **within a given source**.
  - Cross-source correlation/dedup introduces `issue_id` for the public issue layer.

---

## Doc update policy
Docs are updated in **milestone-sized changes**, not after every tiny step.
