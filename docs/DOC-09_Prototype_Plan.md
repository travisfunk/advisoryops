# DOC-09 Prototype & Implementation Plan (v1)

## 0) Purpose
Define a solo-friendly, thin-vertical prototype plan for AdvisoryOps that is:
- grant-aligned (evaluation + public good)
- MVP-focused (minimum integrations)
- expandable (core vs pro)

This plan is intentionally biased toward building a working pipeline quickly.

---

## 1) Guiding principles
- Build the **thin vertical slice first**: ingest → extract → cluster → match → packet → export → (optional) ServiceNow ticket
- Prefer **config-driven** design over per-customer custom code
- Require **evidence/citations** for key recommendations
- Treat “vendor-managed / can’t patch” as first-class
- Avoid PHI and sensitive customer data by design

---

## 2) Milestones (solo-friendly)

### Milestone A — Repo + contracts + playbook ✅
- Docs migrated and canonicalized in repo

### Milestone B — Ingest + AdvisoryRecord extraction (**DONE 2026-02-08**)

What’s implemented:

- Ingest sources and store canonical raw text into `outputs/ingest/<advisory_id>/`
- Extract advisory fields into `outputs/extract/<advisory_id>/advisory_record.json`
- Output contract is the **strict 13-key schema** (see DOC-02 “Current implementation note”)
- Deterministic output text cleanup removes common mojibake artifacts (e.g., `â€™`, `Â`, `â€…`)
- Offline unit tests exist for the mojibake cleaner (`python -m pytest`)

Acceptance criteria (must stay green):

- `advisory_record.json` exists and contains exactly the 13 expected keys
- Deep scan of all strings/lists shows **no** mojibake markers
- Extract completes with exit code 0 on at least one real advisory run
### Milestone C — Clustering (IssueCluster)
Acceptance criteria:
- Given N advisories, system can:
  - group likely duplicates/updates into clusters
  - output `IssueCluster.json` with relationships and a timeline

### Milestone D — Matching (CSV inventory)
Acceptance criteria:
- Given an IssueCluster and a CSV inventory:
  - classify assets (impacted/suspected/not impacted)
  - output match trace + confidence
  - roll up counts for packet

### Milestone E — RemediationPacket generation + exports
Acceptance criteria:
- Given IssueCluster + match results:
  - generate RemediationPacket.json
  - generate PDF (human readable)
  - generate CSV tasks (optional)

### Milestone F — ServiceNow connector (optional for firstt prototype)
Acceptance criteria:
- Upsert an Incident ticket with:
  - consistent external_id tag
  - attachments (PDF/JSON)
  - work note summary

---

## 3) MVP demo scenario (what we show)
Input:
- 1–3 real public advisories (vendor/FDA/CISA public pages)
- 1 small synthetic inventory CSV (no customer data)

Output:
- AdvisoryRecord
- IssueCluster
- RemediationPacket with role-split tasks + citations
- Export artifacts (PDF/JSON/CSV)
- (Optional) ServiceNow incident created in a test instance

## 4) Architecture overview (MVP)

### 4.1 Components
- Ingest module (DOC-05)
- Extract/Normalize module (AdvisoryRecord)
- Cluster module (IssueCluster)
- Match module (Inventory matching)
- Packet module (RemediationPacket generation using playbook)
- Export module (PDF/CSV/JSON)
- ITSM module (ServiceNow adapter)

### 4.2 Storage (MVP)
- Local filesystem for outputs (gitignored)
- Optional lightweight DB later (SQLite/Postgres) for history and multi-run tracking

### 4.3 Configuration
Config should drive:
- site name / org_id
- severity mapping
- role/team mapping
- ServiceNow endpoint + credentials (if enabled)
- enrichment connector enablement (future)

Recommended config file(s):
- `config/app.yaml` (later)
- environment variables for secrets

---

## 5) Security model (no PHI posture)
- Do not store PHI
- Avoid ingesting internal tickets/emails unless sanitized
- Store only public advisory content + synthetic test data in repo
- If customer inventory is used:
  - keep it local / customer-controlled
  - never commit to git
  - treat it as sensitive operational data

---

## 6) Auditability requirements
Every packet must include:
- sources (URLs + hashes)
- citations for key claims
- verification evidence checklist
- role-split tasks
- audit trail events (packet created/updated/exported)

## 7) Build order (recommended)

### 7.1 First: minimal CLI runner
Commands (conceptual):
- `advisoryops ingest --url <...>`
- `advisoryops extract --advisory-id <...>`
- `advisoryops cluster --input <folder>`
- `advisoryops match --cluster <...> --inventory <csv>`
- `advisoryops packet --cluster <...> --matches <...>`
- `advisoryops export --packet <...>`
- `advisoryops itsm servicenow --packet <...>` (optional)

The “runner” can be a Python CLI or Node CLI; choose what’s easiest.

### 7.2 Thin vertical slice target
Minimum to prove value:
1) URL ingestion + text normalization
2) AdvisoryRecord extraction
3) Packet generation (even without clustering/matching at first)
4) PDF export

Then add:
- clustering and matching
- ServiceNow last

---

## 8) Acceptance tests (lightweight)
For each milestone, create:
- 1–3 sample inputs under `samples/`
- expected output checks (schema compliance + key fields present)

---

## 9) What “done” means for the prototype
A non-developer can run:
- one command (or small sequence) and get:
  - a clean packet PDF
  - the JSON artifacts
  - optional ServiceNow ticket created

## 10) Monetization path (solo-first)
Start as a hustle-friendly offering:

### 10.1 Early monetization (services + tool)
- “AdvisoryOps Assisted” for a hospital:
  - weekly/monthly advisory triage + packet generation
  - ITSM ticket outputs
  - evidence packages for audits
This requires low software maturity and produces revenue quickly.

### 10.2 Productize next
- Hosted multi-tenant portal (later)
- Connector packs (ITSM + inventory enrichment)
- Reporting dashboards and SLA tracking
- Managed corpus updates and playbook updates

### 10.3 Pricing options
- per site / per facility
- per device count tier
- per connector pack (Pro)
- premium: intel feed enrichment (e.g., Flashpoint) as add-on

---

## 11) Differentiation vs incumbents
- Focus on **advisory-to-action**, not just intel aggregation
- “Vendor-managed / can’t patch” is first-class
- Evidence-cited remediation packets (audit-ready)
- Constrained mitigations (playbook) → safer, more consistent outputs
- Central InfoSec governance + HTM/CE execution baked into workflow

## 12) Grant alignment
This plan aligns with the Trusted Access for Cyber goals by:
- applying advanced cyber-capable models to defensive extraction + remediation planning
- producing measurable evaluation outcomes (DOC-07)
- publishing schemas, corpus, and harness artifacts for public benefit

---

## 13) Changelog
- 2026-02-06: Initial v1 milestone plan, architecture overview, and monetization path.


## Milestone: Discovery Layer (RSS) — Added 2026-02-06
### Goal
Continuously identify newly published advisories using stable RSS feeds, then hand off to ingestion + extraction.

### MVP Deliverables
- CLI: dvisoryops discover --source cisa-icsma|cisa-icsa|fda-medwatch
- Writes snapshot: outputs/discover/<source>/feed.json
- Produces a queue/list of new link targets for ingestion
- Demonstrate: build a repeatable sample corpus (3–10 advisories per source)

### Success Criteria
- Deterministic dedupe (no duplicate processing across runs)
- Stable provenance metadata captured (guid/link/published/fetched)
