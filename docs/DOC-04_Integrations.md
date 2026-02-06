# DOC-04 Integrations & Connectors (v1)

## 0) Purpose
Define how AdvisoryOps integrates with external systems (ITSM/ticketing, asset inventory enrichment, vendor feeds). This doc is the canonical spec for:
- integration boundaries (core vs pro)
- connector interface patterns
- auth + rate limiting + idempotency
- first-class ServiceNow mapping (MVP)

---

## 1) Core vs Pro boundary (recommended)
To preserve “open-core” flexibility:

### Core (safe to open-source)
- Data contracts & schemas (DOC-02)
- Mitigation playbook (DOC-03)
- Export formats (PDF/CSV/JSON)
- Generic ITSM adapter interface (no vendor secrets)
- Evaluation harness (DOC-07)

### Pro (monetizable / customer-specific)
- Vendor-specific ITSM connectors (beyond ServiceNow MVP) if desired
- Asset enrichment connectors requiring customer credentials
- UI features, deployment hardening, multi-tenant features
- Customer-specific workflow rules and mapping presets

**Note:** ServiceNow can be either:
- in **Core** (maximize adoption), or
- in **Pro** (monetize the “last-mile ticketing”)
We can decide later; build the interface in Core regardless.

---

## 2) Integration principles (apply to all connectors)
1) **Idempotent writes:** same packet → same external record (no duplicates)
2) **Attach evidence:** include packet PDF + JSON export where supported
3) **Minimal required fields:** choose the least-customized mapping first
4) **Config-driven mapping:** avoid hardcoding customer field names
5) **Rate limit + retry:** exponential backoff; respect vendor limits
6) **Audit trail:** always log what was written and links returned
7) **Graceful fallback:** if connector fails, exports still exist (PDF/CSV/JSON)

---

## 3) ITSM adapter interface (contract)
Connectors implement a small set of capabilities. The pipeline creates a ticket using whatever capabilities exist.

### 3.1 Capability model
- create_record (required for an ITSM connector)
- update_record
- add_comment
- add_attachment
- add_worklog
- link_records (parent/child)
- set_state
- search_by_external_id (for idempotency)

### 3.2 Canonical inputs to connectors
Connector input should be derived from the RemediationPacket:
- packet metadata (title, severity, summary)
- affected scope (vendor/product/models/CVEs)
- role-split tasks (checklists)
- evidence/citations and source URLs
- facility context (site/team) *without PHI*

### 3.3 Canonical connector output
- record_id (native ID, e.g., sys_id)
- record_number (human readable, e.g., INC0012345)
- record_url
- created/updated timestamps
- errors/warnings

### 3.4 Suggested interface (pseudo)
- upsert_ticket(packet, config) -> TicketResult
- attach_packet_artifacts(ticket, pdf_path, json_path, csv_path?) -> AttachmentResult
- add_tasks_or_worklog(ticket, tasks_by_role) -> Result
- link_to_parent(ticket, parent_ticket_id) -> Result (optional)
- close_or_update_state(ticket, status) -> Result

---

## 4) Prioritization strategy for ITSM coverage (smart, not exhaustive)
Rather than chasing “top 5” blindly:
1) Start with what we KNOW in healthcare (ServiceNow + Remedy/Helix)
2) Build a **config-driven adapter** where most systems map similarly:
   - create ticket
   - add comment/worklog
   - add attachment
3) Add connectors based on:
   - **market share in healthcare**
   - **API maturity and docs**
   - **customer pull / paid pilots**
   - **incremental effort (how much differs from baseline)**

We expect the *first connector* to be the hardest. After that, each additional connector is usually an incremental mapping + auth + edge cases.

## 5) ServiceNow (MVP) — incident-first mapping

### 5.1 Why incident-first
- Most orgs can ingest into Incident without custom modules.
- Security Incident Response (SIR) and Vulnerability Response (VR) vary by licensing and configuration.
- Incident can be triage entrypoint; teams can convert/relate to change/SIR/VR later.

### 5.2 Default target table
- **table:** `incident`

### 5.3 Minimal field mapping (recommended defaults)
- short_description: Packet title (concise)
- description: Packet summary + key scope + source URLs + “see attachments”
- impact / urgency (or priority): derived from packet severity
- assignment_group: config (e.g., “InfoSec Operations”)
- category / subcategory: config (e.g., “Security” / “Vulnerability”)
- caller_id: service account or configured default
- cmdb_ci: optional (if match can provide a CMDB CI reference)

**Severity mapping suggestion**
- critical -> P1
- high -> P2
- medium -> P3
- low/info -> P4 (or backlog)

### 5.4 Idempotency strategy
We must prevent duplicates on reruns.

Preferred approach:
- Use a deterministic `external_id` (e.g., hash of `cluster_id + site + packet_version`)
- Store it in:
  - a custom field if available (best), else
  - work notes tag line like: `[AdvisoryOpsExternalId: ...]`

Workflow:
1) search_by_external_id
2) if found -> update existing
3) else -> create new

### 5.5 Attachments (high value)
Attach:
- RemediationPacket PDF (human-friendly)
- RemediationPacket JSON (machine-friendly)
- Optional CSV tasks export

Naming convention:
- `AdvisoryOps_<packet_id>_packet.pdf`
- `AdvisoryOps_<packet_id>_packet.json`
- `AdvisoryOps_<packet_id>_tasks.csv`

### 5.6 Comments / work notes structure
Post one structured work note on create:
- Summary
- Impacted/suspected counts (if available)
- Recommended next actions (top 3)
- Role split overview
- Links to source advisories
- External ID tag line

Then optionally add role-specific work notes if the customer wants task separation.

### 5.7 States and closure (MVP)
Keep it minimal:
- create in “New”
- update to “In Progress” when acknowledged (manual for MVP)
- closure uses customer workflow; AdvisoryOps can recommend but not auto-close unless configured

### 5.8 Authentication options
- Basic auth (least preferred)
- OAuth (preferred)
- Service account with least privileges (scoped to incident + attachments + comments)

### 5.9 Rate limiting / retry
- Respect 429s
- Exponential backoff with jitter
- Fail gracefully: export artifacts still generated even if ticket write fails

## 6) Other ITSM systems (future)

### 6.1 BMC Remedy / BMC Helix ITSM
Common in healthcare (especially legacy Remedy).
- Typically supports REST APIs (Helix modernizes this)
- Mapping concepts: Incident + Worklog + Attachments
Key differences vs ServiceNow:
- Auth patterns differ (tokens, sessions)
- Field names and required fields vary more across implementations

### 6.2 Jira Service Management (JSM)
- Strong REST APIs, issue-based model
- Easy mapping: issue type + description + attachments + comments
- Workflows highly customizable

### 6.3 Ivanti (Neurons / older Ivanti ITSM variants)
- APIs exist but vary by product/version
- Often requires more customer-specific mapping

### 6.4 Freshservice / Zendesk
- Both have mature APIs
- Usually simpler models
- Often used in smaller orgs/clinics, not always large hospital systems

---

## 7) How much work is each additional ITSM connector?
Think of effort in layers:

### Layer A: “Core adapter” (one-time)
- Ticket payload model from RemediationPacket
- Attachment generation (PDF/JSON/CSV)
- Idempotency + retry framework
- Logging/audit record format

### Layer B: Per-ITSM connector (incremental)
- Auth implementation (API keys/OAuth/sessions)
- Field mapping config template
- 3–6 API calls implemented:
  - search_by_external_id
  - create
  - update
  - add_comment / worklog
  - add_attachment
  - (optional) link_records / set_state

### Layer C: Per-customer tuning (optional / paid)
- Custom fields
- Assignment logic
- CMDB linking
- Workflow state transitions
- Multiple ticket strategy (parent control ticket + child tasks)

**Rule of thumb (solo-friendly):**
- First connector (ServiceNow): hardest; establishes patterns.
- Next connectors are typically 30–60% of the first connector effort *if we reuse the adapter framework*.
- The big variable is customer-specific customization, not the vendor API itself.

---

## 8) “Packet = ticket?” (clarified)
A **RemediationPacket** is the canonical unit of work.
A **ticket** is one projection of that packet into an ITSM system.

MVP approach:
- 1 packet -> 1 “control” Incident ticket (central InfoSec)
- Attach packet artifacts
- Tasks live in the packet PDF/JSON (and optionally posted as work notes)

Future approach (optional):
- 1 control ticket (InfoSec) + N child tasks (HTM/NetOps/IT Ops) if the customer wants task automation

## 9) Asset inventory enrichment connectors (future)
Goal: make “are we impacted?” far less manual by ingesting inventory context via API.

### 9.1 Candidate platforms
- Forescout
- Armis
- Claroty
- (Later) CMDB platforms or clinical engineering asset systems

### 9.2 What we want from enrichment APIs
Minimum useful fields:
- device identifier: hostname/IP/MAC
- vendor/manufacturer + model
- OS/firmware where available
- device category/type (clinical device classification)
- location/site/segment (VLAN, subnet)
- last seen
- tags/labels and confidence scores (if provided by platform)

### 9.3 Why this differentiates AdvisoryOps
Many advisory workflows fail because inventory is incomplete or unnormalized.
Enrichment improves:
- applicability determination
- matching confidence
- scope estimation
- targeting of compensating controls (VLAN/ACL/NAC)

---

## 10) Connector operational standards (applies to all integrations)

### 10.1 Secrets handling
- No secrets committed to repo
- Use `.env` locally (gitignored)
- Use environment variables in deployment

### 10.2 Rate limiting and retries
- Respect 429
- exponential backoff with jitter
- max retry window configurable
- hard fail -> still produce exports

### 10.3 Logging & audit trail
Every connector call should log:
- packet_id / external_id
- target system
- record IDs + URLs
- actions taken (create/update/comment/attach)
- errors/warnings

### 10.4 Permissions (least privilege)
- Service accounts scoped to required tables/actions only
- If OAuth: scoped tokens where possible

---

## 11) Changelog
- 2026-02-06: Initial v1 integration architecture, ServiceNow incident-first MVP spec, and connector standards.


## RSS Discovery Connectors — Added 2026-02-06
### Purpose
Provide a stable, low-cost way to detect new advisories without scraping listing pages.

### Connector Types
- discover_cisa_icsma → polls CISA ICS Medical Advisories RSS
- discover_cisa_icsa → polls CISA ICS Advisories RSS
- discover_fda_medwatch → polls FDA MedWatch RSS and filters for cybersecurity-relevant items

### Output Contract
Each connector emits a normalized FeedItem object:
- source, guid, title, link, published_date, summary, fetched_at

### Scheduling (MVP → Production)
- MVP: manual runs via CLI (dvisoryops discover)
- Later: scheduled runs via cron/GitHub Actions/container scheduler
