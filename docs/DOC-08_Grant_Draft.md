# DOC-08 Grant Proposal Draft - AdvisoryOps for Medical Device Remediation

## 0) Purpose
Draft the complete OpenAI Trusted Access for Cyber / grant application narrative for **AdvisoryOps**: a defensive system that converts medical device security advisories into facility-specific, role-split remediation packets and ticket-ready tasks.

This document is written to be adapted directly into application form fields.

---

## 1) Project Title
**AdvisoryOps: AI-Assisted Medical Device Advisory Normalization & Remediation Packets for Healthcare**

---

## 2) One-Paragraph Abstract
Healthcare organizations receive a constant stream of medical device cybersecurity advisories from vendors and regulators. Translating these into safe, actionable remediation work is time-consuming and error-prone—especially when devices are vendor-managed, patching is delayed, or access is restricted. AdvisoryOps is a defensive system that ingests public advisories, normalizes them into a structured schema, matches them to a facility’s device inventory, and generates evidence-cited remediation packets with role-split tasks (InfoSec, NetOps, HTM/Clinical Engineering, vendor) and compensating controls when patching is not feasible. We will open-source a normalization schema, a public advisory corpus derived from public sources, and an evaluation harness that measures extraction correctness, task completeness, citation quality, and safety constraints.

---

## 3) Problem Statement

### 3.1 Operational gap in healthcare
Healthcare environments contain thousands of specialized clinical devices (imaging, monitoring, lab analyzers, etc.) and supporting controller systems. Security advisories frequently lack consistent machine-readable fields (affected models/versions, patch steps, constraints), and many devices are vendor-managed or cannot be patched rapidly. Central InfoSec teams are often responsible for governance and tracking, while HTM/Clinical Engineering and modality teams execute remediation—creating handoffs that slow response and increase audit burden.

### 3.2 Why current workflows fail
- Advisories arrive as unstructured PDFs/HTML/emails with inconsistent detail.
- Organizations struggle to quickly determine **“are we impacted?”** due to inventory gaps and naming inconsistencies.
- Patching is often infeasible (vendor-only maintenance, downtime constraints), requiring compensating controls (segmentation/ACLs/NAC/monitoring).
- Remediation tracking becomes spreadsheets, email threads, and inconsistent ticket creation.
- Evidence collection for audits and risk acceptance is ad hoc.

---

## 4) Proposed Solution
AdvisoryOps provides an end-to-end defensive workflow:

### 4.1 Ingest and normalize advisories
- Intake advisories from public sources (regulators + public vendor bulletins) and user-submitted advisories (URL/text/PDF).
- Normalize into an **AdvisoryRecord** schema (vendor/product/model/version/CVE/actions/constraints) while preserving raw source text and hashes.

### 4.2 Deduplicate into Issue Clusters
- Cluster related advisories and updates into a canonical **IssueCluster** to prevent duplicated response work.

### 4.3 Match against facility inventory
- Match IssueClusters to facility inventory (CSV import in MVP; optional enrichment connectors later).
- Classify assets as impacted/suspected/not impacted with explainability and human-confirmation triggers.

### 4.4 Generate Remediation Packets
- Produce a **RemediationPacket** with:
  - evidence-cited actions
  - patch feasibility and owner (customer vs vendor-only)
  - compensating controls selected from an approved mitigation playbook
  - role-split tasks with verification and rollback guidance
  - optional clinical communications templates for downtime-sensitive environments

### 4.5 Integrate into governance and execution
- Create a central InfoSec “control ticket” (ServiceNow incident-first) plus exports (PDF/CSV/JSON) for broad portability.

---

## 5) Why Advanced Cyber-Capable Models Help (Trusted Access Value)
This project benefits from advanced cyber-capable models for:
- **Robust extraction** from inconsistent, technical advisory prose (models/versions/conditions/mitigations).
- **Long-horizon reasoning** across advisory text + inventory context to determine applicability.
- **Safe remediation planning** when patching is delayed or impossible, selecting appropriate compensating controls and role splits.
- **Consistency and auditability** via evidence-cited outputs and structured schemas.

AdvisoryOps is defensive-only and designed to minimize harmful dual-use by constraining outputs to approved mitigation patterns and requiring citations.

---

## 6) Methodology & Technical Approach

### 6.1 Data model
- AdvisoryRecord JSON (v1)
- IssueCluster JSON (v1)
- RemediationPacket JSON (v1)
- Mitigation Playbook YAML (v1)

### 6.2 Pipeline
1) Ingest advisory (URL/text/PDF) → store raw text + hash
2) Normalize into AdvisoryRecord
3) Cluster into IssueCluster (dedupe + timeline)
4) Match to facility inventory (confidence scoring)
5) Generate RemediationPacket using mitigation playbook patterns
6) Export PDF/CSV/JSON + create ITSM ticket

### 6.3 Safety controls
- Defensive-only scope
- Evidence-cited recommendations
- Playbook-constrained mitigations (no “creative” unapproved steps)
- Human-in-the-loop triggers for ambiguous matches
- Separation of public corpus from any customer inventory data

---

## 7) Evaluation Plan (What we will measure)
We will build an evaluation harness and score outputs across a set of public advisories.

### 7.1 Metrics (initial)
- **Extraction correctness:** field-level accuracy (vendor/model/version/CVEs/actions)
- **Clustering accuracy:** correct grouping of related advisories and updates
- **Matching accuracy:** impacted/suspected classification vs labeled test cases
- **Task completeness:** role-split tasks, verification, rollback, vendor-case steps when needed
- **Citation quality:** coverage and correctness of citations supporting key recommendations
- **Safety score:** absence of prohibited guidance; adherence to mitigation playbook

### 7.2 Baselines
- Compare naive parsing + generic summarization to schema-based extraction and playbook-constrained planning.
- Evaluate before/after iterative prompt/workflow improvements.

---

## 8) Public Benefit / Sharing Plan
We will share defensive artifacts that benefit the broader community:

1) **Open schemas:** AdvisoryRecord, IssueCluster, RemediationPacket
2) **Public advisory corpus (public sources only):** normalized fields + labels + source references
3) **Evaluation harness + rubric:** reproducible scoring and test runner
4) **Reference implementation:** minimal pipeline components excluding proprietary connectors and any customer data
5) **Templates:** vendor outreach, risk acceptance, verification evidence checklists

---

## 9) Expected Outcomes & Impact
- Reduce time from advisory receipt to actionable remediation work.
- Improve accuracy in determining applicability to local inventory.
- Provide consistent governance artifacts for central InfoSec and execution teams.
- Improve audit readiness via structured packets and evidence checklists.
- Provide open standards and evaluation resources for the healthcare security community.

---

## 10) Scope, Feasibility, and Solo-Founder Execution

### 10.1 MVP focus
- Advisory ingestion + normalization
- Issue clustering
- CSV inventory match
- Remediation packet generation
- ServiceNow incident creation + exports

### 10.2 Non-goals for MVP
- Network scanning / passive discovery
- Automatic patch deployment
- Full multi-ITSM integrations

---

## 11) Timeline (bootstrap)
- **Phase A (Weeks 1–2):** finalize schemas + playbook; ingest/normalize 25 advisories; build basic UI/CLI.
- **Phase B (Weeks 3–4):** matching engine + packet generation; export artifacts.
- **Phase C (Weeks 5–6):** ServiceNow connector; end-to-end thin vertical prototype.
- **Phase D (Weeks 7–8):** evaluation harness + public release of schemas/corpus subset.
- **Phase E (post-grant):** first inventory enrichment connector; pilot deployments.

---

## 12) Resource / Credit Usage Plan
- Model usage for:
  - advisory extraction & normalization
  - clustering and dedupe assistance
  - packet generation constrained by playbook
  - evaluation runs across corpus

We will optimize prompts/workflows to reduce token usage and run evaluations in batch.

---

## 13) Risks & Mitigations
- **Ambiguous advisories** → preserve raw strings + warnings + human confirmation
- **Dual-use concerns** → defensive-only playbook constraints and refusal patterns
- **Inventory mismatch** → confidence scoring + enrichment connectors later
- **Customer ITSM variance** → incident-first + config mapping; exports as fallback

---

## 14) Team / Background
This project is led by an experienced healthcare information security professional with extensive exposure to real-world constraints (vendor-managed devices, patch delays, downtime sensitivity) and deep familiarity with device classification and inventory challenges in healthcare.

---

## 15) Appendix: Key differentiators
- Advisory-to-action focus (not just intelligence)
- Vendor-managed / can’t-patch workflows are first-class
- Evidence-cited remediation packets for auditability
- Playbook-constrained mitigations for safety and consistency
- Central InfoSec governance + CE execution baked into the model
