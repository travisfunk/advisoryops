# Evaluation & Scoring (DOC-07)

**Last updated:** 2026-02-10


## 0) Purpose
Define:
1) the **public good** outputs AdvisoryOps will contribute, and  
2) the **evaluation harness** used to measure correctness, quality, and safety.

This is central to both the grant application and long-term credibility.

---


## 0.1 Current evaluation/testing status (as of 2026-02-10)

What we have today (offline, deterministic):

- **Unit tests** for mojibake cleanup (`tests/test_mojibake_cleaning.py`) — no network/LLM required
- A **contract-level validation** that `advisory_record.json` is the strict 13-key schema (see DOC-02) and does not contain common mojibake markers (see DOC-10 scripts)

What’s next for this document:

- Add an integration “golden set” (N advisories) and score extraction accuracy field-by-field
- Add a regression harness that runs nightly/CI to catch output drift and schema violations

## 1) Public good: what we will publish
AdvisoryOps will publish defensive resources derived from **public sources only**:

### 1.1 Open schemas (Core)
- AdvisoryRecord (v1)
- IssueCluster (v1)
- RemediationPacket (v1)

### 1.2 Public advisory corpus (public sources only)
A curated dataset of advisories with:
- source URL
- normalized fields (vendor/product/model/version/CVEs/actions)
- labels for clustering and applicability (where feasible)
- extracted key points for citations

No customer inventory data, no PHI.

### 1.3 Mitigation playbook patterns (defensive-only)
- A catalog of approved mitigation patterns (DOC-03)
- Parameters and verification evidence templates

### 1.4 Evaluation harness & rubric
- A reproducible runner that:
  - ingests advisory text
  - extracts AdvisoryRecord
  - clusters into IssueClusters
  - generates packets (without facility-specific secrets)
  - scores outputs using a rubric
- Baseline comparisons

### 1.5 Templates
- Risk acceptance template (time-bound)
- Vendor case escalation template
- Evidence checklist template for audits

---

## 2) Responsible release boundaries
We will **not** publish:
- exploitation instructions or offensive guidance
- proprietary vendor documentation or paywalled content
- customer inventories or internal incident data
- anything containing PHI

All published datasets are derived from public sources and reviewed for safety.

## 3) Evaluation goals
We evaluate the system on:
- correctness of extracted structured fields
- correctness of clustering / deduplication
- quality and safety of remediation packets
- citation quality and auditability

---

## 4) Datasets (evaluation inputs)
### 4.1 Public advisory set
Start with a manageable set (e.g., 50–150 advisories) across:
- multiple vendors
- multiple device types (imaging, monitoring, lab, etc.)
- varying structure (HTML, PDF, bulletins)

### 4.2 Labeled subsets
Create a labeled subset for deeper scoring:
- field-level extraction ground truth (for key fields)
- known “same-issue” groupings for clustering tests
- a small synthetic inventory (non-real) for matching tests

---

## 5) Metrics and scoring

### 5.1 Extraction correctness (AdvisoryRecord)
Score key fields:
- vendor / publisher_org
- product_family / product_name
- models
- CVEs
- affected_versions / fixed_versions
- recommended_actions presence and alignment

Metrics:
- precision / recall where possible
- field-level accuracy (exact/fuzzy)
- “missing critical fields” count

### 5.2 Clustering correctness (IssueCluster)
Metrics:
- pairwise precision/recall for “same issue” grouping
- over-merge rate (unrelated advisories grouped)
- under-merge rate (same issue split)

### 5.3 Matching correctness (facility applicability)
Because real inventories are sensitive, MVP uses:
- synthetic inventories and/or publicly describable device lists

Metrics:
- impacted vs suspected vs not impacted classification accuracy
- confidence calibration (do 0.8 scores tend to be correct?)
- ambiguity flagging rate (HITL triggers)

### 5.4 Remediation packet quality
Score:
- task completeness (role split, steps, verification, rollback)
- feasibility realism (vendor-managed constraints acknowledged)
- compensating control appropriateness (from playbook)
- clarity and actionability

### 5.5 Citation quality
Score:
- coverage: key recommendations have citations
- correctness: cited key points support the recommendation
- traceability: sources are clear and stable

### 5.6 Safety score
Score:
- adherence to defensive-only patterns
- avoidance of prohibited offensive guidance
- avoidance of unsafe instructions for clinical environments
- presence of clinical safety notes and downtime considerations

## 6) Evaluation harness architecture (MVP)
A simple, reproducible harness that can run locally or CI:

Pipeline stages:
1) ingest advisory text (from local test fixtures)
2) extract AdvisoryRecord
3) cluster into IssueClusters
4) generate RemediationPacket (without customer context)
5) score outputs vs rubric

Inputs:
- `samples/advisories/*.txt` or `.json`
- optional: `samples/expected/*.json` (golden outputs)

Outputs:
- per-sample JSON outputs (AdvisoryRecord, IssueCluster, Packet)
- per-sample score report (JSON)
- summary report (markdown + JSON)

---

## 7) Reproducibility rules
- Fixed prompts and versioned schemas
- Store model + config identifiers in outputs
- Deterministic IDs based on content_hash where feasible
- Separate “human labels” from machine outputs

---

## 8) Baselines
Compare:
- naive summarization (unstructured) -> cannot score well on structure
- generic extraction without constraints
- playbook-constrained packet generation (target approach)

Goal: demonstrate measurable improvement in correctness and safety.

## 9) Public release plan (phased)
- Phase 1: publish schemas + playbook + rubric
- Phase 2: publish small public advisory corpus subset + harness
- Phase 3: expand corpus and add labels; publish benchmark results

---

## 10) Changelog
- 2026-02-06: Initial v1 public good deliverables and evaluation harness plan.