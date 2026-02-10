# DOC-02 Data Contracts & Schemas

## 0) Purpose
Canonical home for all **data contracts**, **schemas**, and **examples** used by AdvisoryOps.

This doc is implementation-facing: developers should be able to build the pipeline from these contracts without guesswork.

---

## 1) Versioning
- **Current contracts:** v1.0
- Breaking changes require:
  - What changed
  - Why
  - Migration notes

---

## 2) Shared Conventions

### 2.1 IDs
- advisory_id: `adv_<sha-or-uuid>`
- cluster_id: `clu_<sha-or-uuid>`
- packet_id: UUID

### 2.2 Timestamps
- published_date: `YYYY-MM-DD`
- retrieved_at, created_at, updated_at: ISO-8601

### 2.3 Citations
- Citations refer to extracted key_points stored under the Packet’s sources[].
- Format: `src_<n>.kp_<m>`

### 2.4 Raw vs normalized fields
- Preserve raw strings where parsing is uncertain.
- Provide typed normalized structures when confidence is high.

---

## 3) AdvisoryRecord JSON Contract (v1.0)

### 3.0 Current implementation note (as of 2026-02-10)

The extractor currently writes **`advisory_record.json` as a strict, stable subset with exactly 13 keys**.
This contract is enforced by `scripts/verify_extract.ps1`.

Note: `scope: dataset` sources are discovery-only in v1 and do **not** produce `AdvisoryRecord` outputs.

Required keys:

- `advisory_id`
- `title`
- `published_date` (YYYY-MM-DD)
- `vendor`
- `product`
- `cves` (list of strings)
- `severity` (string or null)
- `affected_versions` (list of strings)
- `summary`
- `impact`
- `exploitation`
- `mitigations` (list of strings)
- `references` (list of `{"label": "...", "url": "..."}` objects)

This “13-key contract” is what downstream tooling should treat as **source-of-truth today**.

__VERIFY_EXTRACT_SCRIPT_DOC02__

### Contract enforcement

The strict **13-key** `advisory_record.json` contract is enforced end-to-end by:

- `scripts/verify_extract.ps1` (runs a real extract, validates keys, deep-scans for mojibake markers)
- `pytest` unit tests for deterministic cleaning behavior


The more expansive schema below remains the **target/roadmap** contract (it may be partially populated over time as ingestion/parsing improves). When new fields are added to the on-disk output, they must be gated behind an explicit version bump and migration notes.

**Encoding note (Windows):** `advisory_record.json` is written as UTF-8. PowerShell 5.x may display mojibake if read without specifying encoding. Use `Get-Content -Raw -Encoding utf8` when validating output.

**Mojibake guarantee:** the extractor performs deterministic cleanup so the written JSON should not contain common mojibake markers like `\u00e2\u20ac\u2122`, `\u00c2`, or `\u00e2\u20ac\u2026`. See DOC-10 for a canonical validation script.

### 3.0.1 Stable extract output example (current)

~~~json
{
  "advisory_id": "adv_…",
  "title": "…",
  "published_date": "YYYY-MM-DD",
  "vendor": "…",
  "product": "…",
  "cves": ["CVE-…"],
  "severity": "High",
  "affected_versions": ["…"],
  "summary": "…",
  "impact": "…",
  "exploitation": "…",
  "mitigations": ["…"],
  "references": [{"label": "…", "url": "https://…"}]
}
~~~

Goal: Strict, source-agnostic representation of a single advisory notice (vendor/FDA/CISA/etc.) enabling clustering, matching, and packet generation.

### 3.1 Schema outline
~~~json
{
  "advisory_id": "adv_<sha-or-uuid>",
  "advisory_version": "optional-source-revision-or-date",
  "record_version": "1.0",

  "publisher": "FDA | Vendor | CISA | Other",
  "publisher_org": "string",
  "vendor": "string (if applicable)",

  "advisory_type": "cybersecurity_notice | safety_communication | security_bulletin | vulnerability_notice | recall_notice | other",

  "title": "string",
  "summary": "string (1-3 paragraphs max)",

  "published_date": "YYYY-MM-DD",
  "retrieved_at": "ISO-8601",
  "source_url": "https://...",
  "source_canonical_urls": ["https://..."],

  "content": {
    "content_type": "html | pdf | text",
    "raw_text": "string",
    "content_hash": "sha256...",
    "language": "en"
  },

  "identifiers": {
    "cves": ["CVE-YYYY-NNNN"],
    "cwes": ["CWE-###"],
    "other_ids": [{"type": "vendor", "value": "ABC-2026-001"}]
  },

  "severity": {
    "vendor_severity": "critical | high | medium | low | unknown",
    "cvss": [{"cve": "CVE-...", "version": "3.1", "vector": "optional", "score": 9.8}],
    "epss": [{"cve": "CVE-...", "score": 0.42, "as_of": "YYYY-MM-DD"}]
  },

  "exploitability": {
    "known_exploited": false,
    "kev_listed": false,
    "exploit_notes": "string",
    "citations": ["src_1.kp_2"]
  },

  "affected_product_definition": {
    "vendor": "string",
    "product_family": "string",
    "products": [
      {
        "product_name": "string",
        "models": ["string"],
        "device_type": "string",
        "udi_di": ["optional"],
        "part_numbers": ["optional"],
        "components": [
          {
            "name": "string",
            "type": "software | firmware | os | library | service",
            "notes": "optional"
          }
        ]
      }
    ],
    "affected_versions": [
      {
        "raw": "<= 3.2.1",
        "normalized": {"lte": "3.2.1"},
        "applies_to": "product/component",
        "confidence": 0.85
      }
    ],
    "fixed_versions": [
      {
        "raw": "3.2.2",
        "normalized": {"eq": "3.2.2"},
        "applies_to": "product/component",
        "confidence": 0.9
      }
    ],
    "conditions": ["Only when remote access enabled"]
  },

  "technical_details": {
    "attack_vectors": ["network"],
    "auth_required": "yes | no | unknown",
    "user_interaction_required": "yes | no | unknown",
    "network_preconditions": [
      {"type": "port", "value": "optional", "notes": "optional"}
    ],
    "affected_protocols": ["SMB"],
    "services_features": ["remote management"],
    "citations": ["src_1.kp_3"]
  },

  "healthcare_constraints": {
    "vendor_managed_possible": true,
    "no_admin_access_possible": true,
    "patch_window_required": true,
    "clinical_downtime_sensitivity": "high | medium | low | unknown",
    "patient_safety_notes": "string",
    "workflow_impact_notes": "string",
    "citations": ["src_1.kp_4"]
  },

  "recommended_actions": [
    {
      "action_id": "act_001",
      "action_type": "patch | configuration_change | compensating_control | monitoring | vendor_case | communication | validation",
      "summary": "string",
      "details": "string",
      "role_hints": ["infosec", "netops", "htm_ce", "vendor", "clinical_ops"],
      "priority": "critical | high | medium | low",
      "citations": ["src_1.kp_1"]
    }
  ],

  "vendor_contact": {
    "support_url": "optional",
    "security_contact": "optional",
    "phone": "optional",
    "notes": "optional"
  },

  "source_extraction": {
    "model": "string",
    "run_id": "optional",
    "confidence": 0.82,
    "warnings": ["Versions ambiguous; human confirmation recommended"]
  }
}
~~~

### 3.2 Minimum required fields (MVP)
**Required (best-effort):**
- advisory_id
- record_version
- publisher
- title
- published_date (best-effort)
- retrieved_at
- source_url

**Required content:**
- content.raw_text
- content.content_hash

**Required scope (best-effort):**
- affected_product_definition (vendor/product/models)

**At least one of:**
- identifiers.cves
- affected_product_definition.affected_versions
- recommended_actions (explicit mitigations)

**Required actions:**
- recommended_actions (at least 1 entry)
---

## 4) IssueCluster JSON Contract (v1.0)
Goal: Deduplicate and track multiple advisories/updates for the same underlying issue.

~~~json
{
  "cluster_id": "clu_<sha-or-uuid>",
  "record_version": "1.0",

  "title": "Canonical issue title",
  "summary": "Canonical summary",

  "created_at": "ISO-8601",
  "updated_at": "ISO-8601",
  "status": "active | superseded | retired",

  "canonical_identifiers": {
    "cves": ["CVE-YYYY-NNNN"],
    "cwes": ["CWE-###"],
    "vendor_ids": ["ABC-2026-001"],
    "other_ids": []
  },

  "canonical_product_scope": {
    "vendor": "string",
    "product_family": "string",
    "device_type": "string",
    "models": ["string"],
    "affected_versions": [
      {"raw": "<= 3.2.1", "normalized": {"lte": "3.2.1"}, "confidence": 0.85}
    ],
    "fixed_versions": [
      {"raw": "3.2.2", "normalized": {"eq": "3.2.2"}, "confidence": 0.9}
    ]
  },

  "advisories": [
    {
      "advisory_id": "adv_...",
      "publisher": "FDA | Vendor | CISA | Other",
      "published_date": "YYYY-MM-DD",
      "source_url": "https://...",
      "relationship": "primary | supporting | update | duplicate",
      "notes": "optional"
    }
  ],

  "timeline": [
    {
      "date": "YYYY-MM-DD",
      "event": "published | updated | mitigation_changed | patch_released | exploit_observed",
      "source_ref": "adv_...",
      "notes": "optional"
    }
  ],

  "severity_rollup": {
    "max_vendor_severity": "critical | high | medium | low | unknown",
    "max_cvss": 9.8,
    "known_exploited": false,
    "kev_listed": false,
    "confidence": 0.8
  },

  "recommended_actions_rollup": {
    "patch_guidance": "string",
    "compensating_controls": ["ACL_ALLOWLIST"],
    "vendor_case_recommended": true,
    "citations": []
  },

  "healthcare_constraints_rollup": {
    "vendor_managed_common": true,
    "no_admin_access_common": true,
    "downtime_sensitivity": "high | medium | low | unknown",
    "citations": []
  },

  "dedupe_logic": {
    "rules_triggered": ["CVE_MATCH", "PRODUCT_FAMILY_MATCH"],
    "confidence": 0.87
  }
}
~~~

### 4.1 Minimum required fields (MVP)
**Required:**
- cluster_id
- record_version
- title
- created_at, updated_at
- canonical_product_scope.vendor
- advisories[] (at least 1 entry with advisory_id + source_url)
- dedupe_logic.confidence
---

## 5) RemediationPacket JSON Contract (v1.0)
Goal: Ticket-system-agnostic unit of work that can be exported to PDF/CSV/JSON and mapped into ServiceNow (or others).

### 5.1 Enums
- severity: `critical | high | medium | low | informational`
- status: `new | triaged | in_progress | blocked_vendor | mitigated | patched | risk_accepted | closed`
- patch_feasible: `yes | no | unknown`
- patch_owner: `customer | vendor_only | shared | unknown`
- task_role: `infosec | netops | htm_ce | vendor | clinical_ops | it_ops`
- action_type: `patch | configuration_change | compensating_control | monitoring | vendor_case | communication | validation`

### 5.2 Schema outline
~~~json
{
  "packet_id": "uuid",
  "packet_version": "1.0",
  "created_at": "ISO-8601",
  "updated_at": "ISO-8601",

  "title": "string",
  "severity": "high",
  "status": "triaged",

  "owner": {
    "primary_role": "infosec",
    "assigned_team": "Central InfoSec",
    "assigned_to": "optional"
  },

  "issue_cluster": {
    "cluster_id": "clu_...",
    "summary": "string",
    "cves": ["CVE-..."],
    "weaknesses": ["CWE-..."],
    "exploit_notes": {"known_exploited": false, "evidence": []},
    "affected_product_definition": {
      "vendor": "string",
      "product_family": "string",
      "models": ["string"],
      "device_type": "string",
      "affected_versions": [],
      "fixed_versions": [],
      "conditions": []
    }
  },

  "sources": [
    {
      "source_id": "src_1",
      "publisher": "FDA | Vendor | CISA | Other",
      "title": "string",
      "source_url": "https://...",
      "published_date": "YYYY-MM-DD",
      "retrieved_at": "ISO-8601",
      "content_hash": "sha256...",
      "key_points": [
        {"id": "kp_1", "text": "Short extracted point", "anchor": "optional"}
      ]
    }
  ],

  "facility_context": {
    "org_id": "optional",
    "site": "string",
    "environment_assumptions": {
      "touch_constraints": ["vendor_managed", "no_admin_access", "patch_window_limited"],
      "maintenance_windows": [
        {"day": "sun", "start": "02:00", "end": "06:00", "timezone": "local"}
      ]
    }
  },

  "impact_assessment": {
    "match_summary": {
      "impacted_assets_count": 0,
      "suspected_assets_count": 0,
      "not_impacted_assets_count": 0
    },
    "impacted_assets": [],
    "suspected_assets": []
  },

  "plan": {
    "patch": {
      "patch_feasible": "unknown",
      "patch_owner": "unknown",
      "recommended_patch_path": []
    },
    "recommended_actions": [],
    "compensating_controls": [],
    "tasks": [],
    "verification_evidence_checklist": [],
    "communications": {
      "clinical_ops_required": false,
      "drafts": []
    }
  },

  "risk_acceptance": {
    "needed": false,
    "residual_risk_summary": "",
    "approved_by": "",
    "approval_date": "",
    "review_date": ""
  },

  "exports": {
    "pdf_generated": false,
    "csv_generated": false,
    "json_generated": true,
    "itsm": {
      "system": "servicenow",
      "target_table": "incident",
      "record_sys_id": "optional",
      "links": []
    }
  },

  "audit_trail": [
    {"at": "ISO-8601", "actor": "system", "event": "packet_created", "details": ""}
  ]
}
~~~
### 5.3 Full examples
We will add:
- a complete AdvisoryRecord example
- a complete IssueCluster example
- a complete RemediationPacket example

…as golden artifacts once the ingestion + extraction pipeline is running.

---

## 6) Next: JSON Schema files
When ready, we will generate formal JSON Schema documents for:
- `schemas/advisoryrecord.schema.json`
- `schemas/issuecluster.schema.json`
- `schemas/remediationpacket.schema.json`

---

## 7) Changelog
- 2026-02-06: Migrated v1.0 contract outlines for AdvisoryRecord, IssueCluster, and RemediationPacket into repo docs.
