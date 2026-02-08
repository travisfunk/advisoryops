# DOC-06 Matching & Confidence Engine (v1)

## 0) Purpose
Define how AdvisoryOps determines whether a healthcare facility is impacted by an IssueCluster, using facility inventory data (MVP: CSV import) and producing explainable match results with confidence scores and human-in-the-loop triggers.

---


## 0.1 Dependency note (as of 2026-02-08)

Matching consumes the extractor’s canonical output `advisory_record.json` (strict 13-key schema; DOC-02).  
Field names used below should map directly to:

- `vendor`, `product`
- `cves`, `severity`
- `affected_versions`
- `summary`, `impact`, `exploitation`, `mitigations`, `references`


## 1) Inventory input (MVP)
MVP accepts a facility inventory CSV (or exported report) with a minimum set of fields.

### 1.1 Minimal inventory CSV template (v1)
Required:
- asset_id (unique row id)
- vendor (manufacturer)
- model
- product_name (if different from model)
- ip_address (optional but helpful)
- hostname (optional)
- location / site (optional)
- owner_team (optional: HTM/CE group)

Optional enrichment fields:
- serial_number
- mac_address
- os_version / firmware_version
- network_segment (vlan/subnet)
- modality_type (e.g., PACS, MRI, patient monitor)
- tags (freeform)

---

## 2) Normalization (make strings comparable)
### 2.1 Vendor normalization
- trim whitespace
- normalize punctuation
- common aliases (e.g., “GE Healthcare” vs “GEHC”)
- case-insensitive comparison

### 2.2 Model/product normalization
- remove obvious noise tokens (e.g., “system”, “series” where safe)
- normalize hyphens/slashes
- preserve numeric sequences and revision suffixes
- keep raw values for transparency

### 2.3 Version normalization (best-effort)
- preserve raw version strings
- parse common patterns:
  - semantic versions (x.y.z)
  - dotted firmware revisions
  - ranges (<=, <, >=, >)
- if parsing uncertain, mark as ambiguous and require human confirmation

## 3) Matching logic (MVP)
Matching happens at the IssueCluster level using:
- vendor match
- product family / model match
- optional version applicability
- optional device type/modality hints

### 3.1 Match stages
1) **Vendor gating**
   - high confidence if vendor matches (normalized)
   - medium if vendor unknown in advisory but strong model match
   - low if both are ambiguous

2) **Product/model match**
   - exact model match (strong)
   - fuzzy match (moderate) using token overlap
   - alias match (moderate) using curated alias table later

3) **Version applicability (if both sides have versions)**
   - if advisory defines affected versions and asset has version → evaluate range
   - if asset version missing → “suspected” unless other evidence is strong
   - if advisory versions ambiguous → require human confirmation

4) **Conditions**
   - apply advisory conditions if we can determine them (e.g., “only when remote access enabled”)
   - if conditions cannot be evaluated → lower confidence and flag

### 3.2 Output classes
- **impacted**: strong match, and version/conditions indicate affected (or versions unknown but highly likely)
- **suspected**: likely match but missing version/conditions or ambiguity exists
- **not_impacted**: vendor/model mismatch or version clearly not affected

### 3.3 Confidence scoring (0–1)
Suggested scoring components:
- vendor_score (0–0.4)
- model_score (0–0.4)
- version_score (0–0.15)
- condition_score (0–0.05)

Confidence is explainable by storing:
- which rules fired
- which normalized fields matched
- why ambiguity reduced confidence

### 3.4 Human-in-the-loop triggers
Auto-flag for review when:
- confidence in a “suspected” match is between 0.5–0.75
- affected version range cannot be parsed
- advisory model list is too broad or unclear
- asset version missing for a high-severity issue

## 4) Facility rollups (packet-level)
From asset-level matches, produce rollups:
- impacted_assets_count
- suspected_assets_count
- not_impacted_assets_count
- top modalities/locations impacted (if available)

Packet should include:
- list of impacted assets (or representative samples if huge)
- list of suspected assets requiring validation
- “what data is missing” list (e.g., firmware versions absent)

---

## 5) Inventory gaps (common in healthcare)
Healthcare facilities often lack accurate device inventories for:
- vendor-managed modality controllers
- unmanaged embedded systems
- legacy devices with inconsistent naming

MVP should handle this by:
- allowing “suspected” classification
- generating validation tasks:
  - verify model/firmware
  - confirm remote access enabled
  - confirm network segment membership
- recommending enrichment connectors as next step

---

## 6) Enrichment connectors (future)
API enrichment can provide:
- vendor/model classification confidence
- device type/modality tagging
- network segment and last seen data
- firmware/OS details where discoverable

Candidate platforms:
- Forescout (strong healthcare device classification potential)
- Armis
- Claroty

Connector selection criteria:
- customer prevalence in healthcare
- API maturity
- ease of deployment
- incremental lift per integration

## 7) Matching output structure (packet-facing)
Matching results should be stored in RemediationPacket.impact_assessment:
- match_summary (counts)
- impacted_assets (list)
- suspected_assets (list)

Each asset match entry should include:
- asset_id
- raw vendor/model/version fields
- normalized vendor/model/version fields (optional)
- match_class (impacted/suspected/not_impacted)
- confidence (0–1)
- rule_trace (list of fired rules)
- notes (why it matched / what’s missing)

---

## 8) Changelog
- 2026-02-06: Initial v1 matching approach, confidence scoring, and HITL triggers.
