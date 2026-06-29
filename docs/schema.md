# AdvisoryOps Issue Schema — Field Reference

Every issue in `issues_public.jsonl` and `feed_latest.json` follows this schema.

## Identity

| Field | Type | Populated by | Description | Example |
|-------|------|-------------|-------------|---------|
| `issue_id` | string | deterministic | CVE ID or SHA-256 hash of title+source | `CVE-2024-21762` |
| `title` | string | deterministic | Longest title across contributing signals | `Fortinet FortiOS Out-of-bound Write` |
| `canonical_link` | string | deterministic | Primary advisory URL | `https://nvd.nist.gov/vuln/detail/CVE-2024-21762` |

## Classification

| Field | Type | Populated by | Description | Example |
|-------|------|-------------|-------------|---------|
| `priority` | string | deterministic | P0 (critical) through P3 (low) | `P0` |
| `score` | integer | deterministic/ai | Composite score (0-200+) | `145` |
| `severity` | string | deterministic | Extracted severity level | `critical` |
| `healthcare_category` | string | deterministic | `medical_device`, `healthcare_it`, `healthcare_infrastructure`, `healthcare_adjacent` | `medical_device` |
| `issue_type` | string | deterministic | `cve`, `advisory`, `alert`, `news` | `cve` |
| `classification` | dict | deterministic | Taxonomy tags (type, CWE class, device category) | `{"type": "advisory"}` |
| `fda_risk_class` | string or null | deterministic | FDA medical device class — `"1"`, `"2"`, `"3"`, or null | `"3"` |

## Content

| Field | Type | Populated by | Description | Example |
|-------|------|-------------|-------------|---------|
| `summary` | string | deterministic/ai | Longest description from contributing signals. When `generated_by == "ai"`, this field is rewritten in place by the AI summarizer — there is no separate `ai_summary` field. | (paragraph of text) |
| `nvd_description` | string | deterministic | Raw NVD description when the issue has a CVE | (NVD text) |
| `cves` | list[string] | deterministic | CVE identifiers | `["CVE-2024-21762"]` |
| `vendor` | string | deterministic | Extracted vendor name | `Fortinet` |
| `affected_products` | list[string] | deterministic | Products affected by the issue | `["FortiOS 7.4.x"]` |
| `affected_versions` | list[string] | deterministic | Affected version ranges | `["< 7.4.3"]` |
| `sources` | list[string] | deterministic | Source IDs that contributed signals (count is `len(sources)` — use `counts.sources` in `meta.json` for the aggregate) | `["cisa-kev-json", "mandiant-blog"]` |

## Trust & Provenance

| Field | Type | Populated by | Description | Example |
|-------|------|-------------|-------------|---------|
| `handling_warnings` | list[string] | ai | Operational cautions for clinical teams | `["do not reboot without vendor guidance"]` |
| `evidence_gaps` | list[string] | ai | What information is missing | `["affected versions unclear"]` |
| `unknowns` | list[string] | ai | What the advisory leaves ambiguous | `["patch availability uncertain"]` |
| `generated_by` | string | deterministic | `deterministic`, `ai`, or `hybrid` | `hybrid` |
| `extracted_facts` | dict | ai | Facts pulled from source text | `{"vendor": "Fortinet"}` |
| `inferred_facts` | dict | ai | Facts derived by the model | `{"device_type": "network appliance"}` |
| `confidence_by_field` | dict | ai | Per-field confidence scores (0.0-1.0) | `{"vendor": 0.95}` |
| `insufficient_evidence` | boolean | ai | True if AI lacks confidence | `false` |
| `evidence_sources` | list[string] | deterministic | Source IDs backing each contributed fact | `["cisa-kev-json"]` |
| `citations` | list[dict] | ai | Verbatim source snippets with attribution | `[{"source_id": "cisa-kev-json", "snippet": "..."}]` |

## Source Consensus (multi-source issues)

| Field | Type | Populated by | Description | Example |
|-------|------|-------------|-------------|---------|
| `source_consensus.agreed` | list[string] | deterministic | Facts all sources agree on | `["severity: critical"]` |
| `source_consensus.contradicted` | list[dict] | deterministic | Disagreements across sources | `[{"field": "severity", ...}]` |
| `source_consensus.unique_contributions` | dict | deterministic | What each source uniquely adds | `{"mandiant-blog": ["exploit detail"]}` |

## Scoring Detail

| Field | Type | Populated by | Description | Example |
|-------|------|-------------|-------------|---------|
| `why` | list[string] | deterministic | Score breakdown reasons | `["keyword: RCE (+30)"]` |
| `actions` | list[string] | deterministic | Recommended pipeline actions | `["notify", "ingest"]` |
| `source_authority_weight` | float | deterministic | Authority tier weight (0.0-1.0) | `0.95` |
| `highest_authority_source` | string | deterministic | Most authoritative contributing source | `cisa-icsma` |

## Remediation

| Field | Type | Populated by | Description | Example |
|-------|------|-------------|-------------|---------|
| `recommended_patterns` | list[dict] | ai | Playbook patterns selected by AI | (see packet schema) |
| `tasks_by_role` | dict | ai | Role-split task assignments (infosec/netops/htm_ce/vendor/clinical_ops) | `{"infosec": ["..."]}` |
| `source_mitigations` | list[dict] | ai | Mitigations cited verbatim from source advisories | `[{"source_id": "cisa-icsma", "text": "..."}]` |
| `remediation_steps` | list[string] | deterministic | Playbook-derived remediation actions | `["Isolate affected VLAN"]` |
| `non_applicability` | list[string] | ai | Conditions where recommendation doesn't apply | `["vendor-managed devices only"]` |
| `iocs` | list[dict] | deterministic | Indicators of compromise extracted from source text | `[{"type": "ip", "value": "1.2.3.4"}]` |

## Timestamps

| Field | Type | Populated by | Description | Example |
|-------|------|-------------|-------------|---------|
| `first_seen_at` | string | deterministic | ISO-8601 when first discovered | `2026-03-23T12:00:00+00:00` |
| `last_seen_at` | string | deterministic | ISO-8601 when last seen | `2026-03-24T02:44:00+00:00` |
| `published_dates` | list[string] | deterministic | Original publication dates from contributing signals (list because multiple sources may report the same issue at different times; index 0 is the primary) | `["2024-02-08T00:00:00+00:00"]` |
