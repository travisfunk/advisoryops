# AdvisoryOps Issue Schema — Field Reference

Every issue in `issues_public.jsonl` and `feed_latest.json` follows this schema.

## Identity

| Field | Type | Populated by | Description | Example |
|-------|------|-------------|-------------|---------|
| `issue_id` | string | deterministic | CVE ID or SHA-256 hash of title+source | `CVE-2024-21762` |
| `title` | string | deterministic | Longest title across contributing signals | `Fortinet FortiOS Out-of-bound Write` |
| `link` | string | deterministic | Primary advisory URL | `https://nvd.nist.gov/vuln/detail/CVE-2024-21762` |

## Classification

| Field | Type | Populated by | Description | Example |
|-------|------|-------------|-------------|---------|
| `priority` | string | deterministic | P0 (critical) through P3 (low) | `P0` |
| `score` | integer | deterministic/ai | Composite score (0-200+) | `145` |
| `severity` | string | deterministic | Extracted severity level | `critical` |
| `healthcare_category` | string | deterministic/ai | `medical_device`, `healthcare_it`, `adjacent`, `deterministic` | `medical_device` |
| `issue_type` | string | deterministic | `cve`, `advisory`, `alert`, `news` | `cve` |
| `scope` | string | deterministic | Source scope category | `advisory` |

## Content

| Field | Type | Populated by | Description | Example |
|-------|------|-------------|-------------|---------|
| `summary` | string | deterministic | Longest description from contributing signals | (paragraph of text) |
| `ai_summary` | string | ai | Plain-language 2-3 sentence summary | `Fortinet has a critical vulnerability...` |
| `cves` | list[string] | deterministic | CVE identifiers | `["CVE-2024-21762"]` |
| `vendor` | string | deterministic | Extracted vendor name | `Fortinet` |
| `sources` | list[string] | deterministic | Source IDs that contributed signals | `["cisa-kev-json", "mandiant-blog"]` |
| `source_count` | integer | deterministic | Number of contributing sources | `3` |

## Trust & Provenance

| Field | Type | Populated by | Description | Example |
|-------|------|-------------|-------------|---------|
| `handling_warnings` | list[string] | ai | Operational cautions for clinical teams | `["do not reboot without vendor guidance"]` |
| `evidence_gaps` | list[string] | ai | What information is missing | `["affected versions unclear"]` |
| `unknowns` | list[string] | ai | What the advisory leaves ambiguous | `["patch availability uncertain"]` |
| `evidence_completeness` | float | ai | 0.0-1.0 completeness score | `0.75` |
| `generated_by` | string | deterministic | `deterministic`, `ai`, or `hybrid` | `hybrid` |
| `extracted_facts` | dict | ai | Facts pulled from source text | `{"vendor": "Fortinet"}` |
| `inferred_facts` | dict | ai | Facts derived by the model | `{"device_type": "network appliance"}` |
| `insufficient_evidence` | boolean | ai | True if AI lacks confidence | `false` |

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
| `non_applicability` | list[string] | ai | Conditions where recommendation doesn't apply | `["vendor-managed devices only"]` |
| `recommendation_disclaimer` | string | deterministic | Legal/safety disclaimer | (standard text) |

## Timestamps

| Field | Type | Populated by | Description | Example |
|-------|------|-------------|-------------|---------|
| `first_seen_at` | string | deterministic | ISO-8601 when first discovered | `2026-03-23T12:00:00+00:00` |
| `last_seen_at` | string | deterministic | ISO-8601 when last seen | `2026-03-24T02:44:00+00:00` |
| `published_date` | string | deterministic | Original publication date from source | `2024-02-08` |
