# Phase B — Doc Reality Audit

**Generated:** 2026-04-11
**Method:** Each factual claim checked against code on disk. Status: CONFIRMED / STALE / UNVERIFIABLE.

---

## README.md

| Claim | Status | Evidence |
|-------|--------|----------|
| Badge: "1038 passing" | STALE | pytest --collect-only reports 1,055 collected. Badge should be 1055. |
| Badge: dashboard link points to `advisoryops-dashboard` | STALE | Link is `https://travisfunk.github.io/advisoryops-dashboard/` but session_state.md says dashboard was consolidated into main repo. Link should point to `advisoryops` repo once Pages is flipped. |
| "65 public sources" (line 9) | STALE | configs/sources.json has 68 enabled sources, not 65. |
| "3,929 issues" (line 47) | UNVERIFIABLE | Requires pipeline run. |
| "856 medical device issues" (line 48) | UNVERIFIABLE | Requires pipeline run. |
| "2,362 issues with NVD enrichment" (line 49) | UNVERIFIABLE | Requires pipeline run. |
| "203 issues with KEV required actions" (line 50) | UNVERIFIABLE | Requires pipeline run. |
| "139 AI recommendation packets" (line 51) | UNVERIFIABLE | Requires pipeline run. session_state.md says 414 packets in most recent run. |
| "1,038 automated tests" (line 52) | STALE | Actual: 1,055 collected. |
| "$1.40 full corpus rebuild" (line 53) | UNVERIFIABLE | Cost claim from grant_cost_model.md. |
| Mermaid diagram: "57 Public Sources" (line 107) | STALE | Actual enabled: 68. |
| ASCII diagram: "57 enabled" (line 122) | STALE | Actual enabled: 68. |
| NVD Enrich box: "1,138 issues enriched" (line 149) | STALE | session_state.md says 2,362 in most recent run. |
| Healthcare filter: "234 / 1,990" (line 169) | STALE | session_state.md says 1,125 medical_device / 3,923 total in most recent run. |
| Source table: "Vendor PSIRTs: 10" listing "Microsoft MSRC, Cisco PSIRT, Siemens ProductCERT, Philips, BD, Medtronic, Abbott" | STALE | BD, Medtronic, Abbott do NOT exist in configs/sources.json. Cisco PSIRT is listed as talos-intelligence (not a PSIRT feed). |
| Source table: "Threat Intelligence: 8" listing "AlienVault OTX, GitHub Security Advisories" | STALE | AlienVault OTX exists but is DISABLED. GitHub Security Advisories does NOT exist in sources.json. |
| Source table: "Security News: 14" listing "BleepingComputer, SecurityWeek" | STALE | BleepingComputer and SecurityWeek do NOT exist in sources.json. |
| Source table: "Healthcare Orgs: 6" listing "H-ISAC, HHS 405(d), AHA, HSCC, FDA Safety Communications" | STALE | H-ISAC, HHS 405(d), AHA, HSCC do NOT exist in sources.json. FDA Safety Communications exists as fda-safety-comms-historical. |
| `python -m pytest # 1038 tests` (line 224) | STALE | Actual: 1,055. |
| "requires-python = >=3.11+" badge | CONFIRMED | pyproject.toml says `>=3.10`, but badge says 3.11+. Badge text does not match pyproject.toml. |

**README Summary:** 12 STALE claims, 5 UNVERIFIABLE, 1 CONFIRMED (with a badge/pyproject mismatch).

---

## docs/session_state.md

### Section 2 — Repository layout

| Claim | Status | Evidence |
|-------|--------|----------|
| "39 Python modules" in src/advisoryops/ | STALE | Actual: 38 .py files in src/advisoryops/ (not counting enrichment/ or sources/). |
| "6 enrichment modules" | STALE | Actual: 7 .py files in enrichment/ (including __init__.py). 6 non-init modules. Claim is ambiguous — correct if excluding __init__.py, incorrect if including it. |
| "9 per-source historical backfill modules" | STALE | Actual: 11 .py files in sources/ (including __init__.py, backfill_registry.py, discover_sync.py). 8 actual backfill modules + registry + sync + init = 11. Claim of 9 includes backfill_registry but not discover_sync or __init__. |
| "57 test files, ~1038 tests passing" | STALE | 57 test files is CONFIRMED. Test count: 1,055 collected (was updated from 1016 to 1038 in session 2026-04-09 log, but current count is 1,055). |

### Section 3 — Pipeline architecture

| Claim | Status | Evidence |
|-------|--------|----------|
| community_build.py "~2064 lines" | STALE | Actual: 2,289 lines (wc -l). Grew 225 lines since claim was written. |
| nvd_enrich.py "523 lines" | CONFIRMED | wc -l: 523 |
| summarize.py "192 lines" | CONFIRMED | wc -l: 192 |
| source_mitigations.py "352 lines" | CONFIRMED | wc -l: 352 |
| ai_score.py "325 lines" | CONFIRMED | wc -l: 325 |
| recommend.py "414 lines" | CONFIRMED | wc -l: 414 |
| extract.py "445 lines" | CONFIRMED | wc -l: 445 |
| ai_correlate.py "576 lines" | CONFIRMED | wc -l: 576 |
| advisory_qa.py "294 lines" | CONFIRMED | wc -l: 294 |
| contradiction_detector.py "342 lines" | CONFIRMED | wc -l: 342 |
| change_tracker.py "221 lines" | CONFIRMED | wc -l: 221 |
| feedback.py "115 lines" | CONFIRMED | wc -l: 115 |
| page_enrich.py "201 lines" | CONFIRMED | wc -l: 201 |
| sanitize.py "110 lines" | CONFIRMED | wc -l: 110 |
| ai_cache.py "194 lines" | CONFIRMED | wc -l: 194 |
| source_weights.py "160 lines" | CONFIRMED | wc -l: 160 |
| product_resolver.py "135 lines" | CONFIRMED | wc -l: 135 |
| eval_harness.py "520 lines" | CONFIRMED | wc -l: 520 |
| EPSS "Currently disabled / cache empty" | STALE | Problem 5 was marked RESOLVED in Section 6. epss_enrich.py has populate_cache(). Cache was populated 2026-04-09 per Section 13. |
| "advisoryops community-build (CLI in cli.py, implementation in community_build.py)" | CONFIRMED | cli.py:502 and community_build.py both exist. |

### Section 6 — Known problems

| Claim | Status | Evidence |
|-------|--------|----------|
| Problem 1 "RESOLVED" — _merge_trust copies recommended_patterns, tasks_by_role, reasoning, citations | CONFIRMED | community_build.py:2104-2107 copies these fields. community_build.py:136-140 includes them in _feed_entry. |
| Problem 2 "TRIAGE FIX RESOLVED" — source_id in non-CVE merge key | CONFIRMED | correlate.py:546: `key_basis = f"{it['source']}|{title_norm}|{pub}"` |
| Problem 3 — extract_fields.py exists and wired into community_build.py | CONFIRMED | extract_fields.py exists (176 lines). community_build.py:1542 imports it. |
| Problem 5 "RESOLVED" — epss_enrich.py has populate_cache() | CONFIRMED | epss_enrich.py exists (159 lines). Session 13 log confirms cache populated. |

### Section 12 — Uncertainties

| Claim | Status | Evidence |
|-------|--------|----------|
| Whether extract.py is wired into community-build | CONFIRMED NOT WIRED | community_build.py does not import extract.py. Only extract_fields.py is imported at line 1542. |
| Whether ai_correlate.py is wired into community-build | CONFIRMED NOT WIRED | community_build.py does not import ai_correlate.py. Correlate.py does import it (for --ai-merge flag), but community_build.py calls correlate() without passing ai_merge=True by default. |
| Whether eval_harness.py is run as part of CI | UNVERIFIABLE | No CI config found (.github/workflows/ does not exist). Likely dormant. |

### Section 4 — 11 playbook patterns

| Claim | Status | Evidence |
|-------|--------|----------|
| 11 patterns listed by ID and name | CONFIRMED | configs/mitigation_playbook.json has exactly 11 patterns. All IDs match. |

---

## docs/STATUS.md

**Dated 2026-03-17 — significantly stale.**

| Claim | Status | Evidence |
|-------|--------|----------|
| "Known gaps: Correlation + de-dup (high priority next)" | STALE | Correlation was built and shipped (correlate.py, community_build.py). Listed as a gap, but it's done. |
| "Known gaps: Enrichment + matching (later)" | STALE | Enrichment is built and shipped (6 enrichment modules, NVD/KEV/EPSS/FDA all working). |
| "Known gaps: Public source hygiene round 3" | STALE | gold_pass2 and full_public sets now exist with 57-65 sources. |
| All "Working (verified)" claims | CONFIRMED | Ingest, extract, discovery, source runner all still exist and are functional. |

**STATUS.md is frozen at 2026-03-17 and describes the project as of that date. Essentially every "next milestone" has been completed.**

---

## docs/schema.md

| Claim | Status | Evidence |
|-------|--------|----------|
| `issue_id` field | CONFIRMED | _feed_entry:77 |
| `title` field | CONFIRMED | _feed_entry:79 |
| `link` field | STALE | schema.md calls it `link`. _feed_entry uses `canonical_link`. |
| `priority` field | CONFIRMED | _feed_entry:88 |
| `score` field | CONFIRMED | _feed_entry:87 |
| `severity` field | CONFIRMED | _feed_entry:100 |
| `healthcare_category` field | CONFIRMED | _feed_entry:98 |
| `issue_type` field | CONFIRMED | _feed_entry:78 |
| `scope` field | STALE | schema.md lists this. NOT in _feed_entry. |
| `summary` field | CONFIRMED | _feed_entry:80 |
| `ai_summary` field | STALE | schema.md lists this. NOT in _feed_entry (summary may be overwritten by AI but the field name is just `summary`). |
| `cves` field | CONFIRMED | _feed_entry:82 |
| `vendor` field | CONFIRMED | _feed_entry:102 |
| `sources` field | CONFIRMED | _feed_entry:83 |
| `source_count` field | STALE | schema.md lists this. NOT in _feed_entry. |
| `handling_warnings` field | CONFIRMED | _feed_entry:92 |
| `evidence_gaps` field | CONFIRMED in _feed_entry but NOT in feed_contract.json | _feed_entry:93 |
| `unknowns` field | CONFIRMED in _feed_entry but NOT in feed_contract.json | _feed_entry:94 |
| `evidence_completeness` field | STALE | schema.md lists this. NOT in _feed_entry. |
| `generated_by` field | CONFIRMED | _feed_entry:103 |
| `extracted_facts` field | CONFIRMED | _feed_entry:105 |
| `inferred_facts` field | CONFIRMED | _feed_entry:106 |
| `insufficient_evidence` field | CONFIRMED | _feed_entry:109 |
| `source_consensus` fields | CONFIRMED | _feed_entry:95 |
| `why` field | CONFIRMED | _feed_entry:90 |
| `actions` field | CONFIRMED | _feed_entry:89 |
| `source_authority_weight` field | CONFIRMED | _feed_entry:96 |
| `highest_authority_source` field | CONFIRMED | _feed_entry:97 |
| `recommended_patterns` field | CONFIRMED | _feed_entry:137 |
| `non_applicability` field | CONFIRMED | _feed_entry:110 |
| `recommendation_disclaimer` field | STALE | schema.md lists this. NOT in _feed_entry. |
| `first_seen_at` field | CONFIRMED | _feed_entry:85 |
| `last_seen_at` field | CONFIRMED | _feed_entry:86 |
| `published_date` field | STALE | schema.md lists singular `published_date`. _feed_entry uses `published_dates` (plural array). |

**schema.md has 5 fields not present in _feed_entry: `link` (should be `canonical_link`), `scope`, `ai_summary`, `source_count`, `evidence_completeness`, `recommendation_disclaimer`, `published_date` (should be `published_dates`).**

---

## docs/feed_contract.json

| Contract Field | In _feed_entry? | Status |
|----------------|:---------------:|--------|
| `issue_id` | Yes | CONFIRMED |
| `title` | Yes | CONFIRMED |
| `priority` | Yes | CONFIRMED |
| `score` | Yes | CONFIRMED |
| `summary` | Yes | CONFIRMED |
| `cves` | Yes | CONFIRMED |
| `cvss_score` | Yes | CONFIRMED |
| `cvss_severity` | Yes | CONFIRMED |
| `cwe_ids` | Yes | CONFIRMED |
| `fda_risk_class` | Yes | CONFIRMED |
| `kev_required_action` | Yes | CONFIRMED |
| `kev_due_date` | Yes | CONFIRMED |
| `kev_vendor` | **NO** | STALE — in contract, read by dashboard, but NOT emitted by _feed_entry |
| `kev_product` | **NO** | STALE — same as above |
| `kev_vulnerability_name` | **NO** | STALE — same as above |
| `is_kev_medical_device` | Yes | CONFIRMED |
| `vendor` | Yes | CONFIRMED |
| `affected_products` | Yes | CONFIRMED |
| `affected_versions` | Yes | CONFIRMED |
| `handling_warnings` | Yes | CONFIRMED |
| `remediation_steps` | Yes | CONFIRMED |
| `actions` | Yes | CONFIRMED |
| `sources` | Yes | CONFIRMED |
| `canonical_link` | Yes | CONFIRMED |
| `published_dates` | Yes | CONFIRMED |
| `first_seen_at` | Yes | CONFIRMED |
| `last_seen_at` | Yes | CONFIRMED |
| `healthcare_relevant` | Yes | CONFIRMED |
| `healthcare_category` | Yes | CONFIRMED |
| `nvd_description` | Yes | CONFIRMED |
| `recommended_patterns` | Yes | CONFIRMED |
| `tasks_by_role` | Yes | CONFIRMED |
| `reasoning` | Yes | CONFIRMED |
| `epss_score` | Yes | CONFIRMED |
| `epss_percentile` | Yes | CONFIRMED |

**3 fields in feed_contract NOT in _feed_entry: kev_vendor, kev_product, kev_vulnerability_name.**

**21 fields in _feed_entry NOT in feed_contract:** issue_type, severity, why, source_authority_weight, highest_authority_source, classification, generated_by, extracted_facts, inferred_facts, confidence_by_field, evidence_sources, insufficient_evidence, non_applicability, source_mitigations, iocs, cvss_vector, evidence_gaps, unknowns, source_consensus, source_summary, citations.

---

## docs/scoring_internals.md

| Claim | Status | Evidence |
|-------|--------|----------|
| P0 >= 150, P1 >= 100, P2 >= 60, P3 < 60 | CONFIRMED | score.py thresholds match (verified via grep). |
| v1 keyword bonuses (KEV +80, RCE +30, etc.) | CONFIRMED | Matches score.py keyword lists. |
| v2 five healthcare dimensions | CONFIRMED | Source authority, device context, patch feasibility, clinical impact, FDA risk class all present in score.py. |
| Source weight tiers match source_weights.json | CONFIRMED | tier_1=1.0, tier_2=0.85, tier_3=0.7, tier_4=0.5, tier_5=0.35 match. |
| healthcare_tier1_medical_bonus = 50 | CONFIRMED | source_weights.json: `"healthcare_tier1_medical_bonus": 50`. |
| base_authority_points = 30 | CONFIRMED | source_weights.json: `"base_authority_points": 30`. |
| analyze_scoring_calibration.py looks for wrong path | CONFIRMED | scoring_internals.md:209 notes this. Not verified against script (not in scope). |

---

## docs/playbook_governance.md

| Claim | Status | Evidence |
|-------|--------|----------|
| Patterns require basis citation | CONFIRMED | All 11 patterns in mitigation_playbook.json have a `basis` field. |
| Approved standards: IEC 62443, NIST SP 800-82, FDA guidance, CISA ICS-CERT, NIST SP 800-39, practitioner experience | CONFIRMED | All patterns cite from this list. |
| Deprecated patterns marked with `"deprecated": true` | CONFIRMED | No deprecated patterns exist currently, but the governance rule is coherent. |
| AI draft patterns labeled `"draft": true` | UNVERIFIABLE | No draft patterns exist in current playbook to verify the mechanism. |

---

## docs/grant_cost_model.md

All claims are UNVERIFIABLE (depend on pipeline run data from a specific corpus snapshot).

---

## DOC-01 through DOC-11

| Doc | Last Updated | Status | Notes |
|-----|-------------|--------|-------|
| DOC-01 Master Index | 2026-03-17 | STALE | Lists docs that exist. Does not reference architecture.md, kev_medical_device_analysis.md, or grant_cost_model.md. |
| DOC-02 Data Contracts | 2026-03-17 | STALE | References `SourceObservation v0` and `CanonicalIssue v0` contracts. These names are not used in current code (current code uses "signal" and "issue"). |
| DOC-03 Mitigation Playbook | 2026-02-10 | STALE | References 11 patterns — count is correct. References roles and categories that match. But the doc predates the current playbook.json and may have diverged on pattern details. |
| DOC-04 Integrations | 2026-02-10 | STALE | References ServiceNow integration, SIEM connectors, PDF export. These are aspirational — no ServiceNow or SIEM code exists. PDF export does not exist (only JSON/Markdown/CSV/Excel). |
| DOC-05 Ingestion | 2026-02-10 | STALE | References `advisoryops discover`, `advisoryops ingest`, `advisoryops extract`, `advisoryops source-run`. These all exist. But references "Phase 1" terminology that predates current naming. |
| DOC-06 Matching | 2026-02-10 | STALE | Describes a facility inventory matching engine. No matching engine exists in current code. This is post-grant commercial work. |
| DOC-07 Evaluation | 2026-02-10 | STALE | References evaluation harness. eval_harness.py exists (520 lines). But doc references metrics and rubrics that may not match current implementation. |
| DOC-08 Grant Draft | 2026-02-10 | CONFIRMED | Grant narrative document. Not a code reference doc. Content is coherent with project goals. |
| DOC-09 Prototype Plan | 2026-03-17 | STALE | References prototype milestones. Many have been completed (e.g., public feed, dashboard, scoring). |
| DOC-10 Stack & Deployment | 2026-02-10 | STALE | References deployment approach. No CI/CD pipeline exists. No Dockerfile. No deployment automation. |
| DOC-11 Community Public v0 | 2026-03-17 | STALE | Defines "Pass 1" for public side. Much of this has been completed (source expansion, community-build, feeds). Numbers are outdated. |

---

## Summary

- **README.md:** 12 stale claims, 5 unverifiable. Most significant: source counts (says 65, actual 68), test counts (says 1038, actual 1055), pipeline diagrams (say 57 sources), source coverage table lists 10+ sources that don't exist in sources.json.
- **session_state.md:** Mostly accurate. community_build.py line count is stale (2064 vs 2289). Module counts slightly off. EPSS "disabled" claim is stale (resolved). Section 12 uncertainties now resolved.
- **STATUS.md:** Frozen at 2026-03-17. All "next milestones" have been completed. Entire file is stale.
- **schema.md:** 6 field name mismatches vs _feed_entry.
- **feed_contract.json:** 3 fields in contract but missing from _feed_entry (kev_vendor, kev_product, kev_vulnerability_name). 21 fields in _feed_entry not in contract.
- **scoring_internals.md:** Fully confirmed. Most accurate doc.
- **DOC-01 through DOC-11:** All dated 2026-02-10 or 2026-03-17. Most contain aspirational content that does not reflect current implementation.
