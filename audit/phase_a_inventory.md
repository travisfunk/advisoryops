# Phase A — Inventory

**Generated:** 2026-04-11
**Branch:** `feature/v1-readiness`
**Method:** Direct filesystem inspection. All counts measured, not estimated.

---

## 1. Repo Tree (depth 3, excluding .venv, __pycache__, .git, outputs/*_cache, outputs/discover)

```
advisoryops/
├── .claude/
│   ├── settings.json
│   └── settings.local.json
├── .env.example
├── .github/
│   └── ISSUE_TEMPLATE/
│       ├── bad_merge.md
│       ├── source_correction.md
│       └── wrong_product_match.md
├── .gitattributes
├── .gitignore
├── CONTRIBUTING.md
├── LICENSE
├── README.md
├── RELEASE_NOTES.md
├── advisoryops_context_report.md
├── advisoryops_vision.md
├── calibration_samples.txt
├── master_source_list_complete.md
├── sample_test_report.md
├── pyproject.toml
├── requirements.txt
├── configs/
│   ├── community_public_sources.json  (6,864 bytes)
│   ├── mitigation_playbook.json       (35,438 bytes)
│   ├── source_weights.json            (4,085 bytes)
│   ├── sources.json                   (59,518 bytes)
│   └── sources_expansion_candidates.json (9,242 bytes)
├── dashboard/
│   └── index.html                     (74,855 bytes, 1,386 lines)
├── docs/
│   ├── DOC-01_Master_Index.md through DOC-11_Community_Public_v0.md
│   ├── STATUS.md, schema.md, scoring_internals.md, playbook_governance.md
│   ├── feed_contract.json, grant_cost_model.md, session_state.md
│   ├── architecture.md, data_rights.md, kev_medical_device_analysis.md
│   ├── Feature 1 Spec — FDA Risk Class Ext.txt
│   ├── index.html (74,855 bytes — copy of dashboard/index.html)
│   └── [data artifacts: feed_latest.json, feed_healthcare.json, feed.csv, feed.xml, etc.]
├── logs/                              (backfill and verification logs)
├── outputs/                           (pipeline output, gitignored)
├── prompts/
│   └── extract_prompt.md
├── samples/
│   └── advisories/raw/               (CISA and FDA sample advisories)
├── schemas/
│   └── advisory_record_schema.json
├── scripts/                           (18 scripts: backfill runners, verification, calibration)
├── src/advisoryops/                   (38 .py files)
│   ├── enrichment/                    (7 .py files)
│   └── sources/                       (11 .py files)
└── tests/                             (57 test files)
    └── fixtures/golden/               (14 golden fixtures)
```

---

## 2. Python Module Inventory

### src/advisoryops/ — Core (38 files, 12,143 total lines)

| File | Lines | Purpose |
|------|------:|---------|
| `__init__.py` | 2 | Package init |
| `advisory_qa.py` | 294 | Natural-language Q&A against the advisory corpus |
| `ai_cache.py` | 194 | Content-hash-based cache for AI API responses |
| `ai_correlate.py` | 576 | AI merge candidate detection using text similarity + GPT decision |
| `ai_score.py` | 325 | Optional AI healthcare relevance classification |
| `change_tracker.py` | 221 | Detects changes between pipeline runs |
| `cli.py` | 624 | CLI entry point with 15 subcommands |
| `community_build.py` | 2289 | End-to-end pipeline orchestrator |
| `community_manifest.py` | 134 | Loads validated source sets from config |
| `contradiction_detector.py` | 342 | Cross-source contradiction detection |
| `correlate.py` | 630 | Groups signals into deduplicated Issues |
| `discover.py` | 520 | Fetches configured feeds, parses items, tracks state |
| `eval_harness.py` | 520 | Golden fixture evaluation harness |
| `excel_export.py` | 155 | Produces formatted .xlsx workbook |
| `extract.py` | 445 | LLM-based structured AdvisoryRecord extraction |
| `extract_fields.py` | 176 | LLM-based vendor/product/severity extraction |
| `feed_parsers.py` | 371 | JSON and CSV feed normalizers |
| `feedback.py` | 115 | Append-only feedback recorder |
| `healthcare_filter.py` | 308 | Tags issues with healthcare_relevant + category |
| `ingest.py` | 262 | Downloads/normalizes advisory documents |
| `ioc_extract.py` | 192 | Deterministic IOC extraction via regex |
| `models.py` | 106 | Pydantic data models for AdvisoryRecord |
| `mojibake.py` | 118 | UTF-8 mojibake repair |
| `nvd_enrich.py` | 523 | Queries NIST NVD 2.0 API per-CVE |
| `packet_export.py` | 575 | Formats RemediationPacket into JSON/Markdown/CSV |
| `page_enrich.py` | 201 | Fetches advisory web pages for richer mitigation text |
| `playbook.py` | 235 | Loads mitigation playbook into validated pattern catalog |
| `product_resolver.py` | 135 | Product-name lookup against issues |
| `recommend.py` | 414 | LLM selects mitigation patterns, generates RemediationPacket |
| `sanitize.py` | 110 | Prompt-injection hardening |
| `score.py` | 598 | Priority scoring P0-P3 (v1 keyword + v2 healthcare) |
| `source_mitigations.py` | 352 | Source-cited mitigation extraction |
| `source_run.py` | 334 | Stage 1 orchestrator: discovery + optional ingest |
| `source_weights.py` | 160 | Loads source authority weights |
| `sources_config.py` | 186 | Loads sources.json into typed dataclasses |
| `summarize.py` | 192 | Plain-language summary rewriting |
| `tag.py` | 185 | Exploit/impact tagging via keyword heuristics |
| `util.py` | 78 | Shared utilities: hashing, text normalization, JSON I/O |

### src/advisoryops/enrichment/ (7 files, 975 total lines)

| File | Lines | Purpose |
|------|------:|---------|
| `__init__.py` | 6 | Package init with apply_enrichments orchestrator |
| `attack_ics.py` | 143 | MITRE ATT&CK ICS technique/tactic lookups |
| `cross_reference.py` | 80 | Orchestrator applying EPSS/CWE/Vulnrichment enrichments |
| `cwe_catalog.py` | 191 | CWE ID-to-name lookup from MITRE |
| `epss_enrich.py` | 159 | EPSS exploit probability scores |
| `fda_classification.py` | 209 | FDA device risk class extraction |
| `vulnrichment.py` | 187 | CISA-enriched CVE records from GitHub |

### src/advisoryops/sources/ (11 files, 5,088 total lines)

| File | Lines | Purpose |
|------|------:|---------|
| `__init__.py` | 1 | Package init |
| `backfill_registry.py` | 151 | Registry of all backfill modules |
| `cisa_icsma_backfill.py` | 704 | Backfill CISA ICS-Medical advisories |
| `discover_sync.py` | 150 | Publishes backfill signals into discover output |
| `fda_safety_comms_backfill.py` | 771 | Backfill FDA safety communications |
| `health_canada_backfill.py` | 461 | Backfill Health Canada recalls |
| `mhra_uk_backfill.py` | 388 | Backfill MHRA UK device alerts |
| `nvd_backfill.py` | 682 | Backfill NVD CVE data |
| `openfda_backfill.py` | 810 | Backfill openFDA device recalls |
| `philips_psirt_backfill.py` | 441 | Backfill Philips PSIRT advisories |
| `siemens_productcert_backfill.py` | 529 | Backfill Siemens ProductCERT advisories |

---

## 3. Config Files

| File | Size | Description |
|------|-----:|-------------|
| `configs/sources.json` | 59,518 B | 96 source definitions (68 enabled, 28 disabled). Enablement field: `enabled` |
| `configs/community_public_sources.json` | 6,864 B | 4 validated source sets: gold_pass1 (10), expanded_pass1 (58), gold_pass2 (57), full_public (65). Plus 1 candidate |
| `configs/mitigation_playbook.json` | 35,438 B | 11 approved mitigation patterns, 6 roles, 10 categories |
| `configs/source_weights.json` | 4,085 B | 5-tier authority weighting model |
| `configs/sources_expansion_candidates.json` | 9,242 B | Expansion candidate tracking |

---

## 4. docs/ and dashboard/ Files

### dashboard/
| File | Size |
|------|-----:|
| `dashboard/index.html` | 74,855 B |

### docs/ — All files with sizes

| File | Size | Notes |
|------|-----:|-------|
| `index.html` | 74,855 B | Copy of dashboard/index.html |
| `session_state.md` | 38,215 B | |
| `Feature 1 Spec — FDA Risk Class Ext.txt` | 13,386 B | **EXTRA** — not in expected set |
| `DOC-04_Integrations.md` | 11,305 B | |
| `DOC-03_Mitigation_Playbook.md` | 11,090 B | |
| `DOC-08_Grant_Draft.md` | 9,458 B | |
| `scoring_internals.md` | 7,809 B | |
| `DOC-02_Data_Contracts.md` | 7,142 B | |
| `DOC-06_Matching.md` | 6,270 B | |
| `DOC-07_Evaluation.md` | 6,011 B | |
| `DOC-11_Community_Public_v0.md` | 5,510 B | |
| `schema.md` | 4,866 B | |
| `DOC-05_Ingestion.md` | 4,806 B | |
| `architecture.md` | 4,446 B | **EXTRA** — not in expected set |
| `STATUS.md` | 4,290 B | |
| `DOC-09_Prototype_Plan.md` | 3,612 B | |
| `grant_cost_model.md` | 3,134 B | |
| `feed_contract.json` | 2,992 B | |
| `kev_medical_device_analysis.md` | 2,939 B | **EXTRA** — not in expected set |
| `DOC-01_Master_Index.md` | 2,146 B | |
| `playbook_governance.md` | 2,141 B | |
| `DOC-10_Stack_and_Deployment.md` | 1,974 B | |
| `data_rights.md` | 1,684 B | **EXTRA** — not in expected set |

**Extra files in docs/ (not numbered DOC-NN, not expected utility files, and not data artifacts):**
1. `Feature 1 Spec — FDA Risk Class Ext.txt` (13,386 B)
2. `architecture.md` (4,446 B)
3. `data_rights.md` (1,684 B)
4. `kev_medical_device_analysis.md` (2,939 B)

---

## 5. Test Files

57 test files, 1,055 tests collected (1 deselected) per `pytest --collect-only -q`.

| File | Lines | Tests |
|------|------:|------:|
| `test_advisory_qa.py` | 558 | 22 |
| `test_ai_cache.py` | 275 | 22 |
| `test_ai_correlate.py` | 603 | 30 |
| `test_ai_score.py` | 369 | 15 |
| `test_backfill_registry.py` | 206 | 8 |
| `test_change_tracker.py` | 175 | 19 |
| `test_cisa_icsma_backfill.py` | 571 | 37 |
| `test_community_build.py` | 653 | 17 |
| `test_community_manifest.py` | 14 | 1 |
| `test_contradiction_detector.py` | 257 | 30 |
| `test_correlate_ai_merge.py` | 526 | 22 |
| `test_correlate_hardening.py` | 99 | 2 |
| `test_cross_source_mitigations.py` | 108 | 7 |
| `test_dashboard_html.py` | 96 | 7 |
| `test_discover_sync.py` | 167 | 13 |
| `test_docs.py` | 53 | 10 |
| `test_enrichment.py` | 345 | 24 |
| `test_eval_harness.py` | 255 | 31 |
| `test_excel_export.py` | 160 | 11 |
| `test_extract_fields.py` | 104 | 10 |
| `test_fda_classification.py` | 318 | 28 |
| `test_fda_safety_comms_backfill.py` | 451 | 32 |
| `test_feed_contract.py` | 113 | 6 |
| `test_feed_entry_mitigations.py` | 59 | 3 |
| `test_feed_parsers.py` | 101 | 6 |
| `test_health_canada_backfill.py` | 210 | 20 |
| `test_healthcare_category.py` | 64 | 14 |
| `test_healthcare_filter.py` | 223 | 22 |
| `test_ioc_export.py` | 105 | 10 |
| `test_ioc_extract.py` | 169 | 17 |
| `test_kev_medical_device.py` | 83 | 8 |
| `test_mhra_uk_backfill.py` | 151 | 14 |
| `test_mojibake_cleaning.py` | 20 | 2 |
| `test_new_fields.py` | 119 | 8 |
| `test_nvd_backfill.py` | 512 | 27 |
| `test_nvd_enrich.py` | 505 | 33 |
| `test_openfda_backfill.py` | 564 | 41 |
| `test_packet_export.py` | 423 | 40 |
| `test_page_enrich.py` | 164 | 17 |
| `test_philips_psirt_backfill.py` | 287 | 23 |
| `test_playbook_new_patterns.py` | 154 | 24 |
| `test_product_resolver.py` | 339 | 22 |
| `test_publish_step.py` | 71 | 4 |
| `test_recommend.py` | 352 | 28 |
| `test_remediation_trust.py` | 412 | 39 |
| `test_rss_feeds.py` | 159 | 9 |
| `test_sanitize.py` | 91 | 15 |
| `test_score_alerts.py` | 56 | 1 |
| `test_score_healthcare.py` | 401 | 35 |
| `test_score_keywords.py` | 186 | 20 |
| `test_score_phase1.py` | 59 | 1 |
| `test_siemens_productcert_backfill.py` | 336 | 22 |
| `test_source_mitigations.py` | 165 | 13 |
| `test_source_weights.py` | 394 | 51 |
| `test_sources_config.py` | 56 | 4 |
| `test_summarize.py` | 111 | 11 |
| `test_tag_phase2.py` | 41 | 1 |

**Total:** 57 files, 13,138 lines, 1,065 test functions (grep count; pytest collects 1,055 after parametrize/deselect).

---

## 6. CLI Surface

15 subcommands registered in `cli.py`:

| Subcommand | Help Text |
|------------|-----------|
| `discover` | Discover items from configured sources (configs/sources.json) |
| `ingest` | Ingest URL/text/PDF -> normalized snapshot + hashes |
| `extract` | Extract AdvisoryRecord.json from ingested snapshot |
| `source-run` | Discover + optional ingest from a configured source |
| `correlate` | Correlate discovered items across sources into Issues |
| `score` | Score correlated issues into priority/actions (writes outputs/scored) |
| `tag` | Tag correlated issues (writes outputs/tags/tags.jsonl + meta.json) |
| `evaluate` | Run golden fixture evaluation harness (writes outputs/eval/) |
| `recommend` | Generate a remediation packet for a scored issue |
| `community-build` | Build the combined community/public feed from the validated source manifest |
| `summarize` | Summarize a single issue into plain language |
| `ask` | Natural-language Q&A against the advisory corpus |
| `lookup` | Product lookup against issues |
| `export-excel` | Export issues JSONL to formatted .xlsx |
| `feedback` | Record recommendation feedback |

---

## 7. Playbook Patterns

Exactly 11 patterns in `configs/mitigation_playbook.json`. Confirmed.

| # | ID | Name |
|---|----|----- |
| 1 | `SEGMENTATION_VLAN_ISOLATION` | VLAN / Zone Isolation |
| 2 | `ACCESS_CONTROL_ACL_ALLOWLIST` | ACL / Firewall Allowlist |
| 3 | `ACCESS_CONTROL_NAC_POLICY` | NAC Device Policy |
| 4 | `ACCESS_CONTROL_REMOTE_ACCESS_RESTRICT` | Vendor Remote Access Restriction |
| 5 | `VENDOR_PROCESS_OPEN_CASE_AND_TRACK` | Vendor Case: Open and Track |
| 6 | `PATCHING_APPLY_VENDOR_OR_CUSTOMER` | Apply Patch / Update / Firmware |
| 7 | `GOVERNANCE_RISK_ACCEPTANCE` | Risk Acceptance (Time-Bound) |
| 8 | `COMMUNICATION_CLINICAL_DOWNTIME_NOTICE` | Clinical Downtime Notice |
| 9 | `MONITORING_ENHANCED_DETECTION` | Enhanced Detection and Monitoring |
| 10 | `CREDENTIAL_HARDENING` | Credential Hardening |
| 11 | `SERVICE_DISABLE_UNUSED` | Disable Unused Services and Protocols |

---

## 8. Source Count

**configs/sources.json:**
- Total sources: 96
- Enabled: 68 (field: `enabled`)
- Disabled: 28
- Scopes: advisory=18, dataset=12, news=29, threatintel=9

**configs/community_public_sources.json:**
- 4 validated sets: gold_pass1 (10), expanded_pass1 (58), gold_pass2 (57), full_public (65)
- 1 candidate source: vuldb-cti-api

---

## 9. Test Count

```
pytest --collect-only -q: 1055/1056 tests collected (1 deselected) in 233.89s
```

The deselected test is marked with `@pytest.mark.integration`.
