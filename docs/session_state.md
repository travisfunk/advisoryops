# AdvisoryOps — Session State (project context for Claude)

**Last updated:** 2026-04-12 by Claude (reality-check pass on branch `feature/v1-readiness`)
**Purpose:** This file is the durable single source of truth for what AdvisoryOps is, where it currently stands, and what the open problems are. It exists because Claude's working memory does not survive context-window compaction, and project context kept getting lost between sessions. **Future Claude: read this file at the start of every working session before doing anything else.** Do not skip it. Do not trust the memory summary in your system prompt as a substitute — that summary is incomplete by design and is the reason this file exists.

If something in this file looks wrong to Travis, **trust Travis over this file**, then update this file. Travis has end-to-end project memory; Claude does not.

---

## Section 1 — What AdvisoryOps is

AdvisoryOps is an open-source healthcare medical device security intelligence platform built and maintained solo by Travis Funkhouser (CISSP, CISM, CPHIMS, HCISPP, Stanford AI in Healthcare; 20+ years healthcare security including IU Health, ForeScout, Attivo, Flashpoint).

It aggregates security advisories from 68 enabled public sources (CISA ICS-CERT, FDA MedWatch, openFDA recalls and adverse events, NVD CVE API, vendor PSIRTs, threat intel feeds, healthcare news, and more), correlates and deduplicates them, scores them with healthcare-specific context, generates plain-language summaries and remediation guidance via LLM, and publishes everything as open data and an open-source dashboard. The whole pipeline currently costs about $1.40 per full corpus rebuild and ~$0.06 per weekly incremental run on `gpt-4o-mini`; total dev API spend across all sessions is roughly $12.70.

The strategic pitch is that hospitals (especially the thousands of small, rural, and community hospitals that can't afford Claroty, Armis, or TRIMEDX) need this exact thing and nothing comparable exists for free. Commercial vulnerability intelligence platforms in this space all start at enterprise pricing. AdvisoryOps fills the gap with a public-good open layer (free forever, free to view, free to fork). A commercial layer with facility-specific device inventory matching, watchlists, and email signup is **planned for after grant submission and is deliberately kept out of the grant proposal** — the grant framing is "everything is open."

The grant target is the **OpenAI Cybersecurity Grant Program** ($10M in API credits, rolling deadline, 3,000-word plaintext form at openai.com/form/cybersecurity-grant-program/).

## Section 2 — Repository layout and key locations

One consolidated repo at `C:\Users\travi\OneDrive\GitRepos\advisoryops`. GitHub: `travisfunk/advisoryops`. Currently public. The dashboard was previously in a separate `advisoryops-dashboard` repo and was consolidated into this repo via PR #12 (commit `c6401ac`, merged to main 2026-04-10). The legacy branch `merge/consolidate-dashboard` still exists locally and on origin but is superseded by the squash merge on main. The old dashboard repo still exists on GitHub — its status (archived or not) is UNVERIFIABLE from code.

Inside the repo:

- `src/advisoryops/` — 38 Python modules (`.py` files). Pipeline core.
- `src/advisoryops/enrichment/` — 6 enrichment modules plus `__init__.py` (FDA classification, EPSS, vulnrichment, CWE catalog, ATT&CK ICS, cross-reference orchestrator).
- `src/advisoryops/sources/` — 8 per-source historical backfill modules plus `backfill_registry.py`, `discover_sync.py`, and `__init__.py` (11 files total). Covers CISA ICSMA, openFDA, FDA safety comms, MHRA UK, Health Canada, NVD, Philips PSIRT, Siemens ProductCERT.
- `dashboard/` — production HTML dashboard (source of truth). Copied to `docs/index.html` by the pipeline's publish step.
- `tests/` — 57 test files, **1,055 tests passing** (as of 2026-04-12 on branch `feature/v1-readiness`). 1 test deselected via `@pytest.mark.integration`.
- `configs/` — `mitigation_playbook.json` (11 patterns), `source_weights.json` (5-tier authority), `community_public_sources.json` (validated source manifest), `sources.json` (full source list — 96 total entries, 68 enabled).
- `docs/` — 11 numbered design docs (DOC-01 through DOC-11) plus `STATUS.md`, `playbook_governance.md`, `schema.md`, `scoring_internals.md`, `feed_contract.json` (schema contract enforced by tests), `grant_cost_model.md`, `architecture.md`, `data_rights.md`, `kev_medical_device_analysis.md`. GitHub Pages serves from `/docs` on the `advisoryops` repo — the pipeline copies `dashboard/index.html` and data files here via `_publish_to_docs()`. Whether the live Pages source has been flipped from `advisoryops-dashboard` to `advisoryops` in the GitHub UI is UNVERIFIABLE from code; only Travis can confirm. The code-side prerequisites (dashboard + data files committed to docs/) are done. Read `schema.md` before touching anything that produces feed entries — it documents most fields, though it has drift with `_feed_entry` (see audit C-012).
- `outputs/community_public/` — pipeline output. Includes `feed_latest.json`, `feed_healthcare.json`, `feed_medical_device_kev.json`, RSS variants, Excel export, `sanity_report.md`, and the `packets/` subdirectory containing per-issue AI remediation packets.
- `outputs/*_cache/` — per-source caches. Persistent. NVD cache has ~340K records, openFDA recalls ~14,630, FDA safety comms ~38,510, Siemens ~779, MHRA ~1,381, EPSS ~325K scores. Reference table is in `docs/scoring_internals.md`.
- `outputs/ai_cache/` — content-hash-based AI response cache. Persistent across runs. 11,157 cached responses on disk. Keeps incremental costs near zero.
- `audit/` — audit and reality-check artifacts (Phase A/B/C findings, fix mission progress log, pipeline log, this session's reality-check report).
- `scripts/republish_docs.py` — reusable one-off script to re-run `_publish_to_docs()` against existing pipeline output without a full rebuild.

## Section 3 — Pipeline architecture (verified by reading code 2026-04-12)

The pipeline runs in stages, orchestrated by `advisoryops community-build` (CLI in `cli.py`, implementation in `community_build.py`, 2,293 lines as of 2026-04-12 on `feature/v1-readiness`).

```
discover → correlate → score → enrich → AI subsystem → output
```

**Discover.** Per-source modules in `discover.py` and `sources/*` pull signals from 60+ sources. Each signal gets a deterministic `signal_id` (SHA-256 of `source_id|guid`). Output: `outputs/discover/<source>/items.jsonl` per source.

**Correlate.** `correlate.py` groups signals into issues. CVE-bearing signals group by CVE ID. Non-CVE signals group by `UNK-<sha256(source_id|title|published_date)[:16]>` (source_id added by Problem 2 triage fix). Output: `outputs/community_public/correlate/issues.jsonl`.

**Score.** `score.py` runs v2 healthcare-aware scoring (v1 keyword baseline + 5 healthcare dimensions: source authority, device context, patch feasibility, clinical impact, FDA risk class). Thresholds are P0 ≥ 150, P1 ≥ 100, P2 ≥ 60, P3 < 60. Theoretical max ~805, observed range ~17–163, most issues 17–60. Full scoring reference is in `docs/scoring_internals.md` (current). Every scoring decision appends a human-readable string to a per-issue `why` field.

**Enrich.** Multiple enrichment passes happen during community-build:
- **NVD enrichment** (`nvd_enrich.py`, 523 lines) — queries NIST NVD 2.0 API for CVSS, CWE, CPE, descriptions. NVD API key is set as a permanent user environment variable. Most-recent run enriched 2,372 of 3,929 issues with CVSS/CWE/CPE data.
- **KEV cross-reference** — pulls KEV-specific fields (required_action, due_date, vendor, product, vulnerability_name) from CISA KEV. Most-recent run flagged 203 issues as KEV-enriched. After FIX 3 (commit `815ee7a`), all five KEV fields including `kev_vulnerability_name` flow through to the feed.
- **CISA Vulnrichment** (`enrichment/vulnrichment.py`) — per-CVE enrichment from `cisagov/vulnrichment` GitHub repo. Disabled by default in `apply_enrichments(vulnrichment=False)` because it requires per-CVE HTTP calls.
- **CWE catalog** (`enrichment/cwe_catalog.py`) — CWE name resolution. Most-recent run: 2,053 issues got CWE names.
- **ATT&CK ICS** (`enrichment/attack_ics.py`) — MITRE ATT&CK for ICS technique mapping. Available via module but not auto-applied to issues.
- **EPSS** (`enrichment/epss_enrich.py`) — Exploit Prediction Scoring System scores. **Cache populated 2026-04-09 with 325,743 scores** at `outputs/epss_cache/epss_scores.json`. Most-recent run: 2,356 issues got EPSS scores.
- **FDA risk class** (`enrichment/fda_classification.py`) — Feature 1. Extracts class from cached recall records (primary) or via openFDA classification API substring/product-code lookup (secondary). Most-recent run enriched 180 issues. Distribution: 8 Class III, 125 Class II, 47 Class I, 3,749 null.
- **Healthcare relevance + category** — `healthcare_filter.py` tags every issue. Categories: medical_device, healthcare_infrastructure, healthcare_it, healthcare_adjacent. Most-recent run: 1,116 medical_device, 170 healthcare_infrastructure, 5 healthcare_it, 2,638 healthcare_adjacent (3,929 total).

**AI subsystem.** Four optional AI features, all gated behind CLI flags on `community-build`. None run unless explicitly requested.

- **`--summarize`** (`summarize.py`, 192 lines) — plain-language 2–3 sentence summaries for hospital security analysts. Extracts unknowns, handling_warnings, evidence_completeness. Output written into the issue's summary and trust fields. Most-recent run: 971 of 971 issues rewritten.
- **`--extract-mitigations`** (`source_mitigations.py`, 352 lines) — source-cited mitigation extraction. Critical prompt rule: "Extract ONLY mitigations explicitly stated in source text. Do NOT invent." Each extracted mitigation includes a `verbatim_snippet` from the source text and is attributed to its source with authority tier.
- **`--extract-fields`** (`extract_fields.py`, 176 lines) — Problem 3 fix. Pulls vendor, product, severity from rewritten summaries for non-CVE issues with empty fields. Added via commit `0f8785d` (main) and `8840c70` (follow-up fix).
- **`--ai-score`** (`ai_score.py`, 325 lines) — AI healthcare classification backstop for issues with no deterministic healthcare signal. Boosts score if the model is ≥0.70 confident the issue is medical_device (+20), healthcare_it (+15), or healthcare_adjacent (+5).
- **`--recommend`** (`recommend.py`, 414 lines) — full remediation recommendation engine. Loads the 11-pattern playbook from `configs/mitigation_playbook.json`, asks the model to select 1–4 patterns, fill parameters, role-split tasks, identify side effects and friction levels, list evidence gaps, and produce per-pattern reasoning and a top-level reasoning string. Hallucinated pattern IDs are silently filtered against the approved list. Default model is `gpt-4o-mini`. Output is a `RemediationPacket` dataclass written to `outputs/community_public/packets/<issue_id>_packet.json`. Most-recent incremental run: 100 packets written for top alerts (`--top 100` default). Accumulated packet files on disk: 695.

Other AI/related modules that exist and are available but are NOT wired into community-build (confirmed by audit C-003, 2026-04-11):
- **`extract.py`** (445 lines) — Stage 2 ingest, structured AdvisoryRecord JSON extraction from raw advisory text. Used by the `extract` CLI command, not by community-build.
- **`ai_correlate.py`** (576 lines) — AI-assisted merge candidate detection for cross-source duplicates. Only reachable via `correlate --ai-merge` flag; community_build.py calls correlate() without it.
- **`advisory_qa.py`** (294 lines) — natural language Q&A against the corpus. Exposed as `advisoryops ask` CLI command.
- **`contradiction_detector.py`** (342 lines) — deterministic cross-source contradiction detection. Note: most-recent runs found 0 real contradictions in the corpus, which is itself a real finding worth investigating.
- **`change_tracker.py`** (221 lines) — deterministic what-changed tracking between pipeline runs.
- **`feedback.py`** (115 lines) — recommendation feedback recorder, exposed as `advisoryops feedback`.
- **`page_enrich.py`** (201 lines) — fetches advisory web pages for richer mitigation extraction.

Cross-cutting:
- **`sanitize.py`** (110 lines) — prompt injection hardening. Strips control chars and oversized chunks before any text goes to the model. Visible in pipeline logs as `sanitize_for_prompt altered summary (len X -> Y)`.
- **`ai_cache.py`** (194 lines) — content-hash response cache. The reason most rerun costs are near zero. 11,157 cached entries on disk.
- **`source_weights.py`** (160 lines) — loads `source_weights.json` for the 5-tier authority weighting used in v2 scoring.
- **`product_resolver.py`** (135 lines) — `resolve_product()` and the `advisoryops lookup` CLI command.
- **`eval_harness.py`** (520 lines) — golden fixture evaluation harness.

**Output stage.** `community_build.py` writes all the public artifacts: `feed_latest.json`, `feed_healthcare.json`, `feed_medical_device_kev.json`, `feed.csv`, `feed.xml` plus filtered RSS variants, `issues_public.xlsx`, `dashboard.html`, `validated_sources.json`, `meta.json`, `sanity_report.md`, and per-issue packets in `packets/`. The `_publish_to_docs()` step then copies the dashboard HTML and 11 data artifacts to `docs/` for GitHub Pages serving.

## Section 4 — The 11-pattern mitigation playbook

`configs/mitigation_playbook.json` contains 11 approved patterns. Every pattern has: `id`, `name`, `category`, `basis` (cited to a real standard), `severity_fit`, `when_to_use` conditions/constraints, `inputs_required`, role-split steps (`infosec`/`netops`/`htm_ce`/`it_ops`/`vendor`/`clinical_ops`), verification evidence, rollback steps, and `safety_notes`. The basis citations are real and were enforced by `docs/playbook_governance.md`, which requires every pattern to cite NIST SP 800-82, IEC 62443, FDA premarket/postmarket guidance, CISA ICS-CERT recommended practice, NIST SP 800-39, or "practitioner experience." No deprecated patterns currently. The 11:

1. **SEGMENTATION_VLAN_ISOLATION** (segmentation) — IEC 62443 zone/conduit model; NIST SP 800-82 Rev 3 Section 5.3.
2. **ACCESS_CONTROL_ACL_ALLOWLIST** (access_control) — NIST SP 800-82 Rev 3 Section 5.1; CISA ICS-CERT defense-in-depth.
3. **ACCESS_CONTROL_NAC_POLICY** (access_control) — Common healthcare network defense practice; IEC 62443 device identity.
4. **ACCESS_CONTROL_REMOTE_ACCESS_RESTRICT** (access_control) — CISA ICS-CERT remote access best practice; FDA postmarket guidance Section VI.B.
5. **VENDOR_PROCESS_OPEN_CASE_AND_TRACK** (vendor_process) — FDA postmarket guidance (vendor coordination); practitioner experience.
6. **PATCHING_APPLY_VENDOR_OR_CUSTOMER** (patching) — FDA premarket guidance (software validation); CISA ICS-CERT advisory remediation.
7. **GOVERNANCE_RISK_ACCEPTANCE** (governance) — NIST SP 800-39 risk management; practitioner experience.
8. **COMMUNICATION_CLINICAL_DOWNTIME_NOTICE** (communication) — Common healthcare practice; FDA postmarket guidance Section VI.
9. **MONITORING_ENHANCED_DETECTION** (monitoring) — NIST SP 800-82 Rev 3 Section 6.2; CISA ICS-CERT defense-in-depth.
10. **CREDENTIAL_HARDENING** (access_control) — NIST SP 800-82 Rev 3 Section 5.2; FDA postmarket guidance.
11. **SERVICE_DISABLE_UNUSED** (hardening) — IEC 62443-3-3 SR 7.7 (least functionality); CISA ICS-CERT attack surface reduction.

The recommendation engine is constrained to select only from these approved patterns. AI-generated draft patterns are labeled `draft: true` and require human review before promotion (per `docs/playbook_governance.md`).

## Section 5 — Current corpus state (verified 2026-04-12 from feature/v1-readiness, after classifier + FDA-floor + FDA-extraction missions)

The corpus numbers below reflect the state after three product missions landed on 2026-04-12 on top of the FIX 4.5 rebuild (`b0f4b5e`):

- **medical_device classifier tightening** (`1d222b2`, `19b3b37`, `ab77ae8`, `28e776f`) — strict 4-rule classifier.
- **FDA clinical-severity floor** (`57d53f7`, `63cf110`, `3cbcb4f`) — Class III auto-floor to P0, Class II to P1.
- **FDA risk class extraction** (`1ee3ab3`, `f888ea9`, `ef21ec0`) — enforcement-cache lookup fills previously-null classifications.

Pipeline baseline (from the FIX 4.5 rebuild; the three missions above re-classified and re-scored in place, no new pipeline run). Counts refreshed 2026-04-12 after the Problem 9 pharmaceutical-exclusion cleanup (`fda-medwatch` and `mhra-uk-alerts` disabled, 205 records dropped):

- **3,724 total issues** (was 3,929 before the pharmaceutical cleanup) correlated across **63 enabled sources** (was 65; `fda-medwatch` and `mhra-uk-alerts` excluded — see Problem 9).
- **Priority distribution (corpus-wide):** 225 P0, 483 P1, 536 P2, 2,480 P3.
- **100 alerts public** in `alerts_public.jsonl` (limited by default `--top 100`).
- **2,372 issues** NVD-enriched with CVSS/CWE/CPE (minor day-to-day variance based on NVD data currency).
- **203 issues** KEV-enriched. **Zero of those KEV issues match medical device vendors** — see Section 6 Problem 4.
- **378 issues** with FDA risk class: 10 Class III, 285 Class II, 83 Class I, 3,346 null. Down 2 from the pre-cleanup 380 populated (both removed records were the pharmaceutical leaks from `mhra-uk-alerts`).
- **971 plain-language summaries** generated (all issues with `generated_by == 'ai'`).
- **99 issues** with populated `recommended_patterns` in the feed (propagated from the top-100 alert packets via `_merge_trust`).
- **6,639 IOCs** extracted (number from 2026-04-08 run; not re-measured during the 2026-04-12 rebuild).
- **1,233 source-cited mitigations** from 899 issues (number from 2026-04-08 run; not re-measured).
- **2,356 issues** EPSS-enriched.
- **2,053 issues** CWE-enriched.
- **100 recommendation packets** newly written this rebuild (for the top-100 P0/P1 alerts). **695 total packet files** accumulated on disk from prior runs.

Healthcare category breakdown (post-pharmaceutical-cleanup): **422 medical_device**, 241 healthcare_infrastructure, 17 healthcare_it, 3,044 healthcare_adjacent. (Pre-pharmaceutical-cleanup: 424 / 258 / 17 / 3,230. The 2 medical_device removals came from `mhra-uk-alerts` "Class 2 Medicines Recall" records whose misparsed `fda_risk_class` triggered Rule 3; the larger drop in `healthcare_adjacent` absorbed the remaining 203 pharmaceutical records. Before the classifier tightening, medical_device was 1,116 — inflated by `philips-psirt` / `siemens-productcert` co-occurrence.)

Medical-device bucket priority distribution: **10 P0, 290 P1, 28 P2, 94 P3.** Down 1 each at P1/P3 from the pre-cleanup distribution as the two MHRA medicines recalls dropped.

**Note on `feed_healthcare.json`:** Still contains all 3,929 issues because `is_healthcare_relevant()` treats a non-empty `healthcare_category` as sufficient (rule c), and the fallback category is `healthcare_adjacent`. The dashboard's "Medical devices" button now filters on `healthcare_category === 'medical_device'` directly, so the broad healthcare-adjacent set no longer leaks into that view — even though the underlying feed file is unchanged.

Tests: **1,076 passing** on branch `feature/v1-readiness` as of 2026-04-12. No known failures.

The full AI subsystem (recommend, summarize, extract-mitigations, ai-score) is operational and producing end-to-end output. All 100 packets during the latest rebuild hit the AI cache — $0 incremental API spend.

## Section 6 — Known problems, prioritized

These are the issues blocking grant submission, in priority order. **Read this section every session.**

### Problem 1 — Packet → feed merge gap — RESOLVED

**Resolved:** 2026-04-09 by commits on `merge/consolidate-dashboard` (squash-merged to main via PR #12 on 2026-04-10, commit `c6401ac`).

Fixed `_merge_trust` to copy `recommended_patterns`, `tasks_by_role`, `reasoning`, and `citations` from packet data into feed rows. Added these fields to `_feed_entry` and to `packet_trust_by_id`. Dashboard now renders pattern cards with friction levels, role-split tasks, and AI reasoning. Regression tests added to `test_remediation_trust.py`.

**Audit follow-up (2026-04-11):** Audit finding C-001 + C-014 found that three additional KEV-related fields (`kev_vendor`, `kev_product`, `kev_vulnerability_name`) were still being dropped by `_feed_entry` even though the dashboard read them and `feed_contract.json` declared them. Resolved 2026-04-12, commit `815ee7a` — added all three to `_feed_entry`, added `kev_vulnerability_name` to `_KEV_FIELDS` (previously missing). Incremental pipeline rebuild commit `b0f4b5e` propagated the new schema to docs/ — feed_latest.json now has 203 entries with populated `kev_vendor`/`kev_product`/`kev_vulnerability_name`.

### Problem 2 — Correlation incorrectly merges unrelated signals — TRIAGE FIX RESOLVED

**Triage fix resolved:** 2026-04-09. Squash-merged to main via PR #12, commit `c6401ac`.

Applied option 2: added `source_id` to the non-CVE merge key basis (`key_basis = f"{it['source']}|{title_norm}|{pub}"`). This prevents cross-source collisions regardless of title. Issue count increased 3,923 → 3,929 as previously-merged distinct signals became separate issues. Source-count anomalies dropped to zero: 0 issues with 10+ sources, 0 mixed-type contamination.

**Architectural fix still pending (post-grant):** The full fix is to separate threatintel from advisory routing entirely — categorize sources as `kind: advisory` vs `kind: threatintel` in `sources.json` and route them through different correlation logic.

### Problem 3 — Field extraction for non-CVE / FDA-recall-derived issues — PARTIALLY RESOLVED

**Resolved:** 2026-04-10 by commits `0f8785d` "Add LLM field extraction for non-CVE issues (Problem 3)" and `8840c70` "Fix extract_fields truncation: bump max_tokens, handle malformed JSON" — both on main via PR #13.

The fix: new module `src/advisoryops/extract_fields.py` (176 lines) and `--extract-fields` flag on `community-build`. Wired into `community_build.py` at line 1546. Pulls vendor, product, and severity from rewritten plain-language summaries for issues where those fields were empty. Then the FDA classification lookup runs again with the extracted device name.

**Also resolved 2026-04-12 by FDA risk class extraction mission** (commits `1ee3ab3`, `f888ea9`, `ef21ec0`). `fda_classification.py` gained `extract_risk_class_from_enforcement` + `lookup_class_by_recall_number` helpers, and `scripts/retag_corpus.py` now parses `Z-NNNN-YYYY` recall numbers out of issue titles to hit the enforcement cache. This back-filled 200 additional `fda_risk_class` values (from 178 → 378 populated), closing most of the FDA-recall-derived extraction gap.

**Still pending:** `vendor` and `affected_products` on FDA-recall-derived issues remain mostly empty (the 424 medical_device rows show `vendor=(none)` in the validation script). Extraction for those two fields needs its own pass, either by cross-referencing enforcement records more fully or by running `--extract-fields` against the re-tagged corpus. Lower leverage than the FDA-class gap was; kept on the list for post-grant triage.

### Problem 4 — KEV / medical device zero overlap (INVESTIGATION IN PROGRESS)

**Status:** Investigation writeup landed 2026-04-10 as commit `86984c0` on main, producing `docs/kev_medical_device_analysis.md`. Root-cause determination still needs Travis to review the writeup's conclusion.

**Symptom:** All 203 KEV-enriched issues are general IT vendors (Cisco, Adobe, Apple, Microsoft, Fortinet, Ivanti, etc.). Zero match medical device vendors. Feature B (KEV cross-reference for medical devices) is architecturally in place but matches nothing. `feed_medical_device_kev.json` currently contains `[]`.

**Possible causes (from Problem 4 writeup):**
1. **The KEV catalog genuinely contains no medical device CVEs** — CISA's KEV is biased toward widely-deployed enterprise software because that's what gets actively exploited at scale. Medical device CVEs may simply not be in KEV in meaningful numbers.
2. **Vendor name mismatching** — the medical device vendor names in our healthcare filter and the vendor names in KEV use different conventions and never match even when the same product is involved.
3. **Healthcare filter scope mismatch** — the healthcare filter may be flagging issues that KEV-enriched CVEs don't overlap with by definition.

**Action:** This is a potentially interesting finding for the grant itself ("KEV doesn't track medical device CVEs at scale, which is part of why a healthcare-focused intelligence system needs to exist"). Worth framing correctly in the grant narrative.

### Problem 5 — EPSS cache empty — RESOLVED

**Resolved:** 2026-04-09. Ran `populate_cache()` from `enrichment/epss_enrich.py`. Cache populated with 325,743 EPSS scores at `outputs/epss_cache/epss_scores.json` (26MB). The pipeline automatically uses this cache via `apply_enrichments(epss=True)` — no code change was needed. Most recent rebuild enriched 2,356 issues.

### Problem 6 — Healthcare filter false positives — RESOLVED

**Resolved:** 2026-04-12 by the medical_device classifier tightening mission (commits `1d222b2`, `19b3b37`, `ab77ae8`, `28e776f`).

The original fix (`d605b28`, 2026-04-10) was a narrow false-positive filter; the root cause was that `classify_healthcare_category` promoted to `medical_device` on source co-occurrence — any issue carrying `philips-psirt` or `siemens-productcert` in its sources was tagged, regardless of whether the affected product was a medical device. That's why Chrome / Windows / Cisco / Citrix CVEs were showing up under the "Medical devices" filter.

Replacement: strict 4-rule classifier in `src/advisoryops/healthcare_filter.py`. An issue is tagged `medical_device` iff at least one of:

1. `cisa-icsma` in sources (CISA ICS-Medical authority),
2. `vendor` field matches the curated `MEDICAL_DEVICE_VENDORS` allowlist,
3. `fda_risk_class` is populated,
4. `affected_products` matches the curated `MEDICAL_DEVICE_PRODUCT_KEYWORDS` list.

Results: medical_device count 1,116 → 224 (after dashboard predicate fix) → 424 (after FDA-class back-fill grew Rule-3 hits). Zero general-IT vendor leaks confirmed by `scripts/validate_medical_device_bucket.py` against the curated blocklist (Microsoft, Google, Adobe, Cisco, Citrix, Oracle, IBM, VMware, Apple, Mozilla, Samsung). Dashboard "Medical devices" button now filters on `healthcare_category === 'medical_device'` exclusively. Bucket composition now dominated by `openfda-recalls-historical` / `cisa-icsma-historical` / `cisa-icsma` sources, which is the intended signal.

`is_healthcare_relevant` was deliberately left unchanged — `feed_healthcare.json` still includes `healthcare_adjacent` rows. That's a separate framing question, not a filter-accuracy bug: the broad "healthcare-relevant" set is fine as a superset, and the dashboard view surfaces the strict medical_device subset by default.

### Problem 7 — Dashboard search box broken — RESOLVED

**Resolved:** 2026-04-10, commit `fa5cbfd` "Verify dashboard search works (Problem 7)" on main via PR #13. Search input now filters issues by title, CVE, vendor, product, affected versions, and CWE IDs.

### Problem 8 — Temporal relevance gap — RESOLVED 2026-04-12 via dashboard top-N latest pagination

**Symptom:** The dashboard P0 lane currently surfaces historical FDA Class III recalls (some from 2010-2016) alongside — and in some cases above — current advisories that hospital security teams need to act on this week. The FDA clinical-severity floor (Section 8 principle 11) is architecturally correct: Class III means "failure can cause serious injury or death," and a P0 floor reflects that. But in the current corpus the Class III set is dominated by historical recalls that long ago cycled into terminated status, so the floor-as-implemented fills the ACT NOW lane with the wrong issues.

**Contradiction with vision:** `docs/advisoryops_vision.md` explicitly frames the product as advisory-to-action with "right now" as the operating cadence. A P0 lane whose top items are 10+ years old contradicts that framing, regardless of how defensible the clinical-severity reasoning is in isolation.

**Fix shape:** presentation-layer pagination only. Issues are sorted by `published_date` descending after all other filters apply, then sliced to top-N (default 25). The FDA clinical-severity floor (principle 11) still fires; historical Class III items remain P0 in the underlying feed and are still visible via the "All" option, but they no longer dominate the default view because more recent items naturally sort above them. Date windows were considered first but rejected because the medical_device bucket has uneven temporal distribution and a fixed window risked an empty default view. Top-N is stable regardless of data distribution. Dropdown options: 25 / 50 / 100 / All. Priority tiles and header counts continue to reflect the full filtered set, not the paginated view.

**Status:** RESOLVED 2026-04-12 by dashboard top-N latest pagination (commit `5052347`).

### Problem 9 — Pharmaceutical record leakage — RESOLVED 2026-04-12 via source exclusion + corpus cleanup

**Symptom:** Live dashboard screenshot revealed records like "Class 2 Medicines Recall: Wockhardt UK Ltd, Heparin sodium 1,000 I.U./ml solution for injection" appearing in the medical_device bucket. Heparin is a drug, not a medical device. AdvisoryOps is a medical device security platform targeted at hospital InfoSec / Clinical Engineering teams; pharmaceutical recalls belong to pharmacy teams integrated with EMR drug-recall workflows (Epic, Cerner, Meditech) and are explicitly out of scope.

**Root cause:** MHRA's "Class 2 Medicines Recall" naming scale collides with FDA's Class I/II/III device classification scale. The upstream backfill parser populated `fda_risk_class` from the MHRA urgency tier, and Rule 3 of the strict 4-rule medical_device classifier (`healthcare_filter.py::_is_medical_device`) then correctly fired on the populated field and promoted pharmaceutical recalls into the medical_device bucket. The rule was right; the upstream data was lying about what was in the field.

**Fix shape:** source-level exclusion rather than classifier modification. `fda-medwatch` and `mhra-uk-alerts` set to `enabled: false` in `configs/sources.json` with an `excluded_reason` field preserving the rationale inline. Same two IDs removed from all validated sets in `configs/community_public_sources.json` and added to a new top-level `excluded_sources` list. Existing corpus records from those sources deleted from the six feed artifacts under `docs/` and `outputs/community_public/`. Regression test (`tests/test_no_pharmaceutical_sources.py`) asserts both sources stay disabled, stay out of validated sets, and carry an exclusion rationale. Validation script (`scripts/validate_medical_device_bucket.py`) extended to fail on pharmaceutical keyword leaks (title regex) or pharmaceutical-source membership in the medical_device bucket.

**Measurable result:** total corpus 3,929 → 3,724 (−205 records). medical_device bucket 424 → 422 (−2; both MHRA medicines recalls). Pharmaceutical-titled records corpus-wide 159 → 0. Source count 65 → 63. Rule 3 of the classifier is unchanged — the principle is correct; only the upstream inputs changed.

**Scope note:** `mhra-uk-alerts` is a genuinely mixed source (79.5% medicines, 20.5% medical devices). Disabling it dropped 41 legitimate UK medical device alerts (e.g., Sprint Fidelis ICD, Accu-Chek Insight insulin pump, HeartStart MRx defibrillator) along with the 159 medicines recalls. Impact is zero on the Medical devices dashboard view because none of those 41 records were in the medical_device bucket anyway — they were classified as `healthcare_adjacent`. Future follow-up: re-enable `mhra-uk-alerts` with a tightened upstream GOV.UK query that filters out medicines alerts at ingest, recovering the 41 legitimate device records.

**Status:** RESOLVED 2026-04-12 by source exclusion + corpus cleanup (commit `ccff0ac`).

### Audit findings still open (from phase_c_code_findings.md, 2026-04-11)

Not elevated to numbered Problems because they're lower leverage than the pre-grant checklist in Section 7. Tracked for completeness:

- **C-002:** `feed_contract.json` has 21 fields that `_feed_entry` emits but the contract doesn't declare (the inverse — 3 missing contract fields — was fixed by FIX 3). Contract is enforced by `tests/test_feed_contract.py` but the test only flags missing fields read by the dashboard, not missing declarations for emitted fields.
- **C-003:** `extract.py` and `ai_correlate.py` are not wired into community-build (intentional for cost reasons, but worth documenting).
- **C-010:** 11 modules (cli.py, feedback.py, ingest.py, models.py, source_run.py, util.py, and 5 enrichment modules) have no dedicated test file.
- **C-012:** `docs/schema.md` has 7 field-name mismatches with `_feed_entry` output (36 documented fields vs 56 actual).
- **C-027:** `community_build.py:1862` and `:1889` contain silent `except Exception:` blocks in the AI enrichment loops. Per-issue AI failures are invisible.
- **C-031:** `_DASHBOARD_HTML` at `community_build.py:419` contains ~860 lines of dead embedded dashboard HTML (light-theme older version). `_publish_to_docs()` copies the standalone `dashboard/index.html` to `docs/` instead; the embedded version is never published.

## Section 7 — What's shipped vs. what's pending

### Shipped and verified working (as of 2026-04-12)

- 60+ source ingestion pipeline (Section 3)
- Historical backfill infrastructure for 8 high-value sources (`sources/*` modules)
- v2 healthcare-aware scoring with 5 dimensions and full per-issue `why` field (`scoring_internals.md`)
- Source authority 5-tier weighting (`source_weights.py`, `configs/source_weights.json`)
- NVD enrichment with CVSS/CWE/CPE (`nvd_enrich.py`)
- KEV cross-reference with `kev_vendor`/`kev_product`/`kev_vulnerability_name` propagated end-to-end (FIX 3)
- FDA risk class extraction from openFDA recalls (Feature 1)
- The 11-pattern mitigation playbook with full citations (`mitigation_playbook.json`, governance in `playbook_governance.md`)
- All four AI features: `--summarize`, `--extract-mitigations`, `--ai-score`, `--recommend`
- Plus `--extract-fields` (Problem 3 fix)
- The `RemediationPacket` dataclass and packet writer
- Source-cited mitigation extraction with verbatim_snippet attribution
- Plain-language summarizer with handling_warnings, unknowns, evidence_completeness
- AI cache (`ai_cache.py`) — content-hash based, persistent, keeps incremental costs near zero
- Prompt injection sanitization (`sanitize.py`)
- Excel export (`excel_export.py`)
- 4 filtered RSS feeds: healthcare, KEV medical device, Class III, P0/P1
- Healthcare category classification
- Cross-source contradiction detection (`contradiction_detector.py`)
- Change tracking between pipeline runs (`change_tracker.py`)
- Recommendation feedback recorder (`feedback.py`)
- Advisory Q&A CLI (`advisory_qa.py`, exposed as `advisoryops ask`)
- Product resolver (`product_resolver.py`, exposed as `advisoryops lookup`)
- Golden fixture evaluation harness (`eval_harness.py`)
- Feed schema contract (`docs/feed_contract.json`) enforced by `tests/test_feed_contract.py`
- Pipeline sanity report generated on every build (`outputs/community_public/sanity_report.md`)
- EPSS scores rendered in the dashboard detail panel (commit `72c3fb2`)
- AI recommendations rendered in the dashboard (commit `9cfd9fc`)
- Dashboard priority thresholds match scoring reality (FIX 2, commit `0682073`)
- Dashboard consolidated into main repo via PR #12 (commit `c6401ac`, 2026-04-10)
- `_publish_to_docs()` copies dashboard HTML + 11 data files to docs/ after each build
- Healthcare filter false-positive reduction (partial — Problem 6, commit `d605b28`)
- Dashboard search functional (Problem 7, commit `fa5cbfd`)
- KEV / medical device overlap investigation writeup (Problem 4, `docs/kev_medical_device_analysis.md`, commit `86984c0`)
- Non-CVE field extraction (Problem 3, `extract_fields.py`, commits `0f8785d` + `8840c70`)
- Architecture diagram + layer descriptions (commit `e778acc`, `docs/architecture.md`)
- CONTRIBUTING.md refreshed for grant readiness (commit `afe40dc`)
- README polish pass (commit `2924a54`) plus audit-driven correction pass (FIX 4, commit `68ae1f3`)
- Repo hygiene: gitignore expansion, script and doc commits (commit `c719b52`)
- `scripts/republish_docs.py` reusable one-off publisher (commit `dab64b3`)
- Test hygiene: 9 `build_community_feed()` calls in test_community_build.py fixed to pass `repo_root=tmp_path` — tests no longer silently overwrite the real `docs/` directory (commit `dab64b3`)
- **Strict 4-rule medical_device classifier** (CISA ICS-Medical authority / vendor allowlist / FDA risk class / product keyword allowlist) — `healthcare_filter.py`, commit `1d222b2`. Dashboard "Medical devices" filter predicate corrected in commit `bcf2d46` to read `healthcare_category === 'medical_device'` exclusively.
- **FDA clinical-severity floor** (`_apply_fda_clinical_floor` in `score.py`, commit `57d53f7`): Class III auto-floors to P0, Class II to P1, Class I receives +10 additive only. Codified as architectural principle #11 in commit `3cbcb4f`.
- **FDA risk class extraction via enforcement cache** (`extract_risk_class_from_enforcement` + `lookup_class_by_recall_number` in `fda_classification.py`, commit `1ee3ab3`). Back-filled 200 previously-null classifications against the existing corpus via `scripts/retag_corpus.py` extension in commit `f888ea9`.
- **Dashboard header wired to live `meta.json`** (source count from `counts.sources_enabled`, "Updated" date from `generated_at`) — `_publish_to_docs` now augments meta.json at publish time, commit `ab77ae8`.
- **Validation script for medical_device bucket purity** (`scripts/validate_medical_device_bucket.py`, commits `28e776f` + `ef21ec0`) — blocks general-IT vendor leaks, reports FDA-coverage metric.
- **Re-tag script `scripts/retag_corpus.py`** — one-shot deterministic re-classification + FDA risk-class re-extraction + clinical-severity floor re-application against an already-built corpus, no paid AI.
- **Dashboard top-N latest pagination** (Problem 8, commit `5052347`) — "LATEST" dropdown (25/50/100/All, default 25) sorts the filtered issue list by `published_date` desc then slices; priority tiles and header counts reflect the full filtered set, not the paginated view.
- **Pharmaceutical source exclusion + corpus cleanup** (Problem 9, 2026-04-12) — `fda-medwatch` and `mhra-uk-alerts` disabled in `configs/sources.json` with inline `excluded_reason`; removed from every validated set in `configs/community_public_sources.json` and added to a new `excluded_sources` list; 205 corpus records cleaned across `docs/` and `outputs/community_public/` feed artifacts via `scripts/clean_pharmaceutical_records.py`; regression test `tests/test_no_pharmaceutical_sources.py`; validation script extended to fail on pharmaceutical title keywords or source membership in the medical_device bucket.
- 1,079 tests passing (1,076 baseline + 3 from `test_no_pharmaceutical_sources.py`)

### Pending pre-grant

In rough priority order:

1. **Push `feature/v1-readiness` to origin and merge to main.** The audit+fix commits plus the 2026-04-12 classifier/floor/extraction commits are local-only. Travis to review and push when comfortable.
2. **Verify live GitHub Pages site.** Either confirm the Pages source is already flipped to `advisoryops/docs` (in which case the README live-demo link needs updating to `https://travisfunk.github.io/advisoryops/`), or flip it now. The old `advisoryops-dashboard` Pages URL is still the value in README.
3. **Archive the old `advisoryops-dashboard` repo on GitHub** after step 2 succeeds.
4. **Footer/link audit.** README line 6 and line 36 still contain the old `advisoryops-dashboard` URL. Other repo-internal links should be spot-checked.
5. **Problem 3 residual — vendor/affected_products extraction.** FDA risk class is now populated on 378 records; vendor and affected_products on FDA-derived rows are still empty. Probably worth a targeted extraction pass or cross-reference against enforcement records' `recalling_firm` / `product_description` fields.
6. **Audit findings triage.** Decide which of C-002/C-003/C-010/C-012/C-027/C-031 to address before grant submission vs. defer.
8. **SE enablement session + mock reviewer Q&A.** Pre-grant requirement explicitly set by Travis. Walk through the pipeline like briefing an SE before a big demo, then 20 hardest-likely reviewer questions. Happens AFTER code is final.
9. **200-word problem statement.** Travis writes himself in his own voice. Do not draft this for him; offer feedback if asked but do not write it for him.
10. **Grant proposal writing.** Travis initiates when ready. **Do not prompt about grant writing until he does.**

### Pending post-grant (out of scope for grant submission)

- Commercial layer: facility-specific device inventory matching, watchlists, work-email-only signup, email capture for sales leads. Architecturally separate from public layer. **Deliberately kept out of the grant proposal.**
- Full architectural fix for Problem 2 (separate threatintel from advisory routing).
- Dashboard rebuild. Phased plan: ship the next high-leverage feature on the existing dashboard first, then redesign the dashboard from scratch with full requirements known. Travis explicitly agreed: "I am not sure we won't have more ideas... I also think we can't really design now as we don't really know what the data will actually look like."
- Ask A Nurse app — separate project, queued behind AdvisoryOps grant work.

## Section 8 — Architectural principles (locked, do not violate)

These are decisions Travis has made and re-confirmed. Treat them as constitutional.

1. **Bounded AI authority.** The AI is allowed to select from approved patterns, extract structured data from source text, and rewrite text into plain language. The AI is NOT allowed to invent guidance, author its own mitigation patterns, or make final clinical decisions. Hallucinated pattern IDs are silently filtered. AI-generated draft patterns require human review before promotion. This is the playbook governance contract.
2. **Aggregator, not authority.** AdvisoryOps cites source mitigations verbatim with attribution rather than generating its own technical rules. The platform aggregates and indexes; it doesn't author guidance. Even rich AI recommendations are framed as "AI-assisted guidance based on approved mitigation patterns and cited standards."
3. **Show your work.** Every output has visible reasoning, source attribution, confidence by field, evidence gaps, and a `generated_by` label distinguishing deterministic from AI output. The disclaimer is mandatory and standard: "AI-assisted guidance based on approved mitigation patterns and cited standards. Verify against vendor documentation and local operational constraints before implementation."
4. **Verified citation.** Every LLM citation is programmatically validated against the source text (`source_mitigations.py` enforces a verbatim_snippet rule). No free-floating URLs.
5. **Healthcare focus is the differentiator.** Defaulting to medical device issues is a conscious strategic choice. Showing general IT vulnerabilities (Chrome, SharePoint, Microsoft Office) makes the product indistinguishable from any other vulnerability database. The dashboard's default view is healthcare-relevant only; the full feed is lazy-loaded.
6. **Open public layer is architecturally separate from commercial layer.** Commercial features (facility-specific inventory matching, watchlists, email capture) are deliberately kept out of the grant proposal. Grant framing is "everything is open."
7. **AI earns its place only when labor is repetitive at scale AND each instance produces different output.** Otherwise rule-based or static curated content is preferred. AI is not used for novelty; it's used because it's the only feasible way to do the work.
8. **Sequential feature delivery.** Time is constraint, scope is variable. Whatever ships before the grant deadline is "demonstrated" in the proposal; everything else is "planned grant-funded work."
9. **Phased dashboard rebuild.** Don't rebuild the UI yet. Phase 1: ship high-leverage features on the existing dashboard first. Phase 2: ship 1–2 more features. Phase 3: redesign from scratch with full requirements known. Phase 4: ship remaining features into new dashboard.
10. **Fix it right, not bandaid it.** Travis explicitly stated this as a preference. Workarounds are not acceptable; correct fixes only. (Exception: if a triage fix is needed to unblock a deadline, do it explicitly and label it as a triage fix with the real fix tracked separately.)
11. **FDA classification is authoritative for clinical severity.** AdvisoryOps inherits FDA's medical device risk classification (Class I/II/III, codified in 21 CFR 860) as authoritative input to severity scoring. FDA Class III auto-floors to P0 because Class III is FDA's regulatory designation for devices whose failure can cause serious injury or death — clinical severity is independent of cyber severity, and we do not second-guess regulators on safety classification. Class II auto-floors to P1 (moderate risk). Class I receives a small additive boost only. This rule is portable to a future two-axis scoring architecture where it becomes the clinical-severity-axis floor.
12. **AdvisoryOps is a medical device security platform. Pharmaceutical / medicines recalls are explicitly out of scope and are filtered at the source ingest layer.** This distinction follows operational reality: medicines recalls are handled by pharmacy teams integrated with modern EMRs (Epic, Cerner, Meditech), and clinical engineering / InfoSec teams (the AdvisoryOps target audience) do not act on drug alerts. Sources producing pharmaceutical content are disabled in `configs/sources.json` rather than routed to a different category, because routing would still consume ingest / storage / AI cost for content that has no user. Enforced by `tests/test_no_pharmaceutical_sources.py` and `scripts/validate_medical_device_bucket.py`. Mixed-content sources (e.g., MHRA) that produce both device and medicines alerts must be re-enabled only with an upstream query filter that excludes medicines before ingest, never with a post-hoc classifier workaround.

## Section 9 — Working agreements between Travis and Claude

These are operational rules that should govern every session. Read them every time.

1. **Every new session starts with a fresh codebase zip OR a transcript read.** Claude has no working memory across sessions and lossy memory across compaction events within a session. Before doing any planning, Claude must verify the current state of the code by reading the most recent zip Travis uploads OR by reading the relevant transcript files in `/mnt/transcripts/`. The Anthropic memory summary in the system prompt is incomplete by design and should not be trusted as a substitute. When in doubt, ask for the zip.
2. **Read this file (`docs/session_state.md`) at the start of every session.** It is the durable single source of truth. Cross-check against the actual code on disk before making confident claims.
3. **Trust Travis over Claude's internal state.** Travis has end-to-end project memory; Claude doesn't. When something feels off — when Travis remembers a feature and Claude doesn't — the right move is to look at the code or the transcripts, not to reason about whether Travis is mistaken.
4. **Sequencing before action.** Travis has explicitly pushed back on Claude jumping ahead of agreed plans. Agree the plan first, then act. Don't propose new features mid-task without checking in.
5. **Prompt mismatch guardrail.** If Travis pastes a prompt that doesn't match the current project focus (e.g., SymSafe code while working on AdvisoryOps), flag it immediately instead of proceeding.
6. **Healthcare focus is the default.** Don't suggest dropping the healthcare framing or pivoting to a general vuln intelligence platform. That conversation is closed.
7. **Don't draft the 200-word problem statement.** Travis writes that himself in his own voice. Offer feedback if asked. Do not write it for him.
8. **Don't prompt about grant writing until Travis initiates.** Code must be final before any grant writing begins. The SE enablement session and mock reviewer Q&A are intermediate prerequisites that happen after the code is showable.
9. **Cost-conscious about API usage.** Travis runs on $100 plan until 2026-05-02. Code sessions are productive but the budget is real. Don't burn calls on speculative work.
10. **One Claude Code session at a time.** Parallel sessions caused confusion in an early experiment. Commit after each successful session.
11. **Run full regression after every session.** Known pre-existing test failures are tracked and not touched.
12. **Claude Code is the implementation tool. This conversation is the architecture/strategy tool.** Don't try to do implementation work in chat when Claude Code is the right venue.
13. **Direct communication style.** Travis pushes back when numbers seem low or when assessments feel sugar-coated. Expect honest evaluation. Don't soften findings to be polite.
14. **Don't curse, don't use emoji unprompted, write in prose not bullet-fests.** Standard formatting hygiene.
15. **No band-aids when correctness is achievable.** See Principle 10 above.

## Section 10 — Tools, environment, accounts

- **OS:** Windows 11, working in PowerShell
- **Python venv:** `.venv\Scripts\python.exe` in main repo
- **NVD API key:** set as permanent User environment variable
- **OpenAI API key:** `OPENAI_API_KEY` set as permanent User environment variable. `openai` Python package version 2.17.0 in venv. `gpt-4o-mini` is current default for AI features. `gpt-5-mini`, `gpt-5`, `gpt-5-nano` are planned per-task model selection but not yet wired in.
- **GitHub:** `travisfunk` account. Main repo public: `travisfunk/advisoryops`. The separate `advisoryops-dashboard` repo still exists but is superseded — its archival status is UNVERIFIABLE from code. Dashboard served via GitHub Pages; intended source is `/docs` folder of `advisoryops` repo after the 2026-04-10 consolidation; whether the Pages source has been flipped in the GitHub UI is UNVERIFIABLE from code.
- **Claude Code:** launched with `claude --allowedTools "Bash(*)"` and `.claude/settings.json` in repo root.
- **Caches:** `outputs/*_cache/` directories. Persistent. NVD cache is large (~340K records). AI cache: 11,157 entries.
- **CI:** None. No `.github/workflows/` directory exists.

## Section 11 — Grant context

- **Target:** OpenAI Cybersecurity Grant Program
- **Form:** 3,000 words plaintext at openai.com/form/cybersecurity-grant-program/
- **Ask:** $10M in API credits (not cash)
- **Deadline:** Rolling
- **Differentiation (verified by competitive search in earlier sessions):** No equivalent open-source system exists. Closest are CISA/HHS toolkits (not aggregated, not scored, not actionable), MISP-based academic prototypes (for device manufacturers, not hospital defenders), H-ISAC (membership-required), and commercial platforms (Claroty, Armis, TRIMEDX, Forescout, Censinet, MedCrypt, Cybellum, Sternum — all enterprise-priced).
- **Cost framing strength:** Pipeline costs $1.40 per full rebuild, ~$0.06 weekly incremental. Total dev API spend ~$12.70. These are grant-strength numbers — they prove the approach is sustainable.
- **Pre-grant requirements:**
  1. Code must be final and showable.
  2. All Section 6 problems addressed (at minimum Problems 1–3). As of 2026-04-12: Problems 1, 2 (triage), 3, 5, 7 resolved; Problem 4 investigation documented; Problem 6 partial fix shipped with residual framing question.
  3. SE enablement session: walk through the pipeline like briefing an SE before a big demo, product-level not code-level.
  4. Mock reviewer Q&A: 20 hardest likely questions.
  5. 200-word problem statement written by Travis in his own voice.
- **What goes in the grant:** Public-good open layer only. Commercial layer is out.
- **What stays out:** Commercial features, customer details, pricing models.

## Section 12 — Things this file is uncertain about

To be honest about the limits of what I (Claude) verified vs. what I'm carrying forward from older context:

- **The exact list of "Features A through D"** that were shipped in specific sessions vs. older session work. The names overlap with earlier "Sessions B through K" naming and may be conflated in places.
- **Whether `eval_harness.py` is currently being run on any schedule.** It exists, has 520 lines, has tests, but there's no CI. Only runs on-demand via `advisoryops evaluate`.
- **The current ai_cache hit rate.** 11,157 cached entries on disk. FIX 4.5 rebuild observed 100% cache hit rate on recommend packets. Full-corpus hit rate not measured.
- **Whether the GitHub Pages source has been flipped from `advisoryops-dashboard` to `advisoryops`.** The code-side prerequisites are done (dashboard + data files on main in `docs/`). README badge and live-demo link still point at `advisoryops-dashboard`. Only Travis can confirm the GitHub UI state.
- **Whether the old `advisoryops-dashboard` GitHub repo has been archived.** Only Travis can confirm.
- **Whether Problem 3's extract_fields is firing on FDA-recall-derived issues in practice.** Recent rebuild still showed 180 FDA-risk-class issues (same as pre-fix runs). Could mean the fix is working but the openFDA matching is limited, or that extract_fields wasn't passed `--extract-fields` in the rebuild. Needs Travis to spot-check.
- **Whether the healthcare_adjacent category aggression in `feed_healthcare.json` (3,929/3,929) is intended.** Section 6 Problem 6 treats it as residual; Travis should confirm whether to exclude adjacent from the default "healthcare" view.

Future Claude: when these uncertainties become relevant, verify against the code or ask Travis. Don't reason from this file as if it were ground truth on the items above.

## Section 13 — Session log

### 2026-04-09 — Dashboard merge (branch `merge/consolidate-dashboard`)

9-commit merge sequence consolidating the dashboard repo into the main repo. Executed by Claude Code, planned and approved by Travis.

- **Commit 1:** Migrated `dashboard/index.html` and `tests/test_dashboard_html.py` from the dashboard repo.
- **Commit 2:** Added `_publish_to_docs()` to `community_build.py` — copies dashboard HTML and all 11 data artifacts to `docs/` for GitHub Pages serving after each build. Replaces the old `_deploy_docs()` which only handled 3 files.
- **Commit 3:** Fixed the packet→feed merge gap (Problem 1). `_merge_trust` now copies `recommended_patterns`, `tasks_by_role`, `reasoning`, and `citations` from packets into feed rows. Added fields to `_feed_entry`. 5 regression tests added.
- **Commit 4:** Rendered AI recommendations in `dashboard/index.html` — pattern cards with friction pills, tasks by role, AI reasoning, and the standard playbook disclaimer.
- **Commit 5:** Triage fix for correlation key (Problem 2). Added `source_id` to non-CVE merge key. Issue count 3923 → 3929, source-count anomalies dropped to zero. Also added `repo_root` parameter to `build_community_feed` for testability.
- **Commit 6:** Skipped (no code change). Populated EPSS cache: 325,743 scores. Pipeline uses it automatically.
- **Commit 7:** Added `docs/feed_contract.json` and `tests/test_feed_contract.py` — schema contract enforcing that every field the dashboard reads is declared, and every required field is present in feed rows.
- **Commit 8:** Added `_write_sanity_report()` generating `outputs/community_public/sanity_report.md` after each build. Surfaces priority distribution, field completeness, correlation health, AI coverage, healthcare classification, FDA risk class.
- **Commit 9:** Updated README (source count 57→65, test count 696→1038, issue count 1990→3929) and this file. Marked Problems 1, 2 (triage), and 5 as resolved.

**Test count at end of session:** 1,038. All passing.

### 2026-04-10 — Pre-grant polish and two-PR merge

Active day. 15 commits reaching main via two pull requests merged within 90 minutes of each other.

**PR #12 (squash merge `c6401ac` at 2026-04-10 00:06):** Consolidated dashboard repo into main. Squashed the entire `merge/consolidate-dashboard` branch plus follow-on work. Message body enumerates Phase 1A NVD historical backfill, Phase 1B CISA ICSMA backfill, incremental discovery for both, and the dashboard-merge commits.

**PR #13 (merge commit `f189ea1` at 2026-04-10 01:37):** "Field extraction, search, false positive cleanup, and polish." Merged `feature/v1-readiness@32810ec` into main. Contained commits:
- `fa5cbfd` Verify dashboard search works (Problem 7)
- `afe40dc` Update CONTRIBUTING.md for grant readiness
- `e778acc` Add architecture diagram and layer descriptions
- `72c3fb2` Render EPSS scores in dashboard detail panel
- `d605b28` Reduce healthcare filter false positives (Problem 6)
- `86984c0` KEV / medical device overlap investigation (Problem 4)
- `2924a54` README polish pass for grant readiness
- `c719b52` Repo hygiene: gitignore caches, commit scripts and docs
- `0f8785d` Add LLM field extraction for non-CVE issues (Problem 3)
- `8840c70` Fix extract_fields truncation: bump max_tokens, handle malformed JSON
- `32810ec` Merge main into v1-readiness branch

After PR #13, origin/main = `f189ea1`. This state contains everything the fix mission later audited against. No session log entry was written at the time. This entry is reconstructed from git history on 2026-04-12.

**Manual steps from 2026-04-09 revisited:**
1. ~~Visually verify dashboard renders new sections.~~ Not tracked in commits; presumed done.
2. ~~Push the branch and merge to main.~~ DONE via PR #12 + PR #13 on 2026-04-10.
3. Flip GitHub Pages source from `advisoryops-dashboard` to `advisoryops`. UNVERIFIABLE from code.
4. Verify the live URL still works. UNVERIFIABLE from code.
5. Archive the `advisoryops-dashboard` repo on GitHub. UNVERIFIABLE from code.

### 2026-04-11 — Audit + fix mission (branch `feature/v1-readiness`, not pushed)

Multi-stage audit of the project followed by a targeted fix mission addressing the HIGH-severity findings. All work on branch `feature/v1-readiness`. Not pushed — Travis will review and push.

- **`7f3b094` — audit: phase A+B+C unattended audit (read-only, findings only).** Full inventory of 56 Python modules / 57 test files / 96 sources / 15 CLI subcommands / 11 playbook patterns. 22+ stale doc claims flagged. 35 findings filed (5 HIGH, 10 MEDIUM, 11 LOW, 9 INFO). Writeups at `audit/phase_a_inventory.md`, `audit/phase_b_doc_reality.md`, `audit/phase_c_code_findings.md`, `audit/continuity.md`.
- **`dab64b3` — fix(C-018): republish docs/ from existing corpus via scripts/republish_docs.py.** Added `scripts/republish_docs.py` to re-run `_publish_to_docs()` against existing outputs/community_public. Also found and fixed 9 calls to `build_community_feed()` in `tests/test_community_build.py` that were missing `repo_root=tmp_path` — tests had been silently overwriting the real `docs/` directory on every run, causing the live GitHub Pages dashboard to show test data (1 issue instead of thousands).
- **`0682073` — fix(C-030): correct priority thresholds in dashboard Methodology tab.** Dashboard showed P0>=190/P1>=150/P2>=100/P3<100; actual thresholds in `score.py:103-108` are P0>=150/P1>=100/P2>=60/P3<60. Every displayed number was wrong.
- **`815ee7a` — fix(C-001,C-014): emit kev_vendor/kev_product/kev_vulnerability_name in _feed_entry.** `_feed_entry` in `community_build.py` was dropping three KEV fields that the dashboard reads and `feed_contract.json` declares. Additionally `_KEV_FIELDS` was missing `kev_vulnerability_name` so it was never even propagated from signals to the issue dict. Fix adds all three to `_feed_entry` and adds `kev_vulnerability_name` to `_KEV_FIELDS` and `_NVD_KEV_FIELDS`.
- **`68ae1f3` — fix(C-004,C-005): correct source counts and remove phantom sources from README.** README source coverage table listed 10+ source names that did not exist in `configs/sources.json` (H-ISAC, AHA, HSCC, BleepingComputer, SecurityWeek, Medtronic, Abbott, BD, GitHub Security, etc.). README used three different source counts (57, 57, 65). Actual is 68. Rebuilt table using the 4 real scope values. Also updated test count 1038→1055, issue count 3929→1990, medical device count 856→234, NVD count 1138→1091.
- **`b0f4b5e` — chore(pipeline): incremental rebuild to regenerate feed with FIX 3 schema.** Ran `community-build --set-id full_public --skip-backfill --summarize --extract-mitigations --ai-score --recommend --min-priority P1` against existing discover/ data. All 100 recommend packets hit the AI cache — effectively $0 API spend. Produced 3,929 issues, 100 alerts, 203 KEV-enriched with `kev_vendor`/`kev_product` populated end-to-end. Runtime ~6 min.
- **`957d09b` — docs(session_state): record audit and fix mission outcomes.** First session_state edit pass after the fix mission.
- **`453494a` — docs(audit): investigate corpus count discrepancy.** FIX 6 writeup confirming the 1,990 vs 3,929 gap was a `--latest N` truncation artifact, not a filtering bug.

Tests: 1,055 passing on every commit. No regressions.

### 2026-04-12 — Documentation reality-check pass (this session)

Read-only audit of how well the documentation reflects the current state of main + feature/v1-readiness. Output: `audit/doc_reality_check.md` report and `audit/proposed_session_state.md` proposed rewrite (this file is the proposed version — Travis reviews before it replaces the live session_state.md).

Key findings:
- The 2026-04-10 work day (15 commits across two PRs) was never logged in Section 13. Added above.
- Problems 3, 7 had been resolved on main before the audit/fix mission but were still marked open. Now marked RESOLVED with commit references.
- Problem 6 had a partial fix on main but session_state still described it as open. Updated to "PARTIAL FIX SHIPPED".
- Section 2 and Section 12 contradicted each other on GitHub Pages cutover state. Section 12 narrowed to "UNVERIFIABLE from code — only Travis can confirm the UI flip."
- Section 7 "Shipped" list was missing ~15 entries; "Pending pre-grant" list had items 1-7 stale/resolved. Rewrote both halves.
- Section 5 corpus numbers updated to current (3,929 issues, 215 P0, 200 P1, etc.) from the FIX 4.5 rebuild sanity_report.md.
- Section 3 removed the "EPSS currently disabled / cache empty" contradiction with Problem 5.
- Module counts corrected: 39→38 core modules (always was 38, doc was wrong), 6→"6 enrichment plus __init__.py", 9→"8 backfill plus registry + sync + __init__" in sources/.

### 2026-04-12 (continued) — Post-rewrite product missions

Three product missions landed on `feature/v1-readiness` after the doc reality-check rewrite (`731643c`). Each updated `audit/fix_mission_progress.md`; this session_state entry catches up the top-level doc.

**Mission 1 — medical_device classifier tightening.** Commits `1d222b2`, `19b3b37`, `ab77ae8`, `28e776f` (plus dashboard-predicate precursor `bcf2d46`, `37bdb45`). Replaced the old keyword-and-source classifier with a strict 4-rule check in `healthcare_filter.py` (CISA ICS-Medical authority / vendor allowlist / FDA risk class / product keyword allowlist), re-tagged the existing corpus via `scripts/retag_corpus.py`, wired the dashboard header source-count and "Updated" date to live `meta.json` fields, added `scripts/validate_medical_device_bucket.py` as a regression guard. Measurable result: medical_device count 1,116 → 224 with zero general-IT vendor leaks; dashboard "Medical devices" filter now surfaces actual medical devices.

**Mission 2 — FDA clinical-severity floor.** Commits `57d53f7`, `63cf110`, `3cbcb4f`. Added `_apply_fda_clinical_floor` to `score.py` as a final step in `score_issue_v2`: FDA Class III auto-floors to 150 (P0), Class II to 100 (P1), Class I adds +10. Re-scored the existing corpus through `retag_corpus.py` without invoking the AI pipeline. Codified the rule as architectural principle #11 in Section 8. Measurable result: medical_device P0 count 0 → 8; the Philips AED family (Class III) moved from P1/117 to P0/150 as intended.

**Mission 3 — FDA risk class extraction.** Commits `1ee3ab3`, `f888ea9`, `ef21ec0`. Extended `fda_classification.py` with `extract_risk_class_from_enforcement` + `lookup_class_by_recall_number` to recover classifications from the enforcement cache at `outputs/fda_safety_comms_cache/enf_<recall_number>.json`, extended `retag_corpus.py` with a `Z-NNNN-YYYY` recall-number parser that runs before re-classification, extended the validation script to report FDA-coverage as a soft metric. Measurable result: null `fda_risk_class` dropped 328 → 128 (61% reduction); 200 back-filled classifications; medical_device bucket grew 224 → 424 as newly-class-tagged rows matched Rule 3; P0 count grew to 10, P1 to 291. The remaining 128 nulls come from sources whose upstream payloads genuinely lack classification (MAUDE adverse events, fda-medwatch RSS).

Tests: 1,055 baseline → 1,076 passing across the three missions (+21 new tests net, -4 legacy tests that asserted the pre-fix behavior).

Principle #11 (FDA classification authoritative for clinical severity) was added to Section 8 during Mission 2 and is already present in the live file — no edit needed here.

Surfaced by Mission 2 but not yet addressed: the ACT NOW (P0) lane is dominated by historical FDA Class III recalls rather than current advisories (temporal-relevance gap). Captured as Problem 8 in Section 6; resolved same day via dashboard top-N pagination — see next entry.

### 2026-04-12 (continued) — Problem 8 dashboard top-N pagination (commit `5052347`)

Resolved Problem 8 (temporal-relevance gap) via presentation-layer pagination in `dashboard/index.html`. Added a "LATEST" dropdown (25 / 50 / 100 / All, default 25) in the filter row. After all existing filters apply, the issue list is sorted by `published_date` descending (items with no published_date sort to the bottom so they remain reachable via "All" but don't pollute the latest view) and sliced to the top N. Priority tiles and header counts continue to reflect the full filtered set, not the paginated view. Replaces an earlier date-window approach that was rejected after the data check showed uneven temporal distribution in the medical_device bucket would have risked an empty default view. Python code (scoring, healthcare_filter, FDA floor) unchanged. Tests: 1,076 passing.

### 2026-04-12 (continued) — Problem 9 pharmaceutical exclusion

Resolved Problem 9 (pharmaceutical record leakage). Surfaced by a live-dashboard screenshot showing "Class 2 Medicines Recall: Wockhardt UK Ltd, Heparin sodium 1,000 I.U./ml solution for injection" in the medical_device bucket. Root cause: MHRA's "Class 2 Medicines Recall" string was parsed into `fda_risk_class=2` by the upstream backfill, and Rule 3 of the strict 4-rule classifier then correctly promoted the record into the medical_device bucket. The rule was right; the upstream data was lying about what was in the field.

**Sources disabled** in `configs/sources.json` (with `enabled: false` and an inline `excluded_reason`):
- `fda-medwatch` (mixed drug + device + biologics + food RSS; 5 corpus records currently all devices but source is fundamentally unsuitable for a device-only platform — device content overlaps with openfda-device-recalls and fda-safety-comms-historical)
- `mhra-uk-alerts` (79.5% medicines recalls; 41 legitimate device alerts lost in the exclusion but none of them were in the medical_device bucket to begin with; future follow-up can re-enable with a tighter upstream query)

Also removed both IDs from every validated set in `configs/community_public_sources.json` and added to a new top-level `excluded_sources` list.

**Corpus cleanup** via `scripts/clean_pharmaceutical_records.py`:
- Total corpus: 3,929 → 3,724 (−205 records)
- medical_device bucket: 424 → 422 (−2)
- Pharmaceutical-titled records corpus-wide: 159 → 0
- Cleaned files: `docs/feed_latest.json`, `docs/feed_healthcare.json`, `docs/feed_medical_device_kev.json`, `docs/meta.json`, and the `outputs/community_public/` equivalents plus `issues_public.jsonl` and `alerts_public.jsonl`

**Regression guards:**
- `tests/test_no_pharmaceutical_sources.py` (3 tests) — asserts both source IDs stay disabled with rationale, absent from validated sets, and declared in `excluded_sources`.
- `scripts/validate_medical_device_bucket.py` extended with a pharmaceutical keyword title regex and pharmaceutical-source-membership check; exits 1 on any leak.

**Architectural principle #12 added** to Section 8: pharmaceutical content is explicitly out of scope; filter at the source ingest layer, not at the classifier. Mixed-content sources (like MHRA) must be re-enabled only with an upstream query filter.

`healthcare_filter.py` Rule 3 unchanged. No classifier code modified. Section 5 corpus counts refreshed. Landed as commit `ccff0ac` on `feature/v1-readiness`. Tests: 1,079 passing (1,076 baseline + 3 from `test_no_pharmaceutical_sources.py`).

---

**End of session_state.md.** If you (future Claude) found this useful, the cost was about an hour of reading code and writing this file. Maintaining it should be cheap: at the end of each meaningful session, append a short "## Session log YYYY-MM-DD" entry with what changed, and update the relevant prior sections in place. Don't let it bit-rot.
