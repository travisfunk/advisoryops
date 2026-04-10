# AdvisoryOps — Session State (project context for Claude)

**Last updated:** 2026-04-08 by Claude (AI assistant working with Travis Funkhouser)
**Purpose:** This file is the durable single source of truth for what AdvisoryOps is, where it currently stands, and what the open problems are. It exists because Claude's working memory does not survive context-window compaction, and project context kept getting lost between sessions. **Future Claude: read this file at the start of every working session before doing anything else.** Do not skip it. Do not trust the memory summary in your system prompt as a substitute — that summary is incomplete by design and is the reason this file exists.

If something in this file looks wrong to Travis, **trust Travis over this file**, then update this file. Travis has end-to-end project memory; Claude does not.

---

## Section 1 — What AdvisoryOps is

AdvisoryOps is an open-source healthcare medical device security intelligence platform built and maintained solo by Travis Funkhouser (CISSP, CISM, CPHIMS, HCISPP, Stanford AI in Healthcare; 20+ years healthcare security including IU Health, ForeScout, Attivo, Flashpoint).

It aggregates security advisories from 60+ public sources (CISA ICS-CERT, FDA MedWatch, openFDA recalls and adverse events, NVD CVE API, vendor PSIRTs, threat intel feeds, healthcare news, and more), correlates and deduplicates them, scores them with healthcare-specific context, generates plain-language summaries and remediation guidance via LLM, and publishes everything as open data and an open-source dashboard. The whole pipeline currently costs about $1.40 per full corpus rebuild and ~$0.06 per weekly incremental run on `gpt-4o-mini`; total dev API spend across all sessions is roughly $12.70.

The strategic pitch is that hospitals (especially the thousands of small, rural, and community hospitals that can't afford Claroty, Armis, or TRIMEDX) need this exact thing and nothing comparable exists for free. Commercial vulnerability intelligence platforms in this space all start at enterprise pricing. AdvisoryOps fills the gap with a public-good open layer (free forever, free to view, free to fork). A commercial layer with facility-specific device inventory matching, watchlists, and email signup is **planned for after grant submission and is deliberately kept out of the grant proposal** — the grant framing is "everything is open."

The grant target is the **OpenAI Cybersecurity Grant Program** ($10M in API credits, rolling deadline, 3,000-word plaintext form at openai.com/form/cybersecurity-grant-program/).

## Section 2 — Repository layout and key locations

One consolidated repo at `C:\Users\travi\OneDrive\GitRepos\advisoryops`. GitHub: `travisfunk/advisoryops`. Currently public. The dashboard was previously in a separate `advisoryops-dashboard` repo and was consolidated on 2026-04-09 (branch `merge/consolidate-dashboard`). The old dashboard repo will be archived after merge verification.

Inside the repo:

- `src/advisoryops/` — 39 Python modules. Pipeline core.
- `src/advisoryops/enrichment/` — 6 enrichment modules (FDA classification, EPSS, vulnrichment, CWE catalog, ATT&CK ICS, cross-reference orchestrator).
- `src/advisoryops/sources/` — 9 per-source historical backfill modules (CISA ICSMA, openFDA, FDA safety comms, MHRA UK, Health Canada, NVD, Philips PSIRT, Siemens ProductCERT, plus a backfill_registry).
- `dashboard/` — production HTML dashboard (source of truth). Copied to `docs/index.html` by the pipeline's publish step.
- `tests/` — 57 test files, ~1038 tests passing as of 2026-04-09.
- `configs/` — `mitigation_playbook.json` (11 patterns), `source_weights.json` (5-tier authority), `community_public_sources.json` (validated source manifest), `sources.json` (full source list).
- `docs/` — 11 numbered design docs (DOC-01 through DOC-11) plus `STATUS.md`, `playbook_governance.md`, `schema.md`, `scoring_internals.md`, `feed_contract.json` (schema contract enforced by tests), `grant_cost_model.md`. GitHub Pages serves from `docs/` — the pipeline copies `dashboard/index.html` and data files here via `_publish_to_docs()`. Read `schema.md` before touching anything that produces feed entries — it documents every field.
- `outputs/community_public/` — pipeline output. Includes `feed_latest.json`, `feed_healthcare.json`, `feed_medical_device_kev.json`, RSS variants, Excel export, `sanity_report.md`, and the `packets/` subdirectory containing per-issue AI remediation packets.
- `outputs/*_cache/` — per-source caches. Persistent. NVD cache has ~340K records, openFDA recalls ~14,630, FDA safety comms ~38,510, Siemens ~779, MHRA ~1,381, EPSS ~325K scores. Reference table is in `docs/scoring_internals.md`.
- `outputs/ai_cache/` — content-hash-based AI response cache. Persistent across runs. Keeps incremental costs near zero.

## Section 3 — Pipeline architecture (verified by reading code 2026-04-08)

The pipeline runs in stages, orchestrated by `advisoryops community-build` (CLI in `cli.py`, implementation in `community_build.py`, ~2064 lines).

```
discover → correlate → score → enrich → AI subsystem → output
```

**Discover.** Per-source modules in `discover.py` and `sources/*` pull signals from 60+ sources. Each signal gets a deterministic `signal_id` (SHA-256 of `source_id|guid`). Output: `outputs/discover/<source>/items.jsonl` per source.

**Correlate.** `correlate.py` groups signals into issues. CVE-bearing signals group by CVE ID. Non-CVE signals group by `UNK-<sha256(title|published_date)[:16]>`. **There's a real bug here — see Section 6 Problem 3.** Output: `outputs/community_public/correlate/issues.jsonl`.

**Score.** `score.py` runs v2 healthcare-aware scoring (v1 keyword baseline + 5 healthcare dimensions: source authority, device context, patch feasibility, clinical impact, FDA risk class). Thresholds are P0 ≥ 150, P1 ≥ 100, P2 ≥ 60, P3 < 60. Theoretical max ~805, observed range ~17–163, most issues 17–60. Full scoring reference is in `docs/scoring_internals.md` (current). Every scoring decision appends a human-readable string to a per-issue `why` field.

**Enrich.** Multiple enrichment passes happen during community-build:
- **NVD enrichment** (`nvd_enrich.py`, 523 lines) — queries NIST NVD 2.0 API for CVSS, CWE, CPE, descriptions. NVD API key is set as a permanent user environment variable. Most-recent run enriched 2,362 of 3,923 issues with CVSS/CWE/CPE data.
- **KEV cross-reference** — pulls KEV-specific fields (required_action, due_date, vendor, product) from CISA KEV. Most-recent run flagged 203 issues as KEV-enriched.
- **CISA Vulnrichment** (`enrichment/vulnrichment.py`) — per-CVE enrichment from `cisagov/vulnrichment` GitHub repo.
- **CWE catalog** (`enrichment/cwe_catalog.py`) — CWE name resolution.
- **ATT&CK ICS** (`enrichment/attack_ics.py`) — MITRE ATT&CK for ICS technique mapping.
- **EPSS** (`enrichment/epss_enrich.py`) — Exploit Prediction Scoring System scores. **Currently disabled / cache empty**, see Section 6.
- **FDA risk class** (`enrichment/fda_classification.py`) — Feature 1. Extracts class from cached recall records (primary) or via openFDA classification API substring/product-code lookup (secondary). Most-recent run enriched 180 issues (178 from recalls, 2 from classification DB). 8 Class III, 86 Class II, 42 Class I, rest unknown.
- **Healthcare relevance + category** — `healthcare_filter.py` tags every issue. Categories: medical_device, healthcare_infrastructure, healthcare_it, healthcare_adjacent. Most-recent run: 1,125 medical_device, 169 healthcare_infrastructure, 5 healthcare_it, 2,624 healthcare_adjacent (3,923 total).

**AI subsystem.** Four optional AI features, all gated behind CLI flags on `community-build`. None run unless explicitly requested. **This is the part that was forgotten and rediscovered today.**

- **`--summarize`** (`summarize.py`, 192 lines, "Session D") — plain-language 2–3 sentence summaries for hospital security analysts. Extracts unknowns, handling_warnings, evidence_completeness. Output written into the issue's `ai_summary` and trust fields. Most-recent run: 971 of 971 issues rewritten.
- **`--extract-mitigations`** (`source_mitigations.py`, 352 lines, "Phase 8 — source authority") — source-cited mitigation extraction. Critical prompt rule: "Extract ONLY mitigations explicitly stated in source text. Do NOT invent." Each extracted mitigation includes a `verbatim_snippet` from the source text and is attributed to its source with authority tier. Most-recent run: 1,233 mitigations extracted from 899 of 971 issues.
- **`--ai-score`** (`ai_score.py`, 325 lines) — AI healthcare classification backstop for issues with no deterministic healthcare signal. Boosts score if the model is ≥0.70 confident the issue is medical_device (+20), healthcare_it (+15), or healthcare_adjacent (+5).
- **`--recommend`** (`recommend.py`, 414 lines, "Phase 4, Task 4.2") — full remediation recommendation engine. Loads the 11-pattern playbook from `configs/mitigation_playbook.json`, asks the model to select 1–4 patterns, fill parameters, role-split tasks, identify side effects and friction levels, list evidence gaps, and produce per-pattern reasoning and a top-level reasoning string. Hallucinated pattern IDs are silently filtered against the approved list. Default model is `gpt-4o-mini`. Output is a `RemediationPacket` dataclass written to `outputs/community_public/packets/<issue_id>_packet.json`. Most-recent run: 414 of 414 packets written for P0/P1 alerts.

Other AI/related modules that exist and are working but are not necessarily wired into community-build:
- **`extract.py`** (445 lines) — Stage 2 ingest, structured AdvisoryRecord JSON extraction from raw advisory text. Used by the `extract` CLI command, not by community-build.
- **`ai_correlate.py`** (576 lines) — AI-assisted merge candidate detection for cross-source duplicates.
- **`advisory_qa.py`** (294 lines, "Session G") — natural language Q&A against the corpus. Exposed as `advisoryops ask` CLI command.
- **`contradiction_detector.py`** (342 lines, "Task 8.5") — deterministic cross-source contradiction detection. Note: most-recent runs found 0 real contradictions in the corpus, which is itself a real finding worth investigating.
- **`change_tracker.py`** (221 lines, "Task 8.7") — deterministic what-changed tracking between pipeline runs.
- **`feedback.py`** (115 lines) — recommendation feedback recorder, exposed as `advisoryops feedback`.
- **`page_enrich.py`** (201 lines) — fetches advisory web pages for richer mitigation extraction.

Cross-cutting:
- **`sanitize.py`** (110 lines) — prompt injection hardening. Strips control chars and oversized chunks before any text goes to the model. Visible in pipeline logs as `sanitize_for_prompt altered summary (len X -> Y)`.
- **`ai_cache.py`** (194 lines) — content-hash response cache. The reason most rerun costs are near zero.
- **`source_weights.py`** (160 lines) — loads `source_weights.json` for the 5-tier authority weighting used in v2 scoring.
- **`product_resolver.py`** (135 lines, "Session I") — `resolve_product()` and the `advisoryops lookup` CLI command.
- **`eval_harness.py`** (520 lines, "Phase 5, Task 5.2") — golden fixture evaluation harness.

**Output stage.** `community_build.py` writes all the public artifacts: `feed_latest.json`, `feed_healthcare.json`, `feed_medical_device_kev.json`, `feed.csv`, `feed.xml` plus filtered RSS variants, `issues_public.xlsx`, `dashboard.html`, `validated_sources.json`, `meta.json`, and per-issue packets in `packets/`. **There is a critical merge gap here — see Section 6 Problem 1.**

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

## Section 5 — Current corpus state (verified from 2026-04-08 pipeline run)

The most recent successful pipeline run (with `--recommend --summarize --extract-mitigations --ai-score` enabled, `--min-priority P1`) produced:

- **3,923 total issues** correlated from **5,573 signals** across **65 sources** (the `full_public` set).
- **414 alerts** at P0/P1 priority (this is the threshold for `--min-priority P1`).
- **2,362 issues** NVD-enriched with CVSS/CWE/CPE.
- **203 issues** KEV-enriched. **Zero of those KEV issues match medical device vendors** — this is a real finding, see Section 6.
- **180 issues** with FDA risk class (8 Class III, 86 Class II, 42 Class I, rest unknown).
- **971 plain-language summaries** generated (covering all P0/P1/P2 issues).
- **6,639 IOCs** extracted from 3,923 issues.
- **1,233 source-cited mitigations** extracted from 899 of 971 issues.
- **414 recommendation packets** written to `outputs/community_public/packets/` for all P0/P1 alerts.
- **P0–P2 guidance coverage: 994/994 (100%)**.

Healthcare category breakdown: 1,125 medical_device, 169 healthcare_infrastructure, 5 healthcare_it, 2,624 healthcare_adjacent.

Tests: ~1,016 passing pre-pipeline-run, no regressions.

**This run was the first time today's session saw the AI subsystem produce end-to-end output.** It validated that the entire AI subsystem (recommend, summarize, extract-mitigations, ai-score) is operational and producing rich packet output. The blocking question turned out to be not "does the AI work" but "why isn't the dashboard showing the AI work" — see Section 6.

## Section 6 — Known problems, prioritized

These are the issues blocking grant submission, in priority order. **Read this section every session.**

### Problem 1 — Packet → feed merge gap — RESOLVED

**Resolved:** 2026-04-09, branch `merge/consolidate-dashboard`, commits 3 and 4.

Fixed `_merge_trust` to copy `recommended_patterns`, `tasks_by_role`, `reasoning`, and `citations` from packet data into feed rows. Added these fields to `_feed_entry` and to `packet_trust_by_id`. Dashboard now renders pattern cards with friction levels, role-split tasks, and AI reasoning. Regression tests added to `test_remediation_trust.py`. Verified: 138/139 P0/P1 issues now have `recommended_patterns` in the feed output.

### Problem 2 — Correlation incorrectly merges unrelated signals — TRIAGE FIX RESOLVED

**Triage fix resolved:** 2026-04-09, branch `merge/consolidate-dashboard`, commit 5.

Applied option 2: added `source_id` to the non-CVE merge key basis (`key_basis = f"{it['source']}|{title_norm}|{pub}"`). This prevents cross-source collisions regardless of title. Issue count increased 3923 → 3929 as previously-merged distinct signals became separate issues. Source-count anomalies dropped to zero: 0 issues with 10+ sources, 0 mixed-type contamination.

**Architectural fix still pending (post-grant):** The full fix is to separate threatintel from advisory routing entirely — categorize sources as `kind: advisory` vs `kind: threatintel` in `sources.json` and route them through different correlation logic.

### Problem 3 — Field extraction failing for non-CVE / FDA-recall-derived issues (MEDIUM PRIORITY)

**Symptom:** The Impella record has `title="item"`, `vendor=""`, `severity=""`, `affected_products=[]`, `fda_risk_class=null`. The plain-language `summary` literally says "Abiomed's Automated Impella Controller could be susceptible to security vulnerabilities related to its operating system, with a severity rated as high. While no patch has been released yet..." — every piece of information needed to populate those fields is in the summary text. Nothing is reading the summary and extracting structured fields.

**Why FDA risk class is null:** Verified by reading `enrichment/fda_classification.py`. The `lookup_risk_class` function needs either a `product_code` or a `device_name` to match against the openFDA classification database. The Impella record has neither — `vendor=""` and `affected_products=[]`. **Feature 1 isn't broken; Feature 1 is starving.** It's working correctly given empty input. The upstream extraction never populated the device name field for FDA-recall-derived issues, so the classification lookup never had anything to match against. An Abiomed Impella is unambiguously a Class III implantable cardiac device — it should be at the very top of every priority list, and instead it sits at P2 with score 82.

**Fix:** Add a non-CVE field extraction pass that runs after the AI summarizer. Pull vendor name, device name, severity word, and any version strings from the rewritten plain-language summary using either targeted regex or a small extraction prompt. Then re-run the FDA classification lookup with the extracted device name. Probably half a day. Could plausibly be implemented as an extension to `extract.py` or as a new dedicated module.

### Problem 4 — KEV / medical device zero overlap (REAL FINDING, NOT NECESSARILY A BUG)

**Symptom:** All 203 KEV-enriched issues are general IT vendors (Cisco, Adobe, Apple, Microsoft, Fortinet, Ivanti, etc.). Zero of them match medical device vendors. Feature B (KEV cross-reference for medical devices) is architecturally in place but matches nothing.

**Possible causes:**

1. **The KEV catalog genuinely contains no medical device CVEs** — possible. CISA's KEV is biased toward widely-deployed enterprise software because that's what gets actively exploited at scale. Medical device CVEs may simply not be in KEV in meaningful numbers.
2. **Vendor name mismatching** — the medical device vendor names in our healthcare filter and the vendor names in KEV use different conventions and never match even when the same product is involved.
3. **Healthcare filter scope mismatch** — the healthcare filter may be flagging issues that KEV-enriched CVEs don't overlap with by definition.

**Action:** Investigate before grant submission. Worth understanding so the grant narrative can address it accurately rather than discovering it during a reviewer Q&A. This is also a potentially interesting finding for the grant itself ("KEV doesn't track medical device CVEs at scale, which is part of why a healthcare-focused intelligence system needs to exist").

### Problem 5 — EPSS cache empty — RESOLVED

**Resolved:** 2026-04-09, branch `merge/consolidate-dashboard`. Ran `populate_cache()` from `enrichment/epss_enrich.py`. Cache populated with 325,743 EPSS scores at `outputs/epss_cache/epss_scores.json` (26MB). The pipeline automatically uses this cache via `apply_enrichments(epss=True)` — no code change was needed.

### Problem 6 — Healthcare filter false positives

**Symptom:** Known false positives include Vivian Spa cosmetics, Ombrelle sunscreen (filtered as medical_device because of the literal phrase "medical devices" in marketing copy), BRICKSTORM general malware reports, Volt Typhoon threat actor, Siemens SIPROTEC industrial power.

**Cause:** `healthcare_filter.py` matches on the literal phrase "medical devices" too aggressively without context disambiguation.

**Fix:** Add negative-keyword exclusions and/or context-window checks. Low priority (cosmetic, doesn't break the demo) but should be cleaned up before grant submission for credibility.

### Problem 7 — Dashboard search box broken

The search input field exists in the dashboard but doesn't actually filter. Add to the dashboard rebuild phase, low priority, won't block grant submission.

## Section 7 — What's shipped vs. what's pending

### Shipped and verified working

- 60+ source ingestion pipeline (Section 3)
- Historical backfill infrastructure for 9 high-value sources (`sources/*` modules)
- v2 healthcare-aware scoring with 5 dimensions and full per-issue `why` field (`scoring_internals.md`)
- Source authority 5-tier weighting (`source_weights.py`, `configs/source_weights.json`)
- NVD enrichment with CVSS/CWE/CPE (`nvd_enrich.py`)
- KEV cross-reference (Feature B architecture)
- FDA risk class extraction from openFDA recalls (Feature 1)
- The 11-pattern mitigation playbook with full citations (`mitigation_playbook.json`, governance in `playbook_governance.md`)
- All four AI features: `--summarize`, `--extract-mitigations`, `--ai-score`, `--recommend`
- The `RemediationPacket` dataclass and packet writer (414 packets generated in latest run)
- Source-cited mitigation extraction with verbatim_snippet attribution
- Plain-language summarizer with handling_warnings, unknowns, evidence_completeness
- AI cache (`ai_cache.py`) — content-hash based, persistent, keeps incremental costs near zero
- Prompt injection sanitization (`sanitize.py`)
- Excel export (`excel_export.py`) — Feature A bug fix shipped
- 4 filtered RSS feeds (Feature C): healthcare, KEV medical device, Class III, P0/P1
- Healthcare category classification (Feature D)
- Cross-source contradiction detection (`contradiction_detector.py`)
- Change tracking between pipeline runs (`change_tracker.py`)
- Recommendation feedback recorder (`feedback.py`)
- Advisory Q&A CLI (`advisory_qa.py`, exposed as `advisoryops ask`)
- Product resolver (`product_resolver.py`, exposed as `advisoryops lookup`)
- Golden fixture evaluation harness (`eval_harness.py`)
- ~1,016 tests passing

### Pending pre-grant

In rough priority order:

1. **Problem 1: Packet → feed merge gap.** Highest leverage. 2–3 hours. Makes the entire AI subsystem visible.
2. **Problem 2: Correlation correctness.** Triage fix (option 2 or 3) before grant; full fix (option 1) after grant. Half a day.
3. **Problem 3: Non-CVE field extraction.** Half a day. Especially needed so Feature 1 actually fires for FDA-recall-derived issues.
4. **Problem 5: EPSS cache populate.** One-time setup, ~30 min.
5. **Problem 6: Healthcare filter false positives cleanup.** A couple of hours.
6. **Architecture diagram.** For the grant narrative. A clean visual showing pipeline stages.
7. **README and CONTRIBUTING.md currency check.** Both should reflect the current pipeline and source counts before submission.
8. **Footer/link audit.** Make sure all GitHub links go to `github.com/travisfunk/...`.
9. **SE enablement session + mock reviewer Q&A.** Pre-grant requirement explicitly set by Travis. Walk through the pipeline like briefing an SE before a big demo, then 20 hardest-likely reviewer questions. Happens AFTER code is final.
10. **200-word problem statement.** Travis writes himself in his own voice. Do not draft this for him; offer feedback if asked but do not write it for him.
11. **Grant proposal writing.** Travis initiates when ready. **Do not prompt about grant writing until he does.**

### Pending post-grant (out of scope for grant submission)

- Commercial layer: facility-specific device inventory matching, watchlists, work-email-only signup, email capture for sales leads. Architecturally separate from public layer. **Deliberately kept out of the grant proposal.**
- Full architectural fix for Problem 2 (separate threatintel from advisory routing).
- Dashboard rebuild. Phased plan: ship the merge fix on the existing dashboard first, then ship 1–2 more features, then redesign the dashboard from scratch with full requirements known, then ship remaining features into the new dashboard. Travis explicitly agreed: "I am not sure we won't have more ideas... I also think we can't really design now as we don't really know what the data will actually look like."
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
9. **Phased dashboard rebuild.** Don't rebuild the UI yet. Phase 1: ship the next high-leverage feature (now Problem 1's merge fix) on the existing dashboard. Phase 2: ship 1–2 more features. Phase 3: redesign from scratch with full requirements known. Phase 4: ship remaining features into new dashboard.
10. **Fix it right, not bandaid it.** Travis explicitly stated this as a preference. Workarounds are not acceptable; correct fixes only. (Exception: if a triage fix is needed to unblock a deadline, do it explicitly and label it as a triage fix with the real fix tracked separately.)

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
- **GitHub:** `travisfunk` account. Both repos public. Dashboard served via GitHub Pages from `/docs` folder of advisoryops-dashboard repo.
- **Claude Code:** launched with `claude --allowedTools "Bash(*)"` and `.claude/settings.json` in repo root.
- **Caches:** `outputs/*_cache/` directories. Persistent. NVD cache is large (~340K records).

## Section 11 — Grant context

- **Target:** OpenAI Cybersecurity Grant Program
- **Form:** 3,000 words plaintext at openai.com/form/cybersecurity-grant-program/
- **Ask:** $10M in API credits (not cash)
- **Deadline:** Rolling
- **Differentiation (verified by competitive search in earlier sessions):** No equivalent open-source system exists. Closest are CISA/HHS toolkits (not aggregated, not scored, not actionable), MISP-based academic prototypes (for device manufacturers, not hospital defenders), H-ISAC (membership-required), and commercial platforms (Claroty, Armis, TRIMEDX, Forescout, Censinet, MedCrypt, Cybellum, Sternum — all enterprise-priced).
- **Cost framing strength:** Pipeline costs $1.40 per full rebuild, ~$0.06 weekly incremental. Total dev API spend ~$12.70. These are grant-strength numbers — they prove the approach is sustainable.
- **Pre-grant requirements:**
  1. Code must be final and showable.
  2. All Section 6 problems addressed (at minimum Problems 1–3).
  3. SE enablement session: walk through the pipeline like briefing an SE before a big demo, product-level not code-level.
  4. Mock reviewer Q&A: 20 hardest likely questions.
  5. 200-word problem statement written by Travis in his own voice.
- **What goes in the grant:** Public-good open layer only. Commercial layer is out.
- **What stays out:** Commercial features, customer details, pricing models.

## Section 12 — Things this file is uncertain about

To be honest about the limits of what I (Claude) verified vs. what I'm carrying forward from older context:

- **Whether `extract.py` and `ai_correlate.py` are wired into community-build by default or only available as separate CLI commands.** Both modules exist with substantial code. I confirmed `extract.py` is exposed via the `extract` CLI command but did not verify whether community-build invokes them.
- **The exact list of "Features A through D"** that were shipped yesterday vs. older session work. The names overlap with earlier "Sessions B through K" naming and I may have conflated some.
- **Whether `eval_harness.py` is currently being run as part of CI or is dormant.** It exists, has 520 lines, has tests, but I didn't verify recent execution.
- **The current ai_cache hit rate.** I know it exists and works; I haven't measured it on the current corpus.
- **GitHub Pages cutover hasn't happened yet.** The live URL still points at the `advisoryops-dashboard` repo. Travis needs to manually flip GitHub Pages source to the merged repo (Settings → Pages → Source → main / docs) after verifying the merge branch.

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

**Test count:** 1016 → 1038. All passing.

**Manual steps still pending for Travis:**
1. Visually verify dashboard renders new sections by opening `docs/index.html` in a browser.
2. Push the branch and merge to main.
3. Flip GitHub Pages source from `advisoryops-dashboard` to `advisoryops` (Settings → Pages → Source → main / docs).
4. Verify the live URL still works.
5. Archive the `advisoryops-dashboard` repo on GitHub.

---

**End of session_state.md.** If you (future Claude) found this useful, the cost was about an hour of reading code and writing this file. Maintaining it should be cheap: at the end of each meaningful session, append a short "## Session log YYYY-MM-DD" entry with what changed, and update the relevant prior sections in place. Don't let it bit-rot.
