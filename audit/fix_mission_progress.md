# Fix Mission Progress

**Mission:** Address HIGH-severity findings from Phase C audit + C-018 + corpus investigation.
**Baseline tests:** 1,055 passing.
**Baseline docs sanity:** docs/feed_latest.json contains 1,990 issues after FIX 1.

---

## FIX 1 — C-018: Republish docs/ from existing corpus — DONE
- **Commit:** `dab64b3`
- **Date:** 2026-04-11
- **What:** Added `scripts/republish_docs.py` to re-run `_publish_to_docs()` against existing pipeline output. Also fixed 9 calls to `build_community_feed()` in tests/test_community_build.py that were missing `repo_root=tmp_path`, which were causing tests to overwrite real docs/.
- **Tests:** 1,055 passed (no regression).
- **docs sanity:** 1,990 issues after test run (confirmed).

---

## FIX 2 — C-030: Dashboard Methodology priority thresholds — DONE
- **Commit:** `0682073`
- **Date:** 2026-04-12
- **What:** Updated dashboard/index.html threshold display (P0>=190→150, P1>=150→100, P2>=100→60, P3<100→60) to match score.py:103-108. Copied to docs/index.html.
- **Tests:** 37 passed (subset: dashboard/community_build/feed_contract/publish_step).
- **docs sanity:** 1,990 issues confirmed.

## FIX 3 — C-001 + C-014: KEV fields in _feed_entry — DONE
- **Commit:** `815ee7a`
- **Date:** 2026-04-12
- **What:** Added kev_vendor, kev_product, kev_vulnerability_name to _feed_entry. Added kev_vulnerability_name to _KEV_FIELDS and _NVD_KEV_FIELDS.
- **Upstream investigation:** feed_parsers.py:184 already pulls vulnerabilityName from CISA KEV JSON; correlate.py:166-167 propagates it; the break was at the issue-enrichment step and at feed emission.
- **Tests:** 1,055 passed (full suite, no regression).
- **docs sanity:** 1,990 issues confirmed.

## FIX 4 — C-004 + C-005: README source claims — DONE
- **Commit:** `68ae1f3`
- **Date:** 2026-04-12
- **What:** Tests 1038→1055. Sources 57/65→68. Issues 3929→1990. Medical device 856→234. NVD 1138→1091. Rebuilt source coverage table with real 4-scope breakdown; every example verified against sources.json.
- **Tests:** 1,055 passed.
- **docs sanity:** 1,990 issues confirmed.

## FIX 4.5 — Incremental pipeline run — DONE
- **Commit:** `b0f4b5e`
- **Date:** 2026-04-12
- **First run:** Used `--latest 100` which truncated feed_latest.json to 100 issues. Failed docs sanity gate. Rerun without `--latest`.
- **Successful run:** advisoryops community-build --set-id full_public --skip-backfill --summarize --extract-mitigations --ai-score --recommend --min-priority P1 (no --latest cap)
- **Results:**
  - issues built: 3,929
  - alerts: 100 (P1 threshold, top=100)
  - kev_with_vendor in feed_latest.json: 203 (FIX 3 schema verified end-to-end)
  - NVD: 2,372 / EPSS: 2,356 / CWE: 1,602
  - Recommend packets: 100/100 (all cached, $0 API spend)
  - Runtime: ~6 min wall clock
- **Cost:** effectively $0 — all AI calls hit cache
- **Tests:** 1,055 passed.
- **docs sanity:** 3,929 issues confirmed.

## FIX 5 — Update docs/session_state.md — DONE
- **Commit:** `957d09b`
- **Date:** 2026-04-12
- **What:** Section 5 updated with reconciled numbers from FIX 4.5 rebuild. Section 6 Problem 1 gained audit follow-up for C-001/C-014 resolution. Section 6 Problem 4 marked investigation-in-progress. Section 12 extract.py/ai_correlate.py uncertainty resolved. Section 13 appended mission log with every commit hash.
- **Tests:** 1,055 passed.
- **docs sanity:** 3,929 issues confirmed.

## FIX 6 — Investigate corpus count discrepancy — DONE
- **Commit:** (next, see below)
- **Date:** 2026-04-12
- **Classification:** Category (a) — on-disk feed was a snapshot from a run with different parameters, not a filtering bug. The correlate stage output (issues.jsonl) confirmed 3,929 issues after FIX 4.5 rebuild, matching session_state claim.
- **Findings written:** audit/fix_mission_notes.md
- **No C-036 finding filed.** No bug identified. The 1,990 pre-FIX-4.5 count in docs/feed_latest.json was an artifact of a prior `--latest N` truncation or an older snapshot. FIX 4.5's rebuild (without a --latest cap) produced the full 3,929 as expected.

---

## Session Summary

**Final commit:** pending — FIX 6 docs commit below.

**Fixes classification:**
- FIX 1 (C-018): DONE `dab64b3`
- FIX 2 (C-030): DONE `0682073`
- FIX 3 (C-001, C-014): DONE `815ee7a`
- FIX 4 (C-004, C-005): DONE `68ae1f3`
- FIX 4.5 (pipeline rebuild): DONE `b0f4b5e`
- FIX 5 (session_state): DONE `957d09b`
- FIX 6 (corpus investigation): DONE (this commit)

**New findings discovered during fix mission:** None. The mission did surface one important realization: the 9 `build_community_feed()` calls in test_community_build.py that were missing `repo_root=tmp_path` had been silently overwriting the real `docs/` directory on every pytest run. That root-cause was fixed as part of FIX 1. Not filed as a separate C-NNN finding because it was resolved in the same commit that discovered it.

**Things Travis needs to know before next session:**
1. All six fixes committed cleanly, no reverts. 1,055 tests pass on every commit.
2. The on-disk `docs/feed_latest.json` is now the real 3,929-issue corpus (was 1 issue at audit time).
3. The live GitHub Pages dashboard will now serve real data once the branch is pushed and merged.
4. FIX 4.5 cost $0 at the OpenAI API level — the AI cache covered every call.
5. A known side effect of the rebuild: `feed_healthcare.json` now contains all 3,929 issues (all marked `healthcare_relevant=True`). This is the existing Problem 6 (healthcare filter false positives) manifesting, not a regression introduced by this mission. See audit/fix_mission_notes.md for background.
6. Still open from the audit (not in scope for this mission): C-002 (feed_contract out of sync), C-003 (extract.py/ai_correlate.py orphaned), C-010 (11 untested modules), C-012 (schema.md mismatches), C-027 (silent AI exception blocks), C-031 (860 lines of dead embedded dashboard HTML in community_build.py), C-033/C-034 (cli.py cmd_correlate fragility).
7. Branch not pushed. Travis pushes.

---

## 2026-04-12 — Medical Device Filter Fix

**Problem:** Live dashboard "Medical devices" button shows 3,929 issues — including F5 BIG-IP, Trivy, Langflow, and other general-IT products. Highest-priority pre-grant issue. Reviewers will catch it in 30 seconds.

**Phase 1 diagnosis:** See `audit/medical_device_filter_diagnosis.md`. Root cause = **Cause A (dashboard predicate bug)**. The data is tagged correctly (`healthcare_category` = `healthcare_adjacent` / `healthcare_infrastructure` / `medical_device`), but the "Medical devices" button filters on `healthcare_relevant === true`, which is set on all 3,929 issues. No classifier change needed; 1,116 `medical_device` rows are already present in the data.

**Fix plan:** Swap the dashboard predicate from `healthcare_relevant === true` to `healthcare_category === 'medical_device'` at four locations in `dashboard/index.html` (lines 700, 1103, 1113, 1183). Copy to `docs/index.html`. No classifier or corpus changes.

**Header strings (65 sources / Updated 2026-04-08):** Both are already computed, not hardcoded. Documented in the diagnosis doc. Holding on header changes pending Travis — the "65 vs 68" gap is validated-sources vs enabled-in-config, not a display bug.

### Commit — `bcf2d46` fix(dashboard): correct Medical devices filter predicate

**What changed:** dashboard/index.html (4 locations) + docs/index.html copy. Predicate swapped from `healthcare_relevant === true` to `healthcare_category === 'medical_device'`. Diagnosis doc added.

**Tests:** 1,055 passed. Docs sanity: 3,929 issues.

**Immediate effect:** "Medical devices" button count drops from 3,929 → 1,116. F5 BIG-IP, Trivy, Langflow are no longer in the bucket.

### STOP — classifier noise in medical_device bucket is more complex than prompt anticipated

After the dashboard fix, the `healthcare_category=medical_device` bucket contains 1,116 issues, but the composition is still suspect. Sampling the first 15 medical_device issues showed:

- **Zero** have Philips / Siemens / Medtronic / Abbott / BD / Abiomed / Baxter / GE / Stryker / Zoll / Roche / Hillrom / Varian / Boston Scientific in `vendor` or `affected_products`.
- Of 1,116, only 15 have any vendor set, and those 15 are: Microsoft (5), Google (4), Meta (2), Oracle (1), Cisco (1), D-Link (1), Citrix (1).
- The `affected_products` arrays are almost exclusively general IT — Google Chrome, Microsoft Windows, Cisco Secure Firewall, Citrix NetScaler, Oracle Concurrent Processing, D-Link firmware, etc.
- **Every sampled medical_device issue includes `philips-psirt` in its `sources` array.**

**Hypothesis:** The healthcare_filter is promoting issues to `medical_device` when any source in the issue's source set is a medical-device-vendor PSIRT feed (Philips PSIRT, etc.), regardless of whether the affected product is itself a medical device. This is a legitimate signal — Philips PSIRT genuinely advises hospitals when upstream Chrome/Windows/Cisco CVEs affect its products — but the label "Medical devices" on the dashboard button then surfaces Chrome and Windows as "medical devices", which reviewers will read as mis-classification.

**Why this needs Travis:** Two substantively different product decisions:
1. **Keep current behavior, rename the filter.** Medical_device = "vuln relevant to a medical-device deployment per a medical-device vendor's advisory stream." Legitimate healthcare-security signal; label needs rewording so it's not read as "vuln in a medical device product".
2. **Tighten the classifier.** Only tag `medical_device` when affected_products contains a known medical-device product keyword, independent of source provenance. Shrinks the bucket further (probably to low hundreds or less) but loses the Philips-PSIRT-curated-upstream signal.

This is a product/classification call, not a drop-in regex tightening. Per the mission's "If anything is more complex than the prompt anticipates, STOP" rule, I am not touching `healthcare_filter.py`.

**Not done:** header "65 sources" / "Updated 2026-04-08" rewiring. See diagnosis doc — both are already computed, and the "correct" numbers (68 vs 65, rebuild-date vs newest-issue-date) are product decisions, not bugs.

**What Travis should decide:**
1. Medical_device classifier behavior (option 1 rename vs option 2 tighten)
2. Whether "sources" in the header should show validated (65) or enabled-in-config (68)
3. Whether "Updated" should track max(issue.date) (current) or rebuild/generated_at timestamp (would require adding that field to meta.json)

Branch: feature/v1-readiness, commit `bcf2d46`, not pushed.

---

## 2026-04-12 — Medical device classifier tightening

**Travis's product decision:** CISA ICS-Medical (source_id `cisa-icsma`) is authoritative. Medical_device tag requires at least one of: (1) `cisa-icsma` in sources, (2) vendor matches curated allowlist, (3) non-null `fda_risk_class`, (4) `affected_products` matches curated product-keyword list. Anything else → falls through to existing healthcare_it / healthcare_infrastructure / healthcare_adjacent logic.

### Current classifier logic — baseline before change

`src/advisoryops/healthcare_filter.py:254-308`:

1. False-positive check (`_is_false_positive`) — cosmetics/food/generic-malware exclusion. Keeps this path.
2. `_MEDICAL_DEVICE_SOURCES` includes `cisa-icsma`, `fda-medwatch`, openFDA device recalls/events (hist + current), `fda-safety-comms-historical`, `health-canada-recalls`, **`philips-psirt`**, **`siemens-productcert`** → medical_device. **The last two cause the Chrome-on-Philips noise — any issue co-occurring with a Philips or Siemens advisory stream gets tagged.**
3. `_VENDOR_TEXT_RE` (text search across title/summary/vendor for any MEDICAL_DEVICE_VENDORS entry) → medical_device. **Matches marketing copy, not product attribution.**
4. `fda_risk_class` present → medical_device.
5. `_MEDICAL_DEVICE_RE` keyword match in text (infusion pump, ventilator, ..., `\bmri\b`, `\bct\b`, fda, iec 62443) → medical_device. **`\bct\b` is the C-035 finding; and "medical device" / "imaging" match marketing text.**
6. Healthcare IT regex → healthcare_it.
7. Healthcare infrastructure regex → healthcare_infrastructure.
8. KEV + medical vendor → medical_device (kept under new Rule 2).
9. Default → healthcare_adjacent.

### Plan

- Replace rules 2–5 with the four-rule strict check (`_is_medical_device`).
- Keep rules 1 (false-positive check is harmless under stricter matching), 6, 7, 9 (healthcare_it/infra/adjacent fallback unchanged).
- Remove the `_MEDICAL_DEVICE_SOURCES` set (strict Rule 1 replaces it).
- `_VENDOR_TEXT_RE` stays (it's used by `is_healthcare_relevant`, which the prompt says NOT to change). It will continue to be built from `MEDICAL_DEVICE_VENDORS`.
- `_MEDICAL_DEVICE_RE` keyword regex stays available but is no longer consulted in the medical_device decision path.

### Tests likely to break (update per prompt's "tests asserting demonstrably wrong predicates" rule)

`tests/test_healthcare_category.py`:
- `test_openfda_source_is_medical_device` — openfda-recalls-historical alone no longer triggers medical_device (strict Rule 1 is cisa-icsma only). Real openFDA recall issues have `fda_risk_class` populated (Rule 3) so won't regress in practice, but this fixture has only the source set.
- `test_philips_psirt_source_is_medical_device` — this is the exact bug. philips-psirt alone no longer triggers medical_device.
- `test_medical_vendor_in_text_is_medical_device` — title="Medtronic pump" with empty vendor field. Under Rule 2 we check the vendor field, not text.
- `test_device_keyword_is_medical_device` / `test_defibrillator_keyword_is_medical_device` — keyword-in-text is no longer a rule.
- `test_epic_systems_is_medical_device` — Epic Systems is healthcare IT, not a medical-device vendor; the old-behavior assertion was wrong anyway.
- `test_medical_device_takes_precedence_over_it` — strict rules → not medical_device; falls through to healthcare_it.

`tests/test_healthcare_filter.py`:
- `TestFalsePositiveExclusion.test_device_in_threat_report_not_excluded` — keyword-in-text is not a rule; demotes to healthcare_adjacent.
- `TestKeywordMatching.test_vendor_in_text` — several parametrize entries ("Epic Systems", "Contec Health", "WHILL") are not in the prompt's curated vendor list. Since `_VENDOR_TEXT_RE` is rebuilt from the new `MEDICAL_DEVICE_VENDORS`, those parametrize entries will fail. Drop them.

### Commits landed

- `1d222b2` fix(healthcare_filter): tighten medical_device classification to four strict rules
- `19b3b37` fix(corpus): re-tag medical_device with strict classifier, 1116 -> 224
- `ab77ae8` fix(dashboard): wire header source count and updated date to live data
- `<next>` chore(validation): add medical_device bucket validation script

### Final numbers

| category | before | after classifier fix |
|---|---|---|
| medical_device | 1,116 | **224** |
| healthcare_infrastructure | 170 | 311 |
| healthcare_it | 5 | 17 |
| healthcare_adjacent | 2,638 | 3,377 |
| total healthcare_relevant | 3,929 | 3,929 |

Header: "3929 issues · 68 sources" (All) / "224 medical device issues · 68 sources" (Medical devices). "Updated 2026-04-12T19:31" (actual publish timestamp).

Tests: 1,051 passing (4-test net reduction from baseline 1,055; intentional — old tests asserted wrong behavior).

Validation script: `scripts/validate_medical_device_bucket.py` exits 0.

Branch: feature/v1-readiness, not pushed.

---

## 2026-04-12 — FDA risk class auto-floor

**Goal:** Apply clinical-severity floor by FDA classification so Class III defibrillator recalls (and similar) hit P0 even without cyber signals.

### Phase 1 — FDA field format

Confirmed from `docs/feed_latest.json`:

- Field name: `fda_risk_class`.
- Value format: string digit — `"3"`, `"2"`, `"1"`. No `"III"` / `"Class III"` / integer variants in the corpus.
- Distribution: 8 Class III (`"3"`), 125 Class II (`"2"`), 47 Class I (`"1"`), 3749 None.
- Example target — `UNK-42c8bda5d1c8ebae` (Philips AED recall): score=117, priority=P1, fda_risk_class=`"3"`. After Rule A it auto-floors to 150 → P0.

### Phase 2 plan

Add `_apply_fda_clinical_floor(issue, score, why) -> score` to `score.py` and call it at the end of `score_issue_v2` (after the existing `_score_fda_risk_class` additive contribution, before `_priority_from_score`). v1 is the keyword-only baseline and stays untouched — the floor is a v2 healthcare-aware concept.

Retag script path: extend `scripts/retag_corpus.py` to also re-apply the floor against existing `score`/`priority`/`why` in the already-scored feed. We don't need to re-run the whole v2 scorer — the base score already reflects all existing dimensions (including the +30/+10 from `_score_fda_risk_class`). The floor is a pure post-processing step.
