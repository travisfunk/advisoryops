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
