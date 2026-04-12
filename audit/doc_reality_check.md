# Documentation Reality Check

**Generated:** 2026-04-12
**Method:** Read-only verification of docs against code, git history, and on-disk state.
**Output:** This report + `audit/proposed_session_state.md` (a full proposed rewrite of session_state.md for Travis to review).

---

## CRITICAL FINDING — Dashboard / GitHub Pages cutover DID happen

Travis's note was correct. Two facts confirmed by `git log`:

1. **PR #12 "Consolidate dashboard repo into main repo" merged to main 2026-04-10 00:06:35** (commit `c6401ac`). This consolidated the dashboard into the main repo via squash merge. The `dashboard/index.html` file and the `_publish_to_docs()` logic are both on main.
2. **PR #13 "Field extraction, search, false positive cleanup, and polish" merged to main 2026-04-10 01:37:33** (merge commit `f189ea1`). This brought feature/v1-readiness@32810ec into main, including the Problem 3 field extraction work.

Both merges happened TWO days before session_state.md was last updated on 2026-04-12 by the fix mission. Yet session_state.md Section 2 still says "The old dashboard repo will be archived after merge verification" and Section 12 still lists "GitHub Pages cutover hasn't happened yet" as an uncertainty. Session 13's session-log entry for 2026-04-09 still lists these as pending manual steps for Travis.

Whether Travis has actually flipped GitHub Pages source from `advisoryops-dashboard` to `advisoryops/docs` in the GitHub UI is UNVERIFIABLE from code — only Travis can confirm. But the code-side prerequisite (dashboard + data files committed to `docs/` on main) has been done.

Additional finding: the README badge and "Live demo" link still point to `https://travisfunk.github.io/advisoryops-dashboard/`. If the Pages cutover has happened, the README link is wrong. If not, the code is ready but the UI flip is pending.

---

## Section 1 — Git history timeline (Phase 1 output)

### Branches present

| Branch | HEAD | Date | Note |
|--------|------|------|------|
| `main` (local) | `e1ac728` | 2026-04-06 20:44 | Stale locally — 2 commits behind origin/main |
| `origin/main` | `f189ea1` | 2026-04-10 01:37 | PR #13 merge. Contains dashboard consolidation + field extraction |
| `feature/v1-readiness` (local) | `453494a` | 2026-04-12 | Has 8 audit+fix commits NOT yet pushed |
| `origin/feature/v1-readiness` | `32810ec` | 2026-04-10 01:05 | Pre-merge snapshot; no audit/fix mission commits |
| `merge/consolidate-dashboard` (local) | `fd2fdc5` | 2026-04-09 | Superseded by PR #12 squash |
| `origin/merge/consolidate-dashboard` | `fd2fdc5` | 2026-04-09 | Same; can likely be deleted as stale branch |
| `feature/historical-backfill` (local) | `e1ac728` | 2026-04-06 | No activity in 6+ days |
| `origin/feature/historical-backfill` | `e1ac728` | 2026-04-06 | Same |

### Commits on origin/main since 2026-04-08

Chronological, earliest to latest:

| Hash | Date | Commit |
|------|------|--------|
| `37f27e2` | 2026-04-06 | Documentation refresh: README, RELEASE_NOTES, CONTRIBUTING all current with 696 tests |
| `e1ac728` | 2026-04-06 20:44 | Add Mermaid architecture diagram to README |
| `c6401ac` | 2026-04-10 00:06 | **Consolidate dashboard repo into main repo (#12)** — squash merge of merge/consolidate-dashboard + Phase 1A/1B historical backfill + post-merge work |
| `f189ea1` | 2026-04-10 01:37 | **Merge pull request #13 from travisfunk/feature/v1-readiness** — brings field extraction, search, FP cleanup, polish |

Two pull-request merges landed on 2026-04-10, within 90 minutes of each other. origin/main = `f189ea1`.

### Commits on feature/v1-readiness NOT yet on origin

All 8 are local-only audit + fix mission work from 2026-04-11/12:

| Hash | Commit |
|------|--------|
| `7f3b094` | audit: phase A+B+C unattended audit (read-only, findings only) |
| `dab64b3` | fix(C-018): republish docs/ from existing corpus via scripts/republish_docs.py |
| `0682073` | fix(C-030): correct priority thresholds in dashboard Methodology tab |
| `815ee7a` | fix(C-001,C-014): emit kev_vendor/kev_product/kev_vulnerability_name in _feed_entry |
| `68ae1f3` | fix(C-004,C-005): correct source counts and remove phantom sources from README |
| `b0f4b5e` | chore(pipeline): incremental rebuild to regenerate feed with FIX 3 schema |
| `957d09b` | docs(session_state): record audit and fix mission outcomes |
| `453494a` | docs(audit): investigate corpus count discrepancy |

### Remote repo

- `origin` = `https://github.com/travisfunk/advisoryops.git`
- No `.github/workflows/` directory exists. No CI.

---

## Section 2 — session_state.md claim verification (Phase 2 output)

### Section 2 — Repository layout

| Claim | Status | Evidence |
|-------|--------|----------|
| "One consolidated repo" | CONFIRMED | origin = travisfunk/advisoryops; no separate dashboard repo referenced in workflows/config |
| "dashboard was ... consolidated on 2026-04-09 (branch `merge/consolidate-dashboard`)" | STALE | Squash-merged via PR #12 on 2026-04-10 (not 04-09). The local branch survives but the commits are already in main via the squash. |
| "The old dashboard repo will be archived after merge verification" | STALE / UNVERIFIABLE | Cannot verify from code whether archival happened. But "will be" framing is no longer accurate — the consolidation is 2 days old. |
| "39 Python modules" in src/advisoryops/ | STALE | Actual: 38 files. Same as audit C-007. |
| "6 enrichment modules" | STALE | Actual: 7 .py files in enrichment/ (6 modules + __init__.py). Ambiguous phrasing. |
| "9 per-source historical backfill modules" | STALE | Actual: 11 .py files in sources/ (8 per-source backfill + backfill_registry + discover_sync + __init__). |
| "~1038 tests passing as of 2026-04-09" | STALE | Fix mission pytest runs confirmed 1,055 (collected 1,056 with 1 deselected). |
| "11 numbered design docs (DOC-01 through DOC-11)" | CONFIRMED | All 11 DOC-NN files exist in docs/. |
| "GitHub Pages serves from `docs/`" | UNVERIFIABLE | Cannot check GitHub UI. Code side is ready — docs/ has dashboard + data files. Section 12 of same file says cutover pending, which contradicts this. |
| "community_build.py, ~2064 lines" | STALE | Actual: 2,293 lines (was 2,289 before FIX 3 added kev fields). Audit C-007. |

### Section 3 — Pipeline architecture

| Claim | Status | Evidence |
|-------|--------|----------|
| community_build.py "~2064 lines" | STALE | See above. 2,293 lines. |
| Problem 3 "see Section 6 Problem 3" — correlate bug | MISLEADING | Section 6 Problem 3 is about non-CVE field extraction, not a correlate bug. Problem 2 is the correlate triage fix. Section 3 reference is pointing at the wrong problem number. |
| All per-module line counts (nvd_enrich 523, summarize 192, etc.) | CONFIRMED | Verified during audit Phase A + FIX mission. |
| EPSS "Currently disabled / cache empty" | STALE | Contradicted within the same file: Section 6 Problem 5 says RESOLVED. Section 3 should not say "disabled / cache empty". |

### Section 5 — Current corpus state (dated "2026-04-08 pipeline run")

| Claim | Status | Evidence |
|-------|--------|----------|
| "3,923 total issues correlated" | STALE | Current: 3,929. Problem 2 triage fix added 6 issues. FIX 4.5 rebuild on 2026-04-12 confirmed 3,929. |
| "5,573 signals across 65 sources (the `full_public` set)" | CONFIRMED | meta.json shows 65 validated sources. FIX 4.5 log confirms 5,573 signals. |
| "414 alerts at P0/P1 priority" | STALE | Current rebuild with `--top 100` default: 100 alerts. True P0/P1 count per sanity_report.md: 215 P0 + 200 P1 = 415 (close to 414 — differs by 1 due to Problem 2 fix). |
| "2,362 issues NVD-enriched" | STALE | FIX 4.5 rebuild: 2,372 NVD-enriched. Current docs/feed_latest.json: 2,317 with cvss_score (minor day-to-day variance in NVD data). |
| "203 issues KEV-enriched" | CONFIRMED | Current: 203. |
| "180 issues with FDA risk class (8 Class III, 86 Class II, 42 Class I, rest unknown)" | STALE ON DETAIL | Current: 180 total but sanity_report shows 8 Class III / 125 Class II / 47 Class I / 3,749 null. Class II went 86→125, Class I went 42→47. |
| "971 plain-language summaries" | CONFIRMED | FIX 4.5 sanity_report: generated_by=='ai' is 971. |
| "1,233 source-cited mitigations" | UNVERIFIABLE | Not captured in the current sanity report. Previous count may still be accurate. |
| "414 recommendation packets" | STALE | Current rebuild wrote 100 new packets (due to --top 100 default). On-disk: 695 total packet files (accumulated from prior runs). |
| "Healthcare category breakdown: 1,125 medical_device, 169 healthcare_infrastructure, 5 healthcare_it, 2,624 healthcare_adjacent" | STALE | Current: 1,116 / 170 / 5 / 2,638. Minor shift. |
| "Tests: ~1,016 passing" | STALE | Current: 1,055. |

### Section 6 — Known problems

| Claim | Status | Evidence |
|-------|--------|----------|
| Problem 1 RESOLVED 2026-04-09 | CONFIRMED with ADDENDUM | Core fix confirmed. Additionally, FIX 3 (commit `815ee7a`) resolved the follow-on C-001/C-014 finding for kev_vendor/kev_product/kev_vulnerability_name. Section 5 of FIX commit already mentions this. |
| Problem 2 TRIAGE FIX RESOLVED 2026-04-09, commit 5 | CONFIRMED | correlate.py:546 has the source_id merge key. Audit C-013 re-verified. |
| Problem 2 "Architectural fix still pending (post-grant)" | CONFIRMED | Still pending. |
| Problem 3 "Field extraction failing... FIX: Add a non-CVE field extraction pass" | STALE | PR #13 "feature/v1-readiness" added extract_fields.py (176 lines) and wired it into community_build.py:1546. commit `0f8785d` (2026-04-10) and `8840c70` (follow-up fix). Problem 3 should be marked RESOLVED. |
| Problem 4 "KEV / medical device zero overlap — INVESTIGATION IN PROGRESS" | CONFIRMED | commit `86984c0` on main added docs/kev_medical_device_analysis.md. Investigation documented. Finding not yet fully resolved; still appropriate as "INVESTIGATION IN PROGRESS". |
| Problem 5 EPSS cache RESOLVED | CONFIRMED | outputs/epss_cache/epss_scores.json exists. |
| Problem 6 "Healthcare filter false positives" | STALE | commit `d605b28` on main "Reduce healthcare filter false positives (Problem 6)". Partial work landed. Should be re-framed as "partial fix shipped, healthcare_adjacent still aggressive". |
| Problem 7 "Dashboard search box broken" | STALE | commit `fa5cbfd` "Verify dashboard search works (Problem 7)". Landed on main 2026-04-10 (within c6401ac squash or PR #13). Needs verification whether it's marked resolved. |

### Section 7 — Shipped vs pending

| "Shipped and verified working" entries | Status |
|----------------------------------------|--------|
| 60+ source ingestion, backfill, scoring v2, playbook, AI features, etc. | CONFIRMED for items that predate this check |
| (None added from the 2026-04-10 main-side work: EPSS dashboard rendering, CONTRIBUTING.md polish, architecture diagram, sanity report, feed contract, dashboard search fix, healthcare filter FP reduction) | MISSING |

| "Pending pre-grant" entries | Status |
|-----------------------------|--------|
| 1. Problem 1 | STALE — resolved |
| 2. Problem 2 triage | STALE — resolved |
| 3. Problem 3 non-CVE field extraction | STALE — resolved via commit `0f8785d` |
| 4. Problem 5 EPSS populate | STALE — resolved |
| 5. Problem 6 healthcare filter FP cleanup | STALE — partial fix shipped |
| 6. Architecture diagram | STALE — commit `e778acc` added architecture.md |
| 7. README/CONTRIBUTING.md currency check | STALE — commit `2924a54` and `afe40dc` did this (though audit C-004/C-005 found issues the grant-readiness pass missed; those are now also fixed via FIX 4) |
| 8. Footer/link audit | UNVERIFIABLE — no commit explicitly addresses this; README badge link is still stale |
| 9-11. SE enablement, mock reviewer Q&A, 200-word problem statement, grant writing | CONFIRMED still pending |

### Section 12 — Uncertainties

| Claim | Status |
|-------|--------|
| "Whether `extract.py` and `ai_correlate.py` are wired into community-build" | RESOLVED (already updated by FIX 5) — Audit C-003 confirmed not wired. |
| "Features A through D naming" | STILL UNVERIFIABLE |
| "Whether `eval_harness.py` is currently being run as part of CI" | STILL UNVERIFIABLE (no CI configured; would be run on-demand only) |
| "The current ai_cache hit rate" | STILL UNVERIFIABLE without measurement. FIX 4.5 observed 100% cache hit on packets, so the rate is high for repeat runs. |
| "GitHub Pages cutover hasn't happened yet" | UNVERIFIABLE from code, but STALE in framing — the code-side prerequisites (dashboard + data files in docs/) were all done on 2026-04-10. Only Travis can confirm the actual UI flip. |

### Section 13 — Session log

| Claim | Status |
|-------|--------|
| 2026-04-09 Dashboard merge entry | CONFIRMED as historical record of that session |
| "Manual steps still pending for Travis" list (items 1-5) | STALE — items 2, 4 clearly completed (push/merge happened via PR #12/#13 on 2026-04-10). Items 1, 3, 5 UNVERIFIABLE. |
| 2026-04-11 Audit + fix mission entry | CONFIRMED — accurate record |

### MISSING — work on main not reflected in session_state

session_state.md's last session-log entry is 2026-04-11 (audit + fix mission). But commits on main between 2026-04-09 and 2026-04-10 include substantial feature work not attributed to any logged session:

- `32d4559` (2026-04-09) Add session state notes for project context
- `fd2fdc5` (2026-04-09) Update README and session_state for merged structure
- `fa5cbfd` (2026-04-10) Verify dashboard search works (Problem 7)
- `e778acc` (2026-04-10) Add architecture diagram and layer descriptions
- `afe40dc` (2026-04-10) Update CONTRIBUTING.md for grant readiness
- `72c3fb2` (2026-04-10) Render EPSS scores in dashboard detail panel
- `d605b28` (2026-04-10) Reduce healthcare filter false positives (Problem 6)
- `86984c0` (2026-04-10) KEV / medical device overlap investigation (Problem 4)
- `2924a54` (2026-04-10) README polish pass for grant readiness
- `c719b52` (2026-04-10) Repo hygiene: gitignore caches, commit scripts and docs
- `0f8785d` (2026-04-10) Add LLM field extraction for non-CVE issues (Problem 3)
- `c6401ac` (2026-04-10) Consolidate dashboard repo into main repo (#12)
- `8840c70` (2026-04-10) Fix extract_fields truncation: bump max_tokens, handle malformed JSON
- `32810ec` (2026-04-10) Merge main into v1-readiness branch
- `f189ea1` (2026-04-10) Merge pull request #13

Section 13 never captured a "2026-04-10 — Pre-grant polish and merge" session. Session_state's next-available session log entry jumps from 2026-04-09 to 2026-04-11, skipping 04-10 entirely.

---

## Section 3 — Other doc verification (Phase 3 output)

### README.md

Already updated by FIX 4 (commit `68ae1f3`). Current state:
- Tests badge: 1055 ✓
- "68 public sources" in prose and diagrams ✓
- Source coverage table rebuilt with real 4 scopes ✓
- Live demo link: STILL POINTS at `https://travisfunk.github.io/advisoryops-dashboard/` (line 36). This may be correct-if-Pages-not-flipped-yet or stale-if-Pages-flipped. Travis must verify.

### docs/STATUS.md

Last audit call (phase_b_doc_reality.md): "Entire file is stale. Superseded by session_state.md." Still true. STATUS.md last-updated 2026-03-17.

### docs/schema.md

Audit C-012: 7 field-name mismatches with _feed_entry. Current state: 36 rows in schema.md vs 56 fields in _feed_entry output. C-012 still valid.

### docs/scoring_internals.md

Previously fully confirmed. No changes needed — most accurate doc in the project.

### docs/playbook_governance.md

Previously fully confirmed. No changes needed.

### docs/grant_cost_model.md

Still UNVERIFIABLE (depends on pipeline run). The "1990 total issues, 234 healthcare-relevant" numbers in the header are stale post-FIX-4.5 (current = 3,929 / 3,929) but the underlying token analysis and cost math don't depend on those counts. If Travis wants the cost model refreshed after FIX 4.5, that's a separate task.

### DOC-01 through DOC-11

Previously marked all stale (dated 2026-02-10 or 2026-03-17). No updates since. Still stale.

### audit/phase_c_code_findings.md

Findings resolved by commits made AFTER the audit was written:

| Finding | Status | Resolved by |
|---------|--------|-------------|
| C-001 | RESOLVED | commit `815ee7a` (FIX 3) |
| C-014 | RESOLVED | commit `815ee7a` (FIX 3) |
| C-030 | RESOLVED | commit `0682073` (FIX 2) |
| C-018 | RESOLVED | commit `dab64b3` (FIX 1) + `b0f4b5e` (FIX 4.5) |
| C-004 | RESOLVED | commit `68ae1f3` (FIX 4) |
| C-005 | RESOLVED | commit `68ae1f3` (FIX 4) |
| C-007 (community_build.py line count) | STILL STALE — line count has grown |
| C-017 (docs/meta.json test paths) | RESOLVED by FIX 4.5 — current meta.json has production paths |

Findings still open (13 items — see C-002, C-003, C-006, C-008, C-009, C-010, C-011, C-012, C-013, C-015, C-016, C-019, C-020, C-021, C-022, C-023, C-025, C-026, C-027, C-028, C-029, C-031, C-032, C-033, C-034, C-035):

- C-002 still valid (partial — 3 missing contract fields resolved via FIX 3, but 21 extra feed fields still not in contract)
- C-003 still valid (extract.py / ai_correlate.py orphaned)
- C-010 still valid (11 modules without tests)
- C-012 still valid (schema.md mismatches)
- C-027 still valid (silent AI exception blocks at community_build.py:1862, 1889)
- C-031 still valid (_DASHBOARD_HTML constant still present at line 419+)
- Most LOW/INFO findings still valid

Phase C finding list hasn't been formally marked-up with resolutions. Travis may want to add a "Status" field to each finding.

---

## Section 4 — Executive Summary

### Claim counts

| Category | Count |
|----------|------:|
| CONFIRMED claims in session_state.md | ~18 |
| STALE claims in session_state.md | ~25 |
| MISSING items (things that happened but aren't in the doc) | 15 commits on main between 2026-04-09 and 2026-04-10 not captured in any session log entry; includes Problem 3, 6, 7 work and the entire grant-readiness polish pass |
| UNVERIFIABLE claims | ~6 (GitHub Pages UI state, old dashboard repo archival status, CI-run status, current ai_cache hit rate, whether Travis completed footer/link audit, whether the "adjacent" category aggression is intended) |

### Top 5 corrections (priority order)

1. **Section 2 + Section 12 + Section 13** — Dashboard consolidation and merge are DONE, not pending. Update Section 2 to remove "will be archived" framing. Update Section 12 to remove the "GitHub Pages cutover hasn't happened yet" uncertainty (or narrow it to "UI flip unverified from code"). Update Section 13's 2026-04-09 manual-steps list to cross off items 2 and 4 (push + merge) and to note items 1, 3, 5 need Travis confirmation.
2. **Section 6 Problem 3** — Mark RESOLVED with commit `0f8785d` + `8840c70`. extract_fields.py exists, is wired into community_build.py line 1546.
3. **Section 7** — Rewrite both halves. "Shipped" list is missing the entire 2026-04-10 pre-grant polish pass. "Pending pre-grant" list is mostly stale (items 1-7 are done or partial-done).
4. **Section 13** — Add a missing session-log entry for 2026-04-10 covering commits `32d4559` through `f189ea1` (15 commits). This was an active day that left no doc footprint.
5. **Section 5** — Update corpus numbers: 3,923→3,929 (Problem 2 fix), ~1,016→1,055 tests, 414 alerts→215 P0+200 P1 (breakdown from sanity_report), NVD 2,362→2,372, packet count context (100 new per rebuild, 695 accumulated on disk). Add a sentence about the healthcare filter marking 3,929/3,929 as healthcare_relevant=True due to the "adjacent" category dominating.

### Honest assessment of session_state.md staleness

The file was last meaningfully updated by the 2026-04-12 fix mission, but that update only appended Section 13 and tweaked Section 5/6/12 language. Earlier sections (1-4, 7, 11) weren't touched. The doc is not badly stale — it captures the shape of the project correctly — but it's drift-accumulating, especially:
- It treats the 2026-04-10 merge as pending (it's done).
- It treats Problem 3 as open (it's fixed — the fix mission itself relied on extract_fields being present).
- Its "Pending pre-grant" checklist is misleading to a fresh reader — most items are done.
- It has an entire day of commit activity (2026-04-10) with no session log entry.

The most dangerous kind of drift here is not factual contradiction but false-incompleteness: a future Claude reading this will think the project is further from grant-ready than it actually is, and may spend effort on items already shipped. The proposed rewrite addresses that.

The architectural principles (Section 8) and working agreements (Section 9) and grant context (Section 11) are all still accurate and don't need touching.
