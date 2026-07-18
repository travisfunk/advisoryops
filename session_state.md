# Session State

Last updated: 2026-07-17
Branch: `feature/cvss-exposure-tagging` (off `clean-orphan`)
Status: implementation complete, Pass-2 baseline-merge gap fixed and re-verified at real scale, `docs/` purged of stale generated artifacts. Ready for merge review.

## Summary

Implemented CVSS-derived exposure tagging per `Implementation Spec: CVSS Exposure Tagging (Badge-Only, Pre-Grant Scope)`, itself following `recon_exposure_tagging.md` (read-only recon, prior session). Badge-only scope, no scoring changes, no reconciliation with AI `extracted_facts`/`inferred_facts`. Two remediation rounds followed the initial implementation — see below.

## What changed (implementation)

- `src/advisoryops/nvd_enrich.py`
  - New pure function `parse_cvss_vector(vector)` — parses CVSS v2 (prefix-less), v3.0/v3.1, and v4.0 vectors into `{version, attack_vector, no_auth_required}`. Never raises.
  - `_extract_nvd_fields()`: added `cvssMetricV40` to the NVD metric preference chain, ordered *after* v3.1/v3.0 (deliberately not NVD's newest-first convention — additive only, does not change resolution for CVEs that already had a v3.1/v3.0 metric).
- `src/advisoryops/community_build.py`
  - New helper `_cvss_exposure_fields(cvss_vector)`, called from `_feed_entry()`. Adds two derived fields to every feed row: `cvss_attack_vector` (string|null) and `remotely_exploitable_no_auth` (bool|null — true only when attack_vector==network and no auth required; false when a vector exists but the condition fails; null when no vector/unparseable).
  - New helper `_normalize_exposure_fields(rows)` — see "Pass-2 fix" below.
  - Not persisted upstream of `_feed_entry()`; not read by `score.py` or the post-hoc KEV scoring block (`community_build.py` ~2337-2364) — out of scope by spec.
- `docs/feed_contract.json` — declared both new fields (not required).
- `dashboard/index.html` — `.exp-badge` CSS, `exposureBadgeHtml(issue)` helper (mirrors `kevMedBadgeHtml`), badge wired into `renderIssueList()` after the priority badge / before the HC badge. Renders nothing for `false`/`null`. Also added an optional `activeExposureFilter` pill (mirrors the existing `activeKevFilter` pattern) — "Remote, no auth".
- `docs/scoring_internals.md` — new "CVSS Exposure Tagging" section: not a scoring input; precedence statement over AI `inferred_facts`/`extracted_facts` exploitability keys (deterministic CVSS fields are authoritative where a vector exists; AI keys are supplementary, not reconciled).
- `docs/STATUS.md` — pointer to this file.
- Tests: `tests/test_nvd_enrich.py` — `TestParseCvssVector` (11 cases), `TestExtractNvdFields` v4.0 cases (extraction + non-regression vs v3.1), `TestFeedEntryExposureFields` (5 cases), `TestNormalizeExposureFields` (4 cases, added in the Pass-2 fix round — see below).

## Remediation round 1 — stale `docs/` purge

**What was found:** `git diff origin/main..HEAD -- docs/` showed 10 generated files (`feed_latest.json`, `feed_healthcare.json`, `feed.csv`, `meta.json`, `feed_medical_device_kev.json`, all 5 `.xml` feeds) diverging massively from `origin/main` — e.g. `feed_latest.json` alone showed 531k+ changed lines.

**Root cause (confirmed, not the offline rebuilds):**
- `_publish_to_docs()` is the *only* function that writes to `docs/` (`community_build.py:610`), gated behind `if publish:` (line 2721) with an explicit `else: print("Skipping docs/ publish (--no-publish)")` (line 2725). Every rebuild this session — both before and after this remediation — passed `--no-publish` and logged that exact skip message. **The offline rebuilds never touched `docs/`.**
- The actual cause: this branch's single commit, `d4aebb2` ("AdvisoryOps — healthcare medical device advisory intelligence platform"), was authored 2026-06-28 22:42:41 — 34 minutes after a commit (`9a3da93`, "refresh docs/ feed to current origin/main (5105 issues)") that synced `docs/` to `origin/main`'s state *at that moment*. `origin/main` has since received 19 additional `chore(feed): daily pipeline run YYYY-MM-DD` automated commits (2026-06-29 through 2026-07-17), growing to 7,298 issues. `clean-orphan` (and this feature branch, cut from it) was never rebased against any of those, so its `docs/` was ~19 days stale by construction, from before this session started.

**Fix applied:** `git checkout origin/main -- docs/feed_latest.json docs/feed_healthcare.json docs/feed.csv docs/meta.json docs/feed_medical_device_kev.json docs/feed.xml docs/feed_healthcare.xml docs/feed_kev_medical_device.xml docs/feed_class_3.xml docs/feed_p0_p1.xml`. Confirmed `git diff origin/main..HEAD -- docs/` (post-commit) now shows only the 3 intentional hand-edits: `docs/feed_contract.json`, `docs/scoring_internals.md`, `docs/STATUS.md`.

**Standing rule (going forward, this repo):** before any build or verification that reads a "baseline" or "current" feed file from the local working tree, `git fetch origin main` and read the file via `git show origin/main:<path>` (or rebase/reset the branch) rather than trusting a local `docs/` copy — a branch's local `docs/` can silently lag `origin/main` by an arbitrary number of daily automated commits with no warning. This session's first real-scale baseline test (previous remediation round) already followed this rule correctly by extracting `origin/main:docs/feed_latest.json` to a scratch path rather than using the branch's local copy; this round's stale-`docs/`-in-the-branch issue is a separate, adjacent problem (stale *committed* branch content, not a stale *baseline input* to a build) — fixed by the checkout above.

## Remediation round 2 — Pass-2 baseline-merge gap (fixed)

**Prior finding (previous session turn, now resolved):** `merge_baseline_feed()`'s Pass 2 (`community_build.py`, baseline-only carried-forward rows) appended previously-published rows verbatim, without re-running `_feed_entry()` — so any row from before this feature existed was permanently missing `cvss_attack_vector`/`remotely_exploitable_no_auth`. Measured at the time: only 37/7,298 rows had the keys.

**Fix:** new function `_normalize_exposure_fields(rows)` in `community_build.py`, called once, immediately after `merge_baseline_feed()` returns and before `latest_rows`/any output is derived:
```python
feed_rows = _sort_feed_entries(
    merge_baseline_feed(feed_rows, baseline_rows, run_timestamp=_merge_ts)
)
_normalize_exposure_fields(feed_rows)
latest_rows = feed_rows[:latest] if latest > 0 else feed_rows
```
It re-derives both fields from each row's own `cvss_vector` via the existing `_cvss_exposure_fields()` helper, for every row (Pass 1 and Pass 2 alike), overwriting whatever is present. This is now **the single authoritative derivation point** whenever baseline merging is in play.

**Decision on `_feed_entry()`'s existing derivation: kept, not removed.** It remains the *only* derivation point for `alert_feed_rows`/`alerts_public.jsonl` (built via `_feed_entry()` directly, line 2428, never passed through `merge_baseline_feed()`) and for first-ever builds with no `--baseline-feed` (where every row is a Pass-1-equivalent fresh `_feed_entry()` output already). For baseline-merged builds it's harmless — Pass 1 rows get overwritten with an identical value by the new normalization step immediately after.

**Test added:** `tests/test_nvd_enrich.py::TestNormalizeExposureFields` (4 cases) — stale rows missing both keys but carrying vectors (including one prefix-less v2) get correctly derived; a vectorless baseline row gets both `null`; existing-but-wrong values get overwritten, not just filled in; and an end-to-end simulation of `merge_baseline_feed()` Pass 2 → `_normalize_exposure_fields()` in the exact production order.

## Verification status (final, post-fix, real scale)

- **Full test suite**: `python -m pytest -q` → **1128 passed, 1 deselected** (integration tests excluded by default `addopts`). No failures, no skips.
- **Real-scale rebuild** against a freshly-fetched `origin/main:docs/feed_latest.json` (re-confirmed 7,298 rows at commit `aa18cfa`, `git fetch origin main` immediately before the run — following the standing rule above), `--out-root-community outputs/community_public`, `--no-publish` (confirmed "Skipping docs/ publish (--no-publish)" in the log):
  - (a) **Total rows: 7,298**
  - (b) **Rows with `cvss_attack_vector` key present: 7,298 / 7,298 — equals total.** (Previously 37/7,298 before the fix.)
  - (c) **`remotely_exploitable_no_auth`: true = 2,343, false = 2,316, null = 2,639, key-absent = 0.** (`true=2,343` matches the figure originally cited in the implementation spec for this same 7,298-item baseline.)
  - (d) Full suite green (see above), run both before and after this rebuild.
- **`docs/` purge verified**: `git diff origin/main..HEAD -- docs/` (post-commit) shows only `feed_contract.json`, `scoring_internals.md`, `STATUS.md`.

Earlier (pre-fix, small-scale) verification detail — offline 37-record build, hand cross-checks of 3 sample records incl. one prefix-less v2 vector (`CVE-2008-4250`), dashboard JS syntax + `exposureBadgeHtml()` render-logic check — is unchanged from before and still holds; not re-run in full since the parser/derivation logic itself did not change in either remediation round, only where/how often it's invoked.

## Explicitly not touched (per spec, still holds)

- `score.py` — no reads/writes of the new fields.
- Post-hoc KEV scoring block (`community_build.py` ~2337-2364) — untouched.
- Orphaned `_DASHBOARD_HTML` constant in `community_build.py` — left as-is (recon finding #8, post-grant backlog).
- `feed.csv`, RSS outputs, `_GUARD_SCALAR`/`_GUARD_COLLECTION` — untouched (derive-at-emission design makes guard changes unnecessary; the Pass-2 fix works alongside these unchanged, not through them).
- No pipeline reordering.
- No `docs/` published-artifact edits *by any pipeline run* (feed_latest.json, index.html, meta.json, etc. — those come only from `_publish_to_docs()`, never invoked this session). The `docs/` purge above was a direct `git checkout` from `origin/main`, not a pipeline write.

## Backlog (logged only — not built, per explicit instruction)

- **Publish guard should validate against the origin-committed baseline, not the local copy.** `_publish_to_docs()`'s atomic health guard (`community_build.py:632-639`, `new_count >= baseline_count`) reads its baseline count from the local `docs/feed_latest.json` on disk. This session's own stale-branch situation (remediation round 1) is a live example of why that's insufficient: a stale local baseline (5,105) would have made the guard compare against the wrong, smaller number rather than `origin/main`'s real 7,298 — the guard would pass in a case where it should legitimately be evaluated against the real published count. The guard should fetch/read `origin/<default-branch>:docs/feed_latest.json` (or equivalent) rather than trusting the working tree's local copy.

## Push / commit status

Branch `feature/cvss-exposure-tagging`, pushed to `origin`. See top of this file / commit history for the current SHA — update this line after each push. Not merged — merge authority is Travis's.
