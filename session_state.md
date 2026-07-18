# Session State

Last updated: 2026-07-17
Branch: `feature/cvss-exposure-tagging` (off `clean-orphan`)
Status: implementation complete, verification passed

## Summary

Implemented CVSS-derived exposure tagging per `Implementation Spec: CVSS Exposure Tagging (Badge-Only, Pre-Grant Scope)`, itself following `recon_exposure_tagging.md` (read-only recon, prior session). Badge-only scope, no scoring changes, no reconciliation with AI `extracted_facts`/`inferred_facts`.

## What changed

- `src/advisoryops/nvd_enrich.py`
  - New pure function `parse_cvss_vector(vector)` — parses CVSS v2 (prefix-less), v3.0/v3.1, and v4.0 vectors into `{version, attack_vector, no_auth_required}`. Never raises.
  - `_extract_nvd_fields()`: added `cvssMetricV40` to the NVD metric preference chain, ordered *after* v3.1/v3.0 (deliberately not NVD's newest-first convention — additive only, does not change resolution for CVEs that already had a v3.1/v3.0 metric).
- `src/advisoryops/community_build.py`
  - New helper `_cvss_exposure_fields(cvss_vector)`, called from `_feed_entry()`. Adds two derived fields to every feed row: `cvss_attack_vector` (string|null) and `remotely_exploitable_no_auth` (bool|null — true only when attack_vector==network and no auth required; false when a vector exists but the condition fails; null when no vector/unparseable).
  - Not persisted upstream of `_feed_entry()`; not read by `score.py` or the post-hoc KEV scoring block (`community_build.py` ~2337-2364) — out of scope by spec.
- `docs/feed_contract.json` — declared both new fields (not required).
- `dashboard/index.html` — `.exp-badge` CSS, `exposureBadgeHtml(issue)` helper (mirrors `kevMedBadgeHtml`), badge wired into `renderIssueList()` after the priority badge / before the HC badge. Renders nothing for `false`/`null`. Also added an optional `activeExposureFilter` pill (mirrors the existing `activeKevFilter` pattern) — "Remote, no auth" — since it composed trivially with `applyFilters()` without touching the healthcare dataset-swap toggle or its count displays.
- `docs/scoring_internals.md` — new "CVSS Exposure Tagging" section: not a scoring input; precedence statement over AI `inferred_facts`/`extracted_facts` exploitability keys (deterministic CVSS fields are authoritative where a vector exists; AI keys are supplementary, not reconciled).
- `docs/STATUS.md` — pointer to this file.
- Tests: `tests/test_nvd_enrich.py` — new `TestParseCvssVector` (11 cases: v3.1/v3.0/v4.0/v2 versions, network/local/physical attack vectors, auth required/not, empty/None/garbage never raises), two new `TestExtractNvdFields` cases (v4.0-only extraction, v3.1-wins-over-v4.0-when-both-present), new `TestFeedEntryExposureFields` (5 cases proving `_feed_entry()` derivation and same-path inheritance). `_nvd_cve_item()` fixture generalized with a `version`/`extra_metrics` param (kept `use_v31` for backward compat).

## Explicitly not touched (per spec)

- `score.py` — no reads/writes of the new fields.
- Post-hoc KEV scoring block (`community_build.py` ~2337-2364) — untouched.
- Orphaned `_DASHBOARD_HTML` constant in `community_build.py` — left as-is (recon finding #8, post-grant backlog).
- `feed.csv`, RSS outputs, `_GUARD_SCALAR`/`_GUARD_COLLECTION` — untouched (derive-at-emission design makes guard changes unnecessary).
- No pipeline reordering.
- No `docs/` published-artifact edits (feed_latest.json, index.html, meta.json, etc. — those come only from the pipeline + `_publish_to_docs()`). Hand-authored docs (`feed_contract.json`, `scoring_internals.md`, `STATUS.md`) were edited directly, as the spec explicitly required for the contract file and this file.

## Verification status

- **Full test suite**: `python -m pytest -q` → **1123 passed, 1 skipped, 1 deselected** (integration tests excluded by default `addopts`). No regressions.
- **Dashboard/contract tests specifically**: `tests/test_dashboard_html.py` + `tests/test_feed_contract.py` → 15 passed, 1 skipped (green both before and after the dashboard edit).
- **Offline pipeline build** (`community-build --set-id gold_pass1 --out-root-discover outputs/branch_discover --out-root-community outputs/community_public_verify --no-publish`, using cached `outputs/branch_discover` + `outputs/nvd_cache`, `docs/` untouched — confirmed by "Skipping docs/ publish (--no-publish)" in the run log):
  - `feed_latest.json`: 37/37 issues carry both `cvss_attack_vector` and `remotely_exploitable_no_auth`. Distribution: `remotely_exploitable_no_auth` true=7, false=14, null=16. `cvss_attack_vector`: network=7, local=5, adjacent=4, physical=5, null=16.
  - `feed_healthcare.json`: 16/16 issues carry both fields (subset of the above). true=3, false=13, null=0 (small sample — every healthcare issue in this 37-issue snapshot happened to have a vector; not representative of the full corpus's ~88% null rate on that subset, which is expected and not a bug).
  - Confirms `feed_latest.json` and `feed_healthcare.json` inherit the fields via the same `_feed_entry()` path, as designed — no separate wiring needed.
- **Hand cross-check, 3 sample records** (vector string → emitted fields), one deliberately a prefix-less v2 vector:
  1. `CVE-2026-30040` — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L` → `cvss_attack_vector="network"`, `remotely_exploitable_no_auth=True`. Correct (AV:N→network, PR:N→no-auth).
  2. `CVE-2021-26248` — `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` → `cvss_attack_vector="local"`, `remotely_exploitable_no_auth=False`. Correct (AV:L→local, so condition fails regardless of PR).
  3. `CVE-2008-4250` (pulled from the published `docs/feed_latest.json`, prefix-less v2) — `AV:N/AC:L/Au:N/C:C/I:C/A:C` → `cvss_attack_vector="network"`, `remotely_exploitable_no_auth=True`. Correct (no `CVSS:` prefix correctly detected as implicit v2; Au:N→no-auth).
- **Dashboard badge render check**: full browser render wasn't practical in this environment; instead extracted the `<script>` block from `dashboard/index.html` and syntax-checked it with `node --check` (passed), then executed `exposureBadgeHtml()` standalone against `{true, false, null, undefined}` — renders the badge span only for `true`, renders `''` (nothing) for `false`/`null`/`undefined`, matching the spec's "must render nothing, not a false badge" requirement. Combined with the passing `test_dashboard_html.py`/`test_feed_contract.py`, this is the extent of dashboard verification performed; a real-browser check is recommended before merge if Travis wants full visual confirmation.
- **Post-merge, post-publish curl check**: not performed — out of scope for this session (requires merge + publish, which is Travis's call, not mine).

Not pushed, not merged — merge authority is Travis's. Branch `feature/cvss-exposure-tagging` is ready for review.
