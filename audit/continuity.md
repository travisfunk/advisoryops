# Audit Continuity Block

**Session date:** 2026-04-11
**Branch:** `feature/v1-readiness`

---

## 1. What was done this session

- **Phase A (Inventory):** Complete. Full module inventory (56 Python files, 18,206 total lines), config inventory, test inventory (57 files, 1,055 tests), CLI surface (15 subcommands), playbook verification (11 patterns confirmed), source count (96 total, 68 enabled).
- **Phase B (Doc Reality):** Complete. Audited README.md, session_state.md, STATUS.md, schema.md, scoring_internals.md, playbook_governance.md, feed_contract.json, grant_cost_model.md, and DOC-01 through DOC-11.
- **Phase C (Code Findings):** Complete. 29 findings (C-001 through C-029).
- **Files written:** `audit/phase_a_inventory.md`, `audit/phase_b_doc_reality.md`, `audit/phase_c_code_findings.md`, `audit/continuity.md`, `audit/README.md`.
- **Commit:** Pending (see below).

---

## 2. What was NOT done and why

- Background agents were launched for deeper exploration of Python module internals (function-level inventory), test file details, full Phase B doc checks, and full Phase C code walkthrough. These agents did not return results before the main audit was completed. All findings in the written reports are based on direct investigation by the primary session using Read, Grep, Bash introspection, and targeted code reads.
- **Not verified:** Whether `recommend.py` actually filters hallucinated pattern IDs — would require reading the full recommend.py function. Session_state.md claims it does; not independently verified in this audit.
- **Not verified:** Full read of every DOC-01 through DOC-11. Headers and sizes were checked. Detailed field-level claims within these docs were not exhaustively cross-referenced against code.
- **Not run:** `advisoryops community-build` or any pipeline stage. All corpus metrics (issue counts, enrichment counts, packet counts) are UNVERIFIABLE by design.

---

## 3. Top 10 highest-severity findings

1. **C-001 (HIGH):** _feed_entry missing kev_vendor, kev_product, kev_vulnerability_name — dashboard reads them, contract requires them, enrichment sets them, but _feed_entry drops them.
2. **C-030 (HIGH):** Dashboard Methodology tab displays WRONG priority thresholds (says P0>=190, actual P0>=150; all four values wrong).
3. **C-014 (HIGH):** kev_vulnerability_name is not even in _KEV_FIELDS — never set on the issue dict at all, so it's doubly dead.
4. **C-004 (HIGH):** README source coverage table claims 10+ sources that don't exist in sources.json (H-ISAC, AHA, HSCC, BleepingComputer, SecurityWeek, Medtronic, Abbott, BD, GitHub Security).
5. **C-005 (HIGH):** README uses three different source counts (57, 57, 65) — actual enabled count is 68.
6. **C-018 (MEDIUM):** docs/feed_latest.json contains only 1 issue (from test run). Live dashboard shows 1 issue instead of thousands.
7. **C-031 (MEDIUM):** ~860 lines of dead embedded dashboard HTML in community_build.py (_DASHBOARD_HTML constant).
8. **C-002 (MEDIUM):** feed_contract.json missing 21 fields that _feed_entry actually emits.
9. **C-010 (MEDIUM):** 11 modules (2,279 lines) have no dedicated test file, including 5 enrichment modules.
10. **C-012 (MEDIUM):** schema.md has 7 field name mismatches with _feed_entry.

---

## 4. UNVERIFIABLE items from Phase B

| Item | Reason |
|------|--------|
| README: "3,929 issues tracked" | Requires pipeline run |
| README: "856 medical device issues" | Requires pipeline run |
| README: "2,362 issues with NVD enrichment" | Requires pipeline run |
| README: "203 issues with KEV required actions" | Requires pipeline run |
| README: "139 AI recommendation packets" | Requires pipeline run |
| README: "$1.40 full corpus rebuild cost" | Requires pipeline run + API billing |
| grant_cost_model.md: all cost claims | Requires pipeline run + API billing |
| session_state.md Section 5: all corpus metrics | Requires pipeline run |
| eval_harness.py CI status | No CI config exists; cannot verify if it runs automatically |
| playbook_governance.md: AI draft pattern mechanism | No draft patterns exist to verify the mechanism |

---

## 5. Open questions for Travis

- **Q1:** The docs/feed_latest.json contains only 1 issue (from a test run). Has the full pipeline output ever been committed to docs/ for the live dashboard, or has the live demo always shown test data?
- **Q2:** The README source coverage table lists sources that don't exist (H-ISAC, AHA, HSCC, Medtronic PSIRT, etc.). Were these planned additions that never happened, or were they listed aspirationally?
- **Q3:** kev_vulnerability_name is referenced by dashboard JS and feed_contract.json but is never set anywhere in the pipeline code. Was this an intended field that was never implemented, or was it removed?
- **Q4:** extract.py and ai_correlate.py are orphaned from community-build. Is this intentional (they serve different use cases) or should they be wired in?
- **Q5:** Should STATUS.md be updated to reflect current state, or is it deliberately frozen as a historical snapshot?
- **Q6:** docs.zip at repo root — is this needed? Should it be gitignored?
- **Q7:** The advisoryops_context_report.md at repo root — should this be committed or gitignored?
- **Q8:** The GitHub Pages source — has it been flipped from advisoryops-dashboard to advisoryops yet? session_state.md says "pending for Travis."
- **Q9:** The README badge links to advisoryops-dashboard for the dashboard URL. When will this be updated to the main repo?
- **Q10:** Should the 4 "extra" docs files (Feature 1 Spec, architecture.md, data_rights.md, kev_medical_device_analysis.md) be added to DOC-01 Master Index?

---

## 6. Recommended next session scope

Travis should triage the findings before any fix work. The natural next step is:

1. Triage C-001/C-014 (missing KEV fields in _feed_entry) — likely a 5-minute fix but Travis decides.
2. Triage C-004/C-005 (README source table and counts) — decide what sources to claim.
3. Triage C-018 (docs/ contains test data, not production data) — decide whether to commit real pipeline output.
4. Update feed_contract.json to match reality (C-002).
5. Update schema.md field names (C-012).
6. Update README test count and source count badges (C-005, C-006).

No code fixes should happen until Travis reviews and prioritizes.

---

## 7. Exact repo state at end

- **Branch:** `feature/v1-readiness`
- **Commit hash:** `cad72f1`
- **git status:** See commit section.

---

## 8. Environmental observations

- Python venv at `.venv/` works correctly.
- pytest --collect-only takes ~234 seconds (nearly 4 minutes). The test suite is large.
- pytest full run takes ~189 seconds (1,055 tests).
- No CI/CD configuration exists (.github/workflows/ absent).
- `docs.zip` exists at repo root — may be intentional for session transfers.
- `advisoryops_context_report.md` exists at repo root — generated 2026-04-10.
- The `outputs/` directory is gitignored except for docs/ artifacts.
- NVD cache is ~340K records (large, persistent, not in git).
