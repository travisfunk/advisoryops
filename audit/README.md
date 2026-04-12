# Audit Directory — AdvisoryOps

**Audit date:** 2026-04-11
**Branch:** `feature/v1-readiness`
**Scope:** Phases A (Inventory), B (Doc Reality), C (Code Findings)

## Executive Summary

Phase A inventoried 56 Python modules (18,206 lines), 57 test files (1,055 tests), 96 configured sources (68 enabled), 15 CLI subcommands, and 11 playbook patterns. Phase B checked factual claims across 18 documentation files and found 22+ STALE claims, 10 UNVERIFIABLE claims. The most impactful stale claims are in README.md (wrong source counts, nonexistent sources listed in the coverage table, outdated test count). Phase C produced 35 findings: 5 HIGH severity, 10 MEDIUM, 11 LOW, 9 INFO. The highest-severity findings are missing KEV fields in _feed_entry (C-001/C-014), dashboard Methodology tab showing wrong priority thresholds (C-030), the README listing sources that don't exist (C-004), and the docs/ directory containing test data instead of production feed data (C-018).

## Reading Order

1. **`phase_a_inventory.md`** — Complete codebase inventory: directory tree, module list with line counts, config files, test files, CLI surface, playbook patterns, source counts, test counts.

2. **`phase_b_doc_reality.md`** — Every factual claim in README.md, session_state.md, STATUS.md, schema.md, scoring_internals.md, playbook_governance.md, feed_contract.json, grant_cost_model.md, and DOC-01 through DOC-11, marked CONFIRMED/STALE/UNVERIFIABLE with evidence.

3. **`phase_c_code_findings.md`** — 29 numbered findings (C-001 through C-029) with severity, location, description, and category. Pattern search results for TODO/FIXME/except/print/breakpoint.

4. **`continuity.md`** — Full continuity block for the next session: what was done, what was skipped, top 10 findings, open questions for Travis, recommended next steps, exact repo state.

## Files

| File | Contents |
|------|----------|
| `README.md` | This index |
| `phase_a_inventory.md` | Phase A output |
| `phase_b_doc_reality.md` | Phase B output |
| `phase_c_code_findings.md` | Phase C output |
| `continuity.md` | Continuity block |
| `raw/tree_depth3.txt` | Raw directory tree dump |
