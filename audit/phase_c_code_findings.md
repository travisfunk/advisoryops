# Phase C — Code Findings

**Generated:** 2026-04-11
**Method:** Code read-through + pattern search. All findings cite file:line.

---

### C-001: _feed_entry missing kev_vendor, kev_product, kev_vulnerability_name
- **Severity:** HIGH
- **Location:** `src/advisoryops/community_build.py:75-141`
- **Description:** The `_feed_entry` function does not emit `kev_vendor`, `kev_product`, or `kev_vulnerability_name` fields. However, these fields are: (a) listed in `docs/feed_contract.json`, (b) read by `dashboard/index.html` (lines 667-672: `issue.kev_vulnerability_name`, `issue.kev_vendor`, `issue.kev_product`), and (c) set on the issue dict during KEV enrichment at `community_build.py:1419-1432` (`_KEV_FIELDS` tuple includes them). The enrichment writes these to the issue dict, but _feed_entry drops them when building the feed row because they are not explicitly mapped.
- **Why it matters:** Dashboard displays blank/undefined for KEV vendor/product names on 203 KEV-enriched issues.
- **Category:** bug

### C-002: feed_contract.json is incomplete — 21 _feed_entry fields missing from contract
- **Severity:** MEDIUM
- **Location:** `docs/feed_contract.json` vs `src/advisoryops/community_build.py:75-141`
- **Description:** _feed_entry emits 53 fields. feed_contract.json lists only 35. Missing from contract: issue_type, severity, why, source_authority_weight, highest_authority_source, classification, generated_by, extracted_facts, inferred_facts, confidence_by_field, evidence_sources, insufficient_evidence, non_applicability, source_mitigations, iocs, cvss_vector, evidence_gaps, unknowns, source_consensus, source_summary, citations.
- **Why it matters:** The contract was designed to prevent pipeline/dashboard drift, but it only covers a subset of emitted fields.
- **Category:** contradiction

### C-003: extract.py and ai_correlate.py are not wired into community-build
- **Severity:** MEDIUM
- **Location:** `src/advisoryops/community_build.py` (no import of extract or ai_correlate)
- **Description:** `extract.py` (445 lines, structured AdvisoryRecord extraction) and `ai_correlate.py` (576 lines, AI merge candidate detection) are fully implemented but not imported or called by `community_build.py`. They are only accessible via standalone CLI subcommands (`advisoryops extract` and `advisoryops correlate --ai-merge`). This resolves the Section 12 uncertainty in session_state.md.
- **Why it matters:** 1,021 lines of functional AI code are orphaned from the main pipeline.
- **Category:** dead code

### C-004: README source coverage table lists 10+ sources that don't exist
- **Severity:** HIGH
- **Location:** `README.md:199-210`
- **Description:** The source coverage table claims sources that do not exist in configs/sources.json: GitHub Security Advisories, H-ISAC, HHS 405(d), AHA, HSCC, BleepingComputer, SecurityWeek, Medtronic (PSIRT), Abbott (PSIRT), BD (PSIRT). AlienVault OTX exists but is disabled. These are aspirational or were never added.
- **Why it matters:** The README is the public face. Claiming sources that don't exist damages credibility, especially for a grant application.
- **Category:** doc drift

### C-005: README source count inconsistency — three different numbers
- **Severity:** HIGH
- **Location:** `README.md:9,107,122,199`
- **Description:** The README uses three different source counts: "65" (prose, line 9 and line 199), "57" (Mermaid diagram line 107 and ASCII diagram line 122). The actual enabled count is 68. None of the three numbers match reality.
- **Why it matters:** Inconsistent numbers look sloppy. Grant reviewers will notice.
- **Category:** doc drift

### C-006: README test count stale — says 1,038, actual 1,055
- **Severity:** LOW
- **Location:** `README.md:4,52,224`
- **Description:** Badge, table, and test command all say 1,038. pytest --collect-only reports 1,055.
- **Why it matters:** Minor but trivially fixable.
- **Category:** doc drift

### C-007: community_build.py line count stale in session_state.md
- **Severity:** LOW
- **Location:** `docs/session_state.md:38`
- **Description:** Claims "~2064 lines". Actual: 2,289 lines. Grew 225 lines since the claim was written.
- **Why it matters:** Session_state.md is the "read first" doc for Claude. Stale counts cause confusion.
- **Category:** doc drift

### C-008: 71 `except Exception` blocks across src/
- **Severity:** INFO
- **Location:** 71 occurrences across 23 files (see raw list below)
- **Description:** Broad exception catching is pervasive. Most catch `except Exception as exc:` and log/continue. Some catch bare `except Exception:` (no variable) and silently swallow. Notable silent swallowers: ai_cache.py:98, correlate.py:100, extract.py:96, extract.py:210, extract.py:429, ingest.py:133, ingest.py:226, ingest.py:244, mojibake.py:64, page_enrich.py:76, page_enrich.py:79, page_enrich.py:113, community_build.py:1858, community_build.py:1885, source_run.py:156, sources/discover_sync.py:70, enrichment/cross_reference.py:72.
- **Why it matters:** Silent exception swallowing can mask bugs. In a pipeline with many data sources, this is defensible (one bad source shouldn't crash the run), but the ones with no logging are concerning.
- **Category:** other

### C-009: 199 print() calls in src/ (non-test code)
- **Severity:** INFO
- **Location:** 12 files: community_build.py (68), cli.py (50), source_run.py (31), correlate.py (15), score.py (8), discover.py (12), tag.py (5), eval_harness.py (4), ai_correlate.py (3), community_manifest.py (1), playbook.py (1), sources_config.py (1)
- **Description:** print() is used extensively for pipeline output instead of a logging framework. This is a deliberate design choice (CLI tool), not a bug.
- **Why it matters:** Informational only. Makes it harder to silence output or redirect to structured logs.
- **Category:** other

### C-010: 11 modules have no dedicated test file
- **Severity:** MEDIUM
- **Location:** Modules without test files:
  - `cli.py` (624 lines) — no test_cli.py
  - `feedback.py` (115 lines) — no test_feedback.py
  - `ingest.py` (262 lines) — no test_ingest.py
  - `models.py` (106 lines) — no test_models.py
  - `source_run.py` (334 lines) — no test_source_run.py
  - `util.py` (78 lines) — no test_util.py
  - `enrichment/attack_ics.py` (143 lines) — no test_attack_ics.py
  - `enrichment/cross_reference.py` (80 lines) — no test_cross_reference.py
  - `enrichment/cwe_catalog.py` (191 lines) — no test_cwe_catalog.py
  - `enrichment/epss_enrich.py` (159 lines) — no test_epss_enrich.py
  - `enrichment/vulnrichment.py` (187 lines) — no test_vulnrichment.py
- **Description:** 11 modules totaling 2,279 lines have no corresponding test file. Some may be tested indirectly through integration tests in test_community_build.py or test_enrichment.py.
- **Why it matters:** Test gaps weaken confidence in these modules. Enrichment modules are particularly important since they modify issue data.
- **Category:** test gap

### C-011: STATUS.md is entirely stale
- **Severity:** LOW
- **Location:** `docs/STATUS.md` (dated 2026-03-17)
- **Description:** Every "next milestone" listed has been completed. The file describes the project as it was nearly a month ago. Correlation, enrichment, scoring, AI subsystem, dashboard — all listed as "next" — are now shipped.
- **Why it matters:** A stale STATUS.md misleads anyone reading the docs.
- **Category:** doc drift

### C-012: schema.md field name mismatches with _feed_entry
- **Severity:** MEDIUM
- **Location:** `docs/schema.md` vs `src/advisoryops/community_build.py:75-141`
- **Description:** schema.md lists fields that don't match _feed_entry:
  - `link` → should be `canonical_link`
  - `scope` → not in _feed_entry
  - `ai_summary` → not in _feed_entry (AI rewrites `summary` directly)
  - `source_count` → not in _feed_entry
  - `evidence_completeness` → not in _feed_entry
  - `recommendation_disclaimer` → not in _feed_entry
  - `published_date` (singular) → should be `published_dates` (plural)
- **Why it matters:** schema.md is listed in the README as the field reference. It's wrong on 7 fields.
- **Category:** doc drift

### C-013: `pass  # openpyxl not installed; skip silently` in community_build.py
- **Severity:** LOW
- **Location:** `src/advisoryops/community_build.py:2188`
- **Description:** Excel export failure is silently swallowed with `pass`. If openpyxl is not installed, no Excel file is generated and no warning is emitted.
- **Why it matters:** A user might expect issues_public.xlsx to exist and not realize it was skipped.
- **Category:** other

### C-014: Dashboard reads fields that _feed_entry doesn't emit (kev_vulnerability_name)
- **Severity:** HIGH
- **Location:** `dashboard/index.html:667-668`
- **Description:** Dashboard JS reads `issue.kev_vulnerability_name` and uses it as a display name fallback. This field is NOT emitted by _feed_entry. It IS in the feed_contract. The KEV enrichment at community_build.py:1419 lists `_KEV_FIELDS = ("kev_required_action", "kev_due_date", "kev_vendor", "kev_product")` — note `kev_vulnerability_name` is not even in `_KEV_FIELDS`. So it's never set on the issue dict at all.
- **Why it matters:** This field reference in the dashboard is entirely dead. It will always be undefined.
- **Category:** bug

### C-015: pyproject.toml says Python >=3.10, README badge says 3.11+
- **Severity:** LOW
- **Location:** `pyproject.toml:9`, `README.md:3`
- **Description:** `requires-python = ">=3.10"` but badge shows `python-3.11+-blue`.
- **Why it matters:** Minor inconsistency.
- **Category:** contradiction

### C-016: No CI/CD configuration
- **Severity:** INFO
- **Location:** `.github/workflows/` does not exist
- **Description:** No GitHub Actions, no CI pipeline. Tests are run locally only. The `@pytest.mark.integration` marker exists but CI to run or skip it does not.
- **Why it matters:** For a grant application, demonstrating CI would strengthen the credibility of "1,055 tests passing."
- **Category:** other

### C-017: docs/meta.json contains test paths, not production paths
- **Severity:** LOW
- **Location:** `docs/meta.json`
- **Description:** meta.json in the published docs directory contains pytest temp paths (`C:\Users\travi\AppData\Local\Temp\pytest-of-travi\pytest-292\...`) rather than actual production output paths. This was likely copied from a test run.
- **Why it matters:** Anyone inspecting meta.json sees test artifacts, not real build metadata.
- **Category:** bug

### C-018: feed_latest.json and feed_healthcare.json each contain only 1 issue
- **Severity:** MEDIUM
- **Location:** `docs/feed_latest.json` (2,220 bytes), `docs/feed_healthcare.json` (2,220 bytes)
- **Description:** The published feed files in docs/ each contain only a single issue. The most recent pipeline run produced 3,929 issues. The docs/ data artifacts appear to be from a test run, not a production build.
- **Why it matters:** The live dashboard served from GitHub Pages shows 1 issue instead of thousands. This is the public demo.
- **Category:** bug

### C-019: feed_medical_device_kev.json is nearly empty
- **Severity:** LOW
- **Location:** `docs/feed_medical_device_kev.json` (4 bytes)
- **Description:** File contains only `[]`. This is consistent with Problem 4 (zero KEV/medical device overlap), but worth noting.
- **Why it matters:** Expected given Problem 4. Dashboard will show empty for this filter.
- **Category:** other

### C-020: DOC-04 references ServiceNow integration that doesn't exist
- **Severity:** LOW
- **Location:** `docs/DOC-04_Integrations.md`
- **Description:** References ServiceNow connector, SIEM integrations, and PDF export. None of these exist in the codebase. These are post-grant aspirational features.
- **Why it matters:** Aspirational docs mixed with current-state docs could confuse contributors.
- **Category:** doc drift

### C-021: DOC-06 describes matching engine that doesn't exist
- **Severity:** LOW
- **Location:** `docs/DOC-06_Matching.md`
- **Description:** Describes a facility inventory matching and confidence engine. This is post-grant commercial work. No matching code exists beyond product_resolver.py (which does keyword matching, not inventory matching).
- **Why it matters:** Same as C-020.
- **Category:** doc drift

### C-022: docs.zip exists in repo root
- **Severity:** INFO
- **Location:** `docs.zip` (repo root)
- **Description:** A `docs.zip` file exists at the repo root. Purpose unclear. May be a snapshot for a specific session.
- **Why it matters:** Adds clutter. May contain stale content.
- **Category:** other

### C-023: advisoryops_context_report.md exists at repo root
- **Severity:** INFO
- **Location:** `advisoryops_context_report.md` (repo root)
- **Description:** A context report generated on 2026-04-10 exists at repo root. Contains project overview but may become stale.
- **Why it matters:** Informational only.
- **Category:** other

### C-024: No breakpoint() or import pdb found
- **Severity:** INFO
- **Location:** All src/ files
- **Description:** No debug artifacts found. Clean.
- **Why it matters:** Good hygiene.
- **Category:** other

### C-025: No bare `except:` blocks found
- **Severity:** INFO
- **Location:** All src/ files
- **Description:** All exception handlers use `except Exception` or more specific types. No bare `except:` blocks.
- **Why it matters:** Good practice.
- **Category:** other

### C-026: Only 1 TODO/FIXME/XXX comment in all src/ Python files
- **Severity:** INFO
- **Location:** `src/advisoryops/source_mitigations.py:296` — benign documentation string containing "CVE-XXXX" as an example pattern, not an actual XXX marker.
- **Description:** No actionable TODO/FIXME/HACK markers exist anywhere in the Python source.
- **Why it matters:** Unusually clean. Either todos are tracked elsewhere or have been resolved.
- **Category:** other

### C-027: community_build.py has multiple silent exception blocks in AI subsystem
- **Severity:** MEDIUM
- **Location:** `src/advisoryops/community_build.py:1858,1868,1885,2051`
- **Description:** The AI subsystem (summarize, extract-mitigations, recommend) uses try/except blocks that catch Exception and either print a warning or silently continue. At line 1858 and 1885, bare `except Exception:` with no logging. These are in the per-issue processing loops.
- **Why it matters:** If an AI call fails for a specific issue, the failure is invisible. The issue just lacks AI enrichment with no record of why.
- **Category:** bug

### C-028: No pytest.mark.xfail markers in test suite
- **Severity:** INFO
- **Location:** All test files
- **Description:** No tests are marked as expected failures. All 1,055 collected tests are expected to pass.
- **Why it matters:** Clean test health. No known-broken tests being carried.
- **Category:** other

### C-029: dashboard/index.html GitHub link inconsistency
- **Severity:** LOW
- **Location:** `dashboard/index.html:183`
- **Description:** RSS channel link is `https://github.com/advisoryops/advisoryops`. The actual GitHub org is `travisfunk`, not `advisoryops`.
- **Why it matters:** Broken link in the RSS output.
- **Category:** bug

### C-030: Dashboard Methodology tab displays WRONG priority thresholds
- **Severity:** HIGH
- **Location:** `dashboard/index.html:402-407`
- **Description:** The dashboard's Methodology section displays: P0 >= 190, P1 >= 150, P2 >= 100, P3 < 100. The actual thresholds in `score.py:103-108` are: P0 >= 150, P1 >= 100, P2 >= 60, P3 < 60. Every single threshold value is wrong.
- **Why it matters:** Users reading the Methodology section will have incorrect expectations. A P0 issue with score 155 would look miscalibrated if you trust the dashboard's stated thresholds.
- **Category:** contradiction

### C-031: ~860 lines of dead embedded dashboard HTML in community_build.py
- **Severity:** MEDIUM
- **Location:** `src/advisoryops/community_build.py:416-1279`
- **Description:** `_DASHBOARD_HTML` is a 860-line inline HTML/CSS/JS string containing a complete older dashboard (light theme, different design). It's written to `dashboard.html` in the output directory by `_generate_dashboard()`, but `_publish_to_docs()` copies the standalone `dashboard/index.html` to `docs/index.html` instead. The embedded dashboard is never published to GitHub Pages.
- **Why it matters:** 860 lines of dead code inflating community_build.py. The two dashboards have divergent designs (light vs dark theme), different default data sources, and different feature sets.
- **Category:** dead code

### C-032: score.py v1 _score_source_authority function is dead code
- **Severity:** LOW
- **Location:** `src/advisoryops/score.py:185-189, 333-341`
- **Description:** `_SOURCE_AUTHORITY_EXACT`, `_SOURCE_AUTHORITY_CISA_GENERIC`, and `_score_source_authority` are defined but never called. The v2 scorer (default) uses the tier-weight system from `source_weights.py` instead. The v1 scorer also does not call them.
- **Why it matters:** Dead code that could mislead future maintainers about how source authority works.
- **Category:** dead code

### C-033: cli.py cmd_correlate uses runtime inspect.signature() to probe parameter names
- **Severity:** MEDIUM
- **Location:** `src/advisoryops/cli.py:138-148`
- **Description:** `cmd_correlate` uses `inspect.signature(correlate)` to determine at runtime whether the output parameter is named `out_root_correlate`, `out_root_issues`, or `out_root`. This is fragile. The actual parameter name is `out_root_issues` (correlate.py:459).
- **Why it matters:** If someone renames the parameter and forgets the CLI, this silently falls through to TypeError instead of a clear error.
- **Category:** bug

### C-034: cli.py duplicate import of correlate
- **Severity:** LOW
- **Location:** `src/advisoryops/cli.py:34, 125`
- **Description:** `correlate` is imported at module level (line 34) and again inside `cmd_correlate` (line 125). The inner import shadows the outer.
- **Why it matters:** Confusing duplication.
- **Category:** duplication

### C-035: healthcare_filter.py `\bct\b` regex may false-positive on non-medical "ct"
- **Severity:** LOW
- **Location:** `src/advisoryops/healthcare_filter.py:76`
- **Description:** `_DEVICE_TYPES` includes `r"\bct\b"` (computed tomography) which could match "ct" as abbreviation for count, Connecticut, etc.
- **Why it matters:** Potential false positives on non-medical issues.
- **Category:** bug

---

## Pattern Search Results Summary

| Pattern | Hits | Files |
|---------|-----:|------:|
| `TODO` / `FIXME` / `HACK` | 0 | 0 |
| `XXX` | 1 (false positive in docs string) | 1 |
| `pass  #` | 1 | 1 |
| bare `except:` | 0 | 0 |
| `except Exception` | 71 | 23 |
| `print(` (src/ only) | 199 | 12 |
| `breakpoint(` | 0 | 0 |
| `import pdb` | 0 | 0 |
