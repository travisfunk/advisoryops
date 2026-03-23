# AdvisoryOps — Claude Code Build Plan

**Purpose:** This is a task-by-task punch list for Claude Code sessions. Each task has explicit success criteria and verification steps so completion is provable, not claimed.

**Important for Claude Code:** Do NOT mark a task done until the verification steps pass. Run the tests. Show the output. If a test fails, fix it before moving on.

---

## Concurrency Map

```
WEEK 1-2          WEEK 2-3          WEEK 3-4          WEEK 4+
─────────────────────────────────────────────────────────────

TRACK A ──────────────────────────────────────────────────────
Phase 1: Source Expansion
(independent, start immediately)

TRACK B ──────────────────────────────────────────────────────
Phase 5: Eval Harness Setup    Phase 5 continued:
(golden set + test fixtures)   measure phases 2-4

TRACK C ──────────────────────────────────────────────────────
                  Phase 2: AI Dedup ──────────────────────────
                  Phase 3: Healthcare Scoring ────────────────
                  (2 and 3 can run concurrently,
                   both read from correlate output)

TRACK D ──────────────────────────────────────────────────────
                               Phase 4: Fix Recommendations──
                               (needs 2+3 output, but
                                playbook code framework
                                can start in parallel)

Phase 6: Public Packaging ──── runs last, after 1-5 are solid
```

**What can run concurrently:**
- Phase 1 (source expansion) is fully independent — run anytime
- Phase 5 (eval harness) can start Day 1 — build golden set and test fixtures while other phases develop
- Phase 2 (AI dedup) and Phase 3 (healthcare scoring) can run in parallel — they both consume correlate output but don't depend on each other
- Phase 4 (fix recommendations) framework can start early, but real testing needs Phase 2+3 outputs

**What CANNOT run concurrently:**
- Phase 4 full integration needs Phase 2+3 to be at least alpha-functional
- Phase 6 packaging needs all others to be stable

---

## Phase 1: Source Expansion (TRACK A — independent)

### Goal
Expand from 35 configured sources to 60+ enabled sources using existing parser types (rss_atom, json_feed, csv_feed). This is the "most comprehensive list" claim.

### Context for Claude Code
- Source config lives in `configs/sources.json` (schema_version 1)
- Full source list with URLs is in `vuln_sources.txt` (~60 public/free sources identified)
- Existing parsers handle: `rss_atom`, `json_feed`, `csv_feed`
- Sources that require HTML scraping, PDF parsing, or API keys are OUT OF SCOPE for Phase 1
- Each source needs: source_id, name, enabled, scope, page_type, entry_url, filters

### Task 1.1 — Audit vuln_sources.txt against sources.json
**What to do:** Compare the ~60 public sources in vuln_sources.txt against the 35 already in sources.json. Produce a list of sources NOT yet configured that use RSS/Atom, JSON, or CSV feeds.

**Success criteria:**
- A file `configs/sources_expansion_candidates.json` listing each candidate with: url, expected page_type, whether it's RSS/JSON/CSV, healthcare relevance (high/medium/low)
- Console output showing: "X sources already configured, Y new candidates identified, Z require unsupported page types"

**Verification:**
```bash
python -c "import json; d=json.load(open('configs/sources_expansion_candidates.json')); print(f'Candidates: {len(d)}')"
```

### Task 1.2 — Add new RSS/Atom sources to sources.json
**What to do:** For each RSS/Atom candidate from Task 1.1, add a properly configured entry to sources.json. Prioritize healthcare-specific and medical device sources first. Set appropriate filters (keywords_any/keywords_all) for broad sources like Dark Reading or Krebs.

**Success criteria:**
- sources.json has 50+ total sources
- All new entries have: source_id (lowercase-kebab), name, enabled=true, scope (advisory/dataset/news/threatintel), page_type, entry_url, filters
- No duplicate source_ids
- Config loads without errors

**Verification:**
```bash
python -c "
from advisoryops.sources_config import load_sources_config
cfg = load_sources_config()
enabled = [s for s in cfg.sources if s.enabled]
print(f'Total: {len(cfg.sources)}, Enabled: {len(enabled)}')
assert len(enabled) >= 50, f'Only {len(enabled)} enabled, need 50+'
print('PASS')
"
```

### Task 1.3 — Smoke-test all new sources
**What to do:** Run `source-run` against every newly added source with `--limit 5`. Record which succeed, which fail, and why.

**Success criteria:**
- A smoke test script that runs all enabled sources and produces a results summary
- Each source either: (a) produces valid discovery artifacts, or (b) is documented as failing with a specific reason and disabled
- At least 50 sources produce valid output

**Verification:**
```bash
python scripts/smoke_test_all_sources.py
# Should output a table: source_id | status | items_found | error_if_any
# Final line: "X/Y sources passed smoke test"
```

### Task 1.4 — Update community manifest
**What to do:** Update `configs/community_public_sources.json` to expand the validated gold set beyond the current 10. Add a `gold_pass2` set that includes all sources that passed smoke testing.

**Success criteria:**
- community_public_sources.json has a gold_pass2 set with 40+ source_ids
- All referenced source_ids exist in sources.json and are enabled
- `community-build --set-id gold_pass2` runs without errors

**Verification:**
```bash
python -m advisoryops.cli community-build --set-id gold_pass2 --out-root-community outputs/community_public_v2
# Check meta.json for counts
python -c "
import json
meta = json.load(open('outputs/community_public_v2/meta.json'))
print(f'Sources: {meta[\"counts\"][\"validated_sources\"]}')
print(f'Issues: {meta[\"counts\"][\"issues_public\"]}')
print(f'Alerts: {meta[\"counts\"][\"alerts_public\"]}')
assert meta['counts']['validated_sources'] >= 40, 'Need 40+ validated sources'
print('PASS')
"
```

---

## Phase 2: AI-Assisted Normalization & Deduplication (TRACK C)

### Goal
Replace the current deterministic correlate.py (CVE-match or title-hash only) with an AI-assisted layer that can identify when multiple advisories from different sources describe the same underlying issue — even when they have different titles, different CVE references, or no CVE at all.

### Context for Claude Code
- Current correlate.py groups by: exact CVE ID match, or SHA-256 of normalized title + published_date
- This misses: same vulnerability reported by CISA, a vendor PSIRT, and a researcher blog with different titles and partial CVE overlap
- The AI layer should be called AFTER deterministic grouping (as a second pass to merge clusters that the rules missed)
- Use OpenAI API (the project already uses it in extract.py — follow the same pattern with the openai SDK)
- IMPORTANT: Keep the deterministic correlate.py as the first pass. AI is the second pass merge step.
- Costs matter — batch comparisons, don't call the API for every pair of issues

### Task 2.1 — Build the AI merge candidate detector
**What to do:** Create `advisoryops/ai_correlate.py`. After deterministic correlation produces issues, this module identifies candidate pairs that MIGHT be the same issue based on heuristics (overlapping vendors, similar product names, overlapping time windows, similar summaries). These candidates get sent to the AI for a merge/no-merge decision.

**Success criteria:**
- New module `advisoryops/ai_correlate.py` exists
- Function `find_merge_candidates(issues: List[dict]) -> List[Tuple[str, str, float]]` that returns pairs of issue_ids with a similarity score
- Uses text similarity (not AI yet) to pre-filter: vendor/product token overlap, summary cosine similarity or Jaccard, time proximity
- Reduces the N² comparison space to a manageable candidate set (aim for <5% of total pairs)
- Unit tests in `tests/test_ai_correlate.py` with at least 3 test cases using fixture data

**Verification:**
```bash
python -m pytest tests/test_ai_correlate.py -v
# All tests pass

# Integration check with real data:
python -c "
from advisoryops.ai_correlate import find_merge_candidates
import json
issues = [json.loads(l) for l in open('outputs/correlate/issues.jsonl') if l.strip()]
candidates = find_merge_candidates(issues)
print(f'Total issues: {len(issues)}')
print(f'Merge candidates: {len(candidates)}')
for a, b, score in candidates[:5]:
    print(f'  {a} <-> {b} (score={score:.2f})')
"
```

### Task 2.2 — Build the AI merge decision engine
**What to do:** Create the OpenAI-powered merge decision function. Given two issue records, ask the model: "Are these the same underlying vulnerability/issue? Respond with: same_issue (bool), confidence (0-1), reasoning (string)."

**Success criteria:**
- Function `ai_merge_decision(issue_a: dict, issue_b: dict) -> MergeDecision` in ai_correlate.py
- MergeDecision dataclass with: same_issue (bool), confidence (float), reasoning (str), model (str), tokens_used (int)
- Uses structured JSON output from OpenAI (like extract.py does)
- System prompt explicitly tells the model to consider: same vendor? same product family? same vulnerability? overlapping CVEs? similar remediation?
- Includes cost tracking (token counts)
- Handles API errors gracefully (retry with backoff, return uncertain result on failure)
- Works without API key in test mode (mock responses for testing)

**Verification:**
```bash
# Unit tests with mocked API:
python -m pytest tests/test_ai_correlate.py -v -k "merge_decision"

# Live test with real API (requires OPENAI_API_KEY):
python -c "
import os
assert os.getenv('OPENAI_API_KEY'), 'Set OPENAI_API_KEY'
from advisoryops.ai_correlate import ai_merge_decision
issue_a = {'issue_id': 'CVE-2024-1234', 'title': 'Philips ISCV Vulnerability', 'summary': 'Remote code execution in Philips IntelliSpace Cardiovascular'}
issue_b = {'issue_id': 'UNK-abc123', 'title': 'CISA Advisory for Philips IntelliSpace', 'summary': 'Critical vulnerability in Philips ISCV allows remote access'}
result = ai_merge_decision(issue_a, issue_b)
print(f'Same issue: {result.same_issue}')
print(f'Confidence: {result.confidence}')
print(f'Reasoning: {result.reasoning}')
print(f'Tokens: {result.tokens_used}')
"
```

### Task 2.3 — Integrate AI merge into the correlation pipeline
**What to do:** Add a `--ai-merge` flag to the correlate CLI command. When enabled, after deterministic correlation, run the candidate detection + AI merge pipeline. Merged issues should combine their signals, links, sources, and CVEs.

**Success criteria:**
- `advisoryops correlate --ai-merge` runs the full pipeline
- Merged issues have a `merged_from` field listing the original issue_ids
- A merge log is written to `outputs/correlate/merge_log.jsonl` with each decision (for auditability)
- Without `--ai-merge`, behavior is identical to current (no regression)
- Total API cost for a typical run (100-200 issues) stays under $0.50

**Verification:**
```bash
# Regression test (no AI flag):
python -m advisoryops.cli correlate --out-root-discover outputs/discover --out-root-correlate outputs/correlate_baseline
# Should produce identical output to current

# AI merge test:
python -m advisoryops.cli correlate --out-root-discover outputs/discover --out-root-correlate outputs/correlate_ai --ai-merge

# Compare:
python -c "
import json
baseline = [json.loads(l) for l in open('outputs/correlate_baseline/issues.jsonl') if l.strip()]
ai = [json.loads(l) for l in open('outputs/correlate_ai/issues.jsonl') if l.strip()]
print(f'Baseline issues: {len(baseline)}')
print(f'AI-merged issues: {len(ai)}')
assert len(ai) <= len(baseline), 'AI merge should reduce or equal issue count'
merged = [i for i in ai if i.get('merged_from')]
print(f'Merged issues: {len(merged)}')
print('PASS')
"
```

---

## Phase 3: Healthcare-Aware Threat Scoring (TRACK C — parallel with Phase 2)

### Goal
Replace the keyword-based point system in score.py with healthcare-context-aware scoring that understands device criticality, patient safety impact, patch feasibility, and operational constraints.

### Context for Claude Code
- Current score.py uses regex keyword matching with fixed point values (e.g., "actively exploited" = +40 points)
- The regex patterns in score.py have double-escaped backslashes (\\\\b instead of \\b) which means NONE of the keyword patterns actually match anything. This is a bug — the only scoring that works today is the KEV source check and the base issue_type check.
- Healthcare scoring needs to consider: Is this a medical device? Is it patient-care critical? Is it network-accessible? Is it vendor-managed (can't self-patch)? What's the clinical environment (ICU vs back office)?
- Phase 3 scoring should work on the issue records that come out of correlation (Phase 2), but can be developed against current correlate output

### Task 3.1 — Fix the existing scoring bugs
**What to do:** Fix the double-escaped regex patterns in score.py. The `_KEYWORDS` list has patterns like `\\\\bactively exploited\\\\b` which should be `\\bactively exploited\\b`. This is why scoring currently only works for KEV source detection.

**Success criteria:**
- All regex patterns in _KEYWORDS compile and match correctly
- Existing tests in test_score_phase1.py and test_score_alerts.py pass
- New tests prove keyword matching works (e.g., an issue with "remote code execution" in summary gets the RCE bonus)

**Verification:**
```bash
python -m pytest tests/test_score_phase1.py tests/test_score_alerts.py -v

# Verify keywords actually match:
python -c "
from advisoryops.score import score_issue
issue = {
    'issue_id': 'CVE-2024-TEST',
    'issue_type': 'cve',
    'title': 'Remote Code Execution in Medical Device',
    'summary': 'An actively exploited vulnerability allows remote code execution',
    'sources': ['cisa-icsma'],
    'links': ['https://nvd.nist.gov/vuln/detail/CVE-2024-TEST']
}
result = score_issue(issue)
print(f'Score: {result.score}')
print(f'Priority: {result.priority}')
print(f'Why: {result.why}')
assert result.score > 20, f'Score too low ({result.score}), keywords not matching'
assert any('RCE' in w or 'rce' in w.lower() or 'remote code' in w.lower() or 'code execution' in w.lower() for w in result.why), f'RCE keyword not detected in: {result.why}'
print('PASS')
"
```

### Task 3.2 — Add healthcare context scoring dimensions
**What to do:** Extend score.py with healthcare-specific scoring dimensions. Add new scoring factors:
- **Source authority weight:** CISA ICS-Medical > CISA ICS > generic CISA > news (different point values)
- **Device context signals:** Title/summary mentions of device types (infusion pump, ventilator, patient monitor, imaging, PACS, etc.) get a healthcare relevance bonus
- **Patch feasibility indicators:** Mentions of "vendor-managed", "no patch available", "end of life", "firmware" get elevated priority because they indicate harder-to-fix issues
- **Clinical impact indicators:** Mentions of "patient safety", "clinical", "life-sustaining", "ICU" get elevated priority

**Success criteria:**
- New scoring function `score_issue_v2()` that includes all original factors plus healthcare dimensions
- A `--scoring-version` flag on the CLI (default v2, option for v1 legacy)
- At least 8 new test cases covering healthcare-specific scoring scenarios
- Scores are deterministic (same input = same output every time)

**Verification:**
```bash
python -m pytest tests/test_score_healthcare.py -v
# All healthcare scoring tests pass

# Compare v1 vs v2 on real data:
python -c "
from advisoryops.score import score_issue, score_issue_v2
import json
issues = [json.loads(l) for l in open('outputs/correlate/issues.jsonl') if l.strip()][:20]
for iss in issues[:5]:
    v1 = score_issue(iss)
    v2 = score_issue_v2(iss)
    print(f'{iss[\"issue_id\"][:30]:30s} v1={v1.score:3d}/{v1.priority} v2={v2.score:3d}/{v2.priority}')
print('PASS')
"
```

### Task 3.3 — Add AI-assisted healthcare relevance classification
**What to do:** For issues where the deterministic scorer can't determine healthcare/device relevance (no obvious keywords), add an optional AI classification step. The AI should classify each ambiguous issue as: medical_device, healthcare_it, healthcare_adjacent, or not_healthcare.

**Success criteria:**
- Function `classify_healthcare_relevance(issue: dict) -> HealthcareClassification` in a new module `advisoryops/ai_score.py`
- HealthcareClassification dataclass: category (str), confidence (float), reasoning (str), device_types (List[str])
- Only called for issues where deterministic classification is uncertain (saves API costs)
- Integrates into score_issue_v2 when `--ai-score` flag is passed
- Mock-able for testing

**Verification:**
```bash
python -m pytest tests/test_ai_score.py -v

# Live test:
python -c "
from advisoryops.ai_score import classify_healthcare_relevance
issue = {'issue_id': 'CVE-2024-1234', 'title': 'Buffer overflow in device firmware', 'summary': 'A vulnerability in XYZ allows remote access to the management interface'}
result = classify_healthcare_relevance(issue)
print(f'Category: {result.category}')
print(f'Confidence: {result.confidence}')
print(f'Device types: {result.device_types}')
print(f'Reasoning: {result.reasoning}')
"
```

---

## Phase 4: Fix Recommendation Engine (TRACK D)

### Goal
Build the mitigation playbook engine that takes a scored issue and produces specific, actionable defensive recommendations — ACLs, segmentation rules, vendor case steps — selected from the approved playbook patterns in DOC-03.

### Context for Claude Code
- DOC-03_Mitigation_Playbook.md defines the approved patterns (SEGMENTATION_VLAN_ISOLATION, ACCESS_CONTROL_ACL_ALLOWLIST, etc.)
- The engine must ONLY recommend from approved patterns — no freeform AI-generated remediation
- The AI's job is to SELECT the right patterns and PARAMETERIZE them for the specific issue
- Output is a structured "remediation packet" with role-split tasks
- This is the commercial differentiator but the open source version produces generic (non-facility-specific) packets

### Task 4.1 — Codify the mitigation playbook as data
**What to do:** Convert DOC-03 mitigation patterns into a machine-readable format. Create `configs/mitigation_playbook.yaml` (or .json) with all patterns from DOC-03 structured as data.

**Success criteria:**
- `configs/mitigation_playbook.json` exists with all patterns from DOC-03
- Each pattern has: id, name, category, severity_fit, when_to_use (conditions + constraints), inputs_required, steps (with role + action + details), verification, rollback, safety_notes
- A loader function `load_playbook()` that parses and validates the file
- At least the following patterns are included: SEGMENTATION_VLAN_ISOLATION, ACCESS_CONTROL_ACL_ALLOWLIST, ACCESS_CONTROL_NAC_POLICY, ACCESS_CONTROL_REMOTE_ACCESS_RESTRICT, VENDOR_PROCESS_OPEN_CASE_AND_TRACK, PATCHING_APPLY_VENDOR_OR_CUSTOMER, GOVERNANCE_RISK_ACCEPTANCE, COMMUNICATION_CLINICAL_DOWNTIME_NOTICE

**Verification:**
```bash
python -c "
from advisoryops.playbook import load_playbook
pb = load_playbook()
print(f'Patterns loaded: {len(pb.patterns)}')
for p in pb.patterns:
    print(f'  {p.id}: {p.name} ({p.category})')
assert len(pb.patterns) >= 8, 'Need at least 8 patterns'
print('PASS')
"
```

### Task 4.2 — Build the pattern selection engine
**What to do:** Create `advisoryops/recommend.py`. Given a scored issue, use AI to select which playbook patterns apply and why. The AI sees the issue details AND the available playbook patterns, and returns which patterns to recommend with parameterization hints.

**Success criteria:**
- Function `recommend_mitigations(issue: dict, playbook: Playbook) -> RemediationPacket`
- RemediationPacket dataclass with: issue_id, recommended_patterns (list), tasks_by_role (dict), reasoning (str), citations (list)
- Each recommended pattern includes: pattern_id, why_selected (str), parameters (dict of filled-in inputs), priority_order (int)
- Tasks are split by role (infosec, netops, htm_ce, vendor, clinical_ops)
- AI prompt includes the full playbook pattern catalog so it can only select from approved patterns
- Output includes citations back to source advisories

**Verification:**
```bash
python -m pytest tests/test_recommend.py -v

# Live integration test:
python -c "
from advisoryops.recommend import recommend_mitigations
from advisoryops.playbook import load_playbook
pb = load_playbook()
issue = {
    'issue_id': 'CVE-2024-1234',
    'title': 'Remote Code Execution in Philips IntelliSpace Cardiovascular',
    'summary': 'A critical vulnerability allows unauthenticated remote code execution. No patch available. Vendor recommends network segmentation.',
    'sources': ['cisa-icsma'],
    'score': 95,
    'priority': 'P0',
    'cves': ['CVE-2024-1234'],
    'links': ['https://www.cisa.gov/...']
}
packet = recommend_mitigations(issue, pb)
print(f'Issue: {packet.issue_id}')
print(f'Patterns: {[p.pattern_id for p in packet.recommended_patterns]}')
print(f'Roles involved: {list(packet.tasks_by_role.keys())}')
for role, tasks in packet.tasks_by_role.items():
    print(f'  {role}: {len(tasks)} tasks')
assert len(packet.recommended_patterns) >= 1, 'Should recommend at least one pattern'
assert 'SEGMENTATION' in str(packet.recommended_patterns) or 'ACCESS_CONTROL' in str(packet.recommended_patterns), 'Should recommend segmentation or access control for unpatched RCE'
print('PASS')
"
```

### Task 4.3 — Build remediation packet output formatter
**What to do:** Create output formatters that take a RemediationPacket and produce: (a) JSON export, (b) human-readable markdown, (c) CSV task list. These are the public/open-source outputs.

**Success criteria:**
- `advisoryops/packet_export.py` with functions: `export_json()`, `export_markdown()`, `export_csv_tasks()`
- JSON output follows a stable schema (document it)
- Markdown output is readable by a human security analyst — clear sections for each role, specific actions, verification steps
- CSV has columns: task_id, role, action, details, verification, priority, pattern_id
- CLI command: `advisoryops recommend --issue-id <id> --format json|md|csv`

**Verification:**
```bash
# Generate all three formats:
python -m advisoryops.cli recommend --issue-id CVE-2024-1234 --format json --out outputs/packets/
python -m advisoryops.cli recommend --issue-id CVE-2024-1234 --format md --out outputs/packets/
python -m advisoryops.cli recommend --issue-id CVE-2024-1234 --format csv --out outputs/packets/

# Verify files exist and have content:
python -c "
from pathlib import Path
for ext in ['json', 'md', 'csv']:
    p = Path(f'outputs/packets/CVE-2024-1234_packet.{ext}')
    assert p.exists(), f'Missing: {p}'
    content = p.read_text()
    assert len(content) > 100, f'{p} is too short ({len(content)} chars)'
    print(f'{p.name}: {len(content)} chars OK')
print('PASS')
"
```

### Task 4.4 — Integrate recommendations into community build
**What to do:** Add an optional `--recommend` flag to community-build that generates remediation packets for all P0/P1 alerts. Packets are written alongside the public feed artifacts.

**Success criteria:**
- `community-build --recommend` generates packets for top alerts
- Packets are written to `outputs/community_public/packets/`
- community meta.json includes packet counts
- Without `--recommend`, behavior is unchanged (no regression)

**Verification:**
```bash
python -m advisoryops.cli community-build --set-id gold_pass1 --recommend --out-root-community outputs/community_public_with_packets
python -c "
from pathlib import Path
packets = list(Path('outputs/community_public_with_packets/packets').glob('*.json'))
print(f'Packets generated: {len(packets)}')
assert len(packets) >= 1, 'Should generate at least one packet'
print('PASS')
"
```

---

## Phase 5: Evaluation Harness (TRACK B — can start Day 1)

### Goal
Build a reproducible test framework that measures system quality across the pipeline: extraction accuracy, dedup correctness, scoring calibration, and recommendation quality.

### Context for Claude Code
- DOC-07 has the evaluation plan design
- The harness needs golden test data (known-good advisories with expected outputs)
- This phase provides the "proof" that the system works — critical for the grant

### Task 5.1 — Create golden test fixtures
**What to do:** Create a `tests/fixtures/golden/` directory with 10-15 real public advisories and their expected outputs. Include a mix of: CISA ICS-Medical, CISA ICS, KEV entries, FDA notices, and vendor disclosures. Each fixture needs: input (raw advisory text/items), expected correlation (which items should merge), expected scoring (priority range), expected healthcare classification.

**Success criteria:**
- `tests/fixtures/golden/` contains at least 10 advisory fixtures
- Each fixture is a directory with: `input.json` (discovery items), `expected.json` (expected outputs)
- Expected outputs include: expected_issue_count, expected_cves, expected_priority_range, expected_healthcare_category
- A manifest file `tests/fixtures/golden/manifest.json` listing all fixtures with descriptions

**Verification:**
```bash
python -c "
import json
from pathlib import Path
manifest = json.load(open('tests/fixtures/golden/manifest.json'))
print(f'Golden fixtures: {len(manifest[\"fixtures\"])}')
for f in manifest['fixtures']:
    fdir = Path('tests/fixtures/golden') / f['id']
    assert fdir.exists(), f'Missing fixture dir: {fdir}'
    assert (fdir / 'input.json').exists(), f'Missing input.json in {fdir}'
    assert (fdir / 'expected.json').exists(), f'Missing expected.json in {fdir}'
print(f'All {len(manifest[\"fixtures\"])} fixtures validated')
assert len(manifest['fixtures']) >= 10, 'Need at least 10 fixtures'
print('PASS')
"
```

### Task 5.2 — Build the evaluation runner
**What to do:** Create `advisoryops/eval_harness.py` and a CLI command `advisoryops evaluate`. It runs the full pipeline against golden fixtures and scores the outputs.

**Success criteria:**
- CLI: `advisoryops evaluate --fixtures tests/fixtures/golden/ --out outputs/eval/`
- Measures: extraction field accuracy, correlation correctness (did the right items merge?), scoring calibration (is priority in expected range?), healthcare classification accuracy
- Outputs: per-fixture score report (JSON), summary report (JSON + markdown)
- Summary includes: total_fixtures, pass_count, fail_count, accuracy_by_dimension

**Verification:**
```bash
python -m advisoryops.cli evaluate --fixtures tests/fixtures/golden/ --out outputs/eval/
python -c "
import json
summary = json.load(open('outputs/eval/summary.json'))
print(f'Fixtures: {summary[\"total_fixtures\"]}')
print(f'Passed: {summary[\"pass_count\"]}')
print(f'Failed: {summary[\"fail_count\"]}')
for dim, score in summary.get('accuracy_by_dimension', {}).items():
    print(f'  {dim}: {score:.1%}')
print('PASS')
"
```

---

## Phase 6: Public Packaging (runs last)

### Goal
Clean up the codebase, documentation, and outputs for open-source release.

### Task 6.1 — Clean up repo structure
**What to do:** Organize the flat file structure into proper Python package layout. Move source code into `src/advisoryops/`, tests into `tests/`, configs into `configs/`, docs into `docs/`.

**Success criteria:**
- Standard Python project layout: src/, tests/, configs/, docs/
- `pip install -e .` works
- `python -m pytest` runs all tests from project root
- All CLI commands still work

**Verification:**
```bash
pip install -e .
python -m pytest -q
advisoryops --help
advisoryops community-build --set-id gold_pass1 --out-root-community outputs/test_packaging
```

### Task 6.2 — Write public README
**What to do:** Write a proper README.md that explains: what AdvisoryOps is (2-3 sentences), quickstart (install, run first discovery, see results), architecture overview, source list, how to contribute, license.

**Success criteria:**
- README.md at repo root
- Includes: badges (Python version, license), installation steps, quickstart commands that actually work, link to docs
- A new user can go from clone to seeing results in under 5 minutes

**Verification:**
```bash
# Manually verify: follow the README quickstart steps on a clean checkout
# Every command in the README should execute without errors
```

### Task 6.3 — Generate public dataset snapshot
**What to do:** Run the full pipeline with the expanded source set and produce a publishable dataset snapshot. Include: validated_sources.json, issues_public.jsonl, alerts_public.jsonl, feed_latest.json, feed.csv, packets/ directory.

**Success criteria:**
- `outputs/release/` directory with all public artifacts
- A `RELEASE_NOTES.md` with: date, source count, issue count, alert count, methodology notes
- All files are valid (JSON parses, CSV opens, JSONL is line-valid)

**Verification:**
```bash
python -c "
import json, csv
from pathlib import Path
release = Path('outputs/release')
for f in ['validated_sources.json', 'issues_public.jsonl', 'alerts_public.jsonl', 'feed_latest.json', 'feed.csv']:
    p = release / f
    assert p.exists(), f'Missing: {p}'
    if f.endswith('.json'):
        json.load(open(p))
    elif f.endswith('.jsonl'):
        lines = [json.loads(l) for l in open(p) if l.strip()]
        assert len(lines) > 0, f'{f} is empty'
    elif f.endswith('.csv'):
        rows = list(csv.DictReader(open(p)))
        assert len(rows) > 0, f'{f} is empty'
    print(f'{f}: OK')
print('PASS')
"
```

---

## Session Tips for Claude Code

1. **Start each session** by telling Code: "Read the build plan at advisoryops_build_plan.md, specifically Phase X, Task Y. Here's where we left off."

2. **One task per session** works best. Don't try to cram multiple tasks.

3. **Always run verification** before calling a task done. Paste the verification commands from this plan and show the output.

4. **If a test fails**, fix it in the same session. Don't move to the next task with broken tests.

5. **Commit after each task** passes verification. Use descriptive commit messages like: "Phase 2, Task 2.1: Add AI merge candidate detector with tests"

6. **For AI-powered tasks** (2.2, 2.3, 3.3, 4.2): Test with mocks first, then do one live API test to confirm real behavior. Don't burn API credits running the full pipeline repeatedly during development.

7. **Track costs**: Every AI-powered function should log token usage. After each session that uses the API, note the approximate cost.
