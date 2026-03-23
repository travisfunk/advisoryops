# AdvisoryOps — Build Plan v2 Addendum

**Purpose:** This addendum updates the original build plan with trust, provenance, and intelligence improvements identified in the brainstorming review. It replaces the pending Session B–H schedule with an updated plan that weaves these additions into the double-credits-week sessions.

**Status at time of writing:** Phases 1–6 complete. 258 tests. 85 sources, 51 live. Phase 7 Session A (live API validation) complete — gpt-4o-mini confirmed working. Dashboard built. All AI functions (merge, classify, recommend) functional.

**What this addendum changes:**
- Adds Phase 8: Trust & Provenance Layer (new tasks from brainstorm)
- Updates Sessions B–H to incorporate trust layer work
- Adds Sessions I–K for remaining brainstorm items
- Documents what is explicitly DEFERRED to commercial

---

## Current Completion Status

| Phase | Status | Key Deliverable |
|---|---|---|
| Phase 1: Source Expansion | ✅ Complete | 85 sources, 51 live, smoke-tested |
| Phase 2: AI Dedup Pipeline | ✅ Complete | find_merge_candidates + ai_merge_decision + correlate integration |
| Phase 3: Healthcare Scoring | ✅ Complete | v1+v2 scoring + AI classification (ai_score.py) |
| Phase 4: Mitigation Playbook | ✅ Complete | Playbook engine + recommendations + packet export |
| Phase 5: Eval Harness | ✅ Complete | 12 golden fixtures + evaluation runner (11/12 passing) |
| Phase 6: Public Packaging | ✅ Complete | Static dashboard + README + Apache 2.0 + release snapshot |
| Phase 7: Live API Validation | 🔶 Session A done | gpt-4o-mini working, prompt tuning needed |
| **Phase 8: Trust & Provenance** | ❌ New | **Added by this addendum** |

---

## Phase 8: Trust & Provenance Layer (NEW)

### Why this exists

The brainstorming review identified that the biggest gap in the current build is not more features — it's trust infrastructure. Every AI output (merge decisions, healthcare classifications, recommendations) currently returns a result but does not show:
- Where each fact came from
- What was extracted vs what was inferred
- What is still unknown or ambiguous
- When the AI doesn't have enough evidence to give a good answer
- What medical device handling warnings are buried in the advisory text
- When sources contradict each other

Grant reviewers will ask about this. Hospital security teams won't trust output without it. This is the single biggest differentiator we can add before submission.

### Task 8.1 — Add provenance fields to all AI output schemas

**What to do:** Every AI function (ai_merge_decision, classify_healthcare_relevance, recommend_mitigations) needs to return structured provenance alongside its result.

**Schema additions for every AI output:**
```json
{
  "evidence_sources": ["source_id_1", "source_id_2"],
  "extracted_facts": {"field": "value from source text"},
  "inferred_facts": {"field": "value the model derived"},
  "confidence_by_field": {"vendor": 0.95, "affected_versions": 0.4},
  "model": "gpt-4o-mini",
  "tokens_used": 342,
  "cached": true
}
```

**Success criteria:**
- MergeDecision, HealthcareClassification, and RemediationPacket dataclasses all include provenance fields
- AI prompts are updated to request source attribution in JSON output
- Existing tests still pass (provenance fields have defaults for backward compat)
- New tests verify provenance fields are populated on live API calls

### Task 8.2 — Add `insufficient_evidence` as a valid AI outcome

**What to do:** Every AI function must be able to say "I don't have enough information." Currently they always produce a result. In healthcare, overconfident output is dangerous.

**Changes:**
- MergeDecision: add `insufficient_evidence: bool` — true when similarity is ambiguous and model can't determine
- HealthcareClassification: add category value `"insufficient_evidence"` when the advisory text is too vague to classify
- RemediationPacket: add `insufficient_evidence: bool` — true when the issue lacks enough detail to recommend specific playbook patterns
- All outputs: add `evidence_gaps: List[str]` describing what's missing (e.g., "affected versions unclear", "exploit status unknown", "vendor guidance incomplete")

**Success criteria:**
- All three AI functions can return insufficient_evidence state
- Prompts explicitly instruct the model that producing no recommendation is acceptable and preferred over guessing
- At least 2 golden fixture test cases that expect insufficient_evidence
- Dashboard and packet exports handle and display evidence gaps

### Task 8.3 — Add `handling_warnings` extraction

**What to do:** Medical device advisories often contain operational cautions that are critical for hospital teams but currently get lost in the summary text. Add structured extraction of healthcare-specific handling warnings.

**New field in AdvisoryRecord schema:** `handling_warnings: List[str]`

**Examples the AI should extract:**
- "do not actively scan this device"
- "do not reboot without vendor guidance"
- "maintenance window required"
- "clinical engineering coordination required before action"
- "patient-care review required"
- "isolate rather than patch immediately"
- "vendor procedure required before touching device"

**Changes:**
- Add `handling_warnings` to AdvisoryRecord in extract.py
- Update the extraction prompt to specifically ask for handling/safety warnings
- Add `handling_warnings` to the scored issue output so it flows through to dashboard and packets
- Update the recommendation prompt so it considers handling warnings when selecting playbook patterns

**Success criteria:**
- AdvisoryRecord schema includes handling_warnings
- At least 3 golden fixtures include expected handling_warnings
- Dashboard detail view shows handling warnings with visual emphasis
- Recommendation packets include handling warnings in their output

### Task 8.4 — Add `unknowns` extraction

**What to do:** For every advisory, explicitly surface what is still unclear. The difference between "affected_versions: []" (we found none) and "affected_versions: unknown — advisory does not specify" is huge for decision-making.

**New field:** `unknowns: List[str]` on issue records after AI processing

**Examples:**
- "affected versions unclear — advisory says 'certain versions' without specifying"
- "patch availability unclear — vendor says 'contact support'"
- "exploit path unclear — vulnerability described but no attack vector detail"
- "device family naming inconsistent across sources"
- "compensating controls not explicitly provided by vendor"

**Changes:**
- Add unknowns extraction to the AI classification and recommendation prompts
- Store unknowns on the scored issue record
- Display unknowns in dashboard detail view and packet exports

### Task 8.5 — Add cross-source contradiction detection

**What to do:** When multiple sources report on the same issue, they sometimes disagree. The current correlate pipeline picks the longest title and longest summary. It should also flag contradictions.

**New fields on correlated issue records:**
```json
{
  "source_consensus": {
    "agreed": ["vendor is Philips", "affects IntelliSpace"],
    "contradicted": [
      {"field": "severity", "source_a": "CISA says Critical", "source_b": "vendor says High"}
    ],
    "unique_contributions": {
      "cisa-icsma": ["provides CVE detail"],
      "claroty-team82": ["provides exploit PoC reference"]
    }
  }
}
```

**This does NOT need AI for the first version.** Deterministic comparison of severity, CVE lists, affected products, and patch status across sources within the same correlated issue. AI-enhanced version comes later.

### Task 8.6 — Add source quality weighting configuration

**What to do:** Create `configs/source_weights.json` that defines a hierarchy for resolving conflicts and ranking source authority.

**Example:**
```json
{
  "authority_tiers": {
    "tier_1_authoritative": ["cisa-icsma", "cisa-icsa", "fda-medwatch", "certcc-vulnotes"],
    "tier_2_vendor_psirt": ["abb-psirt", "msrc-blog"],
    "tier_3_research": ["claroty-team82", "armis-labs", "google-project-zero"],
    "tier_4_news": ["dark-reading", "krebs-on-security", "healthcare-it-news-security"],
    "tier_5_threatintel": ["urlhaus-recent", "threatfox-iocs"]
  },
  "conflict_resolution": "higher_tier_wins_with_note",
  "scoring_weight_by_tier": {"tier_1": 1.0, "tier_2": 0.8, "tier_3": 0.6, "tier_4": 0.3, "tier_5": 0.2}
}
```

**Changes:**
- New config file with tier definitions
- score.py uses tier weights when multiple sources contribute to the same issue
- Contradiction detection uses tier to determine which source's value is "canonical"
- Dashboard shows source authority tier in the detail view

### Task 8.7 — Add what-changed tracking

**What to do:** Track meaningful state changes between pipeline runs so returning users can instantly see what's new and what changed.

**New output:** `outputs/community_public/changes.jsonl`

**Each change entry:**
```json
{
  "issue_id": "CVE-2024-1234",
  "change_type": "patch_released|severity_changed|new_source|exploit_confirmed|workaround_added",
  "summary": "Vendor released patch v3.2.1 — previously no fix available",
  "detected_at": "2026-03-22T...",
  "previous_value": "no patch",
  "new_value": "patch v3.2.1"
}
```

**First version is deterministic:** Compare current pipeline output against previous run's output (stored as a snapshot). Diff on key fields: severity, patch status, source count, CVE list, score changes. No AI needed for v1.

---

## Updated Session Schedule (Double-Credits Week)

### Session B: Source Expansion (UNCHANGED — run first)

Same as previously planned. Expand from 10-12 gold sources to all 51 enabled sources. Create expanded_pass1 set. Run discovery, correlate (deterministic only), score. Report total issues and merge candidates found. Do NOT run AI yet.

### Session C: Prompt Tuning + Trust Schema (UPDATED)

Previously: just fix healthcare classification and recommendation prompts.

**Now also includes:**
- Task 8.1: Add provenance fields to all AI output dataclasses (MergeDecision, HealthcareClassification, RemediationPacket)
- Task 8.2: Add insufficient_evidence as valid output state on all AI functions
- Task 8.3: Add handling_warnings to AdvisoryRecord and update extraction prompt
- Update AI prompts to return evidence_sources, confidence_by_field, evidence_gaps, and handling_warnings
- Fix healthcare classification prompt (imaging systems = medical_device)
- Fix recommendation prompt (extract parameters from advisory text, not "unknown")
- Clear relevant ai_cache entries, re-run validation, compare before/after

**Prompt for Code:**

> Read advisoryops_build_plan.md and advisoryops_build_plan_v2_addendum.md. This session has two parts: prompt tuning AND trust schema additions.
>
> PART 1 — Trust schema changes (do these first since they change dataclasses):
>
> 1a. Add provenance fields to MergeDecision in ai_correlate.py: evidence_sources (List[str]), extracted_facts (dict), inferred_facts (dict), confidence_by_field (dict). Defaults to empty so existing tests pass.
>
> 1b. Add provenance fields to HealthcareClassification in ai_score.py: same fields as above.
>
> 1c. Add provenance fields to RemediationPacket in recommend.py: same fields plus evidence_gaps (List[str]).
>
> 1d. Add insufficient_evidence (bool, default False) and evidence_gaps (List[str], default []) to ALL three AI output dataclasses.
>
> 1e. Add handling_warnings (List[str], default []) to the AdvisoryRecord schema in extract.py.
>
> 1f. Add unknowns (List[str], default []) to scored issue output schema.
>
> Run all tests after schema changes — everything must still pass with the new defaults.
>
> PART 2 — Prompt tuning:
>
> 2a. Update classify_healthcare_relevance prompt: add explicit guidance that imaging systems (X-ray, CT, MRI, PACS, dental panoramic), infusion pumps, patient monitors, ventilators = medical_device regardless of running on standard IT hardware.
>
> 2b. Update recommend_mitigations prompt: force parameter extraction from advisory text (not "unknown"), require attack-vector analysis before pattern selection, add when-to-use guidance for each pattern.
>
> 2c. Update ALL AI prompts (merge, classify, recommend, extract) to:
> - Return evidence_sources listing which source_ids informed the answer
> - Return confidence_by_field for key output fields
> - Return evidence_gaps listing what information is missing or unclear
> - Return handling_warnings when medical device operational cautions are present
> - Explicitly allow insufficient_evidence=true when the model lacks confidence
>
> Clear relevant ai_cache entries. Re-run Phase 7 validation on the same 5 advisories. Compare before/after. Show the provenance fields populated in real output.

### Session D: Advisory Summarizer (UPDATED)

Previously: just plain-language summaries.

**Now also includes unknowns in the summary output.**

**Prompt update — add to existing Session D prompt:**

> ...and for each summarized advisory, include an "unknowns" list of things the advisory leaves unclear (affected versions ambiguous, patch status uncertain, exploit path not described, etc.). Also include any handling_warnings extracted from the advisory text. The summary output should have fields: summary (str), unknowns (List[str]), handling_warnings (List[str]), evidence_completeness (float 0-1 indicating how complete the evidence picture is).

### Session E: Full Pipeline Run + Metrics (UPDATED)

Previously: deterministic-only vs AI-enhanced comparison.

**Now also includes:**
- Task 8.5: Cross-source contradiction detection (deterministic v1)
- Task 8.7: What-changed tracking (deterministic v1)

**Prompt update — add to existing Session E prompt:**

> After running the full pipeline comparison, also:
>
> 1. Build a deterministic contradiction detector: for each correlated issue with 2+ sources, compare severity, CVE lists, affected products, and patch status across sources. Write source_consensus to each issue record with agreed, contradicted, and unique_contributions fields. This does not need AI — just field comparison.
>
> 2. Build a what-changed tracker: compare current pipeline output against the previous run's snapshot. Diff on severity, patch status, source count, CVE list, score. Write changes to outputs/community_public/changes.jsonl. Each entry has issue_id, change_type, summary, detected_at, previous_value, new_value.
>
> 3. Include contradiction and change counts in the comparison report.

### Session F: Dashboard Upgrade (UPDATED)

Previously: show AI summaries, better detail panels.

**Now also shows trust layer data.**

**Prompt update — add to existing Session F prompt:**

> The dashboard detail panel for each issue should also show:
> - Handling warnings (highlighted in yellow/orange, prominently displayed before recommendations)
> - Unknowns / evidence gaps (shown as a "What We Don't Know" section)
> - Source consensus (what sources agree/disagree on, with authority tier labels)
> - Changes since last run (if changes.jsonl exists, show a "What Changed" badge/section)
> - Evidence completeness indicator (simple progress bar or percentage)
> - For each AI-generated field, show whether it was extracted from source text or inferred by the model

### Session G: Advisory Q&A (UNCHANGED)

Same as previously planned. Natural language Q&A against the corpus.

### Session H: Ask A Nurse App (UNCHANGED)

Separate project, no changes.

### Session I: Source Weighting + Product Resolver (NEW)

**Prompt for Code:**

> Read advisoryops_build_plan_v2_addendum.md, Task 8.6.
>
> Part 1: Create configs/source_weights.json with authority tiers mapping every source_id to a tier (1=authoritative like CISA/FDA, 2=vendor PSIRT, 3=research, 4=news, 5=threatintel). Create a loader in advisoryops/source_weights.py. Update score.py to use tier weights when calculating issue scores — an issue reported by CISA should score higher than the same issue reported only by a news blog. Run tests.
>
> Part 2: Create advisoryops/product_resolver.py with a function resolve_product(query: str) -> List[dict] that takes a product name/nickname (like "Sigma Spectrum" or "MX800" or "Dolphin scanner") and returns matching issues from the corpus by token-matching against vendor + product + title fields. Add a CLI command: advisoryops lookup --product "Sigma Spectrum". This is intentionally simple — no knowledge graph, just text search against existing issue records.

### Session J: RSS Feed Output + Community Templates (NEW)

**Prompt for Code:**

> Part 1: Add RSS/Atom feed generation to community-build. After building the community feed, also write outputs/community_public/feed.xml as a valid RSS 2.0 feed containing the top 50 issues with title, link, pubDate, description, and priority category. You already have the RSS parser — this is the reverse. Validate the output is parseable XML.
>
> Part 2: Create .github/ISSUE_TEMPLATE/ with three templates:
> - bad_merge.md — for reporting incorrect issue merges (fields: issue_id_a, issue_id_b, why_wrong)
> - wrong_product_match.md — for reporting incorrect product/vendor matching (fields: issue_id, expected_product, actual_product)
> - source_correction.md — for reporting outdated source URLs or new sources to add (fields: source_id, current_url, correct_url, notes)
>
> Part 3: Add a simple CONTRIBUTING.md section on how community members can submit corrections using these templates.

### Session K: Pre-Grant Polish (NEW — final session before proposal)

**Prompt for Code:**

> This is the final polish before grant submission. Do these cleanup tasks:
>
> 1. Run the full expanded pipeline one final time with --refresh and --recommend. Capture final counts.
>
> 2. Generate a grant evidence snapshot: write outputs/grant_evidence/ containing:
>    - pipeline_metrics.json (source count, issue count, alert count, merge candidates, AI calls, cache hit rate, total cost)
>    - sample_outputs/ with 5 representative issues showing full provenance, handling warnings, unknowns, source consensus, and recommendations
>    - before_after_comparison.json showing deterministic-only vs AI-enhanced results
>    - dashboard screenshot instructions (or generate a PDF export if possible)
>
> 3. Update README.md with final counts and a "Trust & Provenance" section describing the evidence trail features.
>
> 4. Run all tests one final time and report the count.

---

## Explicitly DEFERRED to Commercial Product

These items from the brainstorming document are valuable but belong in the commercial/enterprise layer, NOT the grant submission:

| Feature | Why Deferred |
|---|---|
| Facility-specific narratives | Requires private CMDB data |
| Local inventory / asset matching | Requires private device lists |
| Enterprise workflow integration (ServiceNow, Jira) | Enterprise connector work |
| Change ticket drafting | Facility-specific |
| Vendor escalation letter drafting | Facility-specific |
| Role-specific internal communication packs | Enterprise workflow |
| Executive memo generation | Enterprise workflow |
| Multi-agent/multi-pass architecture | Overengineering for current scale |
| Attack-path/chained-risk reasoning | Research project, not MVP |
| Operational friction scoring (as separate axis) | Current healthcare scoring approximates this |
| Ontology/knowledge-graph enrichment | Tier 3 feature, unfocused for grant |
| STIX/TAXII export | Target hospitals don't have TAXII consumers |
| Docker-based local mirror | Packaging task, not AI feature |
| Full REST API with OpenAPI docs | Post-grant, needs web server |
| Email digest mode | Post-grant convenience feature |
| Hospital archetype tailoring | Interesting but premature |
| Case-based reasoning ("looks like one of those") | Cool but premature |
| Multilingual advisory normalization | Only if international sources warrant it |
| Supply-chain signal aggregation | Scope creep |

---

## Updated "Future Work" Section for Grant Proposal

These deferred items should be mentioned in the grant proposal as "with additional funding, we would explore" — one paragraph, not a roadmap:

> With additional support, AdvisoryOps would extend to facility-specific guidance through inventory matching, enterprise workflow integration for automated ticket creation and vendor escalation, multi-pass AI reasoning with specialized review agents, and cross-advisory attack-path analysis connecting related vulnerabilities into broader risk patterns. The open-core architecture ensures these enterprise capabilities build on — rather than replace — the public corpus and trust infrastructure.

---

## Summary: What Changed

| Original Plan | Updated Plan |
|---|---|
| Sessions B–H focused on features | Sessions B–K now include trust layer throughout |
| AI outputs return results only | AI outputs return results + provenance + evidence gaps |
| No "I don't know" capability | insufficient_evidence is a valid output state |
| No handling warnings extraction | handling_warnings pulled from every advisory |
| No unknowns surfacing | unknowns explicitly listed for every issue |
| Sources treated equally | Source authority tiers with weighted scoring |
| No change tracking | what-changed tracking between runs |
| No contradiction detection | Cross-source contradiction flagging |
| Dashboard shows data | Dashboard shows data + trust indicators |
| No product lookup | Simple product/model resolver for manual search |
| No community feedback path | GitHub Issues templates for corrections |
| No RSS output | RSS feed alongside JSONL/JSON/CSV |

**Total new Code sessions added:** 3 (I, J, K)
**Total sessions modified:** 4 (C, D, E, F)
**Total sessions unchanged:** 3 (B, G, H)
