# Recon: Exposure-Tagging Design

Read-only recon for adding an exposure/remote-exploitability tag to issue records. No code was changed. Branch: `clean-orphan`.

---

## ⚠️ Findings requiring decision

These are surfaced, not resolved.

1. **CVSS is not currently a scoring input at all.** `score.py` (both v1 and v2) never reads `cvss_score`, `cvss_vector`, or `cvss_severity`. KEV membership *does* affect score (three separate paths — see §1), but nothing derived from the CVSS vector (e.g. `AV:N` remote-attack-vector) does. If "exposure tagging" is meant to feed scoring, there is no existing hook to extend — a new dimension would need to be added from scratch, and its interaction with the FDA clinical-severity floor (which already overrides/floors scores independent of cyber signals) needs a decision.

2. **Scoring happens *before* CVSS data exists.** In `community_build.py`, `score_issues()` runs immediately after `correlate()`; `nvd_enrich.enrich_issues()` (which populates `cvss_vector`) runs *after* scoring, as a separate later step (community_build.py:1764-1829). So even if scoring were extended to use CVSS/exposure data, the current pipeline order would need to change, or exposure-tagging would need to be a distinct post-scoring pass (like NVD enrichment itself).

3. **CVSS v2 vectors have no `CVSS:` version prefix.** ~242 vectors in the live feed are raw v2 strings like `AV:N/AC:L/Au:N/C:C/I:C/A:C` — there is no `CVSS:2.0/` prefix (that convention started with v3.0). A parser that assumes every vector starts with `CVSS:<version>/` will silently mis-bucket or fail on all v2 vectors. See §3.

4. **`_extract_nvd_fields()` in `nvd_enrich.py` does not check `cvssMetricV40`.** It only tries `cvssMetricV31` → `cvssMetricV30` → `cvssMetricV2` (nvd_enrich.py:119-128). No CVSS 4.0 vectors exist in the current dataset, but that may be *because* the extractor can't see them, not because NVD has none for these CVEs — undetermined from static analysis alone.

5. **A second, unstructured, contradictory "exploitability" surface already exists.** The AI classification pipeline (`ai_score.py`) writes free-form `extracted_facts` / `inferred_facts` dicts with LLM-chosen keys. In the live dataset these already include `exploitability`, `exploitation_potential`, `exploitation_risk`, `exploit_vector`, `exploit_type`, `attack_vector`, `is_network_accessible`, `authentication_requirement`, `paths_for_exploitation` — inconsistent key names, free-text (not enum/boolean) values, no fixed vocabulary, populated only for the subset of issues sent to the AI classifier. Example real values: `inferred_facts.exploitability = "remote"`, `inferred_facts.is_network_accessible = "true"` (string, not boolean), `inferred_facts.authentication_requirement = "none for exploitation"`. **A new structured `exposure`/`remotely_exploitable` field would coexist with this and could easily disagree with it for the same issue.** See §6.

6. **The `_feed_entry()` allowlist is the actual gate — not schema validation.** There is no JSON-Schema/Pydantic validation anywhere in the discover→correlate→score→community_build pipeline (the schema in `schemas/advisory_record_schema.json` governs a *separate*, unrelated deep-extraction pipeline — see §4). A new field only reaches the public feeds if it's manually added to `_feed_entry()` in `community_build.py`. Nothing currently rejects an *unexpected* new field; nothing currently *guarantees* a new field propagates either.

7. **The atomic publish guard is count-only, not schema-aware.** It compares `len(new_feed) >= len(baseline_feed)` and nothing else (community_build.py:632-639). Adding a field to every record — even mid-flight, even with a bug that fills it with garbage — will never trip this guard. Any correctness check on the new field would have to be a new, separate check.

8. **There appear to be two dashboard HTML implementations, only one of which is real.** `dashboard/index.html` (repo root, 1832 lines) is the actual source of truth — it's copied to `docs/index.html` by `_publish_to_docs()` and is the only one covered by `tests/test_dashboard_html.py` and `tests/test_feed_contract.py`. But `community_build.py` also embeds a second, ~1000+ line `_DASHBOARD_HTML` constant (community_build.py:795+), written via `_generate_dashboard()` to `outputs/community_public/dashboard.html` — a file `_publish_to_docs()` never copies anywhere. This embedded copy has **no** NEW badge, no `healthcare_category` filter, and no `first_published_to_feed` reference — it's stale/orphaned. Anyone editing "the dashboard" by grepping `community_build.py` first will edit the dead copy.

9. **User's stated "~36% missing CVSS vector" doesn't match measured figures exactly.** `docs/feed_latest.json` (5,105 issues, the full published feed) measures **40.0%** missing (2,042/5,105). `docs/feed_healthcare.json` (434 issues, medical-device subset) measures **88.0%** missing (382/434) — a much starker gap, likely because non-CVE FDA/recall-sourced medical-device issues dominate that subset. Worth confirming which dataset/snapshot the 36% figure came from before designing thresholds around it.

---

## 1. Risk scoring function(s)

**File:** `src/advisoryops/score.py`

Two scorers exist:

- `score_issue(issue)` (line 137) — v1, keyword-only baseline.
- `score_issue_v2(issue, _weights=None)` (line 377) — v2, the default (healthcare-aware); runs v1 first, then adds 5 more dimensions.

### v1 factors (`score_issue`, lines 137-175)
| Factor | Points | Code |
|---|---|---|
| `issue_type == "cve"` | +10 | line 144-146 |
| `issue_type != "cve"` | +2 | line 147-149 |
| `sources` contains `"kev"` / `"cisa-kev"` (substring match) | **+80** | line 151-155 |
| Keyword regex hits on `issue_id\ntitle\nsummary` (11 patterns, see `_KEYWORDS` lines 85-97) — includes `"known exploited"` / `\bkev\b` **+80**, `actively exploited` +40, RCE +30, auth bypass +25, code execution +25, priv esc +20, exfiltration/info disclosure/SQLi +15, DoS +5, PoC +10 | varies | lines 161-164 |
| `links` contains an `nvd.nist.gov/vuln/detail/` URL | +5 | line 168-170 |

### v2 additional dimensions (`score_issue_v2`, lines 377-454), on top of v1
1. **Source authority** — tier-weighted via `source_weights.load_source_weights()`, `auth_pts = round(weights.base_authority_points * max_w)` (line 410), plus a flat `+healthcare_bonus` if any source is tier-1 medical (lines 420-422).
2. **Device context signals** — 7 regex groups (`_DEVICE_SIGNALS`, lines 192-236): infusion/drug pump +25, ventilator/life-support +25, cardiac implant/defibrillator +25, patient monitor +20, imaging/PACS +15, EHR/EMR +10, generic healthcare context +10.
3. **Patch feasibility** — 4 regex groups (`_PATCH_SIGNALS`, lines 239-269): no patch +20, EOL/decommissioned +15, vendor-managed +10, firmware +10.
4. **Clinical impact** — 5 regex groups (`_CLINICAL_SIGNALS`, lines 272-302): life-sustaining +30, patient safety +25, ICU +20, PHI/patient data +15, generic "clinical" +5.
5. **FDA risk class** (`_score_fda_risk_class`, lines 305-319): Class III +30, Class II +10, Class I/null +0.
6. **FDA clinical-severity floor** (`_apply_fda_clinical_floor`, lines 322-352, applied last): Class III floors score to **150** (P0) if below; Class II floors to **100** (P1) if below; Class I gets a flat +10 (no floor). This runs *after* everything else and can override the additive total.

Optional AI pass (`score_issues(..., ai_score=True)`, lines 518-585): only for issues with **no** deterministic device/clinical/source-authority signal in `why`; boosts `medical_device` +20, `healthcare_it` +15, `healthcare_adjacent` +5, only if AI `confidence >= 0.70`.

### Does KEV affect score? Yes — three independent, additive paths, none of which touch CVSS:

```python
# score.py:151-155  (v1, source-string match)
sources = issue.get("sources") or []
src_text = " ".join(str(s) for s in sources).lower() if isinstance(sources, list) else str(sources).lower()
if "kev" in src_text or "cisa-kev" in src_text:
    score += 80
    why.append("source: KEV source (+80)")
```
```python
# score.py:87  (v1, keyword match against title/summary/issue_id text)
(re.compile(r"\bknown exploited\b|\bkev\b", re.I), 80, "keyword: KEV/known exploited (+80)"),
```
```python
# score.py:355-363  (v2 only, requires the separately-computed is_kev_medical_device flag)
def _score_kev_medical_device(issue: Dict[str, Any]) -> Tuple[int, List[str]]:
    """+40 bonus when a CVE is both in CISA's KEV catalog and affects a medical device."""
    if issue.get("is_kev_medical_device"):
        return 40, ["kev-medical-device: actively exploited medical device (+40)"]
    return 0, []
```
Note: `_score_kev_medical_device` is **not** called inside `score_issue_v2`'s body (lines 377-454) — the 5 dimensions listed in that function's docstring are the only ones it runs. It is instead called separately from `community_build.py:2337-2364`, *after* `score_issues()` has already run and written `score`/`priority`/`why`, as a fourth, distinct KEV-related scoring path:

```python
# community_build.py:2350-2363
if has_kev:
    issue["is_kev_medical_device"] = True
    pts, why_strs = _score_kev_medical_device(issue)   # +40 if is_kev_medical_device
    if pts:
        issue["score"] = issue.get("score", 0) + pts
        new_priority = _priority_from_score(issue["score"])
        issue["why"] = [w for w in issue["why"] if not w.startswith("priority:")] + why_strs + [f"priority: {new_priority} (score={issue['score']})"]
        issue["priority"] = new_priority
        issue["actions"] = _actions_for_priority(new_priority)
```
So `score` is mutated a second time, outside `score.py` entirely, in `community_build.py`. Any exposure-tagging design that wants to hook into "final" score needs to account for this post-hoc mutation, not just `score_issue_v2`.

**CVSS involvement in score: none.** No reference to `cvss_score`, `cvss_vector`, or `cvss_severity` anywhere in `score.py`.

---

## 2. CVSS vector provenance

**Populated in:** `src/advisoryops/nvd_enrich.py`, function `_extract_nvd_fields()` (lines 102-173), called via `enrich_issue()` → `_apply_nvd_fields()` (lines 331-344).

```python
# nvd_enrich.py:115-132
for key in ("cvssMetricV31", "cvssMetricV30"):
    metric_list = metrics.get(key) or []
    if metric_list:
        cvss_data = metric_list[0].get("cvssData") or {}
        break
if cvss_data is None:
    v2_list = metrics.get("cvssMetricV2") or []
    if v2_list:
        cvss_data = v2_list[0].get("cvssData") or {}
if cvss_data:
    result["cvss_score"] = cvss_data.get("baseScore", 0)
    result["cvss_vector"] = cvss_data.get("vectorString", "")
```

**Pipeline position:** called from `community_build.py:1801-1828`, *after* `score_issues()` and `detect_contradictions()`, as a dedicated post-scoring enrichment pass (cached to `outputs/nvd_cache/<CVE-ID>.json`, never re-fetched).

There is a **second** independent producer for advisories parsed as CSAF (`community_build.py` CSAF parsing helper, lines ~250-360, and the equivalent in `sources/cisa_icsma_backfill.py` / `sources/siemens_productcert_backfill.py` / `discover.py`) that reads `cvss_v3`/`cvss_v31` blocks from CSAF JSON directly and sets `cvss_vector` before NVD enrichment even runs. `merge_baseline_feed`'s `_GUARD_SCALAR` list (community_build.py:137-159) protects whichever value is already present across baseline merges.

### Why ~36-40% are missing a vector (measured on `docs/feed_latest.json`, 5,105 issues, 2,042 missing = 40.0%):

| Reason | Count | % of missing |
|---|---|---|
| Issue has **no CVE at all** (FDA recalls, advisories without a CVE, etc. — `enrich_issue()` returns immediately if `issue.get("cves")` is empty, line 300-302) | 1,753 | 85.8% |
| Issue's **only** source is CISA KEV, and NVD enrichment deliberately skips KEV-only issues to conserve API rate budget (`_KEV_SOURCE_IDS`, nvd_enrich.py:39-43, 368-372) | 69 | 3.4% |
| Issue has a CVE, multiple sources including KEV, but still no vector (genuine NVD miss for a KEV-corroborated issue) | 1 | ~0% |
| Issue has a CVE, is **not** KEV-only, but still has no vector — real NVD lookup miss (CVE not yet in NVD, 429 rate-limit abort after 3 consecutive 429s, cache miss + network failure, etc.) | 219 | 10.7% |

So the dominant driver is simply "no CVE on the issue" (open-ended FDA/vendor-advisory content), not NVD lookup failure — NVD-side misses account for only ~11% of the missing vectors.

---

## 3. CVSS version distribution

Counted directly from `docs/feed_latest.json` (5,105 issues, current published feed):

| Vector form | Count | Note |
|---|---|---|
| `CVSS:3.1/...` | 2,458 | Standard v3.1 prefix |
| `CVSS:3.0/...` | 363 | Standard v3.0 prefix |
| `AV:N/...` (no version prefix) | 163 | **CVSS v2** — v2 has no `CVSS:` prefix convention |
| `AV:L/...` (no version prefix) | 79 | **CVSS v2** |
| `CVSS:4.0/...` | 0 | None present |
| *(missing)* | 2,042 | See §2 |

**Total non-empty vectors: 3,063.** v2-style (prefix-less) vectors total **242** (163 + 79) — about 7.9% of all populated vectors. On `docs/feed_healthcare.json` (medical-device subset, 434 issues), only `CVSS:3.1` (38) and `CVSS:3.0` (14) appear; no v2 or v4.0 vectors in that subset.

**Parsing implication:** a naive parser that does `vector.split("/")[0]` and expects a `CVSS:` prefix will get `AV:N` or `AV:L` as the "version" token for ~8% of populated vectors, not a real version identifier. Any exposure-tagging parser needs an explicit v2 detection branch (e.g., "does it start with `CVSS:`? If not, and it starts with `AV:`, treat as implicit CVSS v2"). v4.0 needs no special handling today (zero instances) but see Finding #4 above — the extractor itself may be blind to it.

---

## 4. Schema and publish guard

**Two unrelated "schema" concepts exist in this repo — do not confuse them:**

1. **`schemas/advisory_record_schema.json`** — a Pydantic-derived JSON Schema (see `src/advisoryops/models.py`, `AdvisoryRecordMVP` and friends) for the **deep-extraction pipeline** (`ingest.py` → `extract.py` → `outputs/ingest/<id>/advisory_record.json`). This is a *completely separate* pipeline from discover→correlate→score→community_build. I found no `jsonschema.validate()` call anywhere in `src/` that actually validates against this file at runtime — it functions as a documented contract (referenced in `docs/DOC-02_Data_Contracts.md:201`), not an enforced gate. Its one Pydantic model that allows extra fields is `extract.py:44` (`model_config = ConfigDict(extra="allow")`); none of the models in `models.py` set `extra="forbid"`, so even here, an extra field would be silently accepted, not rejected.

2. **`docs/feed_contract.json`** — this is the schema that actually matters for the discover→correlate→score→community_build pipeline, enforced by `tests/test_feed_contract.py`. It documents itself as: *"every field the pipeline emits via `_feed_entry` (community_build.py) plus every field the dashboard renders... If you add a field to `_feed_entry` or to the dashboard JS, add it here first."*

   **The enforcement is one-directional.** `TestDashboardReadsOnlyDeclaredFields` (test_feed_contract.py:78-113) regex-scans `dashboard/index.html` for `issue.<field>` / `i.<field>` accesses and fails if any referenced field isn't declared in the contract. There is **no test that the reverse holds** — nothing checks that every field `_feed_entry()` emits is declared in `feed_contract.json`. So: adding a new field to `_feed_entry()` only, without touching the dashboard, passes all existing tests silently, contract-undeclared. It only becomes enforced once the dashboard JS references it too.

   `TestRequiredFieldsInFeed` (lines 51-75) separately checks that fields marked `"required": true` are present in ≥95% of rows of `outputs/community_public/feed_healthcare.json` — irrelevant unless the new field is marked required.

### Atomic publish guard

**Function:** `_publish_to_docs()`, `community_build.py:576-673`. The guard (lines 610-639) is **purely a record-count comparison**:

```python
# community_build.py:632-639
if new_count < baseline_count:
    raise RuntimeError(
        f"Publish aborted — degraded run detected: "
        f"new feed has {new_count} issues, committed baseline has {baseline_count}. "
        f"Floor rule: new count must be >= baseline count "
        ...
    )
```

`new_count`/`baseline_count` come from `len(json.loads(feed_latest.json))` (lines 614-630) — the number of array elements, nothing about field shape. **Adding a new field to every record would not trip this guard under any circumstance** — it only fires on record-count shrinkage (`tests/test_publish_step.py::test_degraded_run_aborts_entire_commit`, `test_degraded_partial_run_aborts_entire_commit`). Equal counts ("quiet day") explicitly pass (`test_quiet_day_equal_count_is_allowed`).

---

## 5. Feed builder — shared code path

**Confirmed: `feed_latest.json` and `feed_healthcare.json` are built from the same row objects, not independently reconstructed.**

```python
# community_build.py:2392-2394
feed_rows = _sort_feed_entries([_feed_entry(r) for r in scored_rows])
...
alert_feed_rows = _sort_feed_entries([_feed_entry(r) for r in alert_rows])
```
```python
# community_build.py:2549-2559
out_latest.write_text(json.dumps(latest_rows, ...))
...
# Healthcare-relevant feed — strict medical device subset only.
out_healthcare = community_root / "feed_healthcare.json"
healthcare_rows = [r for r in latest_rows if r.get("healthcare_category") == "medical_device"]
out_healthcare.write_text(json.dumps(healthcare_rows, ...))
```

`feed_healthcare.json` is a plain Python-level filter (`healthcare_category == "medical_device"`) over `latest_rows`, which is itself `feed_rows[:latest]` (or the baseline-merged equivalent). Both ultimately trace back to `_feed_entry(issue)` — **but `_feed_entry()` (community_build.py:251-321) is an explicit allowlist dict, not a passthrough.** A new field on the `issue` dict (e.g. from scoring or NVD enrichment) will **not** automatically appear in either feed — it must be explicitly added as a new key inside `_feed_entry()`. Once it is, both `feed_latest.json` and `feed_healthcare.json` get it automatically (same call path), and so does `alerts_public.jsonl` (built from `alert_feed_rows`, same function).

`_publish_to_docs()` then copies both files verbatim from `outputs/community_public/` to `docs/` in the same loop (community_build.py:654-666) — no per-file special-casing.

### Other outputs that would need explicit updates for a new field

- **`_feed_entry()` itself** (community_build.py:251-321) — mandatory; nothing reaches the feeds without this.
- **`docs/feed_contract.json`** — required by `TestDashboardReadsOnlyDeclaredFields` *only if* the dashboard also reads the new field; not required just to add it to `_feed_entry`. Should be added regardless per the contract's own stated convention (§4).
- **`merge_baseline_feed()` guard lists** (`_GUARD_SCALAR` / `_GUARD_COLLECTION`, community_build.py:137-179) — if the new field should survive baseline carry-forward (protected from being silently dropped to empty on a "thin" incoming row) or should always be freshly recomputed (left undeclared, like `healthcare_relevant`/`is_kev_medical_device`/`why`), a decision is needed either way and the field must be placed in the correct bucket.
- **`feed.csv`** (`_write_csv`, community_build.py:428-461) — a fixed 11-column allowlist (`issue_id, issue_type, priority, score, title, canonical_link, cves, sources, published_dates, first_seen_at, last_seen_at`). Does **not** currently include any CVSS field, so it would need explicit addition only if CSV export is in scope.
- **`feed.xml` / filtered RSS feeds** (`_write_rss`, community_build.py:369+) — similarly a fixed field set; not automatic.
- **`meta.json` `methodology_stats`** (`_augment_meta_json`, community_build.py:676-790) — optional; this is where counts like `medical_device_issues`, `fda_risk_class_populated`, `kev_enriched` live. Adding an `exposure_tagged` count here would be a design choice, not a requirement — the top-level `counts` block (record counts only, community_build.py:2659-2667) doesn't need touching for a new *field* (only for a new *output file*).
- **`_generate_dashboard()` / embedded `_DASHBOARD_HTML`** (community_build.py:464-475, 795+) — orphaned/dead output (see Finding #8); can be ignored, but don't be misled into editing it.

---

## 6. Existing overlap: exploitability / exposure-related fields

**No fixed-schema field exists today for "remotely exploitable" or "exposure."** But there is substantial *unstructured* overlap risk:

`ai_score.py`'s AI classification prompt (`_SYSTEM_PROMPT`, lines 65-96) asks the model to return free-form `extracted_facts: {"<key>": "<fact>"}` and `inferred_facts: {"<key>": "<fact>"}` dicts — no fixed key vocabulary, the LLM invents keys per-issue. This is only invoked for issues where deterministic scoring found *no* device/clinical signal (score.py:530-536), so it's a subset of the corpus, but a real one. Enumerating actual keys present today across `docs/feed_latest.json`:

```
attack_vector, attacker_impact, authentication_requirement, exploit_implication,
exploit_type, exploit_vector, exploitability, exploitation_potential,
exploitation_risk, is_network_accessible, paths_for_exploitation,
vulnerability_exploitability, ...
```

Real examples pulled from the live feed:
- `inferred_facts.exploitability = "remote"` (CVE-2018-0171)
- `inferred_facts.attack_vector = "remote code execution"` (CVE-2025-21042)
- `inferred_facts.is_network_accessible = "true"` — **string, not boolean** (CVE-2025-34026)
- `inferred_facts.authentication_requirement = "none for exploitation"` (CVE-2026-20131)

These are prose values with no enum, no schema, and no guaranteed presence per-issue. **Any new structured exposure field (e.g. a boolean `remotely_exploitable` or an enum `exposure: network|adjacent|local|physical` derived from parsing `AV:` out of `cvss_vector`) will sit alongside this pre-existing unstructured signal for the same concept, on the same issues, potentially disagreeing with it.** No reconciliation mechanism between the two exists today. This is the most consequential overlap to resolve before implementation — worth deciding whether the new field supersedes/deprecates these AI-guessed keys, ignores them, or cross-validates against them.

Separately, `recommend.py`'s remediation-pattern prompt (line 156) asks the AI to cite "exploitability" in a free-text `rationale` justification string — narrative only, not a structured field, low overlap risk.

`extract.py` (line 129) treats `"EXPLOITABILITY"` as a known section heading to insert paragraph breaks before, purely for LLM readability during the *unrelated* deep-extraction pipeline — not a stored field, negligible overlap risk.

---

## 7. Dashboard patterns — NEW badge and healthcare filter

**File:** `dashboard/index.html` (1,832 lines) — the actual deployed dashboard (confirmed source of truth; copied to `docs/index.html` by `_publish_to_docs()`; covered by `tests/test_dashboard_html.py` and `tests/test_feed_contract.py`). Do not confuse with the orphaned `_DASHBOARD_HTML` constant in `community_build.py` (Finding #8).

### NEW badge
- **CSS** (line 132): `.new-badge { display:inline-block; font-size:9px; font-weight:700; padding:2px 6px; border-radius:3px; background:#064e3b; color:#6ee7b7; ... }` — sits alongside sibling badge classes `.hc-badge` (124), `.fda-badge` + variants (125-130), `.kev-med-badge` (131).
- **Badge-generating functions** (lines 968-986): `fdaBadgeHtml(rc)` and `kevMedBadgeHtml(issue)` are the pattern to copy — small function returning an HTML string or `''`, driven by a single issue field (`fda_risk_class`, `is_kev_medical_device`).
- **Composition** (lines 993-1022, inside `renderIssueList()`): each badge is computed as a local var, then concatenated in a fixed order:
  ```js
  // dashboard/index.html:1002-1013
  var hcBadge = issue.healthcare_relevant ? '<span class="hc-badge">HC</span>' : '';
  var fdaBadge = fdaBadgeHtml(issue.fda_risk_class);
  var kevMedBadge = kevMedBadgeHtml(issue);
  var newBadge = issue.first_published_to_feed ? '<span class="new-badge">NEW</span>' : '';
  ...
  html += '<div class="issue-card...">' + '<div class="ic-top">' +
    kevMedBadge + newBadge +
    '<span class="badge badge-' + issue.priority + '">' + issue.priority + '</span>' +
    hcBadge + fdaBadge + cvssPill +
    '<span class="ic-title">' + title + '</span>' + '</div>' + ...
  ```
  An exposure badge would follow this identical pattern: a CSS class near line 124-134, a `exposureBadgeHtml(issue)` helper near line 981, a local var near line 1005, inserted into the concatenation near line 1009-1013.

### Healthcare filter
Implemented as a binary "scope toggle," not a checkbox:
- **UI** (lines 398-401): `<div class="scope-toggle"><button class="toggle-btn active" data-scope-mode="healthcare">Medical devices</button><button class="toggle-btn" data-scope-mode="all">All vulnerabilities</button></div>`
- **State + filter logic** (`applyFilters()`, lines 859-863):
  ```js
  var list = issues.slice();
  if (healthcareMode) {
    list = list.filter(function(i) { return i.healthcare_category === 'medical_device'; });
  }
  ```
  `healthcareMode` is a module-level boolean (declared line 679), also referenced at lines 940, 1423, 1435 for count displays and pane rendering. A new filter dimension (if it's meant to be a toggle rather than a badge) would add a sibling boolean state var + a similar `if (xMode) { list = list.filter(...) }` block in `applyFilters()`.
- Note there are **two separate data fetches** depending on mode (lines 1476-1481): `feed_healthcare.json` is fetched, not `feed_latest.json` filtered client-side — i.e. the healthcare/all toggle in the dashboard doesn't even use client-side filtering on `feed_latest.json`, it swaps the fetched dataset (`healthcareIssues` vs the full set). Relevant if a new filter is meant to compose with the existing healthcare toggle rather than be independent.

---

## 8. Test structure

- **Framework:** pytest, config in `pyproject.toml:22-27`. `addopts = "-m 'not integration'"` — real-API tests are marked `@pytest.mark.integration` and excluded by default.
- **Layout:** flat `tests/` directory (no subpackages), one file per module roughly mirroring `src/advisoryops/*.py` (e.g. `test_nvd_enrich.py` ↔ `nvd_enrich.py`, `test_score_phase1.py` / `test_score_healthcare.py` / `test_score_keywords.py` / `test_score_alerts.py` / `test_score_fda_floor.py` ↔ `score.py` — scoring tests are already split by concern across multiple files rather than one monolithic file).
- **Conventions:** no `conftest.py`; each test file does its own `sys.path.insert(0, ...)` to import from `src/` (see `test_publish_step.py:10`, `test_feed_contract.py:17`); tests group into `class Test<Concern>:` blocks with plain `def test_...(self):` methods; fixtures are typically small local builder functions (e.g. `_nvd_cve_item(...)` in `test_nvd_enrich.py:22-69`, `_make_feed(n)` / `_make_repo(...)` / `_make_community(...)` in `test_publish_step.py:17-47`) rather than pytest `@fixture` decorators.
- **Golden fixtures:** `tests/fixtures/golden/fixture-NN-<description>/` — realistic multi-source scenario fixtures (e.g. `fixture-03-kev-single-cve`, `fixture-05-icsma-pacs-server-multi-cve`) used for end-to-end pipeline assertions.

### Where a vector-parsing unit test would live

**`tests/test_nvd_enrich.py`**, inside (or alongside) the existing `class TestExtractNvdFields:` (starts line 76), which already tests `_extract_nvd_fields()` — the exact function that parses the NVD API's `cvssMetricV31/V30/V2` structure into `cvss_vector`/`cvss_score`/`cvss_severity`. The existing fixture helper `_nvd_cve_item(..., vector=..., use_v31=True)` (lines 22-69) already supports building v3.1 vs v2 CVSS metric blocks and would need a `use_v40` (or generalize `use_v31` to a `version` param) to cover CVSS 4.0. A **new** exposure-parsing function (e.g. `parse_cvss_vector(vector_string) -> {"version": ..., "attack_vector": ...}`) would most naturally live in `nvd_enrich.py` next to `_extract_nvd_fields()`, with its unit tests as a new `class TestParseCvssVector:` in the same test file — following the file's existing per-concern class grouping (`TestExtractNvdFields`, `TestSummaryDedup`, `TestRemediationSteps`, `TestKevFieldExtraction`, `TestFeedEntrySchema`, `TestRateLimiter` are the current classes in that file). Given Finding #3 (CVSS v2 has no prefix), tests should explicitly cover: a v3.1 vector, a v3.0 vector, a prefix-less v2 vector, and (per Finding #4) ideally a v4.0 vector once the extractor itself is extended to look at `cvssMetricV40`.
