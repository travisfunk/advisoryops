# Medical Device filter — diagnosis (2026-04-12)

Phase 1 read-only investigation into why the live dashboard's "Medical devices" filter surfaces 3,929 issues including F5 BIG-IP, Trivy, Langflow, etc.

## Root cause classification

**Cause A — dashboard predicate bug.** The data is correctly categorized. The dashboard's "Medical devices" button filters on the wrong field.

## Evidence — sample issue data from `docs/feed_latest.json`

| Issue | `category` | `healthcare_category` | `healthcare_relevant` | Vendor |
|---|---|---|---|---|
| CVE-2025-53521 | `null` | `healthcare_adjacent` | `true` | F5 (BIG-IP APM family) |
| CVE-2026-33634 | `null` | `healthcare_infrastructure` | `true` | Aquasecurity (Trivy) |
| CVE-2026-33017 | `null` | `healthcare_adjacent` | `true` | Langflow |

The granular healthcare tag lives in `healthcare_category`. The top-level `category` field is null for these rows.

Distribution across the full feed (3,929 issues):

| `healthcare_category` | Count |
|---|---|
| `healthcare_adjacent` | 2,638 |
| `medical_device` | **1,116** |
| `healthcare_infrastructure` | 170 |
| `healthcare_it` | 5 |
| (total `healthcare_relevant=true`) | **3,929** |

So `healthcare_relevant` is set on every row that falls into any of the four subcategories — it's essentially the "in-scope" flag, not the medical-device flag. This matches Problem 6 in `docs/session_state.md`.

## The dashboard predicate

`dashboard/index.html:340` — the button that flips the mode:

```html
<button class="toggle-btn active" data-scope-mode="healthcare">Medical devices</button>
<button class="toggle-btn" data-scope-mode="all">All vulnerabilities</button>
```

`dashboard/index.html:699-701` — the filter applied when `healthcareMode` is on:

```js
if (healthcareMode) {
  list = list.filter(function(i) { return i.healthcare_relevant === true; });
}
```

Three other locations use the same too-broad predicate for headline counts:

- `dashboard/index.html:1103` — header stats "N medical device issues"
- `dashboard/index.html:1113` — priority bucket counts in healthcare mode
- `dashboard/index.html:1183` — About panel's "medical device issues" metric

All four need to swap from `healthcare_relevant === true` to `healthcare_category === 'medical_device'`.

## Recommended fix scope

Phase 2 = Cause A only. Single edit to `dashboard/index.html`:
1. Change the `healthcareMode` predicate at line 700 to `i.healthcare_category === 'medical_device'`.
2. Change the three count calculations (1103, 1113, 1183) to the same predicate.
3. Copy `dashboard/index.html` → `docs/index.html`.
4. Run pytest; no dashboard tests assert on this predicate (grepped — zero matches).
5. Commit.

No classifier changes. No re-tagging. The data in `feed_latest.json` is fine — 1,116 correctly-labelled `medical_device` rows are already there waiting to be surfaced.

## Bonus diagnosis — header strings

Both are computed, not hardcoded. The task's stated "should be 68" and "stale date" framings don't quite match the code behavior.

### "65 sources"

`dashboard/index.html:1099-1106`:

```js
var enabledSources = 0;
for (var i = 0; i < sources.length; i++) { if (sources[i].enabled) enabledSources++; }
```

where `sources` is loaded from `docs/validated_sources.json` (line 1155). That file has 66 entries, 65 enabled. `docs/meta.json` also reports `counts.validated_sources: 65`.

- `configs/sources.json` — 96 total, 68 enabled (what the session_state claims).
- `docs/validated_sources.json` — 66 entries, 65 enabled (what the pipeline actually validated and emitted).

The dashboard is showing reality. The gap between 68 (sources *asked to* run) and 65 (sources that produced validated output) is a pipeline-level fact, not a dashboard bug. Before "fixing" 65→68, confirm with Travis which number is the one he wants displayed: validated-and-emitting (65) or enabled-in-config (68).

### "Updated 2026-04-08"

`dashboard/index.html:1170-1175`:

```js
var latest = null;
for (...) {
  var d = getIssueDate(issues[i]);
  if (d && (!latest || d > latest)) latest = d;
}
document.getElementById('meta-updated').textContent = latest ? 'Updated ' + formatDate(latest) : '';
```

Computed from `max(issue.date)` across the feed. Not hardcoded and not driven off `meta.json`. If it reads 2026-04-08, that's the latest issue date in the current feed — not the rebuild date. "Updated" is misleading as a label (it implies publish time; it shows newest-source-advisory time), but it is not stale in the sense of being wrong.

If Travis wants it to show the publish/rebuild timestamp, `meta.json` would need a `generated_at` field (it currently has none) and the dashboard would need to read it. That's a separate small change — not in the original fix-mission scope and worth a brief confirmation before doing.

## Fix mission progress note

Proceeding with Phase 2 Cause A (dashboard predicate only). Holding on header-string changes pending clarification.
