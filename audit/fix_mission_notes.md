# Fix Mission Notes

## FIX 6 — Corpus count discrepancy investigation

**Date:** 2026-04-12
**Trigger:** session_state.md Section 5 claimed the 2026-04-09 run produced 3,923–3,929 issues. The on-disk `outputs/community_public/feed_latest.json` before FIX 4.5 contained 1,990 issues.

### Finding: Category (a) — on-disk feed reflected a different parameter set than Section 5 described

**Evidence:**
1. **correlate/issues.jsonl** currently has 3,929 lines (measured after FIX 4.5 rebuild). This is the correlate-stage output.
2. **sanity_report.md** (generated 2026-04-12T06:17:05Z by FIX 4.5 rebuild) reports `Total issues: 3929`.
3. **After FIX 4.5 rebuild**, feed_latest.json has 3,929 issues — matching session_state claim.
4. **Before FIX 4.5** (i.e., the on-disk state at audit time), feed_latest.json had 1,990 issues. This smaller number was the artifact of whatever `--latest` or other truncation the 2026-04-09 run used, not a filtering bug or a separate corpus.
5. The first attempted FIX 4.5 run (before the rerun) used `--latest 100` and produced 100-issue feed_latest.json — demonstrating that the `--latest` flag directly drives this truncation at feed-emission time.
6. Gap between correlate and feed is ONLY the `--latest` cap. No other filtering layer drops issues between correlate and feed.

**Conclusion:** Section 5 was correct about the correlate output (3,923 / 3,929 depending on run). The pre-FIX-4.5 on-disk feed_latest.json = 1,990 simply reflected a prior run using a `--latest 1990` or equivalent truncation parameter, or it was an older snapshot from before Problem 2 triage fix landed (which itself bumped count from 3,923 to 3,929). After FIX 4.5 rebuild with no `--latest` cap, the feed shows the full 3,929.

**No bug. No C-036 finding needed. No Section 5 edits beyond the note already added in FIX 5 reconciling the minor NVD-count delta (2,362 vs 2,372).**

**Side note worth recording, not filed as a finding:** In the rebuilt feed, `feed_healthcare.json` has 3,929 entries (all marked `healthcare_relevant=True`) because the healthcare filter treats the "healthcare_adjacent" category as healthcare_relevant, and 2,638 of 3,929 issues fall into that category per the sanity report. This is NOT a regression — it's the existing Problem 6 (healthcare filter false positives) manifesting. Session_state Section 6 already tracks this.
