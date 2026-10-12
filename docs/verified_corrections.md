# Verified advisory corrections

`configs/verified_advisory_corrections.json` is a versioned registry of narrowly
matched corrections reviewed against primary evidence. Applying a correction
requires an exact issue ID, contributing source, and an allowed primary link.
The registry retains the evidence URL, review date, rationale, and corrected
fields. Each corrected full record includes its `verified_correction` provenance.

Corrections run before creating alert snapshots and recommendation packets,
after baseline merging, and again at archive publication. They
replace stale generated fields even when the old text is longer, rescore the
corrected evidence, and remain idempotent. They do not delete historical issues.

## FDA recall event 30666

Primary source: [FDA recall Z-0341-05](https://www.accessdata.fda.gov/scripts/cdrh/cfdocs/cfres/res.cfm?id=36309).
Relevant openFDA source fields are preserved in
`tests/fixtures/fda_30666_primary_source.json` (retrieved 2026-10-12).

The prior summary asserted both that no patch was available and that users should
update software. The FDA record does not establish either claim. It describes a
December 2004 customer notification and interim risk mitigation pending correction
by a manufacturer representative; detailed instructions are not supplied in this
record. The feed now directs readers to verify the manufacturer's instructions.
It identifies the recall as historical and terminated, and distinguishes the
2004 initiation date from the 2016 termination date.

The specific corpus check for FDA summaries mentioning no patch/fix or unpatched
status while recommending an update/upgrade/patch found one record in the
2026-10-12 archive. This is a bounded pattern check, not a full factual audit of
all FDA summaries or a guarantee that other source problems are absent.

AI rewriting now preserves input source evidence; mitigation extraction prefers
that preserved evidence rather than generated prose. The summarization prompt
requires unsupported patch status to remain unknown and distinguishes historical
recalls from current claims. This improves evidence handling but does not prove
that every generated sentence is correct; verified corrections are deterministic.

Event 30666 has a reviewed `source_only` recommendation policy: optional AI packet
generation is disabled because this historical record does not supply detailed
manufacturer correction instructions. The builder retires a previously generated
JSON packet for the same issue when recommendations are requested. Direct CLI
recommendation calls also enforce the policy, including on older snapshots that
have not yet received the policy marker.
