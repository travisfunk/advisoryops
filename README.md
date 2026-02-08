# AdvisoryOps (Healthcare)

AdvisoryOps converts public medical-device security advisories into:
- AdvisoryRecord (normalized advisory)
- IssueCluster (deduped issue storyline)
- RemediationPacket (facility-specific, role-split tasks + exports)
- ITSM tickets (ServiceNow first)

## Repo layout
- docs/     Project docs (DOC-01..DOC-10)
- core/     Open-core friendly modules (schemas/playbooks/eval)
- pro/      Paid/private connectors and customer specifics (optional later)
- src/      Pipeline modules (ingest/normalize/cluster/match/packet/export/itsm/eval)
- outputs/  Local runs (gitignored)

## Status
Milestone B (Ingest + Extract) complete as of 2026-02-08. Extract output is a strict 13-key contract (DOC-02) with deterministic mojibake cleanup + offline unit tests (pytest).
