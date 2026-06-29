# Playbook Governance

## Pattern Approval

All mitigation patterns in `configs/mitigation_playbook.json` must be approved by the project maintainer before inclusion. Each pattern requires:

- A unique stable ID (e.g., `SEGMENTATION_VLAN_ISOLATION`)
- A `basis` field citing the regulatory or standards reference (IEC 62443, NIST SP 800-82, FDA guidance, CISA best practice, or documented practitioner experience)
- At least one verification evidence item
- At least one safety note relevant to healthcare/clinical environments
- Defined rollback steps

## Adding New Patterns

To propose a new pattern, submit a pull request that:

1. Adds the pattern to `configs/mitigation_playbook.json` with all required fields
2. Includes a `basis` citation to a published standard, regulation, or documented best practice
3. Adds at least one test in `tests/` verifying the pattern loads, has steps, and has verification evidence
4. Updates the pattern count assertion in test files if applicable

Patterns without a basis citation will not be merged. "Common practice" is acceptable as a basis only when paired with a specific reference (e.g., "Common healthcare network defense practice per CISA ICS-CERT defense-in-depth guidance").

## Deprecating Patterns

Deprecated patterns are marked with `"deprecated": true` in the JSON but are never deleted. This preserves the audit trail for previously generated recommendations that cited the pattern. Deprecated patterns are excluded from new AI recommendation selection but remain loadable for historical reference.

## AI-Generated Draft Patterns

The AI recommendation engine may suggest new patterns not in the playbook. These are clearly labeled with `"draft": true` and `"generated_by": "ai"` in any output. Draft patterns:

- Are **not** included in the approved playbook
- Must undergo human review by a qualified healthcare security practitioner before promotion
- Require a basis citation to be added during review
- Must pass the same approval criteria as manually authored patterns

The pipeline does not automatically promote draft patterns. Human review is a hard gate, not a suggestion.
