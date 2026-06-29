"""Mitigation playbook loader (Phase 4, Task 4.1).

Parses ``configs/mitigation_playbook.json`` into typed, validated dataclasses
and exposes ``load_playbook()`` as the single entry point.

The playbook defines the *approved* set of mitigation patterns that the AI
recommendation engine (``recommend.py``) is allowed to select from.  By
constraining AI output to this explicit catalog, the pipeline avoids hallucinated
or unvalidated remediation steps — a critical property for healthcare settings
where incorrect advice could affect patient safety.

Pattern anatomy
---------------
Each ``MitigationPattern`` has:
    id             — stable string ID (e.g. ``SEGMENTATION_VLAN_ISOLATION``)
    name           — human-readable name
    category       — one of the eight allowed categories (segmentation, access_control, …)
    severity_fit   — list of severity levels this pattern suits (critical/high/medium/low)
    when_to_use    — conditions that suggest using this pattern + constraints that argue against
    inputs_required — variable names the AI must fill (e.g. "affected_network_segment")
    steps          — ordered list of PlaybookStep records (role + action + details)
    verification   — evidence that confirms the pattern was applied correctly
    rollback       — steps to undo the pattern if it causes problems
    safety_notes   — explicit clinical/operational safety warnings

Role vocabulary: infosec · netops · htm_ce · it_ops · vendor · clinical_ops

Usage::

    from advisoryops.playbook import load_playbook
    pb = load_playbook()
    for p in pb.patterns:
        print(p.id, p.name, p.category)
    segmentation = pb.get("SEGMENTATION_VLAN_ISOLATION")  # None if not found
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PlaybookStep:
    role: str
    action: str
    details: str


@dataclass(frozen=True)
class WhenToUse:
    conditions: List[str]
    constraints: List[str]


@dataclass(frozen=True)
class Verification:
    evidence: List[str]


@dataclass(frozen=True)
class Rollback:
    steps: List[str]


@dataclass(frozen=True)
class MitigationPattern:
    id: str
    name: str
    category: str
    severity_fit: List[str]
    when_to_use: WhenToUse
    inputs_required: List[str]
    steps: List[PlaybookStep]
    verification: Verification
    rollback: Rollback
    safety_notes: List[str]
    basis: str = ""


@dataclass(frozen=True)
class Playbook:
    version: str
    patterns: List[MitigationPattern]
    # index by id for fast lookup
    _by_id: Dict[str, MitigationPattern] = field(default_factory=dict, compare=False, hash=False)

    def get(self, pattern_id: str) -> Optional[MitigationPattern]:
        """Return a pattern by its id, or None if not found."""
        return self._by_id.get(pattern_id)


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

_VALID_CATEGORIES = {
    "segmentation", "access_control", "host_hardening", "protocol_hardening",
    "monitoring", "vendor_process", "patching", "governance", "communication",
    "hardening",
}

_VALID_ROLES = {"infosec", "netops", "htm_ce", "it_ops", "vendor", "clinical_ops"}

_VALID_SEVERITIES = {"critical", "high", "medium", "low"}


def _parse_step(raw: Dict[str, Any], pattern_id: str) -> PlaybookStep:
    role = raw.get("role", "")
    if role not in _VALID_ROLES:
        raise ValueError(
            f"Pattern {pattern_id}: invalid role '{role}'. "
            f"Must be one of: {sorted(_VALID_ROLES)}"
        )
    action = raw.get("action", "").strip()
    if not action:
        raise ValueError(f"Pattern {pattern_id}: step missing 'action'")
    return PlaybookStep(
        role=role,
        action=action,
        details=raw.get("details", "").strip(),
    )


def _parse_pattern(raw: Dict[str, Any]) -> MitigationPattern:
    pid = raw.get("id", "").strip()
    if not pid:
        raise ValueError("Pattern missing 'id'")

    name = raw.get("name", "").strip()
    if not name:
        raise ValueError(f"Pattern {pid}: missing 'name'")

    category = raw.get("category", "").strip()
    if category not in _VALID_CATEGORIES:
        raise ValueError(
            f"Pattern {pid}: invalid category '{category}'. "
            f"Must be one of: {sorted(_VALID_CATEGORIES)}"
        )

    severity_fit = raw.get("severity_fit", [])
    for s in severity_fit:
        if s not in _VALID_SEVERITIES:
            raise ValueError(
                f"Pattern {pid}: invalid severity '{s}'. "
                f"Must be one of: {sorted(_VALID_SEVERITIES)}"
            )

    wtu_raw = raw.get("when_to_use", {})
    when_to_use = WhenToUse(
        conditions=list(wtu_raw.get("conditions", [])),
        constraints=list(wtu_raw.get("constraints", [])),
    )

    inputs_required = list(raw.get("inputs_required", []))

    steps_raw = raw.get("steps", [])
    if not steps_raw:
        raise ValueError(f"Pattern {pid}: 'steps' must not be empty")
    steps = [_parse_step(s, pid) for s in steps_raw]

    ver_raw = raw.get("verification", {})
    verification = Verification(evidence=list(ver_raw.get("evidence", [])))

    rb_raw = raw.get("rollback", {})
    rollback = Rollback(steps=list(rb_raw.get("steps", [])))

    safety_notes = list(raw.get("safety_notes", []))
    basis = str(raw.get("basis", "")).strip()

    return MitigationPattern(
        id=pid,
        name=name,
        category=category,
        severity_fit=severity_fit,
        when_to_use=when_to_use,
        inputs_required=inputs_required,
        steps=steps,
        verification=verification,
        rollback=rollback,
        safety_notes=safety_notes,
        basis=basis,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_DEFAULT_PATH = Path(__file__).parent.parent.parent / "configs" / "mitigation_playbook.json"


def load_playbook(path: Optional[str] = None) -> Playbook:
    """Load and validate the mitigation playbook from a JSON file.

    Args:
        path: Path to mitigation_playbook.json. Defaults to
              configs/mitigation_playbook.json relative to the repo root.

    Returns:
        A validated Playbook instance.

    Raises:
        FileNotFoundError: if the file does not exist.
        ValueError: if any pattern fails schema validation.
    """
    resolved = Path(path) if path else _DEFAULT_PATH
    if not resolved.exists():
        raise FileNotFoundError(f"Playbook file not found: {resolved}")

    raw_doc = json.loads(resolved.read_text(encoding="utf-8"))

    raw_patterns = raw_doc.get("patterns", [])
    if not raw_patterns:
        raise ValueError("Playbook JSON has no 'patterns' array")

    patterns: List[MitigationPattern] = []
    seen_ids: set[str] = set()
    for raw in raw_patterns:
        p = _parse_pattern(raw)
        if p.id in seen_ids:
            raise ValueError(f"Duplicate pattern id: {p.id}")
        seen_ids.add(p.id)
        patterns.append(p)

    by_id = {p.id: p for p in patterns}
    version = raw_doc.get("playbook_version", "unknown")

    # Playbook is frozen; construct with the index dict
    return Playbook(version=version, patterns=patterns, _by_id=by_id)
