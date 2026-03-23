"""Remediation packet output formatters (Phase 4, Task 4.3).

Converts a ``RemediationPacket`` (produced by ``recommend.py``) into three
output formats suitable for different audiences:

Three export functions:

* ``export_json``      — stable machine-readable JSON (schema_version=1)
* ``export_markdown``  — human-readable analyst report with role sections
* ``export_csv_tasks`` — flat task list for ticketing-system import

All formatters are pure functions: they receive a RemediationPacket (plus
the Playbook for markdown/CSV step-detail reconstruction), write to the
given path, and return that path.

JSON schema (schema_version=1)
-------------------------------
{
  "schema_version": 1,
  "generated_at": "<ISO-8601 UTC>",
  "issue_id": "<str>",
  "model": "<str>",
  "tokens_used": <int>,
  "from_cache": <bool>,
  "reasoning": "<str>",
  "citations": ["<url>", ...],
  "recommended_patterns": [
    {
      "priority_order": <int>,
      "pattern_id": "<str>",
      "why_selected": "<str>",
      "parameters": {"<key>": "<value>", ...}
    }
  ],
  "tasks_by_role": {
    "<role>": ["<task_str>", ...]
  }
}

CSV columns
-----------
task_id, role, action, details, verification, priority, pattern_id
"""
from __future__ import annotations

import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .playbook import Playbook
from .recommend import RemediationPacket

# JSON schema version — bump when the exported field layout changes
_JSON_SCHEMA_VERSION = 1

_ROLE_DISPLAY: Dict[str, str] = {
    "infosec": "Information Security",
    "netops": "Network Operations",
    "htm_ce": "HTM / Clinical Engineering",
    "it_ops": "IT Operations",
    "vendor": "Vendor",
    "clinical_ops": "Clinical Operations",
}

# Preferred display order for role sections
_ROLE_ORDER = ["infosec", "netops", "htm_ce", "it_ops", "vendor", "clinical_ops"]


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_stem(issue_id: str) -> str:
    """Sanitize an issue_id for use as a filename stem."""
    return re.sub(r"[^A-Za-z0-9_\-]", "_", issue_id)


def _task_rows(
    packet: RemediationPacket,
    playbook: Playbook,
) -> List[Tuple[int, str, str, str, str, str, str]]:
    """Return task rows from playbook steps, ordered by priority_order then step order.

    Yields: (priority_order, pattern_id, pattern_name, role, action, details, verification_str)
    Patterns not found in the playbook are skipped.
    """
    rows = []
    for rec in packet.recommended_patterns:
        pattern = playbook.get(rec.pattern_id)
        if not pattern:
            continue
        verification_str = "; ".join(pattern.verification.evidence)
        for step in pattern.steps:
            rows.append((
                rec.priority_order,
                rec.pattern_id,
                pattern.name,
                step.role,
                step.action,
                step.details,
                verification_str,
            ))
    return rows


# ---------------------------------------------------------------------------
# JSON export
# ---------------------------------------------------------------------------

def export_json(packet: RemediationPacket, out_path: Path) -> Path:
    """Write a stable JSON export of the packet.

    The schema is documented at the top of this module.  ``schema_version``
    is pinned to 1; bump it when field layout changes.

    Args:
        packet:   RemediationPacket to export.
        out_path: File path to write (parent dirs created automatically).

    Returns:
        Resolved path to the written file.
    """
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    doc: Dict[str, Any] = {
        "schema_version": _JSON_SCHEMA_VERSION,
        "generated_at": _utc_now_iso(),
        "issue_id": packet.issue_id,
        "model": packet.model,
        "tokens_used": packet.tokens_used,
        "from_cache": packet.from_cache,
        "generated_by": packet.generated_by,
        "disclaimer": packet.disclaimer,
        "reasoning": packet.reasoning,
        "citations": packet.citations,
        "recommended_patterns": [
            {
                "priority_order": rec.priority_order,
                "pattern_id": rec.pattern_id,
                "why_selected": rec.why_selected,
                "rationale": rec.rationale,
                "basis": rec.basis,
                "parameters": rec.parameters,
            }
            for rec in packet.recommended_patterns
        ],
        "tasks_by_role": packet.tasks_by_role,
    }

    out_path.write_text(
        json.dumps(doc, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return out_path


# ---------------------------------------------------------------------------
# Markdown export
# ---------------------------------------------------------------------------

def export_markdown(packet: RemediationPacket, playbook: Playbook, out_path: Path) -> Path:
    """Write a human-readable Markdown remediation report.

    Sections:
      1. Header metadata
      2. AI Reasoning
      3. Recommended Patterns (one sub-section per pattern with parameters)
      4. Tasks by Role (checklist items grouped by role)
      5. Verification (evidence checklist per pattern)
      6. References / Citations

    Args:
        packet:   RemediationPacket to render.
        playbook: Loaded Playbook for step detail and verification evidence.
        out_path: File path to write.

    Returns:
        Resolved path to the written file.
    """
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    lines: List[str] = []
    add = lines.append

    # ── Header ───────────────────────────────────────────────────────────────
    add(f"# Remediation Packet: {packet.issue_id}")
    add("")
    add(f"**Generated:** {_utc_now_iso()}  ")
    add(f"**Model:** {packet.model or 'unknown'}  ")
    add(f"**Tokens used:** {packet.tokens_used}  ")
    add(f"**From cache:** {'Yes' if packet.from_cache else 'No'}  ")
    add("")

    # ── Disclaimer ─────────────────────────────────────────────────────────
    if packet.disclaimer:
        add(f"> **Disclaimer:** {packet.disclaimer}")
        add("")

    # ── AI Reasoning ─────────────────────────────────────────────────────────
    if packet.reasoning:
        add("## AI Reasoning")
        add("")
        add(packet.reasoning)
        add("")

    # ── Recommended Patterns ──────────────────────────────────────────────────
    if packet.recommended_patterns:
        add("## Recommended Patterns")
        add("")
        for rec in packet.recommended_patterns:
            pattern = playbook.get(rec.pattern_id)
            pname = pattern.name if pattern else rec.pattern_id
            add(f"### {rec.priority_order}. {pname} (`{rec.pattern_id}`)")
            add("")
            add(f"**Why selected:** {rec.why_selected}")
            add("")
            if rec.rationale:
                add(f"**Rationale:** {rec.rationale}")
                add("")
            if rec.basis:
                add(f"**Basis:** {rec.basis}")
                add("")
            if rec.parameters:
                add("**Parameters:**")
                add("")
                for k, v in rec.parameters.items():
                    add(f"- `{k}`: {v}")
                add("")

    # ── Tasks by Role ─────────────────────────────────────────────────────────
    role_tasks: Dict[str, List[Tuple[str, str, str]]] = {}
    for rec in packet.recommended_patterns:
        pattern = playbook.get(rec.pattern_id)
        if not pattern:
            continue
        for step in pattern.steps:
            role_tasks.setdefault(step.role, []).append(
                (pattern.name, step.action, step.details)
            )

    if role_tasks:
        add("## Tasks by Role")
        add("")
        for role in _ROLE_ORDER:
            tasks = role_tasks.get(role)
            if not tasks:
                continue
            display = _ROLE_DISPLAY.get(role, role)
            add(f"### {display}")
            add("")
            for i, (pname, action, details) in enumerate(tasks, 1):
                add(f"{i}. **[{pname}]** {action}  ")
                add(f"   {details}")
                add("")

    # ── Verification ─────────────────────────────────────────────────────────
    if packet.recommended_patterns:
        add("## Verification")
        add("")
        for rec in packet.recommended_patterns:
            pattern = playbook.get(rec.pattern_id)
            if not pattern or not pattern.verification.evidence:
                continue
            add(f"### {pattern.name}")
            add("")
            for ev in pattern.verification.evidence:
                add(f"- [ ] {ev}")
            add("")

    # ── Citations ─────────────────────────────────────────────────────────────
    if packet.citations:
        add("## References")
        add("")
        for c in packet.citations:
            add(f"- {c}")
        add("")

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_path


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------

def export_csv_tasks(packet: RemediationPacket, playbook: Playbook, out_path: Path) -> Path:
    """Write a flat CSV task list suitable for import into ticketing systems.

    Columns: task_id, role, action, details, verification, priority, pattern_id

    ``task_id`` format: ``{sanitized_issue_id}-{seq:03d}``
    ``priority``        = PatternRecommendation.priority_order (1 = highest)
    ``verification``    = pattern evidence items joined with "; "

    Args:
        packet:   RemediationPacket to export.
        playbook: Loaded Playbook for step detail and evidence strings.
        out_path: File path to write.

    Returns:
        Resolved path to the written file.
    """
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    stem = _safe_stem(packet.issue_id)
    rows = _task_rows(packet, playbook)

    with out_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "task_id", "role", "action", "details",
                "verification", "priority", "pattern_id",
            ],
        )
        writer.writeheader()
        for seq, (priority_order, pattern_id, _pname, role, action, details, verif) in enumerate(rows, 1):
            writer.writerow({
                "task_id": f"{stem}-{seq:03d}",
                "role": role,
                "action": action,
                "details": details,
                "verification": verif,
                "priority": priority_order,
                "pattern_id": pattern_id,
            })

    return out_path
