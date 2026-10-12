"""Apply narrowly matched, evidence-reviewed corrections after baseline merging.

Corrections are versioned repository data, not AI output. Matching requires the
issue ID, contributing source, and a known primary link. Reapply after every merge
so richness-preservation and cached generated guidance cannot revive bad facts.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from typing import Any


def apply_verified_corrections(rows: list[dict[str, Any]]) -> int:
    from .score import score_issue_v2

    path = Path(__file__).resolve().parents[2] / 'configs/verified_advisory_corrections.json'
    data = json.loads(path.read_text(encoding='utf-8'))
    if data.get('version') != 1:
        raise ValueError('Unsupported verified-correction registry version')
    rules = {rule['issue_id']: rule for rule in data['corrections']}
    corrected = 0
    for row in rows:
        rule = rules.get(row.get('issue_id'))
        if not rule or rule['source_id'] not in (row.get('sources') or []):
            continue
        if row.get('canonical_link') not in rule['allowed_links']:
            continue
        before = deepcopy(row)
        row.update(deepcopy(rule['fields']))
        result = score_issue_v2(row)
        row.update(score=result.score, priority=result.priority,
                   actions=result.actions, why=result.why)
        row['verified_correction'] = {
            key: rule[key] for key in ('correction_id', 'evidence_url', 'verified_at', 'reason')
        }
        corrected += row != before
    return corrected
