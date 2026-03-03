from __future__ import annotations

import json
from pathlib import Path

from advisoryops.score import score_issues


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


def test_score_writes_alerts_with_min_priority_and_top(tmp_path: Path) -> None:
    issues_in = tmp_path / "issues.jsonl"
    out_root = tmp_path / "scored"

    _write_jsonl(
        issues_in,
        [
            {
                "issue_id": "CVE-2025-00001",
                "issue_type": "cve",
                "title": "Known exploited RCE",
                "summary": "Known exploited. Remote code execution. Actively exploited.",
                "sources": ["cisa-kev-json"],
                "links": ["https://nvd.nist.gov/vuln/detail/CVE-2025-00001"],
                "counts": {"signals": 2, "sources": 1},
            },
            {
                "issue_id": "UNK-aaaaaaaaaaaaaaaa",
                "issue_type": "unknown",
                "title": "Minor issue",
                "summary": "Low impact info",
                "sources": ["some-feed"],
                "links": [],
                "counts": {"signals": 1, "sources": 1},
            },
        ],
    )

    scored_path, alerts_path, meta_path = score_issues(
        in_issues=str(issues_in),
        out_root_scored=str(out_root),
        min_priority="P1",
        top=1,
    )

    assert scored_path.exists()
    assert alerts_path.exists()
    assert meta_path.exists()

    alerts = [json.loads(l) for l in alerts_path.read_text(encoding="utf-8").splitlines()]
    assert len(alerts) == 1
    assert alerts[0]["issue_id"] == "CVE-2025-00001"
    assert alerts[0]["priority"] in ("P0", "P1")
