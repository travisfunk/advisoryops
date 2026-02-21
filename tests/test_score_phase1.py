from __future__ import annotations

import json
from pathlib import Path

from advisoryops.score import score_issues


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


def test_score_outputs_priority_and_actions(tmp_path: Path) -> None:
    issues_in = tmp_path / "issues.jsonl"
    out_root = tmp_path / "scored"

    _write_jsonl(
        issues_in,
        [
            {
                "issue_id": "CVE-2025-00001",
                "issue_type": "cve",
                "title": "Remote Code Execution in Widget",
                "summary": "Known exploited. Remote code execution. Actively exploited.",
                "sources": ["cisa-kev-json", "cisa-kev-csv"],
                "links": ["https://nvd.nist.gov/vuln/detail/CVE-2025-00001"],
                "counts": {"signals": 2, "sources": 2},
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

    scored_path, meta_path = score_issues(in_issues=str(issues_in), out_root_scored=str(out_root))

    assert scored_path.exists()
    assert meta_path.exists()

    rows = [json.loads(l) for l in scored_path.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 2

    top = rows[0]
    assert top["issue_id"] == "CVE-2025-00001"
    assert top["priority"] in ("P0", "P1")  # should be high
    assert "ingest" in top["actions"]

    low = rows[1]
    assert low["issue_id"].startswith("UNK-")
    assert low["priority"] in ("P2", "P3")
