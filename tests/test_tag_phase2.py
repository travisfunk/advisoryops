from __future__ import annotations

import json
from pathlib import Path

from advisoryops.tag import tag_issues


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


def test_tag_writes_tags_and_meta(tmp_path: Path) -> None:
    issues_in = tmp_path / "issues.jsonl"
    out_root = tmp_path / "tags"

    _write_jsonl(
        issues_in,
        [{
            "issue_id": "CVE-2025-00001",
            "issue_type": "cve",
            "title": "Known exploited RCE",
            "summary": "Known exploited. Remote code execution. Actively exploited.",
            "sources": ["cisa-kev-json"],
            "links": ["https://nvd.nist.gov/vuln/detail/CVE-2025-00001"],
            "counts": {"signals": 2, "sources": 1},
        }],
    )

    tags_path, meta_path = tag_issues(in_issues=str(issues_in), out_root_tags=str(out_root))
    assert tags_path.exists()
    assert meta_path.exists()

    tags = [json.loads(l) for l in tags_path.read_text(encoding="utf-8").splitlines()]
    assert len(tags) == 1
    t = tags[0]
    assert t["issue_id"] == "CVE-2025-00001"
    assert "CVE-2025-00001" in t["cves"]
    assert t["exploit"]["kev"] is True
    assert t["impact"]["rce"] is True
