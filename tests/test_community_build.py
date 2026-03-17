from __future__ import annotations

import json
from pathlib import Path

from advisoryops.community_build import build_community_feed


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def test_build_community_feed_from_existing_discover_outputs(tmp_path: Path, monkeypatch) -> None:
    discover_root = tmp_path / "discover"
    out_root = tmp_path / "community"

    src_a = discover_root / "cisa-icsma"
    src_b = discover_root / "openfda-device-recalls"

    _write_jsonl(
        src_a / "items.jsonl",
        [
            {
                "source": "cisa-icsma",
                "guid": "https://example.test/advisory/CVE-2026-1000",
                "title": "Medical device bulletin for CVE-2026-1000",
                "summary": "Known exploited vulnerability in imaging software",
                "link": "https://nvd.nist.gov/vuln/detail/CVE-2026-1000",
                "published_date": "2026-03-17",
                "fetched_at": "2026-03-17T12:00:00Z",
            }
        ],
    )
    _write_jsonl(
        src_b / "items.jsonl",
        [
            {
                "source": "openfda-device-recalls",
                "guid": "res_event_number:97617",
                "title": "Cybersecurity recall for infusion pump controller",
                "summary": "Remote code execution risk; workaround available",
                "link": "https://api.fda.gov/device/recall.json?search=res_event_number:%2297617%22",
                "published_date": "2026-03-16",
                "fetched_at": "2026-03-17T12:05:00Z",
            }
        ],
    )

    monkeypatch.chdir(tmp_path)
    (tmp_path / "configs").mkdir(parents=True, exist_ok=True)

    (tmp_path / "configs" / "sources.json").write_text(
        (Path(__file__).resolve().parents[1] / "configs" / "sources.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (tmp_path / "configs" / "community_public_sources.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "validated_sets": [
                    {
                        "set_id": "gold_pass1",
                        "name": "Gold Pass 1",
                        "description": "test",
                        "source_ids": ["cisa-icsma", "openfda-device-recalls"],
                    }
                ],
                "candidate_sources": [],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    issues_public, alerts_public, meta_path = build_community_feed(
        set_id="gold_pass1",
        refresh=False,
        out_root_discover=str(discover_root),
        out_root_runs=str(tmp_path / "source_runs"),
        out_root_community=str(out_root),
        only_new=False,
        limit_per_source=50,
        limit_issues=0,
        min_priority="P3",
        top=100,
        latest=10,
    )

    assert issues_public.exists()
    assert alerts_public.exists()
    assert meta_path.exists()
    assert (out_root / "feed_latest.json").exists()
    assert (out_root / "feed.csv").exists()
    assert (out_root / "validated_sources.json").exists()

    issues_rows = [json.loads(line) for line in issues_public.read_text(encoding="utf-8").splitlines() if line.strip()]
    alerts_rows = [json.loads(line) for line in alerts_public.read_text(encoding="utf-8").splitlines() if line.strip()]
    meta = json.loads(meta_path.read_text(encoding="utf-8"))

    assert len(issues_rows) == 2
    assert len(alerts_rows) >= 1
    assert meta["counts"]["validated_sources"] == 2
    assert meta["counts"]["issues_public"] == 2
