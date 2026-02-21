from __future__ import annotations

import inspect
import json
from pathlib import Path

from advisoryops.correlate import correlate


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


def _call_correlate(*, out_root_discover: str, out_root_correlate: str, sources=None):
    # call correlate() using whatever kwarg name the current signature expects
    sig = inspect.signature(correlate)
    kwargs = {"out_root_discover": out_root_discover, "sources": sources}
    if "out_root_correlate" in sig.parameters:
        kwargs["out_root_correlate"] = out_root_correlate
    elif "out_root_issues" in sig.parameters:
        kwargs["out_root_issues"] = out_root_correlate
    elif "out_root" in sig.parameters:
        kwargs["out_root"] = out_root_correlate
    else:
        raise TypeError("correlate() missing an output-root parameter")
    return correlate(**kwargs)


def _issues_path(out_root_correlate: Path, result):
    # correlate currently returns (issues_path, meta_path) in your repo; fall back safely
    if isinstance(result, tuple) and len(result) >= 1 and result[0]:
        return Path(result[0])
    return out_root_correlate / "issues.jsonl"


def test_correlate_dedup_two_sources_same_cve(tmp_path: Path) -> None:
    discover = tmp_path / "discover"
    outcorr = tmp_path / "correlate"

    _write_jsonl(discover / "a" / "items.jsonl", [{
        "source": "a",
        "guid": "CVE-2025-00001",
        "title": "CVE-2025-00001",
        "summary": "short",
        "link": "https://example.com/a",
        "published_date": "2026-02-01",
        "fetched_at": "2026-02-20T00:00:00+00:00",
        "signal_id": "sa",
    }])

    _write_jsonl(discover / "b" / "items.jsonl", [{
        "source": "b",
        "guid": "CVE-2025-00001",
        "title": "Patch for CVE-2025-00001",
        "summary": "longer summary text",
        "link": "https://example.com/b",
        "published_date": "2026-02-02",
        "fetched_at": "2026-02-20T00:00:01+00:00",
        "signal_id": "sb",
    }])

    res = _call_correlate(out_root_discover=str(discover), out_root_correlate=str(outcorr), sources=["a", "b"])
    issues_path = _issues_path(outcorr, res)
    lines = issues_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    obj = json.loads(lines[0])
    assert obj["issue_id"] == "CVE-2025-00001"
    assert set(obj["sources"]) == {"a", "b"}
    assert obj["counts"]["sources"] == 2


def test_cve_issue_title_must_match_issue_id_even_with_multi_cve_signal(tmp_path: Path) -> None:
    discover = tmp_path / "discover"
    outcorr = tmp_path / "correlate"

    # One signal mentions two CVEs, but its TITLE is the "other" CVE.
    _write_jsonl(discover / "x" / "items.jsonl", [{
        "source": "x",
        "guid": "x-1",
        "title": "CVE-2024-58136",
        "summary": "Impacts CVE-2025-32432 and CVE-2024-58136",
        "link": "https://example.com/x",
        "published_date": "2026-02-03",
        "fetched_at": "2026-02-20T00:00:02+00:00",
        "signal_id": "sx",
    }])

    res = _call_correlate(out_root_discover=str(discover), out_root_correlate=str(outcorr), sources=["x"])
    issues_path = _issues_path(outcorr, res)
    objs = [json.loads(l) for l in issues_path.read_text(encoding="utf-8").splitlines()]

    # We should have two issues (one per CVE), and each CVE issue's title must contain its own CVE.
    by_id = {o["issue_id"]: o for o in objs}
    assert "CVE-2025-32432" in by_id
    assert "CVE-2024-58136" in by_id

    assert "CVE-2025-32432" in (by_id["CVE-2025-32432"]["title"] or "")
    assert "CVE-2024-58136" in (by_id["CVE-2024-58136"]["title"] or "")
