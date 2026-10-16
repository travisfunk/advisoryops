"""SBOM catalog completeness, publication lifecycle and browser engine behavior."""

import json
from pathlib import Path
import shutil
import subprocess

import pytest

from advisoryops.feed_archive import publish_archive
from advisoryops.sbom_catalog import write_sbom_catalog

ROOT = Path(__file__).resolve().parents[1]


def test_catalog_preserves_old_records_and_evidence_without_private_or_blob_fields(
    tmp_path,
):
    rows = [
        {
            "issue_id": "old",
            "affected_products": ["Apache Log4j"],
            "affected_versions": ["before 2.17"],
            "raw_text": "large source",
            "signals": ["private"],
            "vendor": "Apache",
        },
        {"issue_id": "new", "title": "No identity metadata"},
    ]
    path = tmp_path / "catalog.json"
    catalog = write_sbom_catalog(rows, path, generated_at="2026-10-16T00:00:00Z")
    assert json.loads(path.read_text()) == catalog
    assert catalog["total_records"] == 2
    assert catalog["records_with_products"] == 1
    old = next(r for r in catalog["issues"] if r["issue_id"] == "old")
    assert old["affected_versions"] == ["before 2.17"]
    assert "raw_text" not in old
    assert "signals" not in old


def test_archive_publication_includes_sbom_full_history_even_when_latest_is_bounded(
    tmp_path,
):
    source = tmp_path / "source.json"
    rows = [
        {"issue_id": str(i), "affected_products": [f"Vendor Product {i}"]}
        for i in range(8)
    ]
    source.write_text(json.dumps(rows))
    publish_archive(
        source_path=source, docs_dir=tmp_path / "docs", latest_count=2, shard_count=2
    )
    catalog = json.loads((tmp_path / "docs/sbom_advisories.json").read_text())
    manifest = json.loads((tmp_path / "docs/feed_archive/manifest.json").read_text())
    assert catalog["total_records"] == 8
    assert [r["issue_id"] for r in catalog["issues"]] == [str(i) for i in range(8)]
    assert catalog["generated_at"] == manifest["generated_at"]


def test_dashboard_sbom_behavior():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js required for dashboard behavior checks")
    subprocess.run([node, "tests/dashboard_sbom_cases.js"], cwd=ROOT, check=True)


def test_published_sbom_assets_match_source():
    for name in ("index.html", "sbom.js", "sbom-ui.js"):
        assert (ROOT / "dashboard" / name).read_bytes() == (
            ROOT / "docs" / name
        ).read_bytes()


def test_catalog_failure_keeps_existing_published_snapshot(tmp_path, monkeypatch):
    import advisoryops.sbom_catalog as catalog_module

    docs = tmp_path / "docs"
    source = tmp_path / "source.json"
    source.write_text(
        json.dumps([{"issue_id": "one", "affected_products": ["OpenSSL"]}])
    )
    publish_archive(source_path=source, docs_dir=docs, latest_count=1, shard_count=2)
    before = {
        p.relative_to(docs): p.read_bytes() for p in docs.rglob("*") if p.is_file()
    }
    source.write_text(json.dumps([{"issue_id": "one"}, {"issue_id": "two"}]))

    def failed_catalog(*args, **kwargs):
        raise RuntimeError("catalog size guard")

    monkeypatch.setattr(catalog_module, "write_sbom_catalog", failed_catalog)
    with pytest.raises(RuntimeError, match="catalog size guard"):
        publish_archive(
            source_path=source, docs_dir=docs, latest_count=1, shard_count=2
        )
    after = {
        p.relative_to(docs): p.read_bytes() for p in docs.rglob("*") if p.is_file()
    }
    assert after == before


def test_community_publication_copies_browser_import_script(tmp_path):
    from advisoryops.community_build import _publish_to_docs

    root = tmp_path / "repo"
    (root / "dashboard").mkdir(parents=True)
    (root / "dashboard/index.html").write_text('<script src="sbom.js"></script>')
    (root / "dashboard/sbom.js").write_text("window.AdvisorySBOM = {};")
    (root / "dashboard/sbom-ui.js").write_text("// Browser controller")
    community = tmp_path / "community"
    community.mkdir()
    _publish_to_docs(community, root)
    for name in ("sbom.js", "sbom-ui.js"):
        assert (root / "docs" / name).read_bytes() == (
            root / "dashboard" / name
        ).read_bytes()


def test_dashboard_sbom_controller_behavior():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js required for dashboard controller checks")
    subprocess.run([node, "tests/dashboard_sbom_ui_cases.js"], cwd=ROOT, check=True)
