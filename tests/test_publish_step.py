"""Tests for _publish_to_docs — the dashboard publish step."""

import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "src"))

from advisoryops.community_build import _publish_to_docs


def test_copies_dashboard_html(tmp_path):
    """_publish_to_docs copies dashboard/index.html to docs/index.html."""
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    dashboard_dir = repo_root / "dashboard"
    dashboard_dir.mkdir()
    (dashboard_dir / "index.html").write_text("<html>dashboard</html>", encoding="utf-8")
    community_root = tmp_path / "community"
    community_root.mkdir()

    _publish_to_docs(community_root, repo_root)

    docs_index = repo_root / "docs" / "index.html"
    assert docs_index.exists()
    assert docs_index.read_text(encoding="utf-8") == "<html>dashboard</html>"


def test_copies_feed_files(tmp_path):
    """_publish_to_docs copies feed files from community_root to docs/."""
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    (repo_root / "dashboard").mkdir()
    (repo_root / "dashboard" / "index.html").write_text("<html/>", encoding="utf-8")
    community_root = tmp_path / "community"
    community_root.mkdir()
    (community_root / "feed_latest.json").write_text('{"test": 1}', encoding="utf-8")
    (community_root / "validated_sources.json").write_text("[]", encoding="utf-8")
    (community_root / "meta.json").write_text("{}", encoding="utf-8")

    _publish_to_docs(community_root, repo_root)

    docs = repo_root / "docs"
    assert (docs / "feed_latest.json").exists()
    assert (docs / "validated_sources.json").exists()
    assert (docs / "meta.json").exists()


def test_no_error_when_sources_missing(tmp_path):
    """_publish_to_docs does not error when source files are missing."""
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    community_root = tmp_path / "community"
    community_root.mkdir()
    # No dashboard/index.html, no feed files — should not raise
    _publish_to_docs(community_root, repo_root)
    # docs/ should still be created
    assert (repo_root / "docs").exists()


def test_creates_docs_dir(tmp_path):
    """_publish_to_docs creates docs/ if it doesn't exist."""
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    community_root = tmp_path / "community"
    community_root.mkdir()
    assert not (repo_root / "docs").exists()

    _publish_to_docs(community_root, repo_root)

    assert (repo_root / "docs").is_dir()
