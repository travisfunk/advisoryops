"""Tests for _publish_to_docs — the dashboard publish step."""

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "src"))

from advisoryops.community_build import _publish_to_docs


# ── helpers ────────────────────────────────────────────────────────────────

def _make_feed(n: int):
    """Return a JSON-serialised list of n minimal issue dicts."""
    return json.dumps([{"id": f"ISSUE-{i}"} for i in range(n)])


def _make_repo(tmp_path, baseline_count=None):
    """Create a minimal repo layout; optionally seed docs/feed_latest.json."""
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    (repo_root / "dashboard").mkdir()
    (repo_root / "dashboard" / "index.html").write_text("<html/>", encoding="utf-8")
    if baseline_count is not None:
        docs_dir = repo_root / "docs"
        docs_dir.mkdir()
        (docs_dir / "feed_latest.json").write_text(_make_feed(baseline_count), encoding="utf-8")
        # Simulate existing meta.json and feed.xml so we can check they are NOT
        # overwritten when the guard aborts.
        (docs_dir / "meta.json").write_text('{"counts":{"issues_public":' + str(baseline_count) + '}}', encoding="utf-8")
        (docs_dir / "feed.xml").write_text("<rss>baseline</rss>", encoding="utf-8")
    return repo_root


def _make_community(tmp_path, new_count):
    """Create outputs/community_public with a new feed of *new_count* issues."""
    community_root = tmp_path / "community"
    community_root.mkdir()
    (community_root / "feed_latest.json").write_text(_make_feed(new_count), encoding="utf-8")
    (community_root / "meta.json").write_text('{"counts":{"issues_public":' + str(new_count) + '}}', encoding="utf-8")
    (community_root / "feed.xml").write_text("<rss>new</rss>", encoding="utf-8")
    (community_root / "feed_healthcare.json").write_text("[]", encoding="utf-8")
    return community_root


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


# ── atomic guard — healthy path ────────────────────────────────────────────

def test_healthy_run_publishes_all_files(tmp_path):
    """Healthy run (new >= baseline): all docs/ files are updated atomically.

    Proves that feed_latest.json, meta.json, feed.xml, and feed_healthcare.json
    all receive the new data when the guard passes.
    """
    BASELINE = 100
    NEW = 105  # grew — normal case

    repo_root = _make_repo(tmp_path, baseline_count=BASELINE)
    community_root = _make_community(tmp_path, new_count=NEW)
    docs = repo_root / "docs"

    _publish_to_docs(community_root, repo_root)

    # All data files must be present with new content
    new_feed = json.loads((docs / "feed_latest.json").read_text(encoding="utf-8"))
    assert len(new_feed) == NEW, f"feed_latest.json: expected {NEW} issues, got {len(new_feed)}"

    meta = json.loads((docs / "meta.json").read_text(encoding="utf-8"))
    assert meta["counts"]["issues_public"] == NEW, "meta.json: counts.issues_public not updated"

    feed_xml = (docs / "feed.xml").read_text(encoding="utf-8")
    assert feed_xml == "<rss>new</rss>", "feed.xml: not updated to new content"

    assert (docs / "feed_healthcare.json").exists(), "feed_healthcare.json: missing after healthy run"


def test_quiet_day_equal_count_is_allowed(tmp_path):
    """Equal count (quiet day, 0 new issues but baseline carried forward) must pass.

    The floor rule uses >=, not >.  A count equal to baseline is a valid
    additive-build outcome when no new advisories were published today.
    """
    BASELINE = 100
    NEW = 100  # exactly equal — quiet day

    repo_root = _make_repo(tmp_path, baseline_count=BASELINE)
    community_root = _make_community(tmp_path, new_count=NEW)
    docs = repo_root / "docs"

    _publish_to_docs(community_root, repo_root)  # must not raise

    new_feed = json.loads((docs / "feed_latest.json").read_text(encoding="utf-8"))
    assert len(new_feed) == NEW


# ── atomic guard — broken path ─────────────────────────────────────────────

def test_degraded_run_aborts_entire_commit(tmp_path):
    """Broken run (new < baseline): RuntimeError raised, NO docs/ file is touched.

    This is the core atomicity proof: meta.json, feed.xml, and every other
    file must remain at baseline values.  Before this fix only feed_latest.json
    was protected; meta.json and feed.xml could silently receive bad data.
    """
    BASELINE = 100
    NEW = 0  # completely empty — degraded run

    repo_root = _make_repo(tmp_path, baseline_count=BASELINE)
    community_root = _make_community(tmp_path, new_count=NEW)
    docs = repo_root / "docs"

    with pytest.raises(RuntimeError, match="Publish aborted"):
        _publish_to_docs(community_root, repo_root)

    # feed_latest.json must still have the baseline (100 issues)
    surviving_feed = json.loads((docs / "feed_latest.json").read_text(encoding="utf-8"))
    assert len(surviving_feed) == BASELINE, (
        f"feed_latest.json was overwritten! has {len(surviving_feed)} issues, expected {BASELINE}"
    )

    # meta.json must still have baseline count — the dashboard-header bug
    surviving_meta = json.loads((docs / "meta.json").read_text(encoding="utf-8"))
    assert surviving_meta["counts"]["issues_public"] == BASELINE, (
        f"meta.json was overwritten! shows {surviving_meta['counts']['issues_public']} issues"
    )

    # feed.xml must be untouched — baseline RSS content preserved
    surviving_xml = (docs / "feed.xml").read_text(encoding="utf-8")
    assert surviving_xml == "<rss>baseline</rss>", (
        f"feed.xml was overwritten! content: {surviving_xml!r}"
    )


def test_degraded_partial_run_aborts_entire_commit(tmp_path):
    """Partial degraded run (shrank below baseline): same abort guarantee.

    Covers the case where some sources returned data but fewer total issues
    than the committed feed — e.g., a source that used to contribute 200 issues
    returns only 10 and the baseline merge was not invoked.
    """
    BASELINE = 100
    NEW = 50  # shrank — degraded

    repo_root = _make_repo(tmp_path, baseline_count=BASELINE)
    community_root = _make_community(tmp_path, new_count=NEW)
    docs = repo_root / "docs"

    with pytest.raises(RuntimeError, match="Publish aborted"):
        _publish_to_docs(community_root, repo_root)

    surviving_feed = json.loads((docs / "feed_latest.json").read_text(encoding="utf-8"))
    assert len(surviving_feed) == BASELINE

    surviving_meta = json.loads((docs / "meta.json").read_text(encoding="utf-8"))
    assert surviving_meta["counts"]["issues_public"] == BASELINE


def test_first_ever_build_no_baseline_always_allowed(tmp_path):
    """No baseline in docs/ (first-ever build): any non-empty feed is published.

    baseline_count = 0 when docs/feed_latest.json doesn't exist.
    Any new_count >= 0 passes the guard, so first builds are never blocked.
    """
    repo_root = _make_repo(tmp_path, baseline_count=None)  # no baseline file
    community_root = _make_community(tmp_path, new_count=42)

    _publish_to_docs(community_root, repo_root)  # must not raise

    docs = repo_root / "docs"
    new_feed = json.loads((docs / "feed_latest.json").read_text(encoding="utf-8"))
    assert len(new_feed) == 42
