"""Tests for advisoryops.change_tracker (Task 8.7)."""
from __future__ import annotations

import json
import pytest
from pathlib import Path

from advisoryops.change_tracker import (
    detect_changes,
    load_snapshot,
    write_changes,
    save_snapshot,
    _patch_status,
)


# ---------------------------------------------------------------------------
# Patch status helper
# ---------------------------------------------------------------------------

class TestPatchStatus:
    def test_patch_available(self):
        assert _patch_status({"title": "Patch released", "summary": ""}) == "patch_available"

    def test_no_patch(self):
        assert _patch_status({"title": "", "summary": "No patch available"}) == "no_patch"

    def test_unknown(self):
        assert _patch_status({"title": "Some vuln", "summary": "Details"}) == "unknown"

    def test_mixed(self):
        assert _patch_status({"title": "No fix yet", "summary": "Patch released"}) == "mixed"


# ---------------------------------------------------------------------------
# detect_changes
# ---------------------------------------------------------------------------

class TestDetectChanges:
    TS = "2026-03-23T00:00:00+00:00"

    def _issue(self, issue_id, **overrides):
        base = {
            "issue_id": issue_id,
            "title": f"Test issue {issue_id}",
            "summary": "",
            "priority": "P2",
            "score": 50,
            "sources": ["src_a"],
            "cves": [issue_id] if issue_id.startswith("CVE") else [],
        }
        base.update(overrides)
        return base

    def test_new_issue_detected(self):
        current = [self._issue("CVE-2024-0001")]
        previous = []
        changes = detect_changes(current, previous, detected_at=self.TS)
        assert len(changes) == 1
        assert changes[0]["change_type"] == "new_issue"
        assert changes[0]["issue_id"] == "CVE-2024-0001"

    def test_removed_issue_detected(self):
        current = []
        previous = [self._issue("CVE-2024-0001")]
        changes = detect_changes(current, previous, detected_at=self.TS)
        assert len(changes) == 1
        assert changes[0]["change_type"] == "removed_issue"

    def test_severity_change(self):
        current = [self._issue("CVE-2024-0001", priority="P1")]
        previous = [self._issue("CVE-2024-0001", priority="P2")]
        changes = detect_changes(current, previous, detected_at=self.TS)
        sev_changes = [c for c in changes if c["change_type"] == "severity_changed"]
        assert len(sev_changes) == 1
        assert sev_changes[0]["previous_value"] == "P2"
        assert sev_changes[0]["new_value"] == "P1"

    def test_score_change_significant(self):
        current = [self._issue("CVE-2024-0001", score=80)]
        previous = [self._issue("CVE-2024-0001", score=50)]
        changes = detect_changes(current, previous, detected_at=self.TS)
        score_changes = [c for c in changes if c["change_type"] == "score_changed"]
        assert len(score_changes) == 1

    def test_score_change_below_threshold_ignored(self):
        current = [self._issue("CVE-2024-0001", score=55)]
        previous = [self._issue("CVE-2024-0001", score=50)]
        changes = detect_changes(current, previous, detected_at=self.TS)
        score_changes = [c for c in changes if c["change_type"] == "score_changed"]
        assert len(score_changes) == 0

    def test_new_source(self):
        current = [self._issue("CVE-2024-0001", sources=["src_a", "src_b"])]
        previous = [self._issue("CVE-2024-0001", sources=["src_a"])]
        changes = detect_changes(current, previous, detected_at=self.TS)
        src_changes = [c for c in changes if c["change_type"] == "new_source"]
        assert len(src_changes) == 1
        assert "src_b" in src_changes[0]["summary"]

    def test_new_cve_added(self):
        current = [self._issue("CVE-2024-0001", cves=["CVE-2024-0001", "CVE-2024-9999"])]
        previous = [self._issue("CVE-2024-0001", cves=["CVE-2024-0001"])]
        changes = detect_changes(current, previous, detected_at=self.TS)
        cve_changes = [c for c in changes if c["change_type"] == "cve_added"]
        assert len(cve_changes) == 1
        assert "CVE-2024-9999" in cve_changes[0]["summary"]

    def test_patch_status_change(self):
        current = [self._issue("CVE-2024-0001", title="Patch released for v2", summary="")]
        previous = [self._issue("CVE-2024-0001", title="", summary="No fix available")]
        changes = detect_changes(current, previous, detected_at=self.TS)
        patch_changes = [c for c in changes if c["change_type"] == "patch_status_changed"]
        assert len(patch_changes) == 1
        assert patch_changes[0]["new_value"] == "patch_available"

    def test_no_changes_when_identical(self):
        issue = self._issue("CVE-2024-0001")
        changes = detect_changes([issue], [issue.copy()], detected_at=self.TS)
        assert changes == []

    def test_multiple_changes_same_issue(self):
        current = [self._issue("CVE-2024-0001", priority="P0", score=120, sources=["src_a", "src_b"])]
        previous = [self._issue("CVE-2024-0001", priority="P2", score=50, sources=["src_a"])]
        changes = detect_changes(current, previous, detected_at=self.TS)
        types = {c["change_type"] for c in changes}
        assert "severity_changed" in types
        assert "score_changed" in types
        assert "new_source" in types

    def test_detected_at_in_all_records(self):
        current = [self._issue("CVE-2024-0001")]
        previous = []
        changes = detect_changes(current, previous, detected_at=self.TS)
        for c in changes:
            assert c["detected_at"] == self.TS


# ---------------------------------------------------------------------------
# Snapshot I/O
# ---------------------------------------------------------------------------

class TestSnapshotIO:
    def test_save_and_load(self, tmp_path):
        issues = [
            {"issue_id": "CVE-2024-0001", "title": "Test", "score": 50},
            {"issue_id": "CVE-2024-0002", "title": "Test2", "score": 80},
        ]
        path = tmp_path / "snapshot.jsonl"
        save_snapshot(issues, path)
        loaded = load_snapshot(path)
        assert len(loaded) == 2
        assert loaded[0]["issue_id"] == "CVE-2024-0001"

    def test_load_missing_file(self, tmp_path):
        assert load_snapshot(tmp_path / "nonexistent.jsonl") == []


class TestWriteChanges:
    def test_write_and_read(self, tmp_path):
        changes = [
            {"issue_id": "CVE-2024-0001", "change_type": "new_issue", "summary": "New"},
        ]
        path = tmp_path / "changes.jsonl"
        write_changes(changes, path)
        lines = path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        assert json.loads(lines[0])["change_type"] == "new_issue"

    def test_append_mode(self, tmp_path):
        path = tmp_path / "changes.jsonl"
        write_changes([{"issue_id": "a", "change_type": "new_issue"}], path)
        write_changes([{"issue_id": "b", "change_type": "new_issue"}], path)
        lines = path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 2
