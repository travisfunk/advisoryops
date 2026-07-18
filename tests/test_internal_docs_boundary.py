"""Guard: internal working docs must never be git-tracked in the public repo.

session_state.md, recon_exposure_tagging.md, and internal/ were briefly,
accidentally committed to public origin/main (merge commit b689b87) before
being moved into internal/ and gitignored. This test makes the boundary
enforced rather than remembered — it fails if anything matching the
forbidden patterns below is ever tracked by git again, regardless of how it
got there (a plain `git add`, a `git add -f` bypassing .gitignore, a rebase
that resurrects a deleted file, etc.).
"""
from __future__ import annotations

import fnmatch
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Patterns are matched against the full repo-relative path (POSIX-style,
# as returned by `git ls-files`) using fnmatch, so `internal/**` must be
# expressed as `internal/*` (fnmatch has no `**`) plus the bare `internal`
# directory-prefix check below.
_FORBIDDEN_PATTERNS = (
    "session_state*",
    "recon_*",
    "*_INTERNAL*",
)
_FORBIDDEN_DIR_PREFIXES = (
    "internal/",
)


def _tracked_files() -> list:
    result = subprocess.run(
        ["git", "ls-files"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return [line for line in result.stdout.splitlines() if line.strip()]


class TestInternalDocsNotTracked:
    def test_no_tracked_file_matches_forbidden_patterns(self):
        tracked = _tracked_files()
        violations = []
        for path in tracked:
            basename = path.rsplit("/", 1)[-1]
            for pattern in _FORBIDDEN_PATTERNS:
                # fnmatchcase, not fnmatch: fnmatch is case-insensitive on
                # Windows, which would make e.g. "scoring_internals.md"
                # (a legitimate public doc) falsely match "*_INTERNAL*".
                # The uppercase _INTERNAL / lowercase recon_/session_state
                # casing in the patterns is intentional and load-bearing.
                if fnmatch.fnmatchcase(basename, pattern) or fnmatch.fnmatchcase(path, pattern):
                    violations.append((path, pattern))
            for prefix in _FORBIDDEN_DIR_PREFIXES:
                if path == prefix.rstrip("/") or path.startswith(prefix):
                    violations.append((path, prefix))

        assert not violations, (
            "Internal working docs are git-tracked in the public repo — this must "
            "never happen (session_state.md and recon_exposure_tagging.md were "
            "accidentally merged to public main once already; see internal/BACKLOG.md "
            "P1 and internal/session_state.md addendum). Untrack with "
            "`git rm --cached <path>` and confirm .gitignore covers it. "
            f"Violations (path, matched pattern): {violations}"
        )

    def test_internal_directory_is_gitignored(self):
        """Belt-and-suspenders: even if nothing is tracked yet, internal/
        must be declared in .gitignore so a plain `git add .` can't pull
        it in by accident."""
        gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
        lines = [ln.strip() for ln in gitignore.splitlines()]
        assert "internal/" in lines or "internal" in lines, (
            "internal/ is not declared in .gitignore — add it so internal working "
            "docs can't be accidentally `git add`-ed into the public repo."
        )
