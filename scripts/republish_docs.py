#!/usr/bin/env python3
"""Re-run _publish_to_docs() against existing pipeline output.

Usage:
    python scripts/republish_docs.py [--community-root outputs/community_public]

Copies the dashboard HTML and all generated data files from the pipeline
output directory into docs/ for GitHub Pages serving.  No pipeline run,
no API calls, no cost — pure file copy.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from advisoryops.community_build import _publish_to_docs


def main() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--community-root",
        type=Path,
        default=repo_root / "outputs" / "community_public",
        help="Pipeline output directory (default: outputs/community_public)",
    )
    args = parser.parse_args()

    if not args.community_root.exists():
        raise SystemExit(f"Community root does not exist: {args.community_root}")

    _publish_to_docs(args.community_root, repo_root)


if __name__ == "__main__":
    main()
