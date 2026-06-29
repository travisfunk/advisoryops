#!/usr/bin/env python3
"""MHRA UK medical device alerts backfill launcher.

Pulls all ~1,381 alerts. Estimated time: 2-5 minutes.

Usage:
    python scripts/backfill_mhra_uk.py
    python scripts/backfill_mhra_uk.py --limit 200
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from backfill_common import base_argparser, print_summary, setup_logging


def main():
    parser = base_argparser("MHRA UK medical device alerts full backfill")
    args = parser.parse_args()

    logger = setup_logging("mhra_uk")
    logger.info("Starting MHRA UK backfill (limit=%s)", args.limit or "all")

    from advisoryops.sources.mhra_uk_backfill import run_backfill

    start = time.monotonic()
    stats = run_backfill(max_results=args.limit)
    print_summary("MHRA UK", stats, start)
    return 0


if __name__ == "__main__":
    sys.exit(main())
