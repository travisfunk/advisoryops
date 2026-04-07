#!/usr/bin/env python3
"""openFDA device recalls historical backfill launcher.

Pulls all ~60,000 device recalls. Estimated time: 30-60 minutes.

Usage:
    python scripts/backfill_openfda_recalls.py
    python scripts/backfill_openfda_recalls.py --limit 1000
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from backfill_common import base_argparser, print_summary, setup_logging


def main():
    parser = base_argparser("openFDA device recalls full backfill")
    args = parser.parse_args()

    logger = setup_logging("openfda_recalls")
    logger.info("Starting openFDA recalls backfill (limit=%s)", args.limit or "all")

    from advisoryops.sources.openfda_backfill import run_backfill

    start = time.monotonic()
    stats = run_backfill(max_results=args.limit)
    print_summary("openFDA Recalls", stats, start)
    return 0


if __name__ == "__main__":
    sys.exit(main())
