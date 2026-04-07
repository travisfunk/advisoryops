#!/usr/bin/env python3
"""Health Canada medical device recalls backfill launcher.

Pulls recent recalls from the Health Canada API.
The API returns ~15 recent health product recalls per call.
Estimated time: 1-2 minutes.

Usage:
    python scripts/backfill_health_canada.py
    python scripts/backfill_health_canada.py --limit 50
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from backfill_common import base_argparser, print_summary, setup_logging


def main():
    parser = base_argparser("Health Canada medical device recalls backfill")
    args = parser.parse_args()

    logger = setup_logging("health_canada")
    logger.info("Starting Health Canada backfill (limit=%s)", args.limit or "all")

    from advisoryops.sources.health_canada_backfill import run_backfill

    start = time.monotonic()
    stats = run_backfill(max_results=args.limit)
    print_summary("Health Canada", stats, start)
    return 0


if __name__ == "__main__":
    sys.exit(main())
