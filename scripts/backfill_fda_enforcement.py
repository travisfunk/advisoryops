#!/usr/bin/env python3
"""FDA device enforcement historical backfill launcher.

Pulls all ~38,500 enforcement records. Estimated time: 20-40 minutes.

Usage:
    python scripts/backfill_fda_enforcement.py
    python scripts/backfill_fda_enforcement.py --limit 1000
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from backfill_common import base_argparser, print_summary, setup_logging


def main():
    parser = base_argparser("FDA device enforcement full backfill")
    args = parser.parse_args()

    logger = setup_logging("fda_enforcement")
    logger.info("Starting FDA enforcement backfill (limit=%s)", args.limit or "all")

    from advisoryops.sources.fda_safety_comms_backfill import run_backfill

    start = time.monotonic()
    stats = run_backfill(max_results=args.limit)
    print_summary("FDA Enforcement", stats, start)
    return 0


if __name__ == "__main__":
    sys.exit(main())
