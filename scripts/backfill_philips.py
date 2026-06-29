#!/usr/bin/env python3
"""Philips PSIRT advisory backfill launcher.

Scrapes yearly archive pages (2017-present). ~200 advisories.
Estimated time: 1-3 minutes.

Usage:
    python scripts/backfill_philips.py
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from backfill_common import base_argparser, print_summary, setup_logging


def main():
    parser = base_argparser("Philips PSIRT advisory backfill")
    args = parser.parse_args()

    logger = setup_logging("philips")
    logger.info("Starting Philips PSIRT backfill")

    from advisoryops.sources.philips_psirt_backfill import run_backfill

    start = time.monotonic()
    stats = run_backfill()
    print_summary("Philips PSIRT", stats, start)
    return 0


if __name__ == "__main__":
    sys.exit(main())
