#!/usr/bin/env python3
"""CISA ICSMA historical backfill launcher.

Pulls all ~182 ICS Medical Advisories from CSV + CSAF enrichment.
Estimated time: 3-5 minutes.

Usage:
    python scripts/backfill_cisa_icsma.py
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from backfill_common import base_argparser, print_summary, setup_logging


def main():
    parser = base_argparser("CISA ICSMA full archive backfill")
    args = parser.parse_args()

    logger = setup_logging("cisa_icsma")
    logger.info("Starting CISA ICSMA backfill")

    from advisoryops.sources.cisa_icsma_backfill import run_backfill

    start = time.monotonic()
    stats = run_backfill()
    print_summary("CISA ICSMA", stats, start)
    return 0


if __name__ == "__main__":
    sys.exit(main())
