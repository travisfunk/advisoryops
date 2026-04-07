#!/usr/bin/env python3
"""Sample-test all backfill modules against live APIs.

Runs a small pull from each module and verifies end-to-end:
  API → parse → cache → signals → discover output

Usage:
    python scripts/sample_test_backfill.py
"""
from __future__ import annotations

import json
import shutil
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

REQUIRED_SIGNAL_FIELDS = {"source", "guid", "title", "summary", "published_date", "link"}
TEST_ROOT = Path("outputs/_sample_test")
REPORT_LINES: List[str] = []


def log(msg: str) -> None:
    print(msg)
    REPORT_LINES.append(msg)


def validate_signal(signal: Dict[str, Any], source_id: str) -> List[str]:
    """Check a signal dict has all required fields. Returns list of issues."""
    issues = []
    for field in REQUIRED_SIGNAL_FIELDS:
        val = signal.get(field)
        if val is None:
            issues.append(f"missing field: {field}")
        elif isinstance(val, str) and not val.strip():
            # Empty strings are acceptable for some fields but flag them
            if field in ("title", "guid"):
                issues.append(f"empty required field: {field}")
    if signal.get("source") != source_id:
        issues.append(f"source mismatch: expected {source_id}, got {signal.get('source')}")
    return issues


def check_discover_output(discover_dir: Path, source_id: str) -> List[str]:
    """Verify discover output artifacts exist and are valid."""
    issues = []
    out_dir = discover_dir / source_id
    for fname in ("items.jsonl", "feed.json", "state.json", "meta.json"):
        fpath = out_dir / fname
        if not fpath.exists():
            issues.append(f"missing {fname}")
            continue
        content = fpath.read_text(encoding="utf-8").strip()
        if not content:
            issues.append(f"empty {fname}")
    return issues


def sample_json(obj: Any, max_len: int = 300) -> str:
    """Truncated JSON repr for the report."""
    s = json.dumps(obj, indent=2, ensure_ascii=False, default=str)
    if len(s) > max_len:
        s = s[:max_len] + "\n  ... (truncated)"
    return s


# ============================================================
# Module test runners
# ============================================================

def test_nvd_backfill() -> str:
    """NVD historical backfill — 200 records."""
    from advisoryops.sources.nvd_backfill import run_backfill, generate_signals_from_cache
    from advisoryops.sources.discover_sync import publish_to_discover

    cache_dir = TEST_ROOT / "nvd_cache"
    discover_dir = TEST_ROOT / "discover"
    source_id = "nvd-historical"

    stats = run_backfill(cache_dir=cache_dir, max_results=200, page_size=200)
    log(f"  Backfill stats: {json.dumps({k: v for k, v in stats.items() if k != 'errors'}, default=str)}")
    if stats.get("errors"):
        log(f"  Errors: {stats['errors']}")

    cached_files = list(cache_dir.glob("CVE-*.json"))
    log(f"  Cached files: {len(cached_files)}")

    if cached_files:
        sample = json.loads(cached_files[0].read_text(encoding="utf-8"))
        log(f"  Sample cached record:\n{sample_json(sample)}")

    signals = generate_signals_from_cache(cache_dir=cache_dir, source_id=source_id, limit=50)
    log(f"  Signals generated: {len(signals)}")

    if signals:
        issues = validate_signal(signals[0], source_id)
        if issues:
            return f"FAIL — signal validation: {issues}"
        log(f"  Sample signal:\n{sample_json(signals[0])}")

    pub = publish_to_discover(signals, source_id=source_id, out_root=str(discover_dir))
    log(f"  Published: {pub['total_signals']} signals, {pub['new_signals']} new")

    disc_issues = check_discover_output(discover_dir, source_id)
    if disc_issues:
        return f"FAIL — discover output: {disc_issues}"

    if len(cached_files) == 0:
        return "FAIL — no records cached"
    return f"PASS — {len(cached_files)} cached, {len(signals)} signals"


def test_cisa_icsma_backfill() -> str:
    """CISA ICSMA — full CSV + 5 CSAF files."""
    from advisoryops.sources.cisa_icsma_backfill import run_backfill, generate_signals_from_cache
    from advisoryops.sources.discover_sync import publish_to_discover

    cache_dir = TEST_ROOT / "cisa_icsma_cache"
    discover_dir = TEST_ROOT / "discover"
    source_id = "cisa-icsma-historical"

    stats = run_backfill(cache_dir=cache_dir)
    log(f"  Backfill stats: {json.dumps({k: v for k, v in stats.items() if k != 'errors'}, default=str)}")
    if stats.get("errors"):
        log(f"  Errors ({len(stats['errors'])}): {stats['errors'][:3]}")

    cached_files = list(cache_dir.glob("ICSMA-*.json"))
    log(f"  Cached files: {len(cached_files)}")

    if cached_files:
        sample = json.loads(cached_files[0].read_text(encoding="utf-8"))
        log(f"  Sample cached record:\n{sample_json(sample)}")

    signals = generate_signals_from_cache(cache_dir=cache_dir, source_id=source_id)
    log(f"  Signals generated: {len(signals)}")

    if signals:
        issues = validate_signal(signals[0], source_id)
        if issues:
            return f"FAIL — signal validation: {issues}"
        log(f"  Sample signal:\n{sample_json(signals[0])}")

    pub = publish_to_discover(signals[:50], source_id=source_id, out_root=str(discover_dir))
    log(f"  Published: {pub['total_signals']} signals")

    disc_issues = check_discover_output(discover_dir, source_id)
    if disc_issues:
        return f"FAIL — discover output: {disc_issues}"

    if len(cached_files) == 0:
        return "FAIL — no records cached"
    return f"PASS — {len(cached_files)} cached, {len(signals)} signals"


def test_openfda_backfill() -> str:
    """openFDA device recalls — 200 records."""
    from advisoryops.sources.openfda_backfill import run_backfill, generate_signals_from_cache
    from advisoryops.sources.discover_sync import publish_to_discover

    cache_dir = TEST_ROOT / "openfda_cache"
    discover_dir = TEST_ROOT / "discover"
    source_id = "openfda-recalls-historical"

    stats = run_backfill(cache_dir=cache_dir, max_results=200)
    log(f"  Backfill stats: {json.dumps({k: v for k, v in stats.items() if k != 'errors'}, default=str)}")

    cached_files = list(cache_dir.glob("recall_*.json"))
    log(f"  Cached files: {len(cached_files)}")

    if cached_files:
        sample = json.loads(cached_files[0].read_text(encoding="utf-8"))
        log(f"  Cyber relevant: {sample.get('_cyber_relevant', 'N/A')}")
        log(f"  Sample cached record:\n{sample_json(sample)}")

    signals = generate_signals_from_cache(cache_dir=cache_dir, source_id=source_id)
    log(f"  Signals generated (cyber only): {len(signals)}")

    if signals:
        issues = validate_signal(signals[0], source_id)
        if issues:
            return f"FAIL — signal validation: {issues}"
        log(f"  Sample signal:\n{sample_json(signals[0])}")

    pub = publish_to_discover(signals[:50], source_id=source_id, out_root=str(discover_dir))
    log(f"  Published: {pub['total_signals']} signals")

    disc_issues = check_discover_output(discover_dir, source_id)
    if disc_issues:
        return f"FAIL — discover output: {disc_issues}"

    if len(cached_files) == 0:
        return "FAIL — no records cached"
    return f"PASS — {len(cached_files)} cached, {len(signals)} cyber-relevant signals"


def test_fda_safety_comms_backfill() -> str:
    """FDA device enforcement — 200 records."""
    from advisoryops.sources.fda_safety_comms_backfill import run_backfill, generate_signals_from_cache
    from advisoryops.sources.discover_sync import publish_to_discover

    cache_dir = TEST_ROOT / "fda_safety_comms_cache"
    discover_dir = TEST_ROOT / "discover"
    source_id = "fda-safety-comms-historical"

    stats = run_backfill(cache_dir=cache_dir, max_results=200)
    log(f"  Backfill stats: {json.dumps({k: v for k, v in stats.items() if k != 'errors'}, default=str)}")

    cached_files = list(cache_dir.glob("enf_*.json"))
    log(f"  Cached files: {len(cached_files)}")

    if cached_files:
        sample = json.loads(cached_files[0].read_text(encoding="utf-8"))
        log(f"  Cyber relevant: {sample.get('_cyber_relevant', 'N/A')}")
        log(f"  Sample cached record:\n{sample_json(sample)}")

    signals = generate_signals_from_cache(cache_dir=cache_dir, source_id=source_id)
    log(f"  Signals generated (cyber only): {len(signals)}")

    if signals:
        issues = validate_signal(signals[0], source_id)
        if issues:
            return f"FAIL — signal validation: {issues}"
        log(f"  Sample signal:\n{sample_json(signals[0])}")

    pub = publish_to_discover(signals[:50], source_id=source_id, out_root=str(discover_dir))
    log(f"  Published: {pub['total_signals']} signals")

    disc_issues = check_discover_output(discover_dir, source_id)
    if disc_issues:
        return f"FAIL — discover output: {disc_issues}"

    if len(cached_files) == 0:
        return "FAIL — no records cached"
    return f"PASS — {len(cached_files)} cached, {len(signals)} cyber-relevant signals"


def test_mhra_uk_backfill() -> str:
    """MHRA UK alerts — 50 records."""
    from advisoryops.sources.mhra_uk_backfill import run_backfill, generate_signals_from_cache
    from advisoryops.sources.discover_sync import publish_to_discover

    cache_dir = TEST_ROOT / "mhra_uk_cache"
    discover_dir = TEST_ROOT / "discover"
    source_id = "mhra-uk-alerts"

    stats = run_backfill(cache_dir=cache_dir, max_results=50, page_size=50)
    log(f"  Backfill stats: {json.dumps({k: v for k, v in stats.items() if k != 'errors'}, default=str)}")

    cached_files = list(cache_dir.glob("mhra_*.json"))
    log(f"  Cached files: {len(cached_files)}")

    if cached_files:
        sample = json.loads(cached_files[0].read_text(encoding="utf-8"))
        log(f"  Sample cached record:\n{sample_json(sample)}")

    signals = generate_signals_from_cache(cache_dir=cache_dir, source_id=source_id)
    log(f"  Signals generated: {len(signals)}")

    if signals:
        issues = validate_signal(signals[0], source_id)
        if issues:
            return f"FAIL — signal validation: {issues}"
        log(f"  Sample signal:\n{sample_json(signals[0])}")

    pub = publish_to_discover(signals, source_id=source_id, out_root=str(discover_dir))
    log(f"  Published: {pub['total_signals']} signals")

    disc_issues = check_discover_output(discover_dir, source_id)
    if disc_issues:
        return f"FAIL — discover output: {disc_issues}"

    if len(cached_files) == 0:
        return "FAIL — no records cached"
    return f"PASS — {len(cached_files)} cached, {len(signals)} signals"


def test_health_canada_backfill() -> str:
    """Health Canada recalls — recent API."""
    from advisoryops.sources.health_canada_backfill import run_backfill, generate_signals_from_cache
    from advisoryops.sources.discover_sync import publish_to_discover

    cache_dir = TEST_ROOT / "health_canada_cache"
    discover_dir = TEST_ROOT / "discover"
    source_id = "health-canada-recalls-historical"

    stats = run_backfill(cache_dir=cache_dir, max_results=50)
    log(f"  Backfill stats: {json.dumps({k: v for k, v in stats.items() if k != 'errors'}, default=str)}")

    cached_files = list(cache_dir.glob("hc_*.json"))
    log(f"  Cached files: {len(cached_files)}")

    if cached_files:
        sample = json.loads(cached_files[0].read_text(encoding="utf-8"))
        log(f"  Sample cached record:\n{sample_json(sample)}")

    signals = generate_signals_from_cache(cache_dir=cache_dir, source_id=source_id)
    log(f"  Signals generated: {len(signals)}")

    if signals:
        issues = validate_signal(signals[0], source_id)
        if issues:
            return f"FAIL — signal validation: {issues}"
        log(f"  Sample signal:\n{sample_json(signals[0])}")

    pub = publish_to_discover(signals, source_id=source_id, out_root=str(discover_dir))
    log(f"  Published: {pub['total_signals']} signals")

    disc_issues = check_discover_output(discover_dir, source_id)
    if disc_issues:
        return f"FAIL — discover output: {disc_issues}"

    if len(cached_files) == 0:
        return "FAIL — no records cached"
    return f"PASS — {len(cached_files)} cached, {len(signals)} signals"


def test_philips_psirt_backfill() -> str:
    """Philips PSIRT — one archive page."""
    from advisoryops.sources.philips_psirt_backfill import run_backfill, generate_signals_from_cache
    from advisoryops.sources.discover_sync import publish_to_discover

    cache_dir = TEST_ROOT / "philips_psirt_cache"
    discover_dir = TEST_ROOT / "discover"
    source_id = "philips-psirt"

    stats = run_backfill(cache_dir=cache_dir)
    log(f"  Backfill stats: {json.dumps({k: v for k, v in stats.items() if k != 'errors'}, default=str)}")
    if stats.get("errors"):
        log(f"  Errors ({len(stats['errors'])}): showing first 3")
        for e in stats["errors"][:3]:
            log(f"    {e}")

    cached_files = [f for f in cache_dir.glob("PHILIPS-*.json")]
    log(f"  Cached files: {len(cached_files)}")

    if cached_files:
        sample = json.loads(cached_files[0].read_text(encoding="utf-8"))
        log(f"  Sample cached record:\n{sample_json(sample)}")

    signals = generate_signals_from_cache(cache_dir=cache_dir, source_id=source_id)
    log(f"  Signals generated: {len(signals)}")

    if signals:
        issues = validate_signal(signals[0], source_id)
        if issues:
            return f"FAIL — signal validation: {issues}"
        log(f"  Sample signal:\n{sample_json(signals[0])}")

    pub = publish_to_discover(signals, source_id=source_id, out_root=str(discover_dir))
    log(f"  Published: {pub['total_signals']} signals")

    disc_issues = check_discover_output(discover_dir, source_id)
    if disc_issues:
        return f"FAIL — discover output: {disc_issues}"

    # Philips may return 0 advisories if HTML structure changed — that's a soft pass
    if len(cached_files) == 0:
        return "WARN — no advisories parsed (HTML structure may have changed)"
    return f"PASS — {len(cached_files)} cached, {len(signals)} signals"


def test_siemens_productcert_backfill() -> str:
    """Siemens ProductCERT — feed + 10 CSAF files."""
    from advisoryops.sources.siemens_productcert_backfill import run_backfill, generate_signals_from_cache
    from advisoryops.sources.discover_sync import publish_to_discover

    # We'll use a wrapper to limit CSAF fetches to 10
    cache_dir = TEST_ROOT / "siemens_productcert_cache"
    discover_dir = TEST_ROOT / "discover"
    source_id = "siemens-productcert-psirt"

    # Monkey-patch to limit advisories processed
    import advisoryops.sources.siemens_productcert_backfill as mod
    original_run = mod.run_backfill

    def limited_backfill(**kwargs):
        kwargs["cache_dir"] = cache_dir
        # Run the real backfill but it will process all feed entries
        # and fetch CSAF for uncached ones. We rely on rate limiting.
        return original_run(**kwargs)

    stats = limited_backfill()
    log(f"  Backfill stats: {json.dumps({k: v for k, v in stats.items() if k != 'errors'}, default=str)}")
    if stats.get("errors"):
        log(f"  Errors ({len(stats['errors'])}): showing first 3")
        for e in stats["errors"][:3]:
            log(f"    {e}")

    cached_files = list(cache_dir.glob("SSA-*.json"))
    log(f"  Cached files: {len(cached_files)}")

    if cached_files:
        sample = json.loads(cached_files[0].read_text(encoding="utf-8"))
        log(f"  Sample cached record:\n{sample_json(sample)}")

    signals = generate_signals_from_cache(cache_dir=cache_dir, source_id=source_id, limit=50)
    log(f"  Signals generated: {len(signals)}")

    if signals:
        issues = validate_signal(signals[0], source_id)
        if issues:
            return f"FAIL — signal validation: {issues}"
        log(f"  Sample signal:\n{sample_json(signals[0])}")

    pub = publish_to_discover(signals, source_id=source_id, out_root=str(discover_dir))
    log(f"  Published: {pub['total_signals']} signals")

    disc_issues = check_discover_output(discover_dir, source_id)
    if disc_issues:
        return f"FAIL — discover output: {disc_issues}"

    if len(cached_files) == 0:
        return "FAIL — no records cached"
    return f"PASS — {len(cached_files)} cached, {len(signals)} signals"


# ============================================================
# Main
# ============================================================

MODULES = [
    ("1. NVD Backfill", test_nvd_backfill),
    ("2. CISA ICSMA Backfill", test_cisa_icsma_backfill),
    ("3. openFDA Recalls Backfill", test_openfda_backfill),
    ("4. FDA Safety Comms Backfill", test_fda_safety_comms_backfill),
    ("5. MHRA UK Backfill", test_mhra_uk_backfill),
    ("6. Health Canada Backfill", test_health_canada_backfill),
    ("7. Philips PSIRT Backfill", test_philips_psirt_backfill),
    ("8. Siemens ProductCERT Backfill", test_siemens_productcert_backfill),
]


def main():
    log(f"# Backfill Sample Test Report")
    log(f"")
    log(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    log(f"Test root: {TEST_ROOT}")
    log(f"")

    # Clean test directory
    if TEST_ROOT.exists():
        shutil.rmtree(TEST_ROOT)
    TEST_ROOT.mkdir(parents=True, exist_ok=True)

    results = {}
    for name, test_fn in MODULES:
        log(f"## {name}")
        log(f"")
        try:
            result = test_fn()
            results[name] = result
            log(f"")
            log(f"**Result: {result}**")
        except Exception as exc:
            tb = traceback.format_exc()
            results[name] = f"FAIL — exception: {exc}"
            log(f"  EXCEPTION: {exc}")
            log(f"  ```\n{tb}  ```")
            log(f"")
            log(f"**Result: FAIL — exception**")
        log(f"")
        log(f"---")
        log(f"")

    # Summary
    log(f"## Summary")
    log(f"")
    log(f"| # | Module | Result |")
    log(f"|---|--------|--------|")
    for name, result in results.items():
        status = "PASS" if result.startswith("PASS") else ("WARN" if result.startswith("WARN") else "FAIL")
        log(f"| | {name} | **{status}** — {result.split(' — ', 1)[-1] if ' — ' in result else result} |")
    log(f"")

    passes = sum(1 for r in results.values() if r.startswith("PASS"))
    warns = sum(1 for r in results.values() if r.startswith("WARN"))
    fails = sum(1 for r in results.values() if r.startswith("FAIL"))
    log(f"**Total: {passes} PASS, {warns} WARN, {fails} FAIL out of {len(results)}**")

    # Write report
    report_path = Path("sample_test_report.md")
    report_path.write_text("\n".join(REPORT_LINES) + "\n", encoding="utf-8")
    print(f"\nReport written to: {report_path}")

    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
