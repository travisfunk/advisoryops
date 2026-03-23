from pathlib import Path
import json
import pytest

from advisoryops.sources_config import load_sources_config


def test_load_sources_config_valid() -> None:
    cfg = load_sources_config(Path("configs/sources.json"))
    assert cfg.schema_version == 1
    assert len(cfg.sources) >= 1
    ids = [s.source_id for s in cfg.sources]
    assert len(ids) == len(set(ids))
    # sanity on required fields
    for s in cfg.sources:
        assert s.source_id
        assert s.name
        assert s.scope
        assert s.page_type
        assert s.entry_url


def test_phase1_public_sources_are_live_config_only() -> None:
    cfg = load_sources_config(Path("configs/sources.json"))
    enabled = [s for s in cfg.sources if s.enabled]
    assert len(enabled) >= 30
    assert all(s.page_type in {"rss_atom", "json_feed", "csv_feed"} for s in enabled)


def test_invalid_regex_rejected(tmp_path: Path) -> None:
    bad = {
        "schema_version": 1,
        "defaults": {"timeout_s": 30, "retries": 3, "rate_limit_rps": 1.0},
        "sources": [
            {
                "source_id": "bad-source",
                "name": "Bad Source",
                "enabled": True,
                "scope": "advisory",
                "page_type": "rss_atom",
                "entry_url": "https://example.com/feed.xml",
                "filters": {"url_allow_regex": "("},
            }
        ],
    }
    p = tmp_path / "sources.json"
    p.write_text(json.dumps(bad, indent=2) + "\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_sources_config(p)


def test_smoke_cleanup_source_urls_updated() -> None:
    cfg = load_sources_config(Path("configs/sources.json"))
    assert cfg.get("ncsc-uk").entry_url == "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml"
    assert cfg.get("claroty-team82").entry_url == "https://claroty.com/blog/feed"
    assert cfg.get("health-canada-recalls").entry_url.startswith("https://")
