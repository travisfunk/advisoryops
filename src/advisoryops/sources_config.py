"""Source configuration loader and dataclasses.

Parses ``configs/sources.json`` (schema v1) into typed, immutable dataclasses.
The config file defines every feed the pipeline can consume: its URL, page type
(rss_atom | json_feed | csv_feed), keyword filters, timeout, retry behaviour,
and whether it is enabled for community builds.

Key design decisions
--------------------
* Frozen dataclasses — source definitions should never be mutated at runtime.
* Strict validation at load time — bad regex patterns, unknown page types, and
  duplicate source IDs all raise ``ValueError`` immediately so problems surface
  before any HTTP calls are made.
* ``DECLARED_FUTURE_PAGE_TYPES`` lists page types that are planned but not yet
  implemented; sources that declare them must stay ``enabled=false``.

Typical usage::

    from advisoryops.sources_config import load_sources_config

    cfg = load_sources_config()        # reads configs/sources.json
    src = cfg.get("cisa-icsma")        # raises KeyError if not found
    print(src.entry_url, src.enabled)
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


CONFIG_PATH = Path("configs/sources.json")

ALLOWED_SCOPES = {"advisory", "dataset", "news", "threatintel"}

# v1.1 implemented:
ALLOWED_PAGE_TYPES = {"rss_atom", "json_feed", "csv_feed"}

# declared but not necessarily implemented (keep disabled in config until implemented)
DECLARED_FUTURE_PAGE_TYPES = {"html_generic", "html_list", "html_table", "json_api", "pdf_bulletin"}


@dataclass(frozen=True)
class SourceFilters:
    apply_to: List[str]
    keywords_any: List[str]
    keywords_all: List[str]
    url_allow_regex: Optional[str]
    url_deny_regex: Optional[str]


@dataclass(frozen=True)
class SourceDef:
    source_id: str
    name: str
    enabled: bool
    scope: str
    page_type: str
    entry_url: str
    filters: SourceFilters
    timeout_s: int = 30
    retries: int = 2
    rate_limit_rps: float = 1.0
    api_key_env: Optional[str] = None     # name of env var holding the API key
    api_key_header: Optional[str] = None  # HTTP header name to send the key in (e.g. "x-apikey")
    notes: Optional[str] = None           # human-readable note (e.g. "charges beyond 100 calls")


@dataclass(frozen=True)
class SourcesConfig:
    schema_version: int
    sources: List[SourceDef]

    def get(self, source_id: str) -> SourceDef:
        for s in self.sources:
            if s.source_id == source_id:
                return s
        raise KeyError(f"Unknown source_id: {source_id}")


def _as_list_str(v: Any) -> List[str]:
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip()]
    if isinstance(v, str) and v.strip():
        return [v.strip()]
    return []


def _validate_regex(source_id: str, field_name: str, pattern: Optional[str]) -> Optional[str]:
    if not pattern:
        return None
    try:
        re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        raise ValueError(f"{source_id}: invalid regex for {field_name}: {pattern!r} ({e})") from e
    return pattern


def load_sources_config(path: Path = CONFIG_PATH) -> SourcesConfig:
    if not path.exists():
        raise FileNotFoundError(f"Missing sources config: {path}")

    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: expected object at root")

    schema_version = int(raw.get("schema_version", 1))
    sources_raw = raw.get("sources", [])
    if not isinstance(sources_raw, list):
        raise ValueError(f"{path}: expected list at .sources")

    out: List[SourceDef] = []
    seen_ids: set[str] = set()

    for s in sources_raw:
        if not isinstance(s, dict):
            continue

        source_id = str(s.get("source_id", "")).strip()
        if not source_id:
            raise ValueError(f"{path}: source missing source_id")
        if source_id in seen_ids:
            raise ValueError(f"{path}: duplicate source_id '{source_id}'")
        seen_ids.add(source_id)

        name = str(s.get("name", source_id)).strip()
        enabled = bool(s.get("enabled", False))
        scope = str(s.get("scope", "")).strip()
        page_type = str(s.get("page_type", "")).strip()
        entry_url = str(s.get("entry_url", "")).strip()

        if scope not in ALLOWED_SCOPES:
            raise ValueError(f"{path}: {source_id}: invalid scope '{scope}'")
        if page_type not in (ALLOWED_PAGE_TYPES | DECLARED_FUTURE_PAGE_TYPES):
            raise ValueError(f"{path}: {source_id}: invalid page_type '{page_type}'")
        if page_type in DECLARED_FUTURE_PAGE_TYPES and enabled:
            raise ValueError(
                f"{path}: {source_id}: page_type '{page_type}' is declared-future; keep enabled=false until implemented"
            )
        if not entry_url:
            raise ValueError(f"{path}: {source_id}: missing entry_url")

        f = s.get("filters", {}) or {}
        if not isinstance(f, dict):
            f = {}

        url_allow = _validate_regex(source_id, "filters.url_allow_regex", f.get("url_allow_regex"))
        url_deny = _validate_regex(source_id, "filters.url_deny_regex", f.get("url_deny_regex"))

        filters = SourceFilters(
            apply_to=_as_list_str(f.get("apply_to")) or ["title", "summary", "description"],
            keywords_any=_as_list_str(f.get("keywords_any")),
            keywords_all=_as_list_str(f.get("keywords_all")),
            url_allow_regex=url_allow,
            url_deny_regex=url_deny,
        )

        timeout_s = int(s.get("timeout_s", 30))
        retries = int(s.get("retries", 2))
        rate_limit_rps = float(s.get("rate_limit_rps", 1.0))
        api_key_env = s.get("api_key_env") or None
        api_key_header = s.get("api_key_header") or None
        notes = s.get("notes") or None

        out.append(
            SourceDef(
                source_id=source_id,
                name=name,
                enabled=enabled,
                scope=scope,
                page_type=page_type,
                entry_url=entry_url,
                filters=filters,
                timeout_s=timeout_s,
                retries=retries,
                rate_limit_rps=rate_limit_rps,
                api_key_env=api_key_env,
                api_key_header=api_key_header,
                notes=notes,
            )
        )

    return SourcesConfig(schema_version=schema_version, sources=out)