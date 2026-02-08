from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


VALID_SCOPES = {"advisory", "dataset", "news", "threatintel"}

# Known page types (some may be implemented later; disabled sources can still declare them)
KNOWN_PAGE_TYPES = {
    "rss_atom",
    "html_generic",
    "html_list",
    "html_table",
    "json_feed",
    "pdf_bulletin",
}

_SOURCE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_APPLY_TO_ALLOWED = {"title", "summary", "description"}


@dataclass(frozen=True)
class SourceDef:
    source_id: str
    name: str
    enabled: bool
    scope: str
    page_type: str
    entry_url: str
    filters: Dict[str, Any]
    timeout_s: int
    retries: int
    rate_limit_rps: float


@dataclass(frozen=True)
class SourcesConfig:
    schema_version: int
    defaults: Dict[str, Any]
    sources: List[SourceDef]

    def get(self, source_id: str) -> SourceDef:
        for s in self.sources:
            if s.source_id == source_id:
                return s
        raise KeyError(f"Unknown source_id: {source_id}")

    def enabled_sources(self, scope: Optional[str] = None) -> List[SourceDef]:
        out: List[SourceDef] = []
        for s in self.sources:
            if not s.enabled:
                continue
            if scope is not None and s.scope != scope:
                continue
            out.append(s)
        return out


def _require_type(obj: Any, t: type, ctx: str) -> Any:
    if not isinstance(obj, t):
        raise ValueError(f"{ctx}: expected {t.__name__}, got {type(obj).__name__}")
    return obj


def _validate_filters(filters: Dict[str, Any], ctx: str) -> None:
    # filters is optional; when present it must be a dict
    if not filters:
        return

    if "keywords_any" in filters:
        kws = _require_type(filters["keywords_any"], list, f"{ctx}.filters.keywords_any")
        if not all(isinstance(x, str) and x.strip() for x in kws):
            raise ValueError(f"{ctx}.filters.keywords_any: must be list[str] (non-empty strings)")

    if "keywords_all" in filters:
        kws = _require_type(filters["keywords_all"], list, f"{ctx}.filters.keywords_all")
        if not all(isinstance(x, str) and x.strip() for x in kws):
            raise ValueError(f"{ctx}.filters.keywords_all: must be list[str] (non-empty strings)")

    if "apply_to" in filters:
        targets = _require_type(filters["apply_to"], list, f"{ctx}.filters.apply_to")
        if not all(isinstance(x, str) for x in targets):
            raise ValueError(f"{ctx}.filters.apply_to: must be list[str]")
        bad = [t for t in targets if t not in _APPLY_TO_ALLOWED]
        if bad:
            raise ValueError(f"{ctx}.filters.apply_to: invalid values: {bad}. Allowed: {sorted(_APPLY_TO_ALLOWED)}")

    for k in ("url_allow_regex", "url_deny_regex"):
        if k in filters:
            pat = _require_type(filters[k], str, f"{ctx}.filters.{k}")
            try:
                re.compile(pat)
            except re.error as e:
                raise ValueError(f"{ctx}.filters.{k}: invalid regex: {e}") from e


def load_sources_config(path: Path = Path("configs/sources.json")) -> SourcesConfig:
    """
    Load and validate the sources registry.

    Deterministic rules:
      - Accept UTF-8 with or without BOM (utf-8-sig).
      - Strict schema checks with helpful errors.
      - Unknown page_type is allowed ONLY when enabled=false (future placeholders).
    """
    raw = path.read_text(encoding="utf-8-sig")
    data = json.loads(raw)

    _require_type(data, dict, "config")

    schema_version = data.get("schema_version", None)
    if not isinstance(schema_version, int):
        raise ValueError("config.schema_version: required int")

    defaults = data.get("defaults", {})
    _require_type(defaults, dict, "config.defaults")

    # Defaults (use explicit fallback if missing)
    default_timeout_s = int(defaults.get("timeout_s", 30))
    default_retries = int(defaults.get("retries", 3))
    default_rate = float(defaults.get("rate_limit_rps", 1.0))

    sources_raw = data.get("sources", None)
    _require_type(sources_raw, list, "config.sources")

    seen_ids: set[str] = set()
    sources: List[SourceDef] = []

    for idx, s in enumerate(sources_raw):
        ctx = f"config.sources[{idx}]"
        _require_type(s, dict, ctx)

        source_id = s.get("source_id")
        name = s.get("name")
        enabled = s.get("enabled")
        scope = s.get("scope")
        page_type = s.get("page_type")
        entry_url = s.get("entry_url")
        filters = s.get("filters", {})

        if not isinstance(source_id, str) or not source_id.strip():
            raise ValueError(f"{ctx}.source_id: required non-empty string")
        if not _SOURCE_ID_RE.match(source_id):
            raise ValueError(f"{ctx}.source_id: invalid format '{source_id}' (expected lowercase letters/digits/hyphen)")
        if source_id in seen_ids:
            raise ValueError(f"{ctx}.source_id: duplicate source_id '{source_id}'")
        seen_ids.add(source_id)

        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"{ctx}.name: required non-empty string")

        if not isinstance(enabled, bool):
            raise ValueError(f"{ctx}.enabled: required boolean")

        if not isinstance(scope, str) or scope not in VALID_SCOPES:
            raise ValueError(f"{ctx}.scope: invalid '{scope}'. Allowed: {sorted(VALID_SCOPES)}")

        if not isinstance(page_type, str) or not page_type.strip():
            raise ValueError(f"{ctx}.page_type: required non-empty string")
        if enabled and page_type not in KNOWN_PAGE_TYPES:
            raise ValueError(f"{ctx}.page_type: unknown '{page_type}' for enabled source. Known: {sorted(KNOWN_PAGE_TYPES)}")

        if not isinstance(entry_url, str) or not entry_url.strip():
            raise ValueError(f"{ctx}.entry_url: required non-empty string")

        _require_type(filters, dict, f"{ctx}.filters")
        _validate_filters(filters, ctx)

        timeout_s = int(s.get("timeout_s", default_timeout_s))
        retries = int(s.get("retries", default_retries))
        rate_limit_rps = float(s.get("rate_limit_rps", default_rate))

        sources.append(
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
            )
        )

    return SourcesConfig(schema_version=schema_version, defaults=defaults, sources=sources)