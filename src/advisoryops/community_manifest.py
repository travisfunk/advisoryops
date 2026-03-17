from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List

from .sources_config import CONFIG_PATH as SOURCES_CONFIG_PATH
from .sources_config import load_sources_config


MANIFEST_PATH = Path("configs/community_public_sources.json")


@dataclass(frozen=True)
class CommunitySourceSet:
    set_id: str
    name: str
    description: str
    source_ids: List[str]


@dataclass(frozen=True)
class CommunityManifest:
    schema_version: int
    validated_sets: List[CommunitySourceSet]
    candidate_sources: List[str]

    def get_set(self, set_id: str) -> CommunitySourceSet:
        for s in self.validated_sets:
            if s.set_id == set_id:
                return s
        raise KeyError(f"Unknown community source set: {set_id}")


def _as_list_str(v) -> List[str]:
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip()]
    if isinstance(v, str) and v.strip():
        return [v.strip()]
    return []


def load_community_manifest(
    path: Path = MANIFEST_PATH,
    *,
    sources_path: Path = SOURCES_CONFIG_PATH,
) -> CommunityManifest:
    if not path.exists():
        raise FileNotFoundError(f"Missing community public sources manifest: {path}")

    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: expected object at root")

    cfg = load_sources_config(sources_path)
    known_source_ids = {s.source_id for s in cfg.sources}

    validated_sets_raw = raw.get("validated_sets", [])
    if not isinstance(validated_sets_raw, list):
        raise ValueError(f"{path}: expected list at .validated_sets")

    validated_sets: List[CommunitySourceSet] = []
    seen_set_ids: set[str] = set()

    for row in validated_sets_raw:
        if not isinstance(row, dict):
            continue
        set_id = str(row.get("set_id", "")).strip()
        if not set_id:
            raise ValueError(f"{path}: validated set missing set_id")
        if set_id in seen_set_ids:
            raise ValueError(f"{path}: duplicate validated set_id '{set_id}'")
        seen_set_ids.add(set_id)

        source_ids = _as_list_str(row.get("source_ids"))
        if not source_ids:
            raise ValueError(f"{path}: validated set '{set_id}' has no source_ids")

        missing = [sid for sid in source_ids if sid not in known_source_ids]
        if missing:
            raise ValueError(f"{path}: validated set '{set_id}' references unknown source_ids: {missing}")

        validated_sets.append(
            CommunitySourceSet(
                set_id=set_id,
                name=str(row.get("name", set_id)).strip(),
                description=str(row.get("description", "")).strip(),
                source_ids=source_ids,
            )
        )

    candidate_sources = _as_list_str(raw.get("candidate_sources"))
    unknown_candidates = [sid for sid in candidate_sources if sid not in known_source_ids]
    if unknown_candidates:
        raise ValueError(f"{path}: candidate_sources references unknown source_ids: {unknown_candidates}")

    return CommunityManifest(
        schema_version=int(raw.get("schema_version", 1)),
        validated_sets=validated_sets,
        candidate_sources=candidate_sources,
    )
