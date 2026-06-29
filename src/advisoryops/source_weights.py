"""Source authority weight loader for AdvisoryOps scoring.

Reads ``configs/source_weights.json`` and exposes a cached lookup of per-source
tier numbers, weights, and the set of healthcare-specific tier-1 medical sources.

Typical usage (in score.py)::

    from .source_weights import load_source_weights

    weights = load_source_weights()
    tier   = weights.tier_for("cisa-icsma")        # 1
    weight = weights.weight_for("cisa-icsma")      # 1.0
    is_med = weights.is_healthcare_medical("cisa-icsma")  # True

Module-level helpers for simple dict-based usage::

    from .source_weights import get_weight, get_tier

    w = load_source_weights()
    get_weight("cisa-icsma", w)    # 1.0  (SourceWeights object accepted)
    get_weight("unknown-src", w)   # 0.5  (default for unrecognized sources)
    get_tier("claroty-team82", w)  # 3
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Set, Union

_CONFIG_PATH = Path(__file__).parent.parent.parent / "configs" / "source_weights.json"

# Sentinel weight returned when a source_id is not found in the config.
_DEFAULT_WEIGHT: float = 0.5
_DEFAULT_TIER: int = 3


@dataclass(frozen=True)
class SourceWeights:
    base_authority_points: int
    healthcare_bonus: int
    _tier_map: Dict[str, int] = field(default_factory=dict, compare=False, hash=False)
    _weight_map: Dict[str, float] = field(default_factory=dict, compare=False, hash=False)
    _healthcare_medical: Set[str] = field(default_factory=set, compare=False, hash=False)
    _tier_weights: Dict[int, float] = field(default_factory=dict, compare=False, hash=False)

    def tier_for(self, source_id: str) -> Optional[int]:
        """Return tier number (1–5) for a source_id, or None if unknown."""
        return self._tier_map.get(source_id)

    def weight_for(self, source_id: str, default: float = 0.0) -> float:
        """Return tier weight for a source_id, or ``default`` if unknown."""
        return self._weight_map.get(source_id, default)

    def max_weight(self, sources: list[str], default: float = 0.0) -> float:
        """Return the highest tier weight across a list of source_ids."""
        if not sources:
            return default
        return max((self._weight_map.get(s, 0.0) for s in sources), default=default)

    def is_healthcare_medical(self, source_id: str) -> bool:
        """True if source_id is in the tier-1 healthcare medical bonus set."""
        return source_id in self._healthcare_medical

    def any_healthcare_medical(self, sources: list[str]) -> bool:
        """True if any source_id in the list is a tier-1 healthcare medical source."""
        return any(s in self._healthcare_medical for s in sources)


@lru_cache(maxsize=1)
def load_source_weights(path: Path = _CONFIG_PATH) -> SourceWeights:
    """Load and parse source_weights.json.  Returns a frozen SourceWeights instance."""
    if not path.exists():
        raise FileNotFoundError(f"Missing source weights config: {path}")

    raw = json.loads(path.read_text(encoding="utf-8"))

    base_pts = int(raw.get("base_authority_points", 30))
    hc_bonus = int(raw.get("healthcare_tier1_medical_bonus", 50))
    hc_medical: Set[str] = set(raw.get("healthcare_tier1_medical_sources", []))

    tiers_raw = raw.get("tiers", {})
    tier_map: Dict[str, int] = {}
    weight_map: Dict[str, float] = {}
    tier_weights: Dict[int, float] = {}

    for tier_key, tier_def in tiers_raw.items():
        # tier_key like "tier_1", "tier_2", …
        try:
            tier_num = int(tier_key.split("_")[1])
        except (IndexError, ValueError):
            continue
        weight = float(tier_def.get("weight", 0.0))
        tier_weights[tier_num] = weight
        for sid in tier_def.get("sources", []):
            tier_map[sid] = tier_num
            weight_map[sid] = weight

    return SourceWeights(
        base_authority_points=base_pts,
        healthcare_bonus=hc_bonus,
        _tier_map=tier_map,
        _weight_map=weight_map,
        _healthcare_medical=hc_medical,
        _tier_weights=tier_weights,
    )


# ---------------------------------------------------------------------------
# Module-level helper functions
# ---------------------------------------------------------------------------

def get_weight(
    source_id: str,
    weights: Union[SourceWeights, Dict[str, float]],
    default: float = _DEFAULT_WEIGHT,
) -> float:
    """Return the authority weight for *source_id*.

    Args:
        source_id: The source identifier to look up.
        weights:   Either a ``SourceWeights`` instance (from ``load_source_weights()``)
                   or a plain ``Dict[str, float]`` mapping source_id → weight.
        default:   Value returned when *source_id* is not found (default 0.5).

    Returns:
        Float weight in [0.0, 1.0], or *default* if not recognised.
    """
    if isinstance(weights, SourceWeights):
        w = weights._weight_map.get(source_id)
        return w if w is not None else default
    # Plain dict
    return weights.get(source_id, default)


def get_tier(
    source_id: str,
    weights_config: Union[SourceWeights, List[dict]],
    default: int = _DEFAULT_TIER,
) -> int:
    """Return the authority tier (1–5) for *source_id*.

    Args:
        source_id:      The source identifier to look up.
        weights_config: Either a ``SourceWeights`` instance or a list of dicts,
                        each with keys ``source_id`` and ``tier``.
        default:        Tier returned when *source_id* is not found (default 3).

    Returns:
        Integer tier 1–5, or *default* if not recognised.
    """
    if isinstance(weights_config, SourceWeights):
        t = weights_config.tier_for(source_id)
        return t if t is not None else default
    # List[dict] format: [{"source_id": "...", "tier": N}, ...]
    for entry in weights_config:
        if entry.get("source_id") == source_id:
            return int(entry.get("tier", default))
    return default
