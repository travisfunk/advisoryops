"""MITRE ATT&CK for ICS enrichment.

Downloads the ATT&CK ICS STIX 2.0 bundle from GitHub and provides
technique/tactic lookups for ICS-relevant issues.

Source: https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json

Cache: outputs/attack_ics_cache/ics_attack.json
"""
from __future__ import annotations

import json
import logging
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json"
)
_DEFAULT_CACHE_DIR = Path("outputs/attack_ics_cache")
_CACHE_FILE = "ics_attack.json"
_LOOKUP_FILE = "technique_lookup.json"
_USER_AGENT = "AdvisoryOps/1.0 (security advisory aggregator; ATT&CK ICS enrichment)"
_TIMEOUT = 60


def _http_get(
    url: str,
    *,
    timeout: int = _TIMEOUT,
    _fetch_fn: Optional[Callable[[str], bytes]] = None,
) -> bytes:
    if _fetch_fn is not None:
        return _fetch_fn(url)
    headers = {"User-Agent": _USER_AGENT}
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def parse_stix_bundle(bundle: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Parse a STIX 2.0 bundle into a technique lookup dict.

    Returns {technique_id: {name, description, tactic, url}}.
    Technique IDs are like "T0800", "T0803", etc.
    """
    techniques: Dict[str, Dict[str, Any]] = {}

    for obj in bundle.get("objects") or []:
        obj_type = obj.get("type", "")

        if obj_type == "attack-pattern":
            name = obj.get("name", "")
            description = obj.get("description", "")
            ext_refs = obj.get("external_references") or []
            technique_id = ""
            url = ""
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id", "")
                    url = ref.get("url", "")
                    break

            if technique_id:
                # Extract tactic from kill_chain_phases
                tactics = []
                for phase in obj.get("kill_chain_phases") or []:
                    tactics.append(phase.get("phase_name", ""))

                techniques[technique_id] = {
                    "name": name,
                    "description": description[:500] if description else "",
                    "tactics": tactics,
                    "url": url,
                }

    return techniques


def populate_cache(
    *,
    cache_dir: Optional[Path] = None,
    _fetch_fn: Optional[Callable[[str], bytes]] = None,
) -> Dict[str, Any]:
    """Download ATT&CK ICS STIX bundle and build technique lookup."""
    if cache_dir is None:
        cache_dir = _DEFAULT_CACHE_DIR
    cache_dir.mkdir(parents=True, exist_ok=True)

    raw = _http_get(_STIX_URL, _fetch_fn=_fetch_fn)
    bundle = json.loads(raw.decode("utf-8"))

    # Save raw bundle
    (cache_dir / _CACHE_FILE).write_text(
        json.dumps(bundle, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    # Build and save lookup
    techniques = parse_stix_bundle(bundle)
    lookup_data = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "total_techniques": len(techniques),
        "techniques": techniques,
    }
    (cache_dir / _LOOKUP_FILE).write_text(
        json.dumps(lookup_data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    logger.info("ATT&CK ICS cache populated: %d techniques.", len(techniques))
    return {"status": "completed", "total_techniques": len(techniques)}


def load_cache(
    *,
    cache_dir: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    """Load ATT&CK ICS technique lookup. Returns {technique_id: {...}}."""
    if cache_dir is None:
        cache_dir = _DEFAULT_CACHE_DIR
    lookup_file = cache_dir / _LOOKUP_FILE
    if not lookup_file.exists():
        return {}
    try:
        data = json.loads(lookup_file.read_text(encoding="utf-8"))
        return data.get("techniques") or {}
    except (json.JSONDecodeError, OSError):
        return {}


def get_technique(
    technique_id: str,
    techniques: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Optional[Dict[str, Any]]:
    """Look up an ATT&CK ICS technique by ID."""
    if techniques is None:
        techniques = load_cache()
    return techniques.get(technique_id)
