from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field
from .util import ensure_dir, sha256_text, utc_now_iso, write_json
INGEST_ROOT = Path("outputs/ingest")
EXTRACT_ROOT = Path("outputs/extract")
class AdvisoryRecord(BaseModel):
    """
    MVP schema. Keep it stable. Expand here intentionally later.
    """
    model_config = ConfigDict(extra="allow")
    advisory_id: str
    title: Optional[str] = None
    published_date: Optional[str] = Field(default=None, description="ISO-8601 date if known (YYYY-MM-DD preferred)")
    vendor: Optional[str] = None
    product: Optional[str] = None
    cves: List[str] = Field(default_factory=list)
    severity: Optional[str] = Field(default=None, description="Critical/High/Medium/Low or numeric score string")
    affected_versions: List[str] = Field(default_factory=list)
    summary: Optional[str] = None
    impact: Optional[str] = None
    exploitation: Optional[str] = None
    mitigations: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)
def _load_ingest_inputs(advisory_id: str) -> Dict[str, Any]:
    """
    SINGLE SOURCE OF TRUTH:
    Read outputs/ingest/<id>/source.json and use the artifact paths recorded there.
    """
    in_dir = INGEST_ROOT / advisory_id
    if not in_dir.exists():
        raise FileNotFoundError(f"Missing ingest dir: {in_dir}")
    source_path = in_dir / "source.json"
    if not source_path.exists():
        raise FileNotFoundError(f"Missing: {source_path}")
    source_obj = json.loads(source_path.read_text(encoding="utf-8"))
    raw_path_str = (source_obj.get("raw_path") or "").strip()
    normalized_path_str = (source_obj.get("normalized_path") or "").strip()
    if not raw_path_str:
        raise FileNotFoundError(f"source.json missing raw_path for advisory_id={advisory_id}")
    if not normalized_path_str:
        raise FileNotFoundError(f"source.json missing normalized_path for advisory_id={advisory_id}")
    raw_path = Path(raw_path_str)
    normalized_path = Path(normalized_path_str)
    if not raw_path.exists():
        raise FileNotFoundError(f"Missing raw text at path from source.json: {raw_path}")
    if not normalized_path.exists():
        raise FileNotFoundError(f"Missing normalized text at path from source.json: {normalized_path}")
    raw_text = raw_path.read_text(encoding="utf-8", errors="ignore")
    normalized_text = normalized_path.read_text(encoding="utf-8", errors="ignore")
    return {
        "in_dir": str(in_dir),
        "source_path": str(source_path),
        "raw_path": str(raw_path),
        "normalized_path": str(normalized_path),
        "source": source_obj,
        "raw_text": raw_text,
        "normalized_text": normalized_text,
    }
def extract_advisory_record(advisory_id: str, model: Optional[str] = None) -> Path:
    """
    Required export for cli.py.
    Reads:
      outputs/ingest/<id>/source.json -> raw_path + normalized_path
    Writes:
      outputs/extract/<id>/advisory_record.json
      outputs/extract/<id>/extract_meta.json
    Returns:
      Path to advisory_record.json
    """
    if not advisory_id or not advisory_id.strip():
        raise ValueError("advisory_id is required")
    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY is not set in this environment.")
    data = _load_ingest_inputs(advisory_id)
    # Import inside function so module import never depends on SDK availability.
    from openai import OpenAI  # type: ignore
    client = OpenAI()
    chosen_model = model or os.getenv("OPENAI_MODEL") or "gpt-4o-mini"
    # Deterministic input hash for traceability
    input_hash = sha256_text((data["normalized_text"] or "").strip())
    system_instructions = (
        "You extract cybersecurity advisory information into a JSON object that matches the AdvisoryRecord schema.\n"
        "Rules:\n"
        "- Return ONLY valid JSON (no markdown, no commentary).\n"
        "- Only include facts supported by the provided text.\n"
        "- If unknown: use null for scalars and [] for lists.\n"
        "- Dates: prefer ISO-8601 (YYYY-MM-DD).\n"
        "- cves must be an array of strings like \"CVE-2024-1234\".\n"
    )
    user_input = (
        f"ADVISORY_ID: {advisory_id}\n"
        f"SOURCE_ID: {data['source'].get('source_id')}\n\n"
        "Extract an AdvisoryRecord from the following text:\n\n"
        f"{data['raw_text']}\n"
    )
    resp = client.responses.create(
        model=chosen_model,
        instructions=system_instructions,
        input=user_input,
        response_format={"type": "json_object"},
    )
    json_text = (getattr(resp, "output_text", None) or "").strip()
    if not json_text:
        raise RuntimeError("OpenAI response had empty output_text (expected JSON).")
    try:
        obj = json.loads(json_text)
    except Exception as e:
        snippet = json_text[:600].replace("\r", " ").replace("\n", " ")
        raise RuntimeError(f"Model output was not valid JSON. Snippet='{snippet}'") from e
    record = AdvisoryRecord(**obj)
    record.advisory_id = advisory_id  # enforce folder id
    out_dir = EXTRACT_ROOT / advisory_id
    ensure_dir(out_dir)
    record_path = out_dir / "advisory_record.json"
    meta_path = out_dir / "extract_meta.json"
    write_json(record_path, record.model_dump(mode="json"))
    usage_obj = getattr(resp, "usage", None)
    try:
        if hasattr(usage_obj, "model_dump"):
            usage_obj = usage_obj.model_dump()
    except Exception:
        usage_obj = None
    meta: Dict[str, Any] = {
        "advisory_id": advisory_id,
        "created_utc": utc_now_iso(),
        "model": chosen_model,
        "input_hash": input_hash,
        "ingest_dir": data["in_dir"],
        "source_json": data["source_path"],
        "raw_txt": data["raw_path"],
        "normalized_txt": data["normalized_path"],
        "record_path": str(record_path),
        "response_id": getattr(resp, "id", None),
        "usage": usage_obj,
    }
    write_json(meta_path, meta)
    return record_path