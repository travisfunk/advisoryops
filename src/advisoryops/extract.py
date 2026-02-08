from __future__ import annotations
import json
import os
import re
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

def _prep_llm_text(text: str) -> str:
    """
    Prepare ingested text for LLM extraction:
    - Fix common mojibake (UTF-8 bytes decoded as cp1252 => ??? etc.)
    - Strip obvious site chrome (nav/footer)
    - Add light structure around common headings
    """
    if not text:
        return ""

    s = text

    # __MOJIBAKE_HARDEN_PATCH__
    # Fast-path common mojibake sequences seen in CISA/ICS pages.
    _moji = {
        "???": "?",
        "???": "?",
        "???": "?",
        "\u00e2\u20ac\u009d": "?",
        "???": "?",
        "???": "?",
        "???": "-",
        "?": "",
    }
    for a, b in _moji.items():
        if a in s:
            s = s.replace(a, b)


    # Fix mojibake like "Here???s" -> "Here?s"
    # Try cp1252->utf8 repair when typical markers exist.
    if ("?" in s) or ("?" in s):
        try:
            repaired = s.encode("cp1252", errors="ignore").decode("utf-8", errors="ignore")
            if repaired and repaired != s:
                s = repaired
        except Exception:
            pass

# Normalize NBSP artifacts
    s = s.replace("\u00a0", " ").replace("\u00c2", "").replace("?", "")

    # Strip leading site chrome; keep from first meaningful marker if present
    markers = ["ICS Medical Advisory", "ICS Advisory", "Alert Code", "OVERVIEW", "Overview"]
    start_idx = None
    for m in markers:
        i = s.find(m)
        if i != -1:
            start_idx = i if start_idx is None else min(start_idx, i)
    if start_idx is not None and start_idx > 0:
        s = s[start_idx:]

    # Cut trailing footer
    for end_m in ["Return to top", "Please share your thoughts", "Cybersecurity & Infrastructure Security Agency"]:
        i = s.find(end_m)
        if i != -1:
            s = s[:i]
            break

    # Add newlines before common headings so the model can segment sections
    headings = [
        "OVERVIEW",
        "AFFECTED PRODUCTS",
        "IMPACT",
        "MITIGATION",
        "BACKGROUND",
        "VULNERABILITY CHARACTERIZATION",
        "VULNERABILITY OVERVIEW",
        "VULNERABILITY DETAILS",
        "EXPLOITABILITY",
        "EXISTENCE OF EXPLOIT",
        "DIFFICULTY",
    ]
    for h in headings:
        s = re.sub(rf"\s+{re.escape(h)}\s+", f"\n\n{h}\n", s)

    # Collapse whitespace
    s = re.sub(r"[ \t]+", " ", s)
    s = re.sub(r"\n{3,}", "\n\n", s).strip()
    return s



def _parse_published_date_from_text(text: str) -> Optional[str]:
    # __DATE_FALLBACK_PATCH__
    if not text:
        return None

    # Common CISA ICS pattern: "Last Revised March 23, 2017"
    import re as _re
    m = _re.search(r"\bLast\s+Revised\s+([A-Za-z]+)\s+(\d{1,2}),\s+(\d{4})\b", text)
    if not m:
        m = _re.search(r"\bLast\s+Updated\s+([A-Za-z]+)\s+(\d{1,2}),\s+(\d{4})\b", text)
    if not m:
        return None

    month, day, year = m.group(1), m.group(2), m.group(3)
    month_map = {
        "january":"01","february":"02","march":"03","april":"04","may":"05","june":"06",
        "july":"07","august":"08","september":"09","october":"10","november":"11","december":"12"
    }
    mm = month_map.get(month.strip().lower())
    if not mm:
        return None
    dd = str(int(day)).zfill(2)
    return f"{year}-{mm}-{dd}"


def _normalize_llm_obj(obj: Any, advisory_id: str, source_text: str = "") -> Dict[str, Any]:
    """
    Normalize model output into the stable AdvisoryRecord schema.
    - Maps common synonym keys (date->published_date, overview->summary, mitigation->mitigations, etc.)
    - Coerces list fields to lists
    - Drops extra keys so advisory_record.json stays stable
    """
    list_fields = {"cves", "affected_versions", "mitigations", "references"}
    allowed = set(AdvisoryRecord.model_fields.keys())

    if not isinstance(obj, dict):
        obj = {}

    # __OUTPUT_TEXT_CLEAN_PATCH__
    def _clean_text(v: Any) -> Any:
        if v is None:
            return None
        if isinstance(v, str):
            s = v

            # Fast-path common mojibake sequences
            repl = {
                "???": "?",
                "???": "?",
                "???": "?",
                "??\u009d": "?",
                "??": "?",
                "???": "?",
                "???": "?",
                "???": "-",
                "?": "",
            }
            for a, b in repl.items():
                if a in s:
                    s = s.replace(a, b)

            # If it still looks like mojibake, attempt cp1252->utf8 repair
            if ("?" in s) or ("?" in s):
                try:
                    repaired = s.encode("cp1252", errors="ignore").decode("utf-8", errors="ignore")
                    if repaired and repaired != s:
                        s = repaired
                except Exception:
                    pass
                for a, b in repl.items():
                    if a in s:
                        s = s.replace(a, b)

            # NBSP / stray markers
            s = s.replace("\u00a0", " ").replace("\u00c2", "").replace("?", "")
            return s.strip()

        if isinstance(v, list):
            out = []
            for x in v:
                y = _clean_text(x)
                if y is None:
                    continue
                if isinstance(y, str) and not y.strip():
                    continue
                out.append(y)
            return out

        return v

    # Enforce advisory_id (folder id wins)
    obj["advisory_id"] = advisory_id

    # Synonym mappings (only if canonical is missing/empty)
    if not obj.get("published_date"):
        for k in ("date", "published", "last_revised", "last_updated"):
            if obj.get(k):
                obj["published_date"] = obj.get(k)
                break

    # __DATE_FALLBACK_PATCH__
    if not obj.get("published_date") and source_text:
        d = _parse_published_date_from_text(source_text)
        if d:
            obj["published_date"] = d


    if not obj.get("summary"):
        for k in ("overview", "synopsis", "description"):
            if obj.get(k):
                obj["summary"] = obj.get(k)
                break


    # __SEVERITY_SYNONYMS_PATCH__
    if not obj.get("severity"):
        for k in ("cvss", "cvss_score", "cvss_base_score", "severity_level", "risk", "risk_rating"):
            if obj.get(k):
                obj["severity"] = obj.get(k)
                break

    if not obj.get("mitigations"):
        for k in ("mitigation", "mitigation_steps", "remediation", "recommendations", "workarounds"):
            v = obj.get(k)
            if v:
                obj["mitigations"] = v
                break

    if not obj.get("affected_versions"):
        for k in ("affected_products", "affected", "affected_version", "versions_affected"):
            v = obj.get(k)
            if v:
                obj["affected_versions"] = v
                break

    if not obj.get("references"):
        for k in ("reference", "links", "urls", "resources"):
            v = obj.get(k)
            if v:
                obj["references"] = v
                break

    # Coerce list fields
    for k in list_fields:
        v = obj.get(k)
        if v is None:
            obj[k] = []
        elif isinstance(v, list):
            obj[k] = [str(x) for x in v if x is not None and str(x).strip() != ""]
        else:
            s = str(v).strip()
            obj[k] = [s] if s else []

    # Clean scalars: empty/whitespace strings -> None
    for k in (allowed - list_fields):
        if k in obj and isinstance(obj[k], str) and obj[k].strip() == "":
            obj[k] = None

    # Drop extras (stable schema output)
    normalized = {k: obj.get(k) for k in allowed}
    normalized = {k: _clean_text(v) for k, v in normalized.items()}

    # Ensure list defaults
    for k in list_fields:
        if normalized.get(k) is None:
            normalized[k] = []
    return normalized

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
        "- Output a SINGLE JSON object with EXACTLY these keys: advisory_id, title, published_date, vendor, product, cves, severity, affected_versions, summary, impact, exploitation, mitigations, references.\n"
        "- Do NOT include any additional keys.\n"
    )
    llm_text = _prep_llm_text(data.get("normalized_text") or data.get("raw_text") or "")

    user_input = (
        f"ADVISORY_ID: {advisory_id}\n"
        f"SOURCE_ID: {data['source'].get('source_id')}\n\n"
        "Extract an AdvisoryRecord as JSON from the following text:\n\n"
        f"{llm_text}\n"
    )
    resp = client.responses.create(
        model=chosen_model,
        instructions=system_instructions,
        input=user_input,
        text={"format": {"type": "json_object"}},
    )
    json_text = (getattr(resp, "output_text", None) or "").strip()
    if not json_text:
        raise RuntimeError("OpenAI response had empty output_text (expected JSON).")
    try:
        obj = json.loads(json_text)

        obj = _normalize_llm_obj(obj, advisory_id, llm_text)
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