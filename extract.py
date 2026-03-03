import argparse
import json
from pathlib import Path

DEFAULT_SCHEMA = {
    "type": "object",
    "properties": {
        "vendor": {"type": "string"},
        "product": {"type": "string"},
        "summary": {"type": "string"},
        "cves": {"type": "array", "items": {"type": "string"}},
        "actions": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["summary"],
}


def build_openai_payload(model, system_prompt, normalized_text, schema):
    return {
        "model": model,
        "input": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": normalized_text},
        ],
        "text": {
            "format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "AdvisoryRecord",
                    "schema": schema,
                },
            }
        },
    }


def load_source_paths(ingest_dir):
    source_path = ingest_dir / "source.json"
    with source_path.open("r", encoding="utf-8") as handle:
        source = json.load(handle)
    raw_path = Path(source["raw_path"])
    normalized_path = Path(source["normalized_path"])
    return source, raw_path, normalized_path


def run_extract(advisory_id, outputs_dir, dry_run, model):
    ingest_dir = outputs_dir / "ingest" / advisory_id
    source, raw_path, normalized_path = load_source_paths(ingest_dir)
    normalized_text = normalized_path.read_text(encoding="utf-8")

    payload = build_openai_payload(
        model=model,
        system_prompt="Extract an AdvisoryRecord JSON object.",
        normalized_text=normalized_text,
        schema=DEFAULT_SCHEMA,
    )

    extract_dir = outputs_dir / "extract" / advisory_id
    extract_dir.mkdir(parents=True, exist_ok=True)

    if dry_run:
        advisory_record = {
            "id": advisory_id,
            "summary": "dry-run: no model call executed",
            "source": {
                "raw_path": str(raw_path),
                "normalized_path": str(normalized_path),
            },
            "vendor": None,
            "product": None,
            "cves": [],
            "actions": [],
        }
        meta = {
            "dry_run": True,
            "request_payload": payload,
            "source": source,
        }
    else:
        from openai import OpenAI

        client = OpenAI()
        response = client.responses.create(**payload)
        advisory_record = json.loads(response.output_text)
        meta = {
            "dry_run": False,
            "request_payload": payload,
            "response_id": response.id,
            "source": source,
        }

    (extract_dir / "advisory_record.json").write_text(
        json.dumps(advisory_record, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (extract_dir / "extract_meta.json").write_text(
        json.dumps(meta, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--advisory-id", required=True)
    parser.add_argument("--outputs-dir", default="outputs")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--model", default="gpt-4.1-mini")
    args = parser.parse_args()

    run_extract(
        advisory_id=args.advisory_id,
        outputs_dir=Path(args.outputs_dir),
        dry_run=args.dry_run,
        model=args.model,
    )


if __name__ == "__main__":
    main()
