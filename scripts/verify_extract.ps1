[CmdletBinding()]
param(
  [string]$AdvisoryId = "",
  [string]$IngestRoot = "outputs\ingest"
)

$ErrorActionPreference="Stop"

if (-not $AdvisoryId) {
  if (-not (Test-Path $IngestRoot)) { throw "Missing ingest root: $IngestRoot" }
  $AdvisoryId = (Get-ChildItem $IngestRoot -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1).Name
}

"ADVISORY_ID=$AdvisoryId"

# REAL extract (LLM call)
advisoryops extract --advisory-id $AdvisoryId
if ($LASTEXITCODE -ne 0) { throw "advisoryops extract failed with exitcode=$LASTEXITCODE" }

# Deep schema + mojibake scan (PowerShell-safe python invocation via temp .py)
$py = @"
import json
from pathlib import Path

markers = ["â€™", "Â", "â€"]
expected = ["advisory_id","title","published_date","vendor","product","cves","severity","affected_versions","summary","impact","exploitation","mitigations","references"]

rec = sorted(Path("outputs/extract").glob("*/advisory_record.json"), key=lambda x: x.stat().st_mtime, reverse=True)[0]
raw = rec.read_text(encoding="utf-8", errors="replace")
data = json.loads(raw)

keys = sorted(list(data.keys()))
print("record_path=", rec)
print("keys_count=", len(keys))
print("keys=", ", ".join(keys))

missing = [k for k in expected if k not in data]
extra = [k for k in keys if k not in expected]
print("missing=", missing)
print("extra=", extra)

# __FAIL_ON_CONTRACT__
if missing or extra:
    print("ERROR: output contract violated")
    raise SystemExit(2)


hits = []
def walk(v, path="$"):
    if isinstance(v, dict):
        for k, vv in v.items():
            walk(vv, f"{path}.{k}")
    elif isinstance(v, list):
        for i, vv in enumerate(v):
            walk(vv, f"{path}[{i}]")
    elif isinstance(v, str):
        for m in markers:
            if m in v:
                hits.append((path, m, v))

walk(data)

if hits:
    print("FOUND_HITS=", len(hits))
    for path, m, v in hits[:50]:
        print(f"{path} contains {m}: {v}")
    raise SystemExit(1)
else:
    print("OK: no mojibake markers found anywhere in JSON")
"@

$tmpPy = Join-Path $env:TEMP ("verify_extract_" + [guid]::NewGuid().ToString("N") + ".py")
Set-Content -Path $tmpPy -Value $py -Encoding UTF8 -NoNewline
python $tmpPy
$code = $LASTEXITCODE
Remove-Item -Force $tmpPy -ErrorAction SilentlyContinue
if ($code -ne 0) { throw "verify_extract python scan failed (exitcode=$code)" }

"OK: verify_extract passed"