[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [ValidateSet("cisa-icsma","cisa-icsa","fda-medwatch")]
  [string]$Source,

  [int]$Limit = 50,

  [string]$OutRoot = "outputs\discover",

  [switch]$ShowLinks
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$feeds = @{
  "cisa-icsma"    = "https://www.cisa.gov/cybersecurity-advisories/ics-medical-advisories.xml"
  "cisa-icsa"     = "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml"
  "fda-medwatch"  = "https://www.fda.gov/about-fda/contact-fda/stay-informed/rss-feeds/medwatch/rss.xml"
}

$keywords = @(
  "cyber","cybersecurity","vulnerability","vulnerabilities","cve",
  "ransomware","exploit","unauthorized","malware","remote"
)

function Get-Sha256([string]$text) {
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
    ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join ""
  } finally {
    $sha.Dispose()
  }
}

function Keyword-Hit([string]$text) {
  if ([string]::IsNullOrWhiteSpace($text)) { return $false }
  $t = $text.ToLowerInvariant()
  foreach ($k in $keywords) { if ($t.Contains($k)) { return $true } }
  return $false
}

if (-not $feeds.ContainsKey($Source)) {
  throw "Unknown source: $Source"
}

# Some sites can be picky about TLS/UA
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
$ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AdvisoryOpsRSS/0.0.1"

$url = $feeds[$Source]
$outDir = Join-Path $OutRoot $Source
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$statePath = Join-Path $outDir "state.json"
$seen = New-Object "System.Collections.Generic.HashSet[string]"

if (Test-Path $statePath) {
  try {
    $state = Get-Content $statePath -Raw | ConvertFrom-Json
    foreach ($g in ($state.seen | ForEach-Object { "$_" })) { [void]$seen.Add($g) }
  } catch {
    Write-Warning "Could not read state.json; starting fresh. $($_.Exception.Message)"
  }
}

Write-Host "Fetching RSS: $url"
$xml = Invoke-RestMethod -Uri $url -Headers @{ "User-Agent" = $ua } -TimeoutSec 30

# RSS structure: $xml.rss.channel.item
$itemsRaw = @()
if ($xml.rss -and $xml.rss.channel -and $xml.rss.channel.item) {
  $itemsRaw = @($xml.rss.channel.item)
} else {
  throw "Unexpected RSS structure for $Source"
}

# Limit items
$itemsRaw = $itemsRaw | Select-Object -First $Limit

$all = @()
$new = @()

foreach ($i in $itemsRaw) {
  $title = [string]$i.title
  $link  = [string]$i.link
  $desc  = [string]$i.description

  # guid can be object; normalize
  $guid = $null
  if ($i.guid) {
    try {
      if ($i.guid.'#text') { $guid = [string]$i.guid.'#text' }
      else { $guid = [string]$i.guid }
    } catch { $guid = [string]$i.guid }
  }
  if ([string]::IsNullOrWhiteSpace($guid)) { $guid = $link }
  if ([string]::IsNullOrWhiteSpace($guid)) { $guid = "sha256:" + (Get-Sha256("$title|$desc")) }

  $pub = $null
  if ($i.pubDate) { $pub = [string]$i.pubDate }

  # FDA feed is broad -> filter to cyber-ish entries
  if ($Source -eq "fda-medwatch") {
    $blob = "$title`n$desc`n$link"
    if (-not (Keyword-Hit $blob)) { continue }
  }

  $obj = [ordered]@{
    source        = $Source
    guid          = $guid
    title         = $title
    link          = $link
    published_raw = $pub
    description   = $desc
    fetched_utc   = (Get-Date).ToUniversalTime().ToString("o")
  }

  $all += $obj

  if (-not $seen.Contains($guid)) {
    $new += $obj
    [void]$seen.Add($guid)
  }
}

# Write outputs (all under outputs/, which is gitignored)
$feedOut = [ordered]@{
  source      = $Source
  url         = $url
  fetched_utc = (Get-Date).ToUniversalTime().ToString("o")
  count       = $all.Count
  items       = $all
} | ConvertTo-Json -Depth 10

$newOut = [ordered]@{
  source      = $Source
  url         = $url
  fetched_utc = (Get-Date).ToUniversalTime().ToString("o")
  count       = $new.Count
  items       = $new
} | ConvertTo-Json -Depth 10

$stateOut = [ordered]@{
  source = $Source
  seen   = @($seen)
} | ConvertTo-Json -Depth 6

Set-Content -Encoding utf8 -Path (Join-Path $outDir "feed.json") -Value ($feedOut + "`n")
Set-Content -Encoding utf8 -Path (Join-Path $outDir "new_items.json") -Value ($newOut + "`n")
Set-Content -Encoding utf8 -Path $statePath -Value ($stateOut + "`n")

Write-Host "Done."
Write-Host ("  Items: {0}" -f $all.Count)
Write-Host ("  New:   {0}" -f $new.Count)
Write-Host ("  Wrote: {0}" -f $outDir)

if ($ShowLinks -and $new.Count -gt 0) {
  Write-Host "`nNew links:"
  $new | Select-Object -First 15 | ForEach-Object { Write-Host (" - " + $_.link) }
  if ($new.Count -gt 15) { Write-Host (" ... ({0} more)" -f ($new.Count - 15)) }
}
