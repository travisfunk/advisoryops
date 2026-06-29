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
  } finally { $sha.Dispose() }
}

function Keyword-Hit([string]$text) {
  if ([string]::IsNullOrWhiteSpace($text)) { return $false }
  $t = $text.ToLowerInvariant()
  foreach ($k in $keywords) { if ($t.Contains($k)) { return $true } }
  return $false
}

function NodeText($node, [string]$localName) {
  if (-not $node) { return "" }
  $n = $node.SelectSingleNode("./*[local-name()='$localName']")
  if ($n) { return [string]$n.InnerText } else { return "" }
}

function NodeAttr($node, [string]$localName, [string]$attrName) {
  if (-not $node) { return "" }
  $n = $node.SelectSingleNode("./*[local-name()='$localName']")
  if ($n -and $n.Attributes -and $n.Attributes[$attrName]) {
    return [string]$n.Attributes[$attrName].Value
  }
  return ""
}

if (-not $feeds.ContainsKey($Source)) { throw "Unknown source: $Source" }

try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
$ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AdvisoryOpsRSS/0.0.2"

$url = $feeds[$Source]
$outDir = Join-Path $OutRoot $Source
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$rawPath   = Join-Path $outDir "raw_feed.xml"
$feedPath  = Join-Path $outDir "feed.json"
$newPath   = Join-Path $outDir "new_items.json"
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

Write-Host "Fetching feed: $url"
$resp = Invoke-WebRequest -Uri $url -Headers @{ "User-Agent" = $ua } -TimeoutSec 30 -UseBasicParsing
$content = $resp.Content
if ([string]::IsNullOrWhiteSpace($content)) { throw "Empty response body from $url" }

# Save raw (debug-friendly; outputs/ is gitignored)
Set-Content -Encoding utf8 -Path $rawPath -Value ($content + "`n")

# Parse XML safely
$doc = New-Object System.Xml.XmlDocument
$doc.PreserveWhitespace = $true
try {
  $doc.LoadXml($content)
} catch {
  $snippet = $content.Substring(0, [Math]::Min(300, $content.Length))
  throw "Response was not valid XML. First 300 chars:`n$snippet"
}

# Find items in RSS or Atom (namespace-safe using local-name())
$rssItems  = $doc.SelectNodes("/*[local-name()='rss']/*[local-name()='channel']/*[local-name()='item']")
$atomItems = $doc.SelectNodes("/*[local-name()='feed']/*[local-name()='entry']")
if ($rssItems.Count -eq 0 -and $atomItems.Count -eq 0) {
  $root = $doc.DocumentElement.LocalName
  throw "Unexpected feed format. Root element: <$root>. See $rawPath"
}

$itemsRaw = if ($rssItems.Count -gt 0) { $rssItems } else { $atomItems }

# Limit items
if ($itemsRaw.Count -gt $Limit) {
  $itemsRaw = $itemsRaw | Select-Object -First $Limit
}

$all = @()
$new = @()

foreach ($i in $itemsRaw) {
  $isRss = ($rssItems.Count -gt 0)

  $title = if ($isRss) { NodeText $i "title" } else { NodeText $i "title" }

  # Link handling:
  # - RSS: <link>text</link>
  # - Atom: <link href="..."/> (maybe multiple; prefer rel="alternate")
  $link = ""
  if ($isRss) {
    $link = NodeText $i "link"
  } else {
    $alt = $i.SelectSingleNode("./*[local-name()='link' and (@rel='alternate' or not(@rel))]")
    if ($alt -and $alt.Attributes["href"]) { $link = [string]$alt.Attributes["href"].Value }
    if ([string]::IsNullOrWhiteSpace($link)) {
      $first = $i.SelectSingleNode("./*[local-name()='link']")
      if ($first -and $first.Attributes["href"]) { $link = [string]$first.Attributes["href"].Value }
    }
  }

  $desc = ""
  if ($isRss) {
    $desc = NodeText $i "description"
    if ([string]::IsNullOrWhiteSpace($desc)) { $desc = NodeText $i "summary" }
  } else {
    $desc = NodeText $i "summary"
    if ([string]::IsNullOrWhiteSpace($desc)) { $desc = NodeText $i "content" }
  }

  $guid = ""
  if ($isRss) {
    $guid = NodeText $i "guid"
  } else {
    $guid = NodeText $i "id"
  }
  if ([string]::IsNullOrWhiteSpace($guid)) { $guid = $link }
  if ([string]::IsNullOrWhiteSpace($guid)) { $guid = "sha256:" + (Get-Sha256("$title|$desc")) }

  $pub = ""
  if ($isRss) {
    $pub = NodeText $i "pubDate"
  } else {
    $pub = NodeText $i "published"
    if ([string]::IsNullOrWhiteSpace($pub)) { $pub = NodeText $i "updated" }
  }

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

Set-Content -Encoding utf8 -Path $feedPath  -Value ($feedOut + "`n")
Set-Content -Encoding utf8 -Path $newPath   -Value ($newOut + "`n")
Set-Content -Encoding utf8 -Path $statePath -Value ($stateOut + "`n")

Write-Host "Done."
Write-Host ("  Items: {0}" -f $all.Count)
Write-Host ("  New:   {0}" -f $new.Count)
Write-Host ("  Wrote: {0}" -f $outDir)
Write-Host ("  Raw:   {0}" -f $rawPath)

if ($ShowLinks -and $new.Count -gt 0) {
  Write-Host "`nNew links:"
  $new | Select-Object -First 15 | ForEach-Object { Write-Host (" - " + $_.link) }
  if ($new.Count -gt 15) { Write-Host (" ... ({0} more)" -f ($new.Count - 15)) }
}
