param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('tryhackme','hackthebox')]
  [string]$Platform,

  [Parameter(Mandatory = $true)]
  [string]$Name,

  [string]$IP = ""
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$safe = ($Name -replace '[^a-zA-Z0-9._-]', '_').Trim('_')
if ([string]::IsNullOrWhiteSpace($safe)) {
  throw "Name must contain at least one valid character."
}

$targetDir = Join-Path $root ("challenges\{0}\{1}" -f $Platform, $safe)
$scanDir = Join-Path $targetDir 'scans'
$lootDir = Join-Path $targetDir 'loot'

New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
New-Item -ItemType Directory -Path $scanDir -Force | Out-Null
New-Item -ItemType Directory -Path $lootDir -Force | Out-Null

$template = Join-Path $root 'templates\target-notes.md'
$notes = Join-Path $targetDir 'notes.md'

if (-not (Test-Path $notes)) {
  Copy-Item $template $notes

  if ($IP) {
    (Get-Content $notes) -replace '^- IP:\s*$', "- IP: $IP" |
      Set-Content -Path $notes -Encoding UTF8
  }

  (Get-Content $notes) -replace '^- Platform:\s*$', "- Platform: $Platform" |
    ForEach-Object { $_ -replace '^- Target Name:\s*$', "- Target Name: $Name" } |
    Set-Content -Path $notes -Encoding UTF8
}

Write-Host "Target workspace ready: $targetDir" -ForegroundColor Green
Write-Host "Notes: $notes"
