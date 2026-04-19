param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('tryhackme','hackthebox')]
  [string]$Platform,

  [Parameter(Mandatory = $true)]
  [string]$Name,

  [string]$IP = "",
  [switch]$SkipVPN
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot

if (-not $SkipVPN) {
  & (Join-Path $PSScriptRoot 'Connect-VPN.ps1') -Platform $Platform
}

& (Join-Path $PSScriptRoot 'New-Target.ps1') -Platform $Platform -Name $Name -IP $IP

$safe = ($Name -replace '[^a-zA-Z0-9._-]', '_').Trim('_')
$targetDir = Join-Path $root ("challenges\{0}\{1}" -f $Platform, $safe)

if (Get-Command code -ErrorAction SilentlyContinue) {
  Start-Process -FilePath 'code' -ArgumentList "`"$targetDir`""
  Write-Host "Opened in VS Code: $targetDir" -ForegroundColor Cyan
} else {
  Write-Host "VS Code CLI ('code') not found. Target directory: $targetDir" -ForegroundColor Yellow
}
