param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('tryhackme','hackthebox')]
  [string]$Platform,

  [string]$Config
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$vpnDir = Join-Path $root ("vpn\{0}" -f $Platform)

if (-not (Test-Path $vpnDir)) {
  throw "VPN directory not found: $vpnDir"
}

if (-not (Get-Command openvpn -ErrorAction SilentlyContinue)) {
  throw "openvpn was not found in PATH. Install OpenVPN and/or add it to PATH."
}

if ($Config) {
  $ovpnPath = Join-Path $vpnDir $Config
  if (-not (Test-Path $ovpnPath)) {
    throw "Config not found: $ovpnPath"
  }
} else {
  $ovpn = Get-ChildItem -Path $vpnDir -Filter *.ovpn -File | Select-Object -First 1
  if (-not $ovpn) {
    throw "No .ovpn config found in $vpnDir"
  }
  $ovpnPath = $ovpn.FullName
}

Write-Host "Launching OpenVPN with config: $ovpnPath" -ForegroundColor Cyan
Start-Process -FilePath "openvpn" -ArgumentList "--config", "`"$ovpnPath`"" -WorkingDirectory $vpnDir
Write-Host "OpenVPN process started. Check client logs/window for tunnel status." -ForegroundColor Green
