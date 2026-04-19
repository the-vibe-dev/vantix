param(
  [ValidateSet('tryhackme','hackthebox')]
  [string]$Platform = 'tryhackme',

  [string]$Name = 'DavesBlog'
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot

# Common Windows install locations that are often missing from a fresh shell PATH.
$pathAdds = @(
  'C:\\Program Files (x86)\\Nmap',
  'C:\\Program Files\\Nmap',
  'C:\\Program Files\\OpenVPN\\bin'
)

foreach ($p in $pathAdds) {
  if ((Test-Path $p) -and ($env:Path -notlike "*$p*")) {
    $env:Path += ";$p"
  }
}

$activate = Join-Path $root 'tools\\venv\\Scripts\\Activate.ps1'
if (Test-Path $activate) {
  . $activate
}

$targetDir = Join-Path $root ("challenges\\{0}\\{1}" -f $Platform, (($Name -replace '[^a-zA-Z0-9._-]', '_').Trim('_')))
if (Test-Path $targetDir) {
  Set-Location $targetDir
}

Write-Host "CTF env ready." -ForegroundColor Green
Write-Host "CWD: $(Get-Location)"
Write-Host "Python: $(python --version 2>$null)"
if (Get-Command nmap -ErrorAction SilentlyContinue) {
  Write-Host "Nmap: $(nmap --version | Select-Object -First 1)"
}
if (Get-Command openvpn -ErrorAction SilentlyContinue) {
  Write-Host "OpenVPN CLI: available"
} else {
  Write-Host "OpenVPN CLI: not in PATH (tunnel may still be active via GUI)" -ForegroundColor Yellow
}
