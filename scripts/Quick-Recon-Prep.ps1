param(
  [string]$TargetIP = "",
  [int[]]$Ports = @(22,80,443)
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$venvPy = Join-Path $root 'tools\venv\Scripts\python.exe'

if (-not (Test-Path $venvPy)) {
  throw "Python venv not found at tools\\venv."
}

Write-Host "Python venv: $venvPy" -ForegroundColor Cyan
& $venvPy -c "import requests, httpx, bs4, lxml, rich, dotenv, yaml; print('Python recon deps OK')"

if ($TargetIP) {
  Write-Host "`nQuick port check against $TargetIP" -ForegroundColor Cyan
  foreach ($p in $Ports) {
    $result = Test-NetConnection -ComputerName $TargetIP -Port $p -WarningAction SilentlyContinue
    "Port {0}: {1}" -f $p, ($(if($result.TcpTestSucceeded){'open/reachable'} else {'closed/filtered'}))
  }
}
