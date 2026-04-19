$ErrorActionPreference = 'Stop'

function Resolve-ToolPath {
  param(
    [Parameter(Mandatory = $true)][string]$Name,
    [string[]]$FallbackPaths = @()
  )

  $cmd = Get-Command $Name -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }

  foreach ($p in $FallbackPaths) {
    if (Test-Path $p) { return $p }
  }

  return $null
}

$checks = @(
  @{
    Name = 'openvpn'
    Hint = 'Install OpenVPN Connect/Community and/or run .\\scripts\\Enter-CTF.ps1 to refresh PATH.'
    Fallback = @(
      'C:\\Program Files\\OpenVPN\\bin\\openvpn.exe',
      'C:\\Program Files\\OpenVPN Connect\\OpenVPNConnect.exe'
    )
  },
  @{
    Name = 'nmap'
    Hint = 'Install Nmap and/or run .\\scripts\\Enter-CTF.ps1 to refresh PATH.'
    Fallback = @(
      'C:\\Program Files (x86)\\Nmap\\nmap.exe',
      'C:\\Program Files\\Nmap\\nmap.exe'
    )
  },
  @{ Name = 'python'; Hint = 'Install Python 3 for helper tooling.'; Fallback = @() },
  @{ Name = 'code'; Hint = 'Install VS Code and add `code` CLI to PATH (optional).'; Fallback = @() }
)

$results = foreach ($c in $checks) {
  $resolved = Resolve-ToolPath -Name $c.Name -FallbackPaths $c.Fallback
  [PSCustomObject]@{
    Tool   = $c.Name
    Status = if ($resolved) { 'FOUND' } else { 'MISSING' }
    Path   = if ($resolved) { $resolved } else { '' }
    Hint   = if ($resolved) { '' } else { $c.Hint }
  }
}

$results | Format-Table -AutoSize

$missing = $results | Where-Object { $_.Status -eq 'MISSING' }
if ($missing) {
  Write-Host "`nMissing tools detected: $($missing.Tool -join ', ')" -ForegroundColor Yellow
  exit 1
}

Write-Host "`nAll core tools detected." -ForegroundColor Green
