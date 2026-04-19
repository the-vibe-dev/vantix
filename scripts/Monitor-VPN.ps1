param(
  [string]$TargetIP = '10.64.135.12',
  [int[]]$Ports = @(22,80),
  [int]$IntervalSeconds = 5
)

$ErrorActionPreference = 'Continue'
$log = 'C:\Users\cvosb\CTF\vpn\tryhackme\monitor.log'

"=== Monitor started $(Get-Date -Format o) target=$TargetIP ===" | Tee-Object -FilePath $log -Append

while ($true) {
  $ts = Get-Date -Format o
  $ovpn = Get-Process openvpn -ErrorAction SilentlyContinue
  $route = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '10.64.0.0/12' -ErrorAction SilentlyContinue | Select-Object -First 1

  $parts = @()
  $parts += "time=$ts"
  $parts += "openvpn=$(if($ovpn){'up'}else{'down'})"
  $parts += "route=$(if($route){'ok'}else{'missing'})"

  foreach ($p in $Ports) {
    $ok = (Test-NetConnection $TargetIP -Port $p -WarningAction SilentlyContinue).TcpTestSucceeded
    $parts += "p${p}=$(if($ok){'open'}else{'closed/filtered'})"
  }

  $line = ($parts -join ' ')
  $line | Tee-Object -FilePath $log -Append
  Start-Sleep -Seconds $IntervalSeconds
}
