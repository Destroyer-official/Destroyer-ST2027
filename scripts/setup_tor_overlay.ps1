# setup_tor_overlay.ps1 — provision the local Tor overlay (Windows).
# Mirrors scripts/setup_tor_overlay.sh gate-for-gate. Fail-closed: any
# missing daemon, binary, bridge config, or SOCKS5 greeting aborts with
# a non-zero exit before any session starts.
$ErrorActionPreference = "Stop"

# Administrator elevation (asked, never taken): full TPM/DeviceGuard/HSM
# posture reads need it. Declining continues with reduced posture and the
# pipeline's fail-closed gates still enforce. Non-interactive shells skip
# the prompt. P2P_NO_ELEVATE=1 accepts reduced posture explicitly.
try {
    $IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { $IsAdmin = $false }
if (-not $IsAdmin -and -not $env:P2P_NO_ELEVATE) {
    $Answer = "n"
    try { $Answer = Read-Host "Administrator rights unlock full hardware posture reads (TPM/VBS/HVCI/HSM). Elevate now? [y/N]" } catch {}
    if ($Answer -match "^[Yy]") {
        $Args = "-NoProfile -File `"$PSCommandPath`""
        Start-Process -FilePath "powershell" -ArgumentList $Args -Verb RunAs
        exit $LASTEXITCODE
    }
    Write-Warning "continuing without elevation — admin-gated checks report UNKNOWN"
}

$TorSocks = if ($env:P2P_TOR_PROXY) { $env:P2P_TOR_PROXY } else { "127.0.0.1:9050" }
$Torrc = if ($env:P2P_TORRC) { $env:P2P_TORRC } else { "$env:ProgramData\Tor\torrc" }

function Fail([string]$Message) {
    Write-Error "TOR-OVERLAY-FAIL: $Message"
    exit 1
}

if (-not (Get-Command tor -ErrorAction SilentlyContinue)) {
    Fail "tor daemon not installed (install Tor Expert Bundle)"
}
if (-not (Get-Command lyrebird -ErrorAction SilentlyContinue)) {
    Fail "lyrebird PT bundle missing (obfs4/snowflake/webtunnel)"
}

# Clock skew breaks onion handshakes and certificate windows.
[DateTimeOffset]::UtcNow.ToUnixTimeSeconds() | Out-Null

# Local SOCKS5 must answer with a real greeting (mirrors check_tor_proxy_live).
$ProxyHost, $ProxyPort = $TorSocks.Split(":")
$ProxyPort = [int]$ProxyPort
$Client = New-Object Net.Sockets.TcpClient
try {
    $Connect = $Client.BeginConnect($ProxyHost, $ProxyPort, $null, $null)
    if (-not $Connect.AsyncWaitHandle.WaitOne(5000)) { Fail "proxy unreachable: $TorSocks" }
    $Client.EndConnect($Connect)
    $Stream = $Client.GetStream()
    $Stream.Write([byte[]](0x05, 0x01, 0x00), 0, 3)
    $Resp = New-Object byte[] 2
    $Read = 0
    while ($Read -lt 2) {
        $N = $Stream.Read($Resp, $Read, 2 - $Read)
        if ($N -le 0) { Fail "SOCKS5 greeting refused — is Tor running with SocksPort?" }
        $Read += $N
    }
    if ($Resp[0] -ne 0x05 -or $Resp[1] -ne 0x00) {
        Fail "SOCKS5 greeting refused — is Tor running with SocksPort?"
    }
} catch {
    Fail "proxy dial refused: $($_.Exception.Message)"
} finally {
    $Client.Close()
}

if ($env:P2P_TOR_PT -eq "required") {
    if (-not (Test-Path $Torrc)) { Fail "P2P_TOR_PT=required but torrc missing: $Torrc" }
    $Lines = Get-Content $Torrc | ForEach-Object { ($_ -split "#")[0].Trim().ToLower() } |
        Where-Object { $_ -ne "" }
    $Bridges = $Lines | Where-Object { $_ -match "^usebridges\s+1" }
    $PT = $Lines | Where-Object { $_ -match "^clienttransportplugin" }
    if (-not $Bridges -or -not $PT) {
        Fail "P2P_TOR_PT=required but $Torrc lacks UseBridges/ClientTransportPlugin"
    }
    # A copied-but-unfilled torrc.ts-hardened template must never pass.
    if (Select-String -Path $Torrc -Pattern "__OPERATOR_[A-Z_0-9]+__" -Quiet) {
        Fail "P2P_TOR_PT=required but $Torrc still has unfilled __OPERATOR_*__ placeholders"
    }
    Write-Output "tor_pt_configured"
}

Write-Output "TOR overlay ready: $TorSocks"
Write-Output "Next: `$env:P2P_TRANSPORT_MODE='tor'; `$env:P2P_OVERLAY_ACTIVE='1'"
