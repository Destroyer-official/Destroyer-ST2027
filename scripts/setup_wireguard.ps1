# setup_wireguard.ps1 — provision the sovereign WireGuard / private-APN path.
# Mirrors scripts/setup_wireguard.sh gate-for-gate. Fail-closed: refuses to
# mark the overlay active unless the interface, peer prefix, and handshake
# all verify. Usage: setup_wireguard.ps1 <Interface> <Peer-Prefix>
param(
    [string]$Iface = $env:P2P_WG_IFACE,
    [string]$Prefix = $env:P2P_PEER_PREFIX
)
$ErrorActionPreference = "Stop"

# Administrator elevation (asked, never taken): reading interface/handshake
# state and enforcing tunnel policy need it. Declining continues; the
# overlay-active gate still refuses without a live peer handshake.
# P2P_NO_ELEVATE=1 accepts reduced posture explicitly.
try {
    $IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { $IsAdmin = $false }
if (-not $IsAdmin -and -not $env:P2P_NO_ELEVATE) {
    $Answer = "n"
    try { $Answer = Read-Host "Administrator rights unlock full tunnel verification. Elevate now? [y/N]" } catch {}
    if ($Answer -match "^[Yy]") {
        $Args = "-NoProfile -File `"$PSCommandPath`""
        if ($Iface) { $Args += " `"$Iface`"" }
        if ($Prefix) { $Args += " `"$Prefix`"" }
        Start-Process -FilePath "powershell" -ArgumentList $Args -Verb RunAs
        exit $LASTEXITCODE
    }
    Write-Warning "continuing without elevation — admin-gated checks report UNKNOWN"
}

function Fail([string]$Message) {
    Write-Error "WG-OVERLAY-FAIL: $Message"
    exit 1
}

if (-not $Iface) { Fail "interface required (arg 1 or P2P_WG_IFACE)" }
if (-not $Prefix) { Fail "peer prefix required (arg 2 or P2P_PEER_PREFIX)" }
if (-not (Get-Command wg -ErrorAction SilentlyContinue)) {
    Fail "wireguard tools missing (wg)"
}

$Show = (& wg show $Iface 2>&1)
if ($LASTEXITCODE -ne 0) { Fail "interface $Iface absent" }
if ($Show -notmatch "latest handshake") {
    Fail "interface $Iface has no completed handshake — peer not live"
}

python -c "import ipaddress,sys; net=ipaddress.ip_network(sys.argv[1],strict=False); assert net.version==6 and net.prefixlen<=64, 'peer prefix must be IPv6 /64 or shorter'; print('peer_prefix_ok=%s' % net)" $Prefix
if ($LASTEXITCODE -ne 0) { Fail "peer prefix refused: $Prefix" }

Write-Output "WG overlay ready: $Iface $Prefix"
Write-Output "Next: `$env:P2P_TRANSPORT_MODE='wireguard'; `$env:P2P_OVERLAY_ACTIVE='1'; `$env:P2P_PEER_PREFIX='$Prefix'"
