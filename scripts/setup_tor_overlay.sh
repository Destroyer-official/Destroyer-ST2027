#!/bin/sh
# setup_tor_overlay.sh — provision the local Tor overlay for TOP SECRET transport.
# Fail-closed: every check aborts before any session starts.
# Requirements: tor daemon, lyrebird PT bundle (obfs4/snowflake/webtunnel),
# one or more bridge lines from bridges.torproject.org (or @GetBridgesBot).
set -eu

TOR_SOCKS="${P2P_TOR_PROXY:-127.0.0.1:9050}"
TORRC_HINT="${TORRC:-/etc/tor/torrc}"

fail() { echo "TOR-OVERLAY-FAIL: $1" >&2; exit 1; }

command -v tor >/dev/null 2>&1 || fail "tor daemon not installed (install tor expert bundle)"
command -v lyrebird >/dev/null 2>&1 || fail "lyrebird PT bundle missing (obfs4/snowflake/webtunnel)"

# Clock skew breaks onion handshakes and certificate validity windows.
python3 -c "import time; print('clock_utc=%d' % time.time())" >/dev/null \
  || fail "system clock unreadable"

# Local SOCKS5 must answer with a real greeting (mirrors check_tor_proxy_live).
python3 - "$TOR_SOCKS" <<'EOF'
import socket, sys
host, _, port = (sys.argv[1] or "127.0.0.1:9050").rpartition(":")
s = socket.create_connection((host.strip() or "127.0.0.1", int(port or "9050")), timeout=5)
s.settimeout(5)
s.sendall(b"\x05\x01\x00")
resp = s.recv(2)
if len(resp) != 2 or resp[0] != 0x05 or resp[1] != 0x00:
    raise SystemExit("SOCKS5 greeting refused — is Tor running with SocksPort?")
print("tor_socks5_live")
EOF

if [ "${P2P_TOR_PT:-}" = "required" ]; then
  grep -Eq "ClientTransportPlugin|UseBridges 1" "$TORRC_HINT" 2>/dev/null \
    || fail "P2P_TOR_PT=required but $TORRC_HINT has no ClientTransportPlugin/UseBridges"
  # A copied-but-unfilled torrc.ts-hardened template must never pass:
  # every __OPERATOR_*__ placeholder requires a site value.
  grep -Eq "__OPERATOR_[A-Z_0-9]+__" "$TORRC_HINT" 2>/dev/null \
    && fail "P2P_TOR_PT=required but $TORRC_HINT still has unfilled __OPERATOR_*__ placeholders"
  echo "tor_pt_configured"
fi

echo "TOR overlay ready: $TOR_SOCKS"
echo "Next: export P2P_TRANSPORT_MODE=tor P2P_OVERLAY_ACTIVE=1"
