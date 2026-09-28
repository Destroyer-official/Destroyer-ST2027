#!/bin/sh
# setup_wireguard.sh — provision the sovereign WireGuard / private-APN path.
# Fail-closed: refuses to mark the overlay active unless the interface,
# peer prefix, and handshake all verify.
# Usage: setup_wireguard.sh <interface> <peer-prefix>   (e.g. wg-ts 2001:db8:7::/48)
set -eu

IFACE="${1:-${P2P_WG_IFACE:-}}"
PREFIX="${2:-${P2P_PEER_PREFIX:-}}"

fail() { echo "WG-OVERLAY-FAIL: $1" >&2; exit 1; }
[ -n "$IFACE" ] || fail "interface required (arg 1 or P2P_WG_IFACE)"
[ -n "$PREFIX" ] || fail "peer prefix required (arg 2 or P2P_PEER_PREFIX)"
command -v wg >/dev/null 2>&1 || fail "wireguard tools missing (wg)"

wg show "$IFACE" >/dev/null 2>&1 || fail "interface $IFACE absent"
wg show "$IFACE" | grep -q "latest handshake" \
  || fail "interface $IFACE has no completed handshake — peer not live"

python3 - "$PREFIX" <<'EOF'
import ipaddress, sys
net = ipaddress.ip_network(sys.argv[1], strict=False)
if net.version != 6 or net.prefixlen > 64:
    raise SystemExit("peer prefix must be IPv6 /64 or shorter")
print("peer_prefix_ok=%s" % net)
EOF

echo "WG overlay ready: $IFACE $PREFIX"
echo "Next: export P2P_TRANSPORT_MODE=wireguard P2P_OVERLAY_ACTIVE=1 P2P_PEER_PREFIX=$PREFIX"
