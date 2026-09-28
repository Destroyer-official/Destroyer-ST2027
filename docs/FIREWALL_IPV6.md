# IPv6 Host Firewall Runbook — Direct P2P Listener Stealth
# Applies to the single chosen P2P port on BOTH endpoints (India + US).

## Goal
The listener behaves as a black hole to everyone except the peer's IPv6
prefix: no RST, no ICMP unreachable, no error replies. Scanners must see
`open|filtered` with zero response packets.

## Rules (Linux ip6tables; adapt interface/port)

```bash
PORT=51820
PEER64=<peer-public-/64-prefix>   # e.g. 2401:4900:1c60::/48 narrowed to /64

# 1. Accept ONLY the peer prefix on the P2P port (TCP now; add UDP at cutover)
ip6tables -A INPUT -p tcp --dport $PORT -s $PEER64 -j ACCEPT
# ip6tables -A INPUT -p udp --dport $PORT -s $PEER64 -j ACCEPT  # Phase 3 only

# 2. Drop everything else to that port silently (no --reject, no logging to wire)
ip6tables -A INPUT -p tcp --dport $PORT -j DROP
# ip6tables -A INPUT -p udp --dport $PORT -j DROP  # Phase 3 only

# 3. Bind the app to [::]:$PORT only — no other listening ports on the host
```

## Verify (from an unauthorized external host)

```bash
nmap -6 -sS -p $PORT <target>   # expect: open|filtered, no reply
nmap -6 -sU -p $PORT <target>   # expect: open|filtered, no reply
```

Any RST, ICMP unreachable, or error payload = FAIL, fix before live traffic.
Re-apply rules after every ISP prefix renumber; track peer /64 dynamically
(see Python control plane: prefix-tracking task, Phase 0 work item D0.5).
