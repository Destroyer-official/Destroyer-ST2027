# Program SOP — Sovereign Secure P2P Operations

## 1. Roles

| Role | Owns |
|---|---|
| Operator (each station) | Firewall rules, env flags, OOB ceremony, session monitoring |
| Key custodian | Provisioning (`tactical_key_provisioner.py`), fingerprint whitelist distribution |
| Auditor | `verify_all_dependencies()`, suite runs, log review, report sign-off |

## 2. Environment baseline (both stations)

```powershell
$env:P2P_REQUIRE_AUTH='true'     # default true; never set false for real links
$env:P2P_DATA_PLANE='python'     # set 'rust' only after wheel installed + gates green
# $env:P2P_ALLOW_LOOPBACK='1'    # LAB ONLY. Never on operational machines.
```

## 3. Pre-session checklist

- [ ] `cargo test` 19+ green (if Rust plane used), suites 14+ green
- [ ] `verify_all_dependencies()` passes (oqs.dll sidecar sig + pip floors)
- [ ] Firewall: allow ONLY peer /64 on P2P port, DROP rest; single `[::]` bind
- [ ] OOB channel (verified voice / in person) available for ceremony

## 4. Connection ceremony (every session)

### 4.1. 2027 Top-Secret Transmission Path (Primary)
1. **Receiver Node (Server)**:
   ```powershell
   python secure_transmit_2027.py --listen 50007 --peer <sender_host>
   ```
2. **Transmitter Node (Client)**:
   ```powershell
   # Single Persona Operator:
   python secure_transmit_2027.py --peer <receiver_host>:50007 --payload "FLASH-DEFCON1-ALPHA"
   
   # Dual Persona Operator (DoD S-5210.41M Two-Person Integrity):
   python secure_transmit_2027.py --peer <receiver_host>:50007 --payload "FLASH-DEFCON1-ALPHA" --dpo
   ```
3. **Power-Up Verification**:
   - The node automatically runs `crypto_selftest.py` power-up KATs (AES-256-GCM, HKDF-SHA384, X25519, P-384, SHA-384).
   - Validates OpenSSL FIPS provider and hardware TPM 2.0 posture.
4. **Hardware Root Validation**:
   - Both nodes exchange and verify offline 3-of-5 threshold ML-DSA-87 root certificates (`trust_anchor.py`). TOFU is eliminated in strict mode.
5. **Inner Hybrid Noise_XXhfs Handshake**:
   - Nodes exchange ephemeral `SecP384r1MLKEM1024` keys and authenticate transcripts via `ML-DSA-87`.
6. **Traffic Shaping & Transmission**:
   - Transmitted in constant-rate 50ms ticks using 1232-byte cells with AES-256-CTR whitening over Tor v3 / sovereign APN tunnel.

### 4.2. Legacy Prototype Chat (Research Lab Mode Only)
1. Server: `python secure_p2.py --port 50007` → option 1.
2. Client: option 2 → peer IPv6 + port.
3. TOFU safety number check and interactive chat exchange.

## 5. During operation

- Investigate (never ignore): pin `CHANGED`, reconnect storms, TOFU on a
  supposedly known peer, dependency-verification failures.
- Heartbeats/chaff are automatic (jittered). Do not "quiet" the link by
  disabling cover traffic.

## 6. Shutdown

- `exit` both ends → sessions terminate, profiles shred (DoD wipe).
- Verify `pins.json` persists (continuity) and no session artifacts remain.

## 7. Incident response (suspected compromise)

1. `exit` + power off affected endpoint (cold-boot: RAM decays; do NOT
   hibernate).
2. Preserve `logs/` + `secure_p2p_audit.db` copies for forensics.
3. Rotate identities: reprovision via `tactical_key_provisioner.py`,
   redistribute fingerprints OOB, delete old pins.
4. Root-cause from audit chain before reconnecting anything.
