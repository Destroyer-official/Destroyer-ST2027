# Concept of Operations (CONOPS): Sovereign Military Tactical P2P Communications Mesh

## 1. Document Control & Classification
- **Document ID:** `CONOPS-TACTICAL-P2P-2028-V1`
- **Classification:** UNCLASSIFIED (self-marked work product; no distribution limitation asserted by any authority; FOUO retired 2019 -- not used)
- **Compliance Standards:** DoD Risk Management Framework (RMF), NIST SP 800-53 Rev 5, CNSSI 1253, NSA CNSA 2.0 Strict
- **System Impact Level:** FIPS 199 High-High-High

---

## 2. Operational Mission & Purpose
The Sovereign Military Tactical P2P Communications Mesh (`Destroyer-P2P`) provides quantum-secure, decentralized, point-to-point tactical voice, messaging, telemetry, and file exchange without dependency on centralized infrastructure, cloud brokers, or unauthenticated third-party relays.

---

## 3. Operational Environments

| Environment ID | Designation | Network Topology | Threat Tier | Security Posture |
| :--- | :--- | :--- | :--- | :--- |
| **ENV-AIRGAP** | Strategic Command Post (C2) | Isolated Fiber / Air-gapped LAN | Tier-6 (Nation-State Strategic) | Strict HW TPM 2.0, Chaff Jitter, No Internet Gateways |
| **ENV-EDGE** | Tactical Edge Mobile Relay | Private Cellular APN / UHF Mesh | Tier-5 (EW / SIGINT Intercept) | Tactical Cloak Active, Fixed Quantum Sizing |
| **ENV-DDIL** | Disconnected / Reconnaissance | Peer-to-Peer Ad-Hoc Direct UDP | Tier-6 (Battlefield Physical Overrun) | Stealth Mode, Out-of-Band Safety Pins, Auto-Zeroize |

---

## 4. Operational Roles & Custodianship

1. **Designated Authorizing Official (AO)**:
   - Maintains statutory responsibility under DoD Instruction 8510.01 for system risk acceptance.
   - Evaluates automated OSCAL System Security Plans, ACVP validation reports, and continuous monitoring telemetry.
   - Grants Full Authority to Operate (ATO) and Continuous ATO (cATO).

2. **Cryptographic Officer (CO)**:
   - Oversees generation and registration of root identity keys (FIPS 204 ML-DSA-87 / FIPS 205 SLH-DSA-256f).
   - Manages physical Hardware Root-of-Trust (Win32 TBS TPM 2.0 / PKCS#11 HSM) and sealed PCR measurements.
   - Authorizes key revocation and superintends multi-custodian ceremonies.

3. **Tactical Node Operator (TNO)**:
   - Deploys and manages localized communications nodes in forward operating positions.
   - Verifies Out-Of-Band (OOB) TOFU safety number hashes before initial operational messaging.
   - Enforces `--tactical-cloak` and executes emergency sanitization commands upon breach warning.

4. **Incident Response Commander (IRC)**:
   - Continuously audits remote SIEM forward-secure HMAC-SHA384 log chains.
   - Analyzes automated black-hole silent drop telemetry and probe rate-limiting events.
   - Directs post-compromise key replacement and forensic head anchor verification.

---

## 5. Operational Modes of Operation

### 5.1 Normal Tactical Mode
- **Transport**: WireGuard-style UDP Data Plane leveraging native Rust engine (`destroyer_core`).
- **Framing**: Strict fixed quantum padding (256B, 512B, 1232B) eliminating message length side-channels.
- **Traffic Shaping**: Poisson background chaff (`0xFF` frames) with randomized 2.5s–6.0s jitter.
- **Rate Limiting**: Token-bucket per source IP (64 burst capacity, 16 refill tokens/sec).

### 5.2 Tactical Cloaked Mode (`P2P_TACTICAL_CLOAK=1`)
- **Prohibition**: Zero direct sockets bound to or communicating across unencapsulated public IPv4/IPv6 networks.
- **Permitted Paths**: Loopback, RFC 1918 private subnets, and tactical overlay tunnels (`10.99.0.0/16`).
- **Scanner Stealth**: Non-whitelisted packets or malformed payloads elicit 0 bytes of response (silent black-hole).

### 5.3 Emergency Zeroization Mode
- **Triggers**: Repeated TPM PCR tamper alert, unauthorized enclosure tampering, physical capture threat.
- **Execution Protocol**:
  1. Instantly shred active Double Ratchet symmetric keys and KEM secrets in memory (`ZeroizeOnDrop`).
  2. Overwrite mutable Python bytearrays with `0x00`.
  3. Close all open UDP/TCP sockets without transmitting RST or teardown notifications.
  4. Transmit signed tamper alert to remote SIEM audit stream.
  5. Invalidate TPM 2.0 session handle and purge local credential databases.
