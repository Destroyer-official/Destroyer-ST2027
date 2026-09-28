# Offline 3-of-5 Threshold CA Key Ceremony (TOP SECRET)

This is the operator SOP for the hardware-rooted PQC PKI enforced by
`trust_anchor.py`. It mirrors the IANA Root Zone KSK ceremony shape
(3-of-7 HSM activation, dual occupancy, witnessed scripts, quarterly
cycles) at a 3-of-5 quorum with ML-DSA-87 (FIPS 204) keys.

## Roles (minimum attendance)

| Role | Count | Duty |
|---|---|---|
| Ceremony Administrator (CA) | 1 | owns the script, guard key, go/no-go |
| Internal Witness (IW) | 2 | dual occupancy, countersigns the log |
| Crypto Officers (CO) | 5 custodians | one ML-DSA-87 HSM key each |
| System Administrator (SA) | 1 | air-gapped host, clock, media |

No single person ever holds quorum. HSM activation requires 3 of 5
custodian credentials in the room (Tier-4 equivalent).

## Quorum mapping to code

- TOP SECRET root and identity certificates: **3-of-5**
  (`trust_anchor.py`: `_QUORUM = 3`, `_TOTAL = 5`, 48h max lifetime).
- `scripts/witnessed_key_ceremony.py` defaults to 2-of-3: approved for
  sub-CA and test roots only, never for the TOP SECRET root.
- Revocation broadcasts also require 3-of-5, so no single rogue
  custodian can revoke the fleet (denial-of-service resistance).

## Ceremony script

1. **Prepare (T-7d):** freeze the script revision, verify 5 HSMs show
   factory-fresh attestation, confirm two independent clocks agree
   within 5 s (`_MAX_SKEW_FUTURE`), print serial-numbered audit forms.
2. **Convene:** CA + 2 IW verify room, safes, and camera log; record
   ceremony ID `CEREMONY-CNSA2-<epoch>-<rand>` (see harness).
3. **Generate (air-gapped):** each custodian generates one ML-DSA-87
   keypair inside their HSM (`generate_identity_hsm`, never exportable).
   Export public keys only (2592 bytes each).
4. **Configure:** load the 5 public keys via `trust_anchor.configure()`
   or `P2P_CA_CUSTODIANS` JSON. Refuse on any size/label mismatch.
5. **Issue:** for each officer/device, build `CertTBS` (16-byte serial,
   subject label, 2592-byte ML-DSA-87 pk, ≤48h window) and collect 3
   signatures (`issue_certificate(..., authorized=custodians)`).
   Reject duplicate serials and >48h lifetimes fail-closed.
6. **Publish:** distribute certificates plus the custodian list over the
   already-established secure channel. Never transport private keys.
7. **Revoke on compromise:** build `Revocation` (serial, reason, seq+1),
   collect 3 signatures, `RevocationCache.add()` everywhere. Sequence is
   monotonic per serial; replays and stale broadcasts are refused.
   Revocation persists — it never expires.
8. **Close:** dual-control HSM shutdown, seal audit log
   (`compliance_reports/` Merkle-chained receipt from the harness),
   power off the air-gapped host.

## Failure modes

- Fewer than 3 custodians present → adjourn, no signatures.
- Any HSM attestation mismatch → quarantine that token, continue only
  with 3 remaining authorized custodians or adjourn.
- Clock skew >5 s → halt; timestamps gate every certificate and
  revocation.
- Lost custodian key → re-ceremony with a fresh 5-set; old set's
  certificates age out within 48h and revocations persist.
