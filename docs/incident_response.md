# Incident Response (Compromise Scenarios)

Isolate first, then revoke/rekey. Keep prod flags on while triaging.

## 0. Triage greps (exact strings)

```sh
Select-String -Pattern "CHANGED|MITM guard|TOFU first-contact" logs\*.log secure_p2p_audit.db-wal
Select-String -Pattern "CRL freshness check failed|OCSP staple verification failed|OCSP response verification failed|CRL signature verification failed|CRL hash chain integrity check failed" logs\*.log
Select-String -Pattern "Rollback attack detected|version mismatch vs .* meta \(rollback\?\)|CONFIG_ROLLBACK_DENIED|TAMPER/ROLLBACK DETECTED" logs\*.log tuf_update_state.json
Select-String -Pattern "FAIL-CLOSED: P2P_ALERTS_REQUIRE_SIG=1|unsigned bundle|WORM Policy Violation" logs\*.log
```

| Scenario | Exact log string | Meaning |
|---|---|---|
| Peer key changed | `CRITICAL SECURITY ALERT: Certificate fingerprint for '<host>' CHANGED from pinned value!` / `Certificate continuity failure for peer <host>: Fingerprint has changed unexpectedly (MITM guard).` | TOFU pin `CHANGED` (`ui/safety_numbers.check_pin`). Assume MITM. |
| TOFU first contact | `FAIL-CLOSED: TOFU first-contact certificate for '<host>' (...) rejected: peer is not in pre-authorized whitelist.` | Unknown peer blocked by whitelist gate. |
| CRL/OCSP fail | `CRL freshness check failed in <ctx>: CRL older than ...` / `OCSP staple verification failed in production; fail-closed: ...` / `OCSP Stapling fail-closed in production: no cert/key for staple.` / `OCSP response verification failed: serial=<n>` | Stale CRL or bad/missing OCSP staple. Prod rejects. |
| TUF rollback | `Rollback attack detected: update version_counter=<v> <= current=<c>` / `Rollback attack detected: <role>.json version=<v> ...` / `snapshot.json version mismatch vs timestamp meta (rollback?)` / `targets.json version mismatch vs snapshot meta (rollback?)` | Downgrade/replay of update metadata. |
| Config rollback | `CONFIG_ROLLBACK_DENIED path=<f> signer_id=<id> ...` / `TAMPER/ROLLBACK DETECTED: monotonic_counter <in> <= last_counter <last> ...` | Stale/tampered boot config refused. |
| SIEM alert sig fail | `FAIL-CLOSED: P2P_ALERTS_REQUIRE_SIG=1 but no alert signing key ...` | Alert path misconfigured; alerts not trusted. |

## 1. Peer key CHANGED (suspected MITM)

1. Stop sessions to that peer. Do not reconnect, do not clear pin store.
2. Re-verify fingerprint OOB (second channel / safety numbers both ends).
3. If legitimate rotation: remove old pin only after OOB confirm, re-pin on next verified contact.
4. If not confirmed: treat host/network as compromised; rotate local keys (section 4).

## 2. CRL/OCSP failure

1. Confirm env: `P2P_CRL_REQUIRE_SIG=1`, `P2P_OCSP_MUST_STAPLE=1` (prod auto-strict).
2. Pull fresh CRL/OCSP OOB; check `this_update`/`next_update` freshness.
3. Push revocation bundle to fleet via air-gap flow (section 4). Prod keeps rejecting until fresh.

## 3. TUF / config rollback attempt

1. Quarantine the update package + transport media. Record versions (`version_counter`, per-role `version`, `monotonic_counter`).
2. Re-fetch from trusted source; re-verify (`verify_update_package`, config sig + `.dsse`).
3. Never lower counters to "fix" it. Investigate supplier/host compromise first.

## 4. Revoke + rekey

Revoke (CA):

```python
from pq_certificate_authority import PqCertificateAuthority
ca = PqCertificateAuthority()  # your existing CA instance
ca.revoke_certificate(serial, reason)          # or:
ca.propagate_revocation(serial, reason)        # bumps CRL version + re-signs
ca.rotate_authority_key(new_pub, new_sec)      # CA key rotation; old key kept 7d dual-sign window
```

Distribute (revoking host -> fleet, air-gap):

```sh
python scripts/crl_bundle.py export --out bundle.json --user alice --issuer alice --version 8 --signing-key certs/crl_mldsa87_signer.sk
python scripts/crl_bundle.py import --in bundle.json --verify-key certs/crl_mldsa87_signer.pub --enforce-sig
```

Rekey sessions:

```python
ratchet.force_pq_ratchet()   # at most once per 60s; raises SecurityError on legacy v1 / no DH material
```

Also call `rotate_keys()` / `rotate_key(...)` on `hybrid_kex`, `protocol_manager.rotate_session_keys(session_id)`, `group_key_manager.rotate(group_id)` as applicable. Confirm new handshake + fresh OCSP staple before resuming traffic.

## 5. Device loss

1. Revoke its cert serial + device entry (`MultiDeviceManager.revoke_device`), export CRL bundle (above), import fleet-wide.
2. Rotate group/CA keys it knew. Treat cached messages as exposed; force peer re-verify (TOFU OOB).

## 6. Backup restore

`SecureEnclaveKeyStorage.export_backup(passphrase)` -> `BACKUP_V1` blob (PBKDF2-210k-SHA512 + AES-256-GCM); restore with `import_backup(blob, passphrase)` (all-or-nothing, fail-closed on bad passphrase/version/tamper). Keep passphrase offline (sealed envelope / HSM), separate from blob media.

## 7. Evidence preservation

1. Freeze: copy `logs/`, `secure_p2p_audit.db*`, WORM export (`P2P_WORM_STORAGE_PATH`), `tuf_update_state.json`, CRL bundle + hashes, ceremony receipts. Do not delete.
2. WORM DB has `prevent_audit_update` / `prevent_audit_delete` triggers: updates abort with `WORM Policy Violation: Audit events are immutable ...`. Verify chain (`verify_chain_integrity()` / WORM export verify, genesis `GENESIS_WORM_BLOCK_...`).
3. Lock perms: audit DB + WORM path operator-read-only (Windows: `icacls secure_p2p_audit.db /inheritance:r /grant:r Administrators:F`; Linux: `chmod 600 secure_p2p_audit.db`). Stream to remote SIEM over mutual-TLS; never edit the DB to "clean" alerts.
