# Deployment Hardening Guide (Production)

Fail-closed defaults. No lab overrides on prod hosts.

## 1. Production env matrix

Set in environment (sticky latch; cleared-after-latch is logged):

```bat
set P2P_PRODUCTION=1
set P2P_FAIL_ON_SOFTWARE_FALLBACK=1
set P2P_REQUIRE_SIGNED_DHT=1
set P2P_ENFORCE_DHT_POW=1
set P2P_DHT_POW_DIFFICULTY_BYTES=3
set P2P_OCSP_MUST_STAPLE=1
set P2P_STRICT_ENCRYPT=1
```

| Flag | Prod value | Fail-closed expectation |
|---|---|---|
| `P2P_PRODUCTION` (`SECURE_P2P_PRODUCTION` alias) | `1` | Sticky latch; auto-enables RBAC/ALERTS/CRL/OCSP/STRICT rows below. Opt-outs ignored in prod (`PROD-STRICT: ignoring ...`). |
| `P2P_FAIL_ON_SOFTWARE_FALLBACK` | `1` | No HSM/TPM -> `MILITARY FATAL` + abort. `verify_deployment.py` FAILs if unset/weakened. |
| `P2P_REQUIRE_SIGNED_DHT` | `1` (default `1`) | Unsigned DHT record dropped. `verify_deployment.py` FAILs if set to anything but `1`. |
| `P2P_ENFORCE_DHT_POW` | `1` (default `1`) | Prod refuses `!=1`: `MILITARY FATAL: production refuses P2P_ENFORCE_DHT_POW!=1 (Sybil downgrade)`. |
| `P2P_DHT_POW_DIFFICULTY_BYTES` | `3` for high-threat (default `2`) | Matched gen==verify default is 2 (16-bit, reliable to mine). Raising to 3 requires persistent pre-mined identities (default-3 mining averages ~35s with frequent budget overrun). `verify_deployment.py` WARNs when prod runs below 3. |
| `P2P_RBAC_STRICT` | auto-True in prod | Deny-by-default. Explicit `=0` ignored in prod (`PROD-STRICT`). |
| `P2P_ALERTS_REQUIRE_SIG` | auto-True in prod | Unsigned alert refused: `FAIL-CLOSED: P2P_ALERTS_REQUIRE_SIG=1 but no alert signing key ...`. |
| `P2P_CRL_REQUIRE_SIG` | auto-True in prod (sticky prod) | Unsigned CRL import rejected: `CRL import: unsigned bundle rejected (strict: P2P_CRL_REQUIRE_SIG/prod)`. Explicit `=0` ignored in prod. |
| `P2P_OCSP_MUST_STAPLE` | `1` (default `0` lab, `1` when `P2P_PRODUCTION=1`) | Missing/stale staple rejected: `OCSP staple verification failed in production; fail-closed: ...` / `OCSP Stapling fail-closed in production: no cert/key for staple.` |
| `P2P_STRICT_ENCRYPT` | `1` (auto-on in prod) | Plaintext/unkeyed path refused with `SecurityError`. Lab fallback gone. |

Never set on prod: any `P2P_ALLOW_*=1` / `P2P_DISABLE_*=1` (caught by `verify_deployment.py` anti-downgrade check).

## 2. HSM provisioning (witnessed ceremony)

Terminology matches `scripts/witnessed_key_ceremony.py`: M-of-N Custodian Quorum, default 2-of-3.

```sh
python scripts/witnessed_key_ceremony.py
```

1. Register custodians: `CUSTODIAN-01` Master Security Officer, `CUSTODIAN-02` Independent Security Auditor, `CUSTODIAN-03` Enclave Operations Lead. Need `>= quorum_m` or `CUSTODIAN_QUORUM_VERIFIED` fails.
2. Check root of trust: want `HARDWARE_ROOT_ENFORCED` (TPM 2.0/HSM + PCR count + attestation). `DEGRADED_SECONDARY_SIMULATION` = stop, provision HSM, re-run.
3. File receipt in `compliance_reports/ceremony_receipt_<ts>.json`; pin Merkle root hash out-of-band.
4. Set `P2P_FAIL_ON_SOFTWARE_FALLBACK=1` only after step 2 passes.

## 3. Config signing (DSSE)

On the offline ceremony host:

```sh
python scripts/sign_boot_config.py --config config_production.json --pub-out certs/config_trust_root.pub --dsse
```

Emits `config_production.json.mldsa87.sig` + `.mldsa87.pub` (or `--pub-out`) + `.dsse` (DSSEv1 PAE, `ML-DSA-87`). Prints `sha512(pub)` fingerprint: pin via QR/paper. Verify with `ConfigManager.verify_config_signature()`. Missing/bad sig = fail-closed abort.

## 4. DLL + deployment verify

```sh
python deploy_production.py --check-only
python verify_deployment.py
```

Checks: `oqs.dll` / `libsodium.dll` present, Ed25519 sig (`.sig` + `.pub`) over raw DLL bytes, hash file (`.hashes`) match, `P2P_REQUIRE_SIGNED_DHT` / `P2P_FAIL_ON_SOFTWARE_FALLBACK` not weakened, no `P2P_ALLOW_*`/`P2P_DISABLE_*` overrides. Any FAIL = do not deploy. Baseline written to `notupload/backup/baseline_verification.json`.

## 5. Air-gap bundle flow

```sh
python scripts/crl_bundle.py export --out bundle.json --user alice --issuer alice
python scripts/crl_bundle.py import --in bundle.json --verify-key certs/crl_mldsa87_signer.pub --enforce-sig
```

Details in `docs/airgap_runbook.md`. Always sha3-512 check across the USB hop before import.

## 6. Clock discipline

Use `air_gapped_operation.secure_time_now(peer_times)`; `skew_warn=True` when `abs(local-median) > 60s`. Never auto-adjusts OS clock. On warn: stop PSK/cert acceptance, verify clock OOB (BIOS/operator), then proceed.

## 7. USB malware scan note

Scan every USB on an isolated scanner host before it touches a prod/air-gap host: clean FAT32, single `bundle.json` (+ `.sig`/`.dsse`), no executables/autorun. Hash on scanner, re-hash on destination; mismatch = quarantine media, do not import.
