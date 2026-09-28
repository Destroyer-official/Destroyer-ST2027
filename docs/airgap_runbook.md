# Air-Gap Runbook (short)

No network. Fail-closed. Additive helpers only; default paths unchanged.

## 1. Clock discipline

- `air_gapped_operation.secure_time_now(peer_times=None)`:
  - No args -> `time.time()` (float). All old call sites unchanged.
  - `peer_times` with 3+ samples -> returns `(median, skew_warn)` where
    `median = statistics.median(peer_times)`.
  - If `abs(local - median) > 60s`: logs `WARNING`, sets `skew_warn=True`.
  - **Never auto-adjusts the OS clock.** On `skew_warn=True` stop and require
    explicit operator acknowledgement (manual clock check, BIOS/NTP-out-of-band).
- `check_freshness(ts, window=60)` uses secure time:
  `abs(now - ts) <= window`. Optional `now=` / `peer_times=` kwargs only.
- Discovery broadcasts keep their own guard (`60s`, or
  `P2P_AIRGAP_MAX_CLOCK_SKEW_SECONDS` when `P2P_AIR_GAPPED_MODE=1`); new helpers
  do not change that path.

Operator ack: `now, warn = secure_time_now(peers)`; if `warn`: do not proceed
with PSK/cert acceptance until clock is verified out-of-band.

## 2. USB transfer (sneakernet only)

1. Export on source host to a clean FAT32 USB: `bundle.json` (+ write down hash).
2. Eject, carry, insert on air-gapped host. No Ethernet/Wi-Fi/Bluetooth.
3. Recompute hash on destination, compare to written value before import.
4. Import, then wipe USB or retain per policy. Never run `pip`/`curl` on the gap host.

## 3. CRL bundle flow

Reuse `MultiDeviceManager.export_crl_bundle` / `import_crl_bundle` when importable,
else JSON passthrough with schema + version check:

```sh
# Export (revoking host)
python scripts/crl_bundle.py export --out bundle.json --user alice --issuer alice
# optional: --version 7 --devices-file devices/devices.json --signing-key certs/crl_mldsa87_signer.sk

# Import (air-gapped host, after hash check)
python scripts/crl_bundle.py import --in bundle.json
# optional: --devices-file devices/devices.json --verify-key certs/crl_mldsa87_signer.pub --enforce-sig
```

- Signed when `P2P_CRL_SIGNING_KEY` / `SBOM_SIGNING_KEY` / `certs/crl_mldsa87_signer.sk`
  is present (`alg=mldsa87`); else unsigned (`alg=none`, lab fail-open warning).
- Import verifies ML-DSA-87 `sig` when present, honors `P2P_CRL_REQUIRE_SIG=1` /
  `--enforce-sig`, and enforces per-issuer monotonic `version` (stale `<= stored`
  is ignored). Matching devices are marked `REVOKED`.

## 4. Bundle hash check

Canonical hash (what the CLI prints):

```sh
python -c "import json,hashlib; b=json.load(open('bundle.json')); print(hashlib.sha3_512(json.dumps(b,sort_keys=True,separators=(',',':')).encode()).hexdigest())"
```

- Record `sha3-512:` printed by `export`.
- After USB copy, recompute / run `import` (it prints the hash) and compare.
- Mismatch -> do not import; re-copy, re-verify USB media.

## 5. Ceremony export/import checklist (offline host)

Quorum terminology matches `scripts/witnessed_key_ceremony.py`: M-of-N
Custodian Quorum, default 2-of-3 (`CUSTODIAN-01` Master Security Officer,
`CUSTODIAN-02` Independent Security Auditor, `CUSTODIAN-03` Enclave
Operations Lead). Proceed only on `CUSTODIAN_QUORUM_VERIFIED` with
`quorum_required=2`, `total_registered>=2`, plus `HARDWARE_ROOT_ENFORCED`
(TPM 2.0/HSM); `DEGRADED_SECONDARY_SIMULATION` = stop.

Export (ceremony host, offline):

1. `python scripts/witnessed_key_ceremony.py` -> file receipt in
   `compliance_reports/ceremony_receipt_<ts>.json`; pin Merkle root OOB.
2. `python scripts/sign_boot_config.py --config config_production.json --pub-out certs/config_trust_root.pub --dsse`
   -> `.mldsa87.sig` + `.pub` + `.dsse`; write down `sha512(pub)` fingerprint.
3. `python scripts/crl_bundle.py export --out bundle.json --user alice --issuer alice --signing-key certs/crl_mldsa87_signer.sk`
   -> note printed `sha3-512:`; copy `bundle.json` to clean FAT32 USB.
4. Scan USB on isolated scanner host (no executables/autorun); record hashes on paper.

Import (air-gapped host, no network):

1. Recompute bundle sha3-512 (section 4 command); compare to paper value. Mismatch -> quarantine USB.
2. `python scripts/crl_bundle.py import --in bundle.json --verify-key certs/crl_mldsa87_signer.pub --enforce-sig`
   -> stale `version <= stored` ignored; unsigned rejected under `P2P_CRL_REQUIRE_SIG=1`/prod.
3. Verify boot config sig + `.dsse` via `ConfigManager.verify_config_signature()`; check clock (`secure_time_now`, section 1) before accepting.
4. Wipe USB or retain per policy; log receipt + hashes in ceremony record.
