# Hardware trust: `secure_enclave_key_storage.py`, `tee_manager.py`,
`pq_certificate_authority.py`, `tactical_key_provisioner.py` (verified maps)

## Key storage backends

TPM (Windows/Linux), macOS Enclave, PKCS#11 HSM, plus an explicit
`SoftwareFallbackBackend` that is LOUD about being software (no silent
downgrade). Attestation types recorded per key; unattested keys raise.

## TEE manager

SGX/TrustZone/SEV backends behind a common interface; simulated quotes
raise (verified disabled paths), never accepted.

## PQ CA + provisioner

`PQCertificateAuthority` (ML-DSA-87 roots, hash-chained CRL, CT log, OCSP).
`tactical_key_provisioner.py` mints `mldsa87` node credentials + mutual
whitelists + stealth-knock token OFFLINE (air-gapped ceremony). No network
calls in the provisioning path.
