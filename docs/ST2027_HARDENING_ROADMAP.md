# ST2027 Production Hardening Roadmap (Research-Backed)

Basis: NIST IR 8547 (2026), FIPS 203/204, CNSA 2.0, RFC 10024,
and ePrint 2026/1467 (Crypto-Agility Readiness Score).

## Already implemented
- Production entry point: `secure_p2p.py node` (PSK + pinned mutual ML-DSA-87
  required; PSK-only and lab surfaces gated behind `--lab`).
- Rust data plane: SecP384r1MLKEM1024 + ML-DSA-87 + AES-256-GCM + SHA-384.
- Mutual ML-DSA-87 transcript authentication bound into the KDF and SAS;
  see `docs/ST2027_MUTUAL_AUTH_HARDENING.md`.
- Production crypto-policy self-check refuses known weakening env overrides.
- Simulated NC3/EAM/PTT commands refused on the production message path.
- Python Zero-Gap pipeline: AES-256-GCM inner ratchet + HKDF/HMAC-SHA384.
- SHA-384 cookie PoW and group/TPM/state ratchets.
- Versioned profile KDF (Argon2id/PBKDF2-SHA512).
- Self-test and entrypoint tests (including real mutual-auth KEX).

## Remaining research-backed priorities
1. Architectural decoupling (CARS d3): ensure every crypto primitive is behind
   an interface so swaps do not touch call sites. Current Rust plane is close;
   Python legacy chat is still monolithic and quarantined.
2. Side-channel validation: obtain or build constant-time evidence for ML-KEM
   and P-384 on the target hardware; document timing variance.
3. Hardware root of trust: require TPM/HSM in production, not software fallback.
4. Formal review of hybrid combiner and ratchet composition.
5. Supply-chain and reproducible-build verification of Rust + Python artifacts.
6. Operational: key ceremony, two-person integrity, audit retention, incident response.

## Recommended next implementation
- Add a `crypto_agility` interface layer around all KEM/signature/AEAD calls.
- Add constant-time regression tests (timing variance thresholds).
- Require TPM-backed monotonic counter for state (fail closed if absent).
- Produce a signed migration-readiness report (CARS-style) per deployment.

This roadmap is the "best plane"; implementation should proceed item by item
with verification gates.
