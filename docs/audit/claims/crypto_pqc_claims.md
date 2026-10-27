# Claims Register: crypto_pqc

| Claim | Source File:Line | Evidence Type | Status |
|---|---|---|---|
| Mandatory baseline enforces strict CNSA Suite 2.0 (FIPS 203 ML-KEM-1024, FIPS 204 ML-DSA-87, AES-256-GCM, SHA-384) | README.md:49 | Code inspection (`cnsa_purity.py:5-7`, `cnsa2_policy_engine.py:8-13`) | VERIFIED |
| EnhancedFALCON_1024 labels a hybrid ML-DSA+SLH-DSA construction; no OQS_SIG_new("Falcon-*") call exists | docs/modules/pqc_algorithms.md:29-30 | Code inspection (`liboqs_wrapper.py:656-660`, `pqc_algorithms.py:5023-5034`) | CONTRADICTED |
| EnhancedMLKEM_1024 keygen generates public key 1568 bytes, private key 3168 bytes, ciphertext 1568 bytes, shared secret 32 bytes | docs/modules/pqc_algorithms.md:36 | Code inspection (`pqc_algorithms.py:3838-3841`), test execution (`tests/test_falcon_bundle_mode_consistency.py`) | VERIFIED |
| Pure ML-KEM-1024 uses domain separator string b"MLKEM-1024-FIPS203-v1" | docs/SYSTEM_SECURITY_DOCUMENTATION.md:118 | Code inspection (`pqc_algorithms.py:3830`) | VERIFIED |
| Classic McEliece-8192128f generates public key 1357824 bytes, private key 14120 bytes, ciphertext 208 bytes, shared secret 32 bytes | docs/SYSTEM_SECURITY_DOCUMENTATION.md:120 | Code inspection (`liboqs_wrapper.py:410-415`, `pqc_algorithms.py:3833-3836`) | VERIFIED |
| Hybrid KEM (ML-KEM-1024 + Classic McEliece-8192128f) derives a 48-byte shared secret via HKDF-SHA384 | docs/modules/pqc_algorithms.md:15 | Code inspection (`liboqs_wrapper.py:868-873`, `liboqs_wrapper.py:928`) | VERIFIED |
| ML-DSA-87 generates public key 2592 bytes, private key 4896 bytes, signature 4627 bytes | docs/SYSTEM_SECURITY_DOCUMENTATION.md:119 | Code inspection (`liboqs_wrapper.py:549-551`), test execution (`tests/test_ratchet_dss_mldsa87.py`) | VERIFIED |
| SLH-DSA-256f (pure SHAKE fast) generates public key 64 bytes, private key 128 bytes, signature 49856 bytes | docs/SYSTEM_SECURITY_DOCUMENTATION.md:121 | Code inspection (`liboqs_wrapper.py:606-608`) | VERIFIED |
| HQC-256 is refused by default and requires P2P_ENABLE_VULN_HQC=1 override | README.md:103 | Code inspection (`liboqs_wrapper.py:481-486`) | VERIFIED |
| Power-up self-tests verify AES-GCM, HKDF-SHA384, X25519 (RFC 7748), P-384 ECDH, and ML-KEM/ML-DSA pair consistency before sessions start | README.md:163 | Test execution (`python -c "import crypto_selftest; print(crypto_selftest.run_powerup_selftests())"`) | VERIFIED |
| pqc_algorithms.py contains approximately 6500 lines | docs/modules/pqc_algorithms.md:1 | Line count command (`wc -l pqc_algorithms.py`: 8321 lines) | CONTRADICTED |
| Platform-specific PQC implementations in production_pqc_algorithms.py (Windows CNG, Linux OpenSSL, macOS Security) provide active acceleration | production_pqc_algorithms.py:6-20 | Code inspection (`production_pqc_algorithms.py:106, 119, 132` return False "Not implemented yet") | CONTRADICTED |