# Archive Notice: secure_p2p_core (Superseded Prototype Snapshot)

**Status:** ARCHIVED / HISTORICAL REFERENCE ONLY  
**Classification:** Non-Production Legacy Architecture  
**Authoritative Production Data Plane:** `rust_data_plane` (`destroyer_core` / `secure-transmit`)  
**Active Python Orchestration:** `secure_p2p.py` / `core/` / `tests/`

---

## 1. Architectural Scope & Deprecation Notice

`secure_p2p_core/` represents an early modular Python prototype of the peer-to-peer subsystem. It has been formally superseded by:
1. **The Sovereign Pure-Rust Data Plane (`rust_data_plane/`):** The accredited zero-Python data plane providing constant-time Galois field FEC, ML-KEM-1024 / ML-DSA-87 key encapsulation and signatures, in-band continuous epoch ratcheting (CER), hardware TPM 2.0 dual-monotonic anti-rollback protection, and isochronous wire pacing.
2. **The Active Test Suite (`tests/`):** All active unit, integration, property, and fuzz tests reside under the root `tests/` directory and are executed via `pytest`.

## 2. CI & Test Discovery Policy

In accordance with `pytest.ini`, `secure_p2p_core/` is excluded from automated test collection because its internal test harnesses target a superseded pre-release API. Live production verification is exclusively provided by the 251 native Rust tests and the active root `tests/` battery.

