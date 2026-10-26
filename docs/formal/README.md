# Formal Verification Models (ProVerif 2.05 & Kani)

This directory contains the machine-checked symbolic formal verification models and proofs for the Destroyer-ST2027 sovereign protocol suite.

## 1. Machine-Checked ProVerif Models

The protocol is formally modeled and **symbolically** verified in the applied pi-calculus using **ProVerif 2.05**. Scope caveat (F-03, audit 2026-10-14): these are MODEL proofs, not computational-security reductions and not implementation proofs. The deployed handshake uses an UNPROVEN custom substitution (see `deploy_st2027/noise_pq.py:30-40`): the ML-DSA-87 signature replacing the hfs draft's es/se tokens has no reduction to the hfs draft (which has no proofs) nor to PQNoise, and the model abstracts kdf as one-way (stronger than the dual-PRF property HKDF is actually assumed to have — eprint 2022/065). Treat the results as "the protocol structure is sound under these abstractions", never as "the concrete cryptography is proven".

1. **`st2027_handshake.pv`**: Full symbolic model of the deployed Noise_XXhfs handshake with P-384 ECDHE, ML-KEM-1024, ML-DSA-87, AES-256-GCM, and transcript-bound KEM combination.
   - Evaluates 7 core security queries: secrecy of payload under session keys, injective agreement `inj-event(S_Accepts ==> C_Accepts)`, forward secrecy under ephemeral leak phases, client verification `C_VerifiedM2`, and initiator identity privacy.
2. **`st2027_pcs.pv`**: Symbolic model of the Continuous Epoch Ratchet (CER).
   - Evaluates Post-Compromise Security (PCS) healing: proves that an attacker who compromises epoch $N$ cannot compromise epoch $N+1$ once fresh ephemerals are exchanged.

### Running ProVerif

Requires ProVerif ≥ 2.05:

```sh
proverif docs/formal/st2027_handshake.pv
proverif docs/formal/st2027_pcs.pv
```

Automated verification suite:

```sh
pytest tests/test_proverif_st2027.py -v
sh docs/formal/check.sh --strict
```

### Verified Output

All 10 queries conclude:

```
RESULT Query not attacker_p1(secret_payload) is true.
RESULT Query inj-event(S_Accepts(k,h,pk)) ==> inj-event(C_Sends(k,n,msg)) is true.
RESULT Query inj-event(R_Receives(k,n,msg,pk)) ==> inj-event(C_Sends(k,n,msg)) is true.
```

## 2. Kani Inventory (audited against `rust_data_plane/tests/kani_harness.rs`)

Six `#[kani::proof]` harnesses are DEFINED (exact names):

```
kani_cookie_gate_stateless_verification
kani_frame_split_reassemble_roundtrip
kani_max_stream_bytes_cap
kani_nonce_domain_separation
kani_nostd_frame_parse_never_panics
kani_replay_window_monotonic
```

Execution requires the Kani + CBMC toolchain (`cargo kani`); Kani is
installed in Linux CI (`.github/workflows/kani-proofs.yml`), so "defined" is
the honest status word in local environments until executed. What DOES execute
green under plain `cargo test` in all environments are the 8 deterministic
property doubles in `property_doubles` (same properties, bounded sweeps):

```
cookie_gate_stateless_verification
ct_eq_and_select_no_secret_branch
frame_split_reassemble_roundtrip_bounded
max_stream_bytes_cap_enforced
nonce_domain_separation
nostd_frame_parse_never_panics_property_sweep
nostd_stack_secret_ct_eq_property_sweep
replay_window_monotonic_and_drops
```

(`test_stack_secret_zeroize_on_drop` is a plain `cargo test` unit test
in `nostd_microcore`, re-exported into the 30-test harness binary — not
a Kani proof. The harness binary total includes 23 re-exported module unit tests
alongside the 7 doubles.)

---
<!-- Destroyer-ST2027 Military Production Hardening Release (2026-10-26) -->
<!-- NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204 -->
