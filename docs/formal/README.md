# Formal model stub (not CI-enforced)

`handshake_model.pv` is a **ProVerif skeleton** for the PQXDH-style
combiner used by the 1:1 handshake:

```
SK = HKDF( DH1 || DH2 || DH3 [|| DH4] || KEM_ss )
```

It declares free channels, symbolic constructors for DH / KEM / HKDF,
initiator/responder agreement events, and the intended queries
(secrecy of a payload under the session key + `RespAgrees ==> InitAgrees`
correspondence). The KEM correctness equation and any proofs are
deliberately left out — this is a starting point, not a verified model.

## Running it

Requires ProVerif ≥ 2.05 (manual step, no CI gate):

```sh
proverif docs/formal/handshake_model.pv
```

Install ProVerif from <https://proverif.inria.fr/> (prebuilt binaries
+ manual; `apt install proverif` on Debian/Ubuntu where available, else
the upstream tarball). Any ≥ 2.05 release satisfies the stub model.

CI wiring (`docs/formal/check.sh`, additive, CI-safe):

```sh
sh docs/formal/check.sh            # PR-safe: SKIP exit 0 when proverif missing
sh docs/formal/check.sh --strict   # nightly-only: FAIL exit 1 when proverif missing
```

PR / `adversarial-gates` uses the non-strict form so a runner without
ProVerif never breaks the build. `--strict` is reserved for a nightly
job with ProVerif pre-installed — never add it to PR gates.

## Expected output

When the model is complete and verified, every query must report true,
e.g.:

```
RESULT Query attacker(secret_payload) is false.
RESULT Query event(RespAgrees(k)) ==> event(InitAgrees(k)) is true.
```

i.e. secrecy holds (attacker cannot derive the payload) and the
responder-agreement correspondence holds. Any `is false` on the
correspondence query, or `is true` on the attacker query, is a FAIL.
(The current `handshake_model.pv` is a skeleton — queries above are the
intended properties, not yet proven results.)

## Reference

Modelling style follows Bhargavan et al.'s formal analysis of the
Signal PQXDH protocol, USENIX Security '24:

- USENIX Security '24 proceedings: <https://www.usenix.org/conference/usenixsecurity24>
  (see Bhargavan et al., PQXDH analysis).
- Signal PQXDH specification: <https://signal.org/docs/specifications/pqxdh/>

CI enforcement: `adversarial-gates` in `.github/workflows/defense_ci.yml`
runs `sh docs/formal/check.sh` (non-strict, advisory: SKIP exit 0 when
ProVerif is missing). `--strict` is nightly-only and never runs on PR.

## Kani inventory (audited against `rust_data_plane/tests/kani_harness.rs`)

Five `#[kani::proof]` harnesses are DEFINED (exact names):

```
kani_frame_split_reassemble_roundtrip
kani_nonce_domain_separation
kani_replay_window_monotonic
kani_max_stream_bytes_cap
kani_nostd_frame_parse_never_panics
```

Execution requires the Kani + CBMC toolchain (`cargo kani`); Kani is
installed neither in this environment nor in CI, so no Kani proof has
been EXECUTED here — "defined" is the honest status word, never
"proven". What DOES execute green under plain `cargo test` are the 7
deterministic property doubles in `property_doubles` (same properties,
bounded sweeps):

```
frame_split_reassemble_roundtrip_bounded
nonce_domain_separation
replay_window_monotonic_and_drops
ct_eq_and_select_no_secret_branch
max_stream_bytes_cap_enforced
nostd_frame_parse_never_panics_property_sweep
nostd_stack_secret_ct_eq_property_sweep
```

(`test_stack_secret_zeroize_on_drop` is a plain `cargo test` unit test
in `nostd_microcore`, re-exported into the 29-test harness binary — not
a Kani proof. The harness binary total of 29 includes 22 re-exported
module unit tests alongside the 7 doubles.)
