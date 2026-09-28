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
