#!/bin/sh
# docs/formal/check.sh — ProVerif handshake-model gate (stub, additive only).
#
# Runs `proverif docs/formal/handshake_model.pv` WHEN proverif is installed,
# else prints SKIP and exits 0 (never fails CI when the tool is missing).
#
# Usage:
#   sh docs/formal/check.sh            # PR-safe: SKIP exit 0 when proverif missing
#   sh docs/formal/check.sh --strict   # nightly-only: FAIL exit 1 when proverif missing
#   proverif docs/formal/handshake_model.pv   # manual equivalent
#
# ---------------------------------------------------------------------------
# CI job snippet (NOT installed — for a human to paste into a workflow file,
# e.g. .github/workflows/defense_ci.yml). Do not auto-edit workflows here.
#
#   formal-proverif:
#     runs-on: ubuntu-latest
#     continue-on-error: true   # stub model: advisory only, never blocks merge
#     steps:
#       - uses: actions/checkout@v4
#       - name: Install ProVerif (best-effort)
#         run: |
#           sudo apt-get update -qq || true
#           sudo apt-get install -y -qq proverif || echo "proverif unavailable"
#       - name: Run handshake model (skip when tool missing)
#         run: sh docs/formal/check.sh
#
# Kani snippet (for the Rust harnesses in rust_data_plane/tests/kani_harness.rs;
# also advisory until Kani is pinned in CI):
#
#   kani-harness:
#     runs-on: ubuntu-latest
#     continue-on-error: true
#     steps:
#       - uses: actions/checkout@v4
#       - uses: dtolnay/rust-toolchain@stable
#       - name: cargo test doubles (no Kani needed)
#         run: cargo test --manifest-path rust_data_plane/Cargo.toml --test kani_harness
#       - name: Kani proofs (best-effort)
#         run: |
#           cargo install --locked cargo-kani || echo "SKIP: cargo-kani unavailable"
#           cargo kani --manifest-path rust_data_plane/Cargo.toml || echo "SKIP: kani unavailable"
# ---------------------------------------------------------------------------
set -eu

STRICT=0
if [ "${1:-}" = "--strict" ]; then
    STRICT=1
elif [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    echo "Usage: sh docs/formal/check.sh [--strict]"
    echo "  default : SKIP exit 0 when proverif is missing (PR-safe)"
    echo "  --strict: FAIL exit 1 when proverif is missing (nightly-only, not PR)"
    exit 0
fi

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
MODEL="$ROOT/docs/formal/handshake_model.pv"

if command -v proverif >/dev/null 2>&1; then
    proverif "$MODEL"
else
    if [ "$STRICT" = "1" ]; then
        echo "FAIL: proverif not installed (--strict requested; nightly gate requires ProVerif >= 2.05 from https://proverif.inria.fr/)" >&2
        exit 1
    fi
    echo "SKIP: proverif not installed (formal model not enforced)"
    exit 0
fi
