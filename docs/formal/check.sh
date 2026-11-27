#!/bin/sh
# docs/formal/check.sh — ProVerif formal verification gate for ST2027.
#
# Runs ProVerif 2.05 on the machine-checked models:
#   1. docs/formal/st2027_handshake.pv (Noise_XXhfs handshake & secrecy/auth)
#   2. docs/formal/st2027_pcs.pv (Continuous Epoch Ratchet PCS healing)
#
# Usage:
#   sh docs/formal/check.sh            # Runs when proverif is in PATH or env
#   sh docs/formal/check.sh --strict   # Mandatory blocking: fails if proverif missing
#

set -eu

STRICT=1
ALLOW_STRUCTURAL_ONLY=0
if [ "${1:-}" = "--allow-structural-only" ]; then
    STRICT=0
    ALLOW_STRUCTURAL_ONLY=1
elif [ "${1:-}" = "--strict" ]; then
    STRICT=1
elif [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    echo "Usage: sh docs/formal/check.sh [--strict | --allow-structural-only]"
    echo "  default                : Fail closed (exit 1) if ProVerif is missing or any query fails"
    echo "  --allow-structural-only: Lab-only structural AST test when ProVerif is absent"
    exit 0
fi

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
MODEL_HANDSHAKE="$ROOT/docs/formal/st2027_handshake.pv"
MODEL_PCS="$ROOT/docs/formal/st2027_pcs.pv"
MODEL_KEX_AUTH="$ROOT/docs/formal/st2027_kex_auth.pv"
MODEL_RATCHET_PCS="$ROOT/docs/formal/st2027_ratchet_pcs.pv"
MODEL_TOR_RENDEZVOUS="$ROOT/docs/formal/st2027_tor_rendezvous.pv"

PROVERIF_BIN=""
if command -v proverif >/dev/null 2>&1; then
    PROVERIF_BIN="proverif"
elif [ -n "${P2P_PROVERIF:-}" ] && [ -f "$P2P_PROVERIF" ]; then
    PROVERIF_BIN="$P2P_PROVERIF"
fi

if [ -z "$PROVERIF_BIN" ]; then
    for cand in /tmp/proverif*/proverif /tmp/proverif*/src/proverif; do
        if [ -x "$cand" ]; then
            PROVERIF_BIN="$cand"
            break
        fi
    done
fi

if [ -n "$PROVERIF_BIN" ]; then
    echo "=== Running ProVerif Handshake Model (Noise_XXhfs) ==="
    "$PROVERIF_BIN" "$MODEL_HANDSHAKE"
    echo "=== Running ProVerif Native kex_auth Model (kex_auth.rs) ==="
    "$PROVERIF_BIN" "$MODEL_KEX_AUTH"
    echo "=== Running ProVerif PCS Rehandshake Model ==="
    "$PROVERIF_BIN" "$MODEL_PCS"
    echo "=== Running ProVerif In-Band Hybrid Ratchet PCS Model ==="
    "$PROVERIF_BIN" "$MODEL_RATCHET_PCS"
    echo "=== Running ProVerif Compromised Tor Rendezvous Model ==="
    "$PROVERIF_BIN" "$MODEL_TOR_RENDEZVOUS"
    echo "[+] All formal verification models executed."
    if command -v python3 >/dev/null 2>&1; then
        echo "=== Generating Machine-Checked Verification Certificate ==="
        python3 "$ROOT/tools/formal_verification_orchestrator.py" --strict --out-dir "$ROOT/docs/formal"
    fi
    exit 0
else
    if [ "$STRICT" = "1" ] || [ "$ALLOW_STRUCTURAL_ONLY" != "1" ] || [ "${CI:-}" = "true" ]; then
        echo "FAIL: proverif not installed (fail-closed default requires ProVerif >= 2.05 from https://proverif.inria.fr/; pass --allow-structural-only for structural checks only)" >&2
        exit 1
    fi
    if command -v python3 >/dev/null 2>&1; then
        echo "=== Executing Structural AST Model Check Only (NOT a formal proof) ==="
        python3 -m unittest "$ROOT/tests/test_formal_proverif_models.py"
        echo "[+] STRUCTURAL_CHECK_ONLY: ProVerif not installed; formal properties remain unverified."
        exit 0
    fi
    echo "FAIL: neither proverif nor python3 available" >&2
    exit 1
fi
