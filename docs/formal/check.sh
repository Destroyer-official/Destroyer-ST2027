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

STRICT=0
if [ "${1:-}" = "--strict" ]; then
    STRICT=1
elif [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    echo "Usage: sh docs/formal/check.sh [--strict]"
    echo "  default : Run models if proverif present, else exit 0"
    echo "  --strict: Mandatory blocking gate (FAIL exit 1 if proverif missing or query fails)"
    exit 0
fi

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
MODEL_HANDSHAKE="$ROOT/docs/formal/st2027_handshake.pv"
MODEL_PCS="$ROOT/docs/formal/st2027_pcs.pv"

PROVERIF_BIN=""
if command -v proverif >/dev/null 2>&1; then
    PROVERIF_BIN="proverif"
elif [ -n "${P2P_PROVERIF:-}" ] && [ -f "$P2P_PROVERIF" ]; then
    PROVERIF_BIN="$P2P_PROVERIF"
fi

if [ -n "$PROVERIF_BIN" ]; then
    echo "=== Running ProVerif Handshake Model ==="
    "$PROVERIF_BIN" "$MODEL_HANDSHAKE"
    echo "=== Running ProVerif PCS Healing Model ==="
    "$PROVERIF_BIN" "$MODEL_PCS"
    echo "[+] All formal verification models executed."
else
    if [ "$STRICT" = "1" ] || [ "${CI:-}" = "true" ]; then
        echo "FAIL: proverif not installed (--strict / CI mode requires ProVerif >= 2.05 from https://proverif.inria.fr/)" >&2
        exit 1
    fi
    echo "SKIP: proverif not installed in local environment"
    exit 0
fi
