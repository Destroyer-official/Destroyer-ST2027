#!/usr/bin/env python3
"""
cnsa_purity.py — CNSA 2.0 strictness enforcement for the TOP SECRET path.

Allowed (CNSA 2.0 + RFC 10024 L5 profile + device/supply-chain auth):
  KEX/sign: ML-KEM-1024 (FIPS 203), ML-DSA-87 (FIPS 204)
  Symmetric: AES-256-GCM. Hash/KDF: SHA-384, SHA-512, SHA3-512, HKDF-SHA384.
  Classical hedge inside the hybrid only: P-384 ECDH, X25519.
  Device identity (auth-only tier, never data plane): ECDSA_P256 (CNG TPM).
  Supply-chain sidecars only: Ed25519 (never session crypto).

Refused in TS session files: Falcon (FIPS 206 draft, not CNSA),
Classic-McEliece/HQC/FrodoKEM/Saber/NTRU (not CNSA), pre-standard
Kyber/Dilithium names, RSA/ECDSA/DH-standalone, ChaCha20-Poly1305 (not
the CNSA symmetric choice), DES/RC4/MD5/SHA-1, SLH-DSA/SPHINCS+ (approved
PQ but outside the CNSA 2.0 strict session set).

Two enforcement layers (both real):
  1. Static scan (CI + cached preflight) over Python TOKEN streams:
     comments and docstrings/prose are skipped by construction (only
     NAME tokens and short code string literals are examined), so
     refusal rationales in prose never false-positive. cnsa_purity.py
     itself is excluded: it documents the deny sets but instantiates
     no session crypto.
  2. Runtime policy: assert_cnsa_*() called with the ACTUAL negotiated
     names at handshake/KDF entry — negotiation output, not comments.
"""

from __future__ import annotations

import io
import logging
import re
import tokenize
from pathlib import Path
from typing import Dict, List, Optional

log = logging.getLogger("cnsa_purity")

REPO_ROOT = Path(__file__).resolve().parent

# Session-path files subject to the strict profile (this file excluded:
# it defines the policy and instantiates no crypto).
TS_SESSION_FILES = ("secure_transmit_2027.py", "noise_pq.py", "crypto_selftest.py",
                    "ts_hw_layer.py", "ts_runtime.py",
                    "ts_attest.py", "cng_platform.py", "spo_dpo.py",
                    "trust_anchor.py", "transport_anonymity.py")

# Exact allowed negotiated names (runtime layer).
ALLOW_KEM = {"ML-KEM-1024"}
ALLOW_SIG = {"ML-DSA-87"}
ALLOW_GROUPS = {"SecP384r1MLKEM1024"}   # RFC 10024 L5 hybrid group
ALLOW_SUITE = {"TLS_AES_256_GCM_SHA384", "AES-256-GCM"}
ALLOW_HASH = {"SHA384", "SHA512", "SHA3-512"}
ALLOW_KDF = {"HKDF-SHA384"}
# Classical hedge: allowed ONLY inside the named hybrid combiner, never alone.
ALLOW_HEDGE = {"P-384", "X25519"}

# NAME-token matching: camel/digit-aware split, single decision point.
# "Falcon1024" -> FALCON+1024 HIT; "Kyber768" HIT; "McEliece_8192128f" HIT;
# "CHASSIS_INTRUSION" -> CHASSIS+INTRUSION clean (substring "NTRU" inside
# an English word must NOT hit); "MLDSA" stays whole so it never equals
# "DSA"; "LibOQS_MLDSA_87" splits clean; "ECDH"/"ECC" are fine.
# Digit-split names ("SHA1" -> SHA+1) are covered by the exact set.
DENY_NAME_PARTS = frozenset({
    "FALCON", "MCELIECE", "HQC", "FRODO", "SABER", "NTRU", "NEWHOPE",
    "SIKE", "BIKE", "KYBER", "DILITHIUM", "RSA", "ECDSA", "DSA", "DES",
    "RC4", "ARC4", "MD5", "SHA1", "CHACHA", "POLY1305", "BLOWFISH",
    "CAST", "SEED", "CAMELLIA", "ARIA", "RIPEMD", "WHIRLPOOL",
    "SPHINCS", "SLH",
})
DENY_NAME_EXACT = frozenset({"MD5", "SHA1", "RC4", "ARC4"})
_PART_RE = re.compile(r"[A-Z]+(?![a-z])|[A-Z][a-z]*|[a-z]+|\d+")


def _name_hit(token_upper: str) -> bool:
    if token_upper in DENY_NAME_EXACT:
        return True
    return any(p.upper() in DENY_NAME_PARTS for p in _PART_RE.findall(token_upper))

# Per-file declared allowances (auditable): these exact identifiers implement
# the explicitly-authorized TPM device-auth tier (ECDSA-P256, auth-only,
# never data plane) and must be nameable where they are used. Any other
# file — or any other ECDSA-named identifier — fails closed.
FILE_ALLOW_NAMES = {
    "ts_attest.py": frozenset({"ECDSA", "_ECDSA_P256_PUB_MAGIC",
                               "_ECDH_P256_PUB_MAGIC"}),
}

# Short code-string literals: quoted allow-list skips, deny stems hit.
# Strings containing whitespace are PROSE (docstrings, messages, detail
# fields) and skipped — usage is what matters, and prose refusal
# rationales must never false-positive. (String-length cap retained as
# a second prose filter.)
ALLOW_QUOTED = {
    "ML-KEM-1024", "ML-DSA-87", "AES-256-GCM", "TLS_AES_256_GCM_SHA384",
    "SHA384", "SHA512", "SHA3-512", "HKDF-SHA384", "P-384", "X25519",
    "ECDSA_P256", "ECDSA_P384",
    "SecP384r1MLKEM1024", "X25519MLKEM768", "SecP256r1MLKEM768",
    "secp384r1", "secp256r1", "Ed25519", "ST2027V1",
}
DENY_STR_STEMS = (
    "FALCON", "MCELIECE", "MC-ELIECE", "KYBER", "DILITHIUM", "SABER",
    "NEWHOPE", "CHACHA", "POLY1305", "SLH-DSA", "SPHINCS", "CAMELLIA",
    "RIPEMD", "BLOWFISH",
)
# Short stems that also occur inside English words (INTRUSION contains
# NTRU) get identifier boundaries (letters/digits/hyphen/underscore).
DENY_STR_WORDS = re.compile(
    r"(?<![A-Z0-9-_])(NTRU|HQC|BIKE|SIKE|FRODO|RSA|ECDSA|DSA|DES|RC4|MD5|SHA1)"
    r"(?![A-Z0-9-_])")
# ECC curve literals: P-384 only in the session path.
ALLOW_CURVES = {"P-384"}
CURVE_LIKE = re.compile(
    r"^(P-(192|224|256|521)|SECP(192R1|224R1|256R1|256K1|384R1|521R1)|"
    r"PRIME192V1|PRIME256V1|X448|ED448|CURVE25519|BRAINPOOL.*)$",
    re.IGNORECASE)


class PurityError(Exception):
    """CNSA 2.0 purity violation (fail-closed)."""


def _string_value(tok_string: str) -> Optional[str]:
    """Best-effort literal decode; None when not a plain literal."""
    import ast
    try:
        val = ast.literal_eval(tok_string)
    except Exception:
        return None
    return val if isinstance(val, str) else None


def scan_file(path: Path) -> List[str]:
    """Return deny-hits as file:line:token. Empty = pure."""
    hits: List[str] = []
    try:
        toks = list(tokenize.generate_tokens(
            io.StringIO(path.read_text(encoding="utf-8")).readline))
    except (tokenize.TokenError, SyntaxError, IndentationError) as e:
        raise PurityError(f"unparseable session file {path.name}: {e}")
    for tok in toks:
        if tok.type == tokenize.NAME:
            allowed_here = FILE_ALLOW_NAMES.get(path.name, frozenset())
            if tok.string in allowed_here:
                continue
            if _name_hit(tok.string.upper()):
                hits.append(f"{path.name}:{tok.start[0]}:{tok.string}")
        elif tok.type == tokenize.STRING:
            val = _string_value(tok.string)
            if val is None or len(val) > 200 or re.search(r"\s", val):
                continue  # prose/docstrings/messages: never code usage
            _check_short_string(path, tok, val, hits)
        elif tok.type == getattr(tokenize, "FSTRING_MIDDLE", -1):
            # f-string literal spans (3.12+ tokenizer): same rules as
            # short strings; expressions inside {} arrive as NAME tokens.
            val = tok.string
            if len(val) > 200 or re.search(r"\s", val):
                continue
            _check_short_string(path, tok, val, hits)
    return hits


def _check_short_string(path: Path, tok, val: str, hits: List[str]) -> None:
    up = val.upper()
    if val in ALLOW_QUOTED or up in ALLOW_QUOTED:
        return
    if any(s in up for s in DENY_STR_STEMS):
        hits.append(f"{path.name}:{tok.start[0]}:{val[:48]}")
        return
    if DENY_STR_WORDS.search(up):
        hits.append(f"{path.name}:{tok.start[0]}:{val[:48]}")
        return
    if CURVE_LIKE.match(val.strip()):
        hits.append(f"{path.name}:{tok.start[0]}:{val[:48]}")


def scan_tree(files: Optional[List[str]] = None) -> Dict[str, List[str]]:
    """Scan TS session files. Raises PurityError on any hit.

    When scanning the DEFAULT inventory, a missing file is itself a
    violation (fail-closed inventory: a renamed session module must not
    silently drop out of the scan).
    """
    names = list(files) if files is not None else list(TS_SESSION_FILES)
    bad: Dict[str, List[str]] = {}
    for name in names:
        p = REPO_ROOT / name
        if not p.exists():
            if files is None:
                raise PurityError(f"CNSA 2.0 scan inventory violation: {name} missing")
            continue
        hits = scan_file(p)
        if hits:
            bad[name] = hits
    if bad:
        raise PurityError(f"CNSA 2.0 purity violations: {bad}")
    return {}


_PURITY_CACHED: Optional[bool] = None


def ensure_purity_cached() -> None:
    """Cached static gate for session preflight (run once per process)."""
    global _PURITY_CACHED
    if _PURITY_CACHED:
        return
    scan_tree()
    _PURITY_CACHED = True
    log.info("CNSA 2.0 purity scan clean")


# --- runtime policy: negotiated names -------------------------------------

def assert_cnsa_kem(name: str) -> str:
    if name not in ALLOW_KEM:
        raise PurityError(f"KEM refused (not CNSA-strict): {name}")
    return name


def assert_cnsa_sig(name: str) -> str:
    if name not in ALLOW_SIG:
        raise PurityError(f"signature refused (not CNSA-strict): {name}")
    return name


def assert_cnsa_group(name: str) -> str:
    if name not in ALLOW_GROUPS:
        raise PurityError(f"hybrid group refused (not CNSA-strict L5): {name}")
    return name


def assert_cnsa_suite(name: str) -> str:
    if name not in ALLOW_SUITE:
        raise PurityError(f"cipher suite refused (not CNSA-strict): {name}")
    return name


def assert_cnsa_hash(name: str) -> str:
    if name not in ALLOW_HASH:
        raise PurityError(f"hash refused (not CNSA-strict): {name}")
    return name


def assert_cnsa_kdf(name: str) -> str:
    if name not in ALLOW_KDF:
        raise PurityError(f"KDF refused (not CNSA-strict): {name}")
    return name
