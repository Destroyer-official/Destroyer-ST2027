"""
Central message / frame capability limits (caps unification).

Layered model (documented, strictest-innermost):
  frame (wire)  >  post-auth message  >=  pre-auth frame  >=  chat payload

  - MAX_FRAME (4MB): absolute wire-frame abort ceiling (DoS mitigation).
    Enforced in p2p_core.send_framed / recv_exact / receive_framed.
    Nothing larger is ever allocated or sent.
  - POST_AUTH_MAX (512KB): standard post-auth message ceiling (ratchet /
    serializer FILE path). Only FILE chunks with explicit file flag may
    approach this.
  - PRE_AUTH_MAX (64KB): pre-auth frame ceiling (handshake / unauthenticated).
  - PRE_AUTH_HYBRID_BUNDLE_MAX (2MB): narrow exception for the hybrid KEM
    public bundle only (measured ~1.8MB: McEliece pk + ML-KEM pk + sigs).
    Used solely at the 2 bundle-receive sites; length-checked pre-alloc.
  - MAX_MESSAGE_PAYLOAD (64KB): strictest chat MSG payload ceiling.
    Plain chat (MSG/DATA) must never exceed this. Larger payloads are only
    allowed for FILE chunks with explicit ``is_file`` / FILE type flag.

Ordering invariant: MAX_FRAME > POST_AUTH_MAX >= MAX_MESSAGE_PAYLOAD,
and PRE_AUTH_MAX == MAX_MESSAGE_PAYLOAD == 64KB (strictest).
"""

import os

# --- Canonical caps (single source of truth) -------------------------------
MAX_MESSAGE_PAYLOAD = 65536          # 64KB strictest chat MSG payload
MAX_FILE_PAYLOAD = 512 * 1024        # 512KB FILE chunk payload (explicit flag only)
MAX_FRAME = 4 * 1024 * 1024          # 4MB absolute frame abort ceiling
PRE_AUTH_MAX = 64 * 1024             # 64KB pre-auth frame ceiling
POST_AUTH_MAX = 512 * 1024           # 512KB post-auth message ceiling
# 2026-09-19: hybrid-bundle exception (measured 1,817,211 bytes: ML-KEM-1024
# pk + McEliece-8192128f pk base64 + sigs + certs). Used ONLY at the 2
# hybrid-bundle receive sites per handshake; all other pre-auth frames keep
# PRE_AUTH_MAX. Mirrors the session_manager 2MB McEliece exception.
PRE_AUTH_HYBRID_BUNDLE_MAX = 2 * 1024 * 1024

# Serializer overhead: header (56B) + MAC (32B) = 88B
SERIALIZER_OVERHEAD = 88
MAX_SERIALIZED_MSG = MAX_MESSAGE_PAYLOAD + SERIALIZER_OVERHEAD
MAX_SERIALIZED_FILE = MAX_FILE_PAYLOAD + SERIALIZER_OVERHEAD
# Legacy generic pre-MAC ceiling kept for backward compat (lab permissive).
MAX_SERIALIZED_LEGACY = 128 * 1024


def is_env_true(name: str, default: bool = False) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


_env_true = is_env_true


def is_production() -> bool:
    """True when running in production (fail-closed Auto-strict)."""
    return prod_strict_on()


def prod_strict_on() -> bool:
    """Central sticky-prod strict gate (single source of truth).

    True when P2P_PRODUCTION or SECURE_P2P_PRODUCTION is truthy
    (1/true/yes/on), or P2P_ENV=production. Reused by RBAC strict,
    alerts-require-sig, and CRL-require-sig so prod auto-enables
    strict without extra env. Lab default: False.
    """
    if _env_true("P2P_PRODUCTION") or _env_true("SECURE_P2P_PRODUCTION"):
        return True
    if os.environ.get("P2P_ENV", "").strip().lower() == "production":
        return True
    return False


def is_strict_encrypt() -> bool:
    """True when encrypt-sentinel strict mode is active.

    Active when P2P_STRICT_ENCRYPT=1, or auto-on in production.
    Lab default: False (warn + b'' compat sentinel preserved).
    """
    if _env_true("P2P_STRICT_ENCRYPT"):
        return True
    return is_production()


def validate_frame_size(n: int) -> int:
    """Validate absolute wire-frame size. Raises ValueError if > MAX_FRAME."""
    if n is None:
        raise ValueError("frame size is None")
    ni = int(n)
    if ni < 0:
        raise ValueError(f"negative frame size: {ni}")
    if ni > MAX_FRAME:
        raise ValueError(f"frame size {ni} exceeds MAX_FRAME {MAX_FRAME}")
    return ni


def validate_payload_size(n: int, *, is_file: bool = False, msg_type=None) -> int:
    """Validate chat/FILE payload size against unified caps.

    Args:
        n: payload length in bytes (or object with len()).
        is_file: explicit FILE-chunk flag allowing up to POST_AUTH_MAX.
        msg_type: optional message-type hint; FILE_TRANSFER / 'FILE' values
            imply is_file=True.

    Returns:
        int payload length if within caps.

    Raises:
        ValueError: if size exceeds caps (chat MSG > 64KB, FILE > 512KB,
            or anything > 4MB frame ceiling).
    """
    # Resolve length
    ni = int(n) if isinstance(n, int) else len(n)  # type: ignore[arg-type]
    if ni < 0:
        raise ValueError(f"negative payload size: {ni}")
    # Absolute frame ceiling always applies (layered: frame > message)
    if ni > MAX_FRAME:
        raise ValueError(f"payload size {ni} exceeds MAX_FRAME {MAX_FRAME}")

    # Infer FILE flag from msg_type hint
    _is_file = bool(is_file)
    if not _is_file and msg_type is not None:
        try:
            name = getattr(msg_type, "name", str(msg_type)).upper()
        except Exception:
            name = ""
        if "FILE" in name:
            _is_file = True

    if _is_file:
        if ni > MAX_FILE_PAYLOAD:
            raise ValueError(
                f"FILE payload {ni} exceeds MAX_FILE_PAYLOAD {MAX_FILE_PAYLOAD}"
            )
        return ni
    if ni > MAX_MESSAGE_PAYLOAD:
        raise ValueError(
            f"chat payload {ni} exceeds MAX_MESSAGE_PAYLOAD {MAX_MESSAGE_PAYLOAD} "
            "(larger only for FILE chunks with explicit file flag)"
        )
    return ni
