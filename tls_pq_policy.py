"""TLS 1.3 post-quantum policy probe (shared, stdlib-only).

Single source of truth for the empirical question "does this Python/OpenSSL
runtime actually offer an RFC 10024 hybrid key-exchange group in a default
TLS 1.3 ClientHello?". PQ key exchange rides supported_groups/key_share —
never the ciphersuite name — so probing the emitted ClientHello is the only
reliable capability test on CPython, where ssl.SSLContext exposes neither
``set_groups`` nor ``get_negotiated_group``.

Verified 2026-10-16 on the deployment stack (CPython 3.14.7 / OpenSSL
3.5.7): the default offer includes X25519MLKEM768 (0x11EC), and OPENSSL_CONF
``Groups =`` restriction is honored fail-closed (classical-only peer gets
``SSLV3_ALERT_HANDSHAKE_FAILURE``).

No project imports; safe to import from any module.
"""

import ssl
import struct

# RFC 9954/10024 hybrid key-exchange group codepoints.
RFC10024_HYBRID_GROUP_CODEPOINTS = (0x11EC, 0x11ED, 0x11EB)

# RFC 10024 canonical group names + legacy aliases accepted by OpenSSL.
RFC10024_HYBRID_GROUP_NAMES = (
    "X25519MLKEM768",
    "SecP384r1MLKEM1024",
    "SecP256r1MLKEM768",
    # Legacy/OpenSSL alias spellings (LabOQS-era builds)
    "x25519_kyber768",
    "p256_kyber768",
    "x25519_mlkem768",
    "p256_mlkem768",
    "mlkem768",
    "mlkem1024",
)

_CACHE = None


def client_offers_hybrid_group() -> bool:
    """True when a default TLS 1.3 ClientHello offers an RFC 10024 hybrid group.

    Cached process-local. No network I/O: the ClientHello is emitted into a
    ``ssl.MemoryBIO`` and its supported_groups extension (type 10) is
    parsed. Any failure returns False (fail-closed for policy decisions).
    """
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    ok = False
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        cin, cout = ssl.MemoryBIO(), ssl.MemoryBIO()
        obj = ctx.wrap_bio(cin, cout, server_side=False)
        try:
            obj.do_handshake()
        except ssl.SSLWantReadError:
            pass
        raw = cout.read()
        d = raw[5:]  # skip TLS record header (type/version/len)
        i = 4 + 2 + 32  # handshake header + legacy_version + random
        sid = d[i]
        i += 1 + sid
        cs = struct.unpack('>H', d[i:i + 2])[0]
        i += 2 + cs
        i += 1 + d[i]  # compression methods vector
        et = struct.unpack('>H', d[i:i + 2])[0]
        i += 2
        end = i + et
        while i + 4 <= end:
            t, l = struct.unpack('>HH', d[i:i + 4])
            i += 4
            if t == 10:  # supported_groups
                list_len = struct.unpack('>H', d[i:i + 2])[0]
                n = list_len // 2
                groups = {
                    struct.unpack('>H', d[i + 2 + 2 * k:i + 4 + 2 * k])[0]
                    for k in range(n)
                }
                ok = any(g in RFC10024_HYBRID_GROUP_CODEPOINTS for g in groups)
                break
            i += l
    except Exception:
        ok = False
    _CACHE = ok
    return ok


def reset_cache_for_tests() -> None:
    """Clear the cached probe result (tests only)."""
    global _CACHE
    _CACHE = None
