"""Ratchet DSS migration: ML-DSA-87 session identity (CNSA 2.0 / FIPS 204).

Falcon-1024 is NOT in CNSA 2.0 (NSA will not add FN-DSA). New
DoubleRatchet sessions authenticate messages with ML-DSA-87 dict keys
({'mldsa': bytes}); Falcon-1024 remains verify-only for pre-migration
peers (agile ``self.dss`` routes raw bytes to Falcon).

Covers:
  1. Session DSS identity format + FIPS 204 sizes (PK 2592 / SK 4896).
  2. ML-DSA sign/verify roundtrip through _secure_verify (fail-closed).
  3. Tampered ML-DSA message rejected (SecurityError, no fallback).
  4. Legacy Falcon-1024 peer (bytes keys) still verifies (interop).
  5. Full two-party session roundtrip on ML-DSA identity, both directions.
  6. Wire signature length is ML-DSA-87 (4627), not Falcon (~1.4KB).

Fast, deterministic, no network. Requires native liboqs (oqs.dll).
"""

import secrets

import pytest

from double_ratchet import DoubleRatchet, SecurityError


def _make_pair(protocol_version=2):
    root = secrets.token_bytes(32)
    alice = DoubleRatchet(root_key=root, is_initiator=True,
                          protocol_version=protocol_version)
    bob = DoubleRatchet(root_key=root, is_initiator=False,
                        protocol_version=protocol_version)
    alice.negotiate_pq_ratchet_version(protocol_version)
    bob.negotiate_pq_ratchet_version(protocol_version)
    alice.set_remote_public_key(bob.get_public_key(), bob.get_kem_public_key(),
                                bob.get_dss_public_key())
    bob.set_remote_public_key(alice.get_public_key(), alice.get_kem_public_key(),
                              alice.get_dss_public_key())
    bob.process_kem_ciphertext(alice.get_kem_ciphertext())
    assert alice.is_initialized() and bob.is_initialized()  # nosec: B101
    return alice, bob


def test_session_dss_identity_is_mldsa87():
    alice, _ = _make_pair()
    assert alice.dss_algorithm == "ML-DSA-87"  # nosec: B101
    pk, sk = alice.dss_public_key, alice.dss_private_key
    assert isinstance(pk, dict) and isinstance(sk, dict)  # nosec: B101
    assert set(pk) == {"mldsa"} and set(sk) == {"mldsa"}  # nosec: B101
    assert len(pk["mldsa"]) == 2592, "ML-DSA-87 PK must be 2592 bytes (FIPS 204)"  # nosec: B101
    assert len(sk["mldsa"]) == 4896, "ML-DSA-87 SK must be 4896 bytes (FIPS 204)"  # nosec: B101


def test_mldsa_sign_verify_roundtrip_fail_closed():
    alice, _ = _make_pair()
    msg = b"CNSA-2.0 session auth probe"
    sig = alice.dss.sign(alice.dss_private_key, msg)
    assert isinstance(sig, dict) and "mldsa" in sig  # nosec: B101
    assert len(sig["mldsa"]) == 4627, "ML-DSA-87 sig must be 4627 bytes (FIPS 204)"  # nosec: B101
    assert alice._secure_verify(alice.dss_public_key, msg, sig, "probe") is True  # nosec: B101


def test_tampered_mldsa_message_rejected():
    alice, bob = _make_pair()
    wire = alice.encrypt(b"authentic")
    assert bob.decrypt(wire) == b"authentic"  # nosec: B101
    tampered = bytearray(wire)
    tampered[-1] ^= 0x01
    with pytest.raises(SecurityError):
        bob.decrypt(bytes(tampered))


def test_legacy_falcon_peer_still_verifies():
    """Pre-migration Falcon-1024 peers stay interoperable (verify-only)."""
    from pqc_algorithms import EnhancedFALCON_1024

    alice, _ = _make_pair()
    falcon = EnhancedFALCON_1024()
    fpk, fsk = falcon.keygen()
    assert len(fpk) == 1793 and len(fsk) == 2305  # nosec: B101
    msg = b"legacy falcon interop probe"
    fsig = falcon.sign(fsk, msg)
    # Agile verifier accepts legacy Falcon bytes identity.
    assert alice._secure_verify(fpk, msg, fsig, "legacy-falcon") is True  # nosec: B101
    with pytest.raises(SecurityError):
        alice._secure_verify(fpk, msg + b"x", fsig, "legacy-falcon-tampered")


def test_full_session_roundtrip_mldsa_both_directions():
    alice, bob = _make_pair()
    assert bob.decrypt(alice.encrypt(b"alpha->bravo")) == b"alpha->bravo"  # nosec: B101
    assert alice.decrypt(bob.encrypt(b"bravo->alpha")) == b"bravo->alpha"  # nosec: B101
    # Remote identities on both sides are ML-DSA-87 dicts (not Falcon).
    for sess in (alice, bob):
        rpk = sess.remote_dss_public_key
        assert isinstance(rpk, dict) and set(rpk) == {"mldsa"}  # nosec: B101
        assert len(rpk["mldsa"]) == 2592  # nosec: B101


def test_wire_signature_is_mldsa87_size():
    import struct

    alice, bob = _make_pair()
    wire = alice.encrypt(b"size probe")
    from double_ratchet import MessageHeader

    sig_len = struct.unpack(
        ">H", wire[MessageHeader.HEADER_SIZE:MessageHeader.HEADER_SIZE + 2])[0]
    assert sig_len == 4627, f"wire sig must be ML-DSA-87 (4627), got {sig_len}"  # nosec: B101
    assert bob.decrypt(wire) == b"size probe"  # nosec: B101

