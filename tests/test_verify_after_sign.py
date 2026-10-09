"""Verify-after-sign gates (fault-attack countermeasure, cf. eprint 2025/2009).

Pointer / fault attacks on lattice stacks (observed in LibOQS-style
code, up to 100% forgery success) are defeated when every emitted
signature is verified under the matching public half BEFORE release.
Gates covered:
  1. Ratchet per-message sign (double_ratchet encrypt).
  2. Handshake public bundle sign (hybrid_kex get_public_bundle).
  3. TUF role PQ sign (supply_chain_security._pq_sign_blob).
  4. SBOM sign helper (generate_production_sbom._mldsa_sign_verified).
  5. Noise_XXhfs responder M2 sign with latching quarantine (noise_pq responder_reply).
  6. Noise_XXhfs initiator M3 sign with latching quarantine (noise_pq initiator_complete).
  7. DestroyerNode data plane quarantine barrier (destroyer_node establish_from_noise).

Each gate is proven by fault injection: a corrupted signer output must
raise fail-closed (never emit an unverified signature). Positive paths
are covered by the handshake/TUF/SBOM suites.
"""

import os
import secrets
import shutil
import tempfile
from pathlib import Path

import pytest

# No module-scope env writes (see test_tuf_pq_dual_sign.py header note).


@pytest.fixture(autouse=True)
def _ceremony_secret(monkeypatch):
    """Self-sufficient ceremony secret: immune to other suites' env resets."""
    monkeypatch.setenv("P2P_SIGNING_PASSPHRASE", "test_vas_ceremony_secret")


def _make_ratchet_pair():
    from double_ratchet import DoubleRatchet

    root = secrets.token_bytes(32)
    alice = DoubleRatchet(root_key=root, is_initiator=True, protocol_version=2)
    bob = DoubleRatchet(root_key=root, is_initiator=False, protocol_version=2)
    alice.negotiate_pq_ratchet_version(2)
    bob.negotiate_pq_ratchet_version(2)
    alice.set_remote_public_key(bob.get_public_key(), bob.get_kem_public_key(),
                                bob.get_dss_public_key())
    bob.set_remote_public_key(alice.get_public_key(), alice.get_kem_public_key(),
                              alice.get_dss_public_key())
    bob.process_kem_ciphertext(alice.get_kem_ciphertext())
    assert alice.is_initialized() and bob.is_initialized()  # nosec: B101
    return alice, bob


def test_ratchet_faulted_signature_never_sent():
    """A faulted per-message signature aborts the send (SecurityError)."""
    from double_ratchet import SecurityError

    alice, bob = _make_ratchet_pair()
    assert bob.decrypt(alice.encrypt(b"baseline")) == b"baseline"  # nosec: B101

    real_sign = alice.dss.sign

    def _fault(sk, msg):
        sig = real_sign(sk, msg)
        bad = bytearray(sig["mldsa"])
        bad[0] ^= 0x01
        sig["mldsa"] = bytes(bad)
        return sig

    alice.dss.sign = _fault
    try:
        # Public encrypt() sanitizes to RuntimeError; either way the send
        # aborts fail-closed and no wire bytes are produced.
        with pytest.raises((SecurityError, RuntimeError)):
            alice.encrypt(b"faulted-send-must-abort")
    finally:
        alice.dss.sign = real_sign
    # The faulted attempt consumed a sending-chain step (chain advances
    # before signing), so the next message legitimately gaps the old chain
    # under MAX_SKIP=0. A PCS rotation re-syncs and the session recovers.
    alice.force_ratchet_rotation()
    assert bob.decrypt(alice.encrypt(b"recovered")) == b"recovered"  # nosec: B101


def test_bundle_faulted_signature_no_bundle_emitted():
    """A faulted bundle signature fails bundle creation closed."""
    from hybrid_kex import HybridKeyExchange

    kex = HybridKeyExchange(identity="vas_probe", ephemeral=True, in_memory_only=True)
    bundle = kex.get_public_bundle()
    assert bundle.get("bundle_signature"), "baseline bundle must be signed"  # nosec: B101

    real_sign = kex.dss.sign

    def _fault(sk, msg):
        sig = real_sign(sk, msg)
        if isinstance(sig, dict):
            sig = dict(sig)
            k = "mldsa" if "mldsa" in sig else next(iter(sig))
            bad = bytearray(sig[k])
            bad[0] ^= 0x01
            sig[k] = bytes(bad)
            return sig
        bad = bytearray(sig)
        bad[0] ^= 0x01
        return bytes(bad)

    kex.dss.sign = _fault
    try:
        with pytest.raises(ValueError):
            kex.get_public_bundle()
    finally:
        kex.dss.sign = real_sign


def test_tuf_pq_faulted_signature_rejected():
    """A faulted TUF role signature raises CodeSigningError."""
    from supply_chain_security import CodeSigningError, TUFReleaseManager

    tmpdir = tempfile.mkdtemp()
    try:
        tuf = TUFReleaseManager(state_dir=str(Path(tmpdir) / "tuf_state"))
        blob = b'{"_type":"timestamp","version":1}'
        good = tuf._pq_sign_blob(blob)
        assert len(good) == 4627  # nosec: B101
        assert tuf._pq_verify_blob(blob, good) is True  # nosec: B101

        import liboqs_wrapper
        real_sign = liboqs_wrapper.LibOQS_MLDSA_87.sign

        def _fault(self, sk, msg):
            return b"\x00" * 4627

        liboqs_wrapper.LibOQS_MLDSA_87.sign = _fault
        try:
            with pytest.raises(CodeSigningError):
                tuf._pq_sign_blob(blob)
        finally:
            liboqs_wrapper.LibOQS_MLDSA_87.sign = real_sign
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_sbom_sign_helper_fault_rejected():
    """SBOM sign helper refuses to emit unverified signatures."""
    from generate_production_sbom import _mldsa_sign_verified
    from liboqs_wrapper import LibOQS_MLDSA_87

    signer = LibOQS_MLDSA_87()
    pk, sk = signer.keygen()
    data = b"sbom-vas-probe"
    sig = _mldsa_sign_verified(signer, sk, pk, data, "probe")
    assert signer.verify(pk, data, sig) is True  # nosec: B101

    class _FaultySigner:
        def sign(self, sk, data):
            return b"\x00" * 4627

        def verify(self, pk, data, sig):
            return False

    with pytest.raises(RuntimeError):
        _mldsa_sign_verified(_FaultySigner(), sk, pk, data, "probe-fault")


def test_noise_pq_responder_faulted_signature_quarantines():
    """Faulted responder signature in M2 triggers fail-closed latching quarantine."""
    import noise_pq as npq
    import liboqs_wrapper

    sig_engine = liboqs_wrapper.LibOQS_MLDSA_87()
    ci_pk, ci_sk = sig_engine.keygen()
    cr_pk, cr_sk = sig_engine.keygen()

    ini = npq.NoiseSession(is_initiator=True, sig_pk=ci_pk, sig_sk=ci_sk)
    rsp = npq.NoiseSession(is_initiator=False, sig_pk=cr_pk, sig_sk=cr_sk)
    m1 = npq.initiator_hello(ini)

    real_sign = liboqs_wrapper.LibOQS_MLDSA_87.sign

    def _fault(self, sk, msg):
        sig = real_sign(self, sk, msg)
        bad = bytearray(sig)
        bad[0] ^= 0x01
        return bytes(bad)

    liboqs_wrapper.LibOQS_MLDSA_87.sign = _fault
    try:
        with pytest.raises(npq.NoiseError, match="fault detected"):
            npq.responder_reply(rsp, m1)
    finally:
        liboqs_wrapper.LibOQS_MLDSA_87.sign = real_sign

    # Responder state must be irrevocably quarantined and zeroized
    assert rsp._quarantined is True
    assert rsp._f_ss is None
    assert rsp._k_send is None
    assert rsp._k_recv is None

    # Subsequent operations on quarantined session must fail closed
    with pytest.raises(npq.NoiseError, match="quarantined"):
        npq.split_session(rsp)


def test_noise_pq_initiator_faulted_signature_quarantines():
    """Faulted initiator signature in M3 triggers fail-closed latching quarantine."""
    import noise_pq as npq
    import liboqs_wrapper

    sig_engine = liboqs_wrapper.LibOQS_MLDSA_87()
    ci_pk, ci_sk = sig_engine.keygen()
    cr_pk, cr_sk = sig_engine.keygen()

    ini = npq.NoiseSession(is_initiator=True, sig_pk=ci_pk, sig_sk=ci_sk)
    rsp = npq.NoiseSession(is_initiator=False, sig_pk=cr_pk, sig_sk=cr_sk)
    m1 = npq.initiator_hello(ini)
    m2 = npq.responder_reply(rsp, m1)
    npq.initiator_finish(ini, m2, expected_peer_pk=cr_pk)

    real_sign = liboqs_wrapper.LibOQS_MLDSA_87.sign

    def _fault(self, sk, msg):
        sig = real_sign(self, sk, msg)
        bad = bytearray(sig)
        bad[0] ^= 0x01
        return bytes(bad)

    liboqs_wrapper.LibOQS_MLDSA_87.sign = _fault
    try:
        with pytest.raises(npq.NoiseError, match="fault detected"):
            npq.initiator_complete(ini)
    finally:
        liboqs_wrapper.LibOQS_MLDSA_87.sign = real_sign

    # Initiator state must be irrevocably quarantined and zeroized
    assert ini._quarantined is True
    assert ini._k_send is None
    assert ini._k_recv is None

    # Subsequent operations on quarantined session must fail closed
    with pytest.raises(npq.NoiseError, match="quarantined"):
        npq.split_session(ini)


def test_destroyer_node_rejects_quarantined_session():
    """DestroyerNode rejects establishing session from quarantined NoiseSession."""
    import noise_pq as npq
    import liboqs_wrapper
    from destroyer_node import DestroyerNode

    sig_engine = liboqs_wrapper.LibOQS_MLDSA_87()
    ci_pk, ci_sk = sig_engine.keygen()
    ini = npq.NoiseSession(is_initiator=True, sig_pk=ci_pk, sig_sk=ci_sk)
    ini.quarantine("fault injected")

    try:
        node = DestroyerNode()
    except Exception:
        pytest.skip("destroyer_core native module not available")

    with pytest.raises(RuntimeError, match="quarantined"):
        node.establish_from_noise(ini)

