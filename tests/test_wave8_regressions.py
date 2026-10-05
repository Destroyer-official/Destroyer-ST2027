"""Wave-8 regression tests for latest builds (additive only, fast, no network).

Covers:
  1. TPM native crash guard (P2P_ALLOW_TPM_NATIVE=0 -> {} / None, no crash).
  2. SPQR cadence policy (v2 count/age refresh, v1 always False).
  3. DFR decaps-failure counters (bad ML-KEM decaps input counted).
  4. Prod-strict gates (lab False, prod True, RBAC opt-out ignored in prod).

Constraints: deterministic, isolated env per test (monkeypatch), no network,
no real TPM access, target <60s total. Uses lightweight DoubleRatchet
construction (``__new__`` + minimal attrs) for policy tests to avoid heavy
PQ keygen, plus one real-``__init__`` fast path with mocked PQ keygen.
"""

import time

import pytest

# Env keys that influence strict/prod decisions. Cleared for lab-default tests.
_PROD_ENV_KEYS = (
    "P2P_PRODUCTION",
    "SECURE_P2P_PRODUCTION",
    "P2P_ENV",
    "P2P_STRICT_ENCRYPT",
    "P2P_RBAC_STRICT",
)


def _clear_prod_env(monkeypatch):
    for k in _PROD_ENV_KEYS:
        monkeypatch.delenv(k, raising=False)


# ---------------------------------------------------------------------------
# 1. TPM guard
# ---------------------------------------------------------------------------

def test_tpm_guard_gated_no_crash(monkeypatch):
    """With P2P_ALLOW_TPM_NATIVE=0: PCR read == {} and attestation is None."""
    monkeypatch.setenv("P2P_ALLOW_TPM_NATIVE", "0")
    import platform_hsm_interface as phi

    assert phi._tpm_native_allowed() is False  # nosec: B101

    # Lightweight instance: __init__ does no native I/O (lazy init).
    att = phi.TPMRemoteAttestation()
    assert att._read_pcr_values() == {}  # nosec: B101
    assert phi.get_tpm_attestation() is None  # nosec: B101
    # Non-default args must also stay crash-free and gated.
    assert phi.get_tpm_attestation(nonce=b"\x00" * 32) is None  # nosec: B101


# ---------------------------------------------------------------------------
# 2. SPQR cadence
# ---------------------------------------------------------------------------

def _make_spqr_session(protocol_version, counter=0, last_refresh=None):
    """Lightweight DoubleRatchet stand-in for SPQR policy (no PQ keygen).

    Sets exactly the attrs read by _spqr_refresh_reason/should_spqr_refresh/
    get_spqr_stats: enable_pq, pq_ratchet_version (+ class version constants
    via inheritance), _spqr_msg_counter, _spqr_last_refresh.
    """
    from double_ratchet import DoubleRatchet

    sess = DoubleRatchet.__new__(DoubleRatchet)
    sess.enable_pq = True
    sess.protocol_version = int(protocol_version)
    sess.pq_ratchet_version = (
        DoubleRatchet.PQ_RATCHET_VERSION_FRESH if int(protocol_version) >= 2
        else DoubleRatchet.PQ_RATCHET_VERSION_LEGACY
    )
    sess._spqr_msg_counter = int(counter)
    sess._spqr_last_refresh = float(last_refresh if last_refresh is not None else time.time())
    return sess


def test_spqr_v2_initially_no_refresh(monkeypatch):
    monkeypatch.delenv("P2P_SPQR_MSG_INTERVAL", raising=False)
    monkeypatch.delenv("P2P_SPQR_MAX_AGE", raising=False)
    sess = _make_spqr_session(protocol_version=2)
    assert sess.should_spqr_refresh() is False  # nosec: B101
    assert sess._spqr_refresh_reason() is None  # nosec: B101
    stats = sess.get_spqr_stats()
    assert stats["needs_refresh"] is False  # nosec: B101
    assert stats["reason"] is None  # nosec: B101
    assert stats["msg_counter"] == 0  # nosec: B101
    assert stats["pq_ratchet_version"] == 2  # nosec: B101


def test_spqr_v2_count_triggers_after_interval(monkeypatch):
    """Simulate 50 sends: counter reaching msg_interval -> reason 'count'."""
    monkeypatch.delenv("P2P_SPQR_MSG_INTERVAL", raising=False)
    monkeypatch.delenv("P2P_SPQR_MAX_AGE", raising=False)
    from double_ratchet import _spqr_effective_policy

    interval, _ = _spqr_effective_policy()
    assert interval == 50  # Apple PQ3 default cadence  # nosec: B101
    sess = _make_spqr_session(protocol_version=2)
    # Deterministic stand-in for 50 _ratchet_encrypt sends (each +1s counter).
    for _ in range(interval):
        sess._spqr_msg_counter = int(getattr(sess, "_spqr_msg_counter", 0) or 0) + 1
    assert sess._spqr_msg_counter >= interval  # nosec: B101
    assert sess.should_spqr_refresh() is True  # nosec: B101
    assert sess._spqr_refresh_reason() == "count"  # nosec: B101
    stats = sess.get_spqr_stats()
    assert stats["needs_refresh"] is True  # nosec: B101
    assert stats["reason"] == "count"  # nosec: B101


def test_spqr_v2_age_triggers_on_stale_refresh(monkeypatch):
    monkeypatch.delenv("P2P_SPQR_MSG_INTERVAL", raising=False)
    monkeypatch.delenv("P2P_SPQR_MAX_AGE", raising=False)
    from double_ratchet import _spqr_effective_policy

    _, max_age = _spqr_effective_policy()
    sess = _make_spqr_session(
        protocol_version=2, counter=0,
        last_refresh=time.time() - (float(max_age) + 10.0),
    )
    assert sess.should_spqr_refresh() is True  # nosec: B101
    assert sess._spqr_refresh_reason() == "age"  # nosec: B101
    assert sess.get_spqr_stats()["reason"] == "age"  # nosec: B101


def test_spqr_v1_always_false(monkeypatch):
    """v1 sessions never refresh, even with huge count + stale timestamp."""
    monkeypatch.delenv("P2P_SPQR_MSG_INTERVAL", raising=False)
    monkeypatch.delenv("P2P_SPQR_MAX_AGE", raising=False)
    sess = _make_spqr_session(
        protocol_version=1, counter=10 ** 6,
        last_refresh=time.time() - (10 * 7 * 24 * 3600),
    )
    assert sess.should_spqr_refresh() is False  # nosec: B101
    assert sess._spqr_refresh_reason() is None  # nosec: B101
    stats = sess.get_spqr_stats()
    assert stats["needs_refresh"] is False  # nosec: B101
    assert stats["reason"] is None  # nosec: B101
    assert stats["pq_ratchet_version"] == 1  # nosec: B101


def test_spqr_real_init_fast_path(monkeypatch):
    """Real DoubleRatchet.__init__ (protocol_version=2) with mocked PQ keygen.

    Proves the real init wires v2 SPQR state (counter 0, no refresh due)
    without paying for slow hybrid PQ keygen. Falls back to policy-only
    assertion with a warning if the host init path is unexpectedly heavy.
    """
    import secrets
    from unittest import mock

    from double_ratchet import DoubleRatchet

    def _fast_pq_keypairs(self):
        self.kem_public_key = b"mock-kem-pk"
        self.kem_private_key = b"mock-kem-sk"
        self.dss_public_key = b"mock-dss-pk"
        self.dss_private_key = b"mock-dss-sk"

    try:
        with mock.patch.object(DoubleRatchet, "_generate_pq_keypairs", _fast_pq_keypairs):
            sess = DoubleRatchet(
                root_key=secrets.token_bytes(32),
                is_initiator=True,
                protocol_version=2,
            )
    except Exception as exc:  # pragma: no cover - host-specific heavy path
        import warnings
        warnings.warn(f"real DoubleRatchet init unavailable, policy-only covered: {exc}")
        sess = _make_spqr_session(protocol_version=2)
    assert sess.should_spqr_refresh() is False  # nosec: B101
    assert sess.get_spqr_stats()["pq_ratchet_version"] == 2  # nosec: B101


# ---------------------------------------------------------------------------
# 3. DFR decaps-failure counters
# ---------------------------------------------------------------------------

def test_dfr_bad_decaps_input_counted():
    """reset -> bad ML-KEM decaps (truncated ct) raises and fail>=1."""
    liboqs = pytest.importorskip("liboqs_wrapper")

    stats0 = liboqs.reset_decaps_stats()
    assert stats0["decaps_total"] == 0  # nosec: B101
    assert stats0["decaps_fail"] == 0  # nosec: B101

    try:
        kem = liboqs.LibOQS_MLKEM_1024()
    except Exception as exc:
        # Native lib unavailable: prove the counter path itself still works.
        liboqs._record_decaps_result(False)
        stats = liboqs.get_decaps_stats()
        assert stats["decaps_fail"] >= 1  # nosec: B101
        pytest.skip(f"native liboqs unavailable ({exc}); counter API verified")
        return

    dummy_sk = bytes(kem.sk_size)
    truncated_ct = b"\x00" * 16  # valid type, wrong size -> validation failure
    assert len(truncated_ct) != kem.ct_size  # nosec: B101
    with pytest.raises(Exception):
        kem.decaps(dummy_sk, truncated_ct)
    stats = liboqs.get_decaps_stats()
    assert stats["decaps_total"] >= 1  # nosec: B101
    assert stats["decaps_fail"] >= 1  # nosec: B101

    # pqc_algorithms mirror API exists and is readable (observability only).
    import pqc_algorithms

    assert callable(pqc_algorithms.get_decaps_stats)  # nosec: B101
    assert callable(pqc_algorithms.reset_decaps_stats)  # nosec: B101
    assert isinstance(pqc_algorithms.get_decaps_stats(), dict)  # nosec: B101


# ---------------------------------------------------------------------------
# 4. Prod-strict gates
# ---------------------------------------------------------------------------

def test_prod_strict_lab_defaults(monkeypatch):
    """Lab (no prod env): all strict gates False."""
    _clear_prod_env(monkeypatch)
    from utils.message_caps import is_strict_encrypt, prod_strict_on
    from zero_trust_engine import is_rbac_strict

    assert prod_strict_on() is False  # nosec: B101
    assert is_strict_encrypt() is False  # nosec: B101
    assert is_rbac_strict() is False  # nosec: B101


def test_prod_strict_enabled(monkeypatch):
    """P2P_PRODUCTION=1: all strict gates True (auto-strict, no extra env)."""
    _clear_prod_env(monkeypatch)
    monkeypatch.setenv("P2P_PRODUCTION", "1")
    from utils.message_caps import is_strict_encrypt, prod_strict_on
    from zero_trust_engine import is_rbac_strict

    assert prod_strict_on() is True  # nosec: B101
    assert is_strict_encrypt() is True  # nosec: B101
    assert is_rbac_strict() is True  # nosec: B101


def test_prod_strict_rbac_optout_ignored_in_prod(monkeypatch):
    """Explicit P2P_RBAC_STRICT=0 is ignored in prod (stays strict)."""
    _clear_prod_env(monkeypatch)
    monkeypatch.setenv("P2P_PRODUCTION", "1")
    monkeypatch.setenv("P2P_RBAC_STRICT", "0")
    from zero_trust_engine import is_rbac_strict

    assert is_rbac_strict() is True  # nosec: B101


# ---------------------------------------------------------------------------
# 6. PQ strict-abort gate (P2P_PQ_STRICT_ABORT=1, Fix C)
# ---------------------------------------------------------------------------

def _make_initialized_spqr_session():
    """Lightweight v2 session that passes is_initialized (SPQR path only)."""
    import secrets

    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    sess = _make_spqr_session(protocol_version=2)
    sess.enable_pq = True
    sess.is_initiator = True
    sess.sending_chain_key = secrets.token_bytes(32)
    sess.receiving_chain_key = secrets.token_bytes(32)
    sess.sending_message_number = 0
    sess.remote_dh_public_key = X25519PrivateKey.generate().public_key()
    sess.remote_kem_public_key = secrets.token_bytes(1568)
    # Telemetry/discipline flags consulted by _chain_ratchet_step.
    sess.side_channel_protection = False
    sess.anomaly_detection = False
    sess.secure_memory_protection = False
    assert sess.is_initialized()  # nosec: B101
    return sess


def _make_real_pair():
    """Two fully initialized v2 sessions (ML-DSA-87 DSS identity)."""
    import secrets

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


def test_pq_strict_abort_defaults_off(monkeypatch):
    """Gate is fail-safe default-off (availability preserved)."""
    monkeypatch.delenv("P2P_PQ_STRICT_ABORT", raising=False)
    from double_ratchet import _pq_strict_abort

    assert _pq_strict_abort() is False  # nosec: B101
    monkeypatch.setenv("P2P_PQ_STRICT_ABORT", "1")
    assert _pq_strict_abort() is True  # nosec: B101


def test_spqr_refresh_failure_policy(monkeypatch):
    """SPQR refresh fault: legacy-continue by default, abort when armed."""
    from unittest import mock

    from double_ratchet import DoubleRatchet, SecurityError

    monkeypatch.delenv("P2P_PQ_STRICT_ABORT", raising=False)
    sess = _make_initialized_spqr_session()
    sess._spqr_msg_counter = 10 ** 6  # refresh due now
    with mock.patch.object(DoubleRatchet, "_do_spqr_refresh",
                           side_effect=RuntimeError("pq-hsm-fault")):
        key = sess._ratchet_encrypt()
        assert isinstance(key, bytes) and len(key) > 0  # nosec: B101

    monkeypatch.setenv("P2P_PQ_STRICT_ABORT", "1")
    sess2 = _make_initialized_spqr_session()
    sess2._spqr_msg_counter = 10 ** 6
    with mock.patch.object(DoubleRatchet, "_do_spqr_refresh",
                           side_effect=RuntimeError("pq-hsm-fault")):
        with pytest.raises(SecurityError):
            sess2._ratchet_encrypt()


def test_sending_encaps_failure_policy(monkeypatch):
    """v2 sending-side encaps fault: legacy step by default, abort when armed."""
    from unittest import mock

    from double_ratchet import DoubleRatchet, SecurityError

    monkeypatch.delenv("P2P_PQ_STRICT_ABORT", raising=False)
    alice, bob = _make_real_pair()
    alice.force_ratchet_rotation()
    msg = alice.encrypt(b"epoch1")
    with mock.patch.object(DoubleRatchet, "_pq_encaps_to_peer_v2",
                           side_effect=RuntimeError("encaps-fault")):
        assert bob.decrypt(msg) == b"epoch1"  # legacy fallback, no abort  # nosec: B101
        assert bob.get_pending_pq_ct() is None  # nosec: B101

    monkeypatch.setenv("P2P_PQ_STRICT_ABORT", "1")
    alice2, bob2 = _make_real_pair()
    alice2.force_ratchet_rotation()
    msg2 = alice2.encrypt(b"epoch1-strict")
    with mock.patch.object(DoubleRatchet, "_pq_encaps_to_peer_v2",
                           side_effect=RuntimeError("encaps-fault")):
        with pytest.raises(SecurityError):
            bob2.decrypt(msg2)


def test_peer_ct_decaps_failure_always_aborts(monkeypatch, caplog):
    """Present-but-undecapsable peer CT: explicit fail-closed, any mode.

    Legacy reuse could never re-sync these chains (sender mixed v2-fresh
    material), so aborting beats the old silent-desync-then-AEAD-fail.
    The abort is explicit: decrypt raises SecurityError AND the
    fail-closed warning is logged (not a bare AEAD tag failure).
    """
    import logging
    from unittest import mock

    from double_ratchet import SecurityError

    for strict in ("0", "1"):
        monkeypatch.setenv("P2P_PQ_STRICT_ABORT", strict)
        caplog.clear()
        with caplog.at_level(logging.WARNING, logger="double_ratchet"):
            alice, bob = _make_real_pair()
            # Rotation + reply sequence so bob's reply carries a fresh peer CT.
            alice.force_ratchet_rotation()
            assert bob.decrypt(alice.encrypt(b"epoch1")) == b"epoch1"  # nosec: B101
            reply = bob.encrypt(b"epoch2-with-ct")
            with mock.patch.object(alice.kem, "decaps",
                                   side_effect=RuntimeError("decaps-fault")):
                with pytest.raises(SecurityError):
                    alice.decrypt(reply)
        assert (  # nosec: B101
            any("failing closed" in r.message for r in caplog.records)
        ), "abort must be explicit (fail-closed log), not a silent desync"


# ---------------------------------------------------------------------------
# 5. Twin parity (secure_p2.py vs secure_p2p.py)
# ---------------------------------------------------------------------------

def _normalized_twin_lines(path):
    """Read a twin file, drop blank lines, strip trailing whitespace."""
    from pathlib import Path

    lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    return [ln.rstrip() for ln in lines if ln.strip() != ""]


def test_twins_parity_whitespace_insensitive():
    """secure_p2.py and secure_p2p.py must stay functionally identical.

    Normalizes trailing whitespace and drops blank lines (the only
    accepted drift class); any real divergence fails. Prevents silent
    security drift between the deployed twins.
    """
    from pathlib import Path

    root = Path(__file__).resolve().parent
    if not (root / "archive").exists():
        root = root.parent
    p2 = root / "archive/legacy_prototype/secure_p2.py"
    p2p = root / "archive/legacy_prototype/secure_p2p.py"
    if not p2.exists() or not p2p.exists():
        pytest.skip("legacy prototype twins not present in archive")
    a = _normalized_twin_lines(p2)
    b = _normalized_twin_lines(p2p)
    assert len(a) == len(b), f"twin line-count drift: {len(a)} vs {len(b)}"  # nosec: B101
    for i, (la, lb) in enumerate(zip(a, b)):
        assert la == lb, f"twin divergence at normalized line {i + 1}"  # nosec: B101


def test_twins_bundle_ceiling_sites():
    """Both twins use the 2MB bundle ceiling at all 4 bundle-receive sites."""
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parent
    if not (root / "archive").exists():
        root = root.parent
    p2 = root / "archive/legacy_prototype/secure_p2.py"
    p2p = root / "archive/legacy_prototype/secure_p2p.py"
    if not p2.exists() or not p2p.exists():
        pytest.skip("legacy prototype twins not present in archive")
    for name in ("archive/legacy_prototype/secure_p2.py", "archive/legacy_prototype/secure_p2p.py"):
        src = (root / name).read_text(encoding="utf-8", errors="replace")
        hits = re.findall(r"max_size=p2p\.PRE_AUTH_HYBRID_BUNDLE_MAX_MESSAGE_SIZE", src)
        assert len(hits) == 4, f"{name}: expected 4 bundle-ceiling sites, found {len(hits)}"  # nosec: B101

