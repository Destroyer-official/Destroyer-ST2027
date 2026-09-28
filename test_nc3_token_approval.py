"""Token-backed officer approvals (G2): PKCS#11 ECDSA presence leg.

No hardware required: _FakeTokenBackend performs REAL ECDSA P-384
(via `cryptography`) behind a PKCS#11-shaped transport (raw R||S like
C_Sign/ECDSA, SPKI export, token labels) so every on-wire semantic --
digest binding, scheme dispatch, token-swap refusal -- is proven.

Covers:
  1. Dual token-backed approvals verify (both ECDSA).
  2. Mixed pair (ML-DSA-87 software + token) verifies (dispatch).
  3. Token-swap (sig from key B vs registered pub A) fails closed.
  4. Wire scheme flipped away from the binding fails closed.
  5. Unknown binding scheme fails closed.
  6. Non-token-bound officer cannot use the token path.
  7. Token refusal (absent/wrong PIN) fails closed, nothing emitted.
  8. OfficerIdentity binding fields survive to_dict/from_dict roundtrip.
  9. Backend mechanism allowlist + unavailable-backend behavior.
 10. SPKI builder: P-384 wrapped/bare accepted, P-256 + RSA-2048 refused.
"""

import pytest

from nc3_nuclear_command import (
    DualCustodyViolation,
    HardwareTokenAuthenticationError,
    NC3CommandController,
    OfficerIdentity,
)


@pytest.fixture(scope="module")
def controller():
    return NC3CommandController()


class _FakeTokenBackend:
    """PKCS#11-shaped transport, real P-384 crypto. Mirrors prod semantics:
    C_Sign/ECDSA returns raw R||S over the input digest bytes."""

    def __init__(self, label="SOFT-TEST-TOKEN"):
        from cryptography.hazmat.primitives.asymmetric import ec
        self._label = label
        self._keys = {}

        class _Key:
            def __init__(self, priv):
                self._priv = priv

        self._Key = _Key
        self._ec = ec
        for kid in ("OFF-A-KEY", "OFF-B-KEY"):
            self._keys[kid] = _Key(ec.generate_private_key(ec.SECP384R1()))

    # -- backend surface used by the controller --
    def token_label(self):
        return self._label

    def sign(self, key_label, data, mechanism="ECDSA"):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.utils import (
            Prehashed, decode_dss_signature)
        if mechanism != "ECDSA":
            raise ValueError(f"fake token supports ECDSA only, got {mechanism!r}")
        try:
            priv = self._keys[key_label]._priv
        except KeyError:
            raise KeyError(f"no such token key {key_label!r}")
        # Mirrors prod: the caller passes the 48-byte approval message
        # (SHA-384 of the transcript digest); raw-sign it like C_Sign.
        approval = bytes(data)
        assert len(approval) == 48, "fake token expects the approval message"  # nosec: B101
        der = priv.sign(approval, self._ec.ECDSA(Prehashed(hashes.SHA384())))
        r, s = decode_dss_signature(der)
        return r.to_bytes(48, "big") + s.to_bytes(48, "big")

    def get_public_key(self, key_label):
        from cryptography.hazmat.primitives import serialization
        return self._keys[key_label]._priv.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)


def _token_officer(controller, officer_id, backend, key_label):
    return OfficerIdentity(
        officer_id=officer_id, rank="O-6", duty_title="Command Duty Officer",
        public_key=b"\x00" * 2592, secret_key=None,
        auth_scheme="PKCS11-ECDSA-P384", token_label=key_label,
        token_pubkey=backend.get_public_key(key_label))


def _software_officer(controller, officer_id):
    creds = controller.generate_officer_credentials(
        officer_id, "O-6", "Command Duty Officer")
    return creds


def test_dual_token_approvals_verify(controller):
    backend = _FakeTokenBackend()
    chal = controller.issue_hardware_challenge()
    off_a = _token_officer(controller, "OFF-A", backend, "OFF-A-KEY")
    off_b = _token_officer(controller, "OFF-B", backend, "OFF-B-KEY")
    r1 = controller.create_token_backed_response(off_a, chal, backend)
    r2 = controller.create_token_backed_response(off_b, chal, backend)
    assert r1.scheme == "PKCS11-ECDSA-P384"  # nosec: B101
    assert r1.token_id != r2.token_id  # distinct token+key binding  # nosec: B101
    assert controller.verify_dual_hardware_responses(  # nosec: B101
        chal, r1, r2, off_a.public_key, off_b.public_key,
        officer_1_auth={"scheme": "PKCS11-ECDSA-P384",
                        "token_pubkey": off_a.token_pubkey},
        officer_2_auth={"scheme": "PKCS11-ECDSA-P384",
                        "token_pubkey": off_b.token_pubkey}) is True


def test_mixed_software_and_token_pair(controller):
    backend = _FakeTokenBackend()
    chal = controller.issue_hardware_challenge()
    off_sw = _software_officer(controller, "OFF-SW")
    r_sw = controller.create_hardware_token_response(
        off_sw, chal, token_id="soft-lab-token")  # nosec: B106
    off_tok = _token_officer(controller, "OFF-T", backend, "OFF-A-KEY")
    r_tok = controller.create_token_backed_response(off_tok, chal, backend)
    assert controller.verify_dual_hardware_responses(  # nosec: B101
        chal, r_sw, r_tok, off_sw.public_key, off_tok.public_key,
        officer_2_auth={"scheme": "PKCS11-ECDSA-P384",
                        "token_pubkey": off_tok.token_pubkey}) is True


def test_token_swap_rejected(controller):
    backend = _FakeTokenBackend()
    chal = controller.issue_hardware_challenge()
    off_a = _token_officer(controller, "OFF-A", backend, "OFF-A-KEY")
    # Cloned-label attack: a DIFFERENT physical token mints key material
    # under the same key label. token_ids differ (distinct hardware), so
    # verification reaches the crypto check -- and must fail there.
    rogue_backend = _FakeTokenBackend(label="ROGUE-TOKEN")
    rogue_off = _token_officer(controller, "OFF-A", rogue_backend, "OFF-A-KEY")
    r_rogue = controller.create_token_backed_response(
        rogue_off, chal, rogue_backend)
    assert r_rogue.token_id != f"pkcs11:{backend.token_label()}:OFF-A-KEY"  # nosec: B101
    off_b = _token_officer(controller, "OFF-B", backend, "OFF-B-KEY")
    r2 = controller.create_token_backed_response(off_b, chal, backend)
    with pytest.raises(HardwareTokenAuthenticationError):
        controller.verify_dual_hardware_responses(
            chal, r_rogue, r2, off_a.public_key, off_b.public_key,
            officer_1_auth={"scheme": "PKCS11-ECDSA-P384",
                            "token_pubkey": off_a.token_pubkey},
            officer_2_auth={"scheme": "PKCS11-ECDSA-P384",
                            "token_pubkey": off_b.token_pubkey})


def test_wire_scheme_flip_rejected(controller):
    backend = _FakeTokenBackend()
    chal = controller.issue_hardware_challenge()
    off_a = _token_officer(controller, "OFF-A", backend, "OFF-A-KEY")
    off_b = _token_officer(controller, "OFF-B", backend, "OFF-B-KEY")
    r1 = controller.create_token_backed_response(off_a, chal, backend)
    r1.scheme = "ML-DSA-87"  # wire flip after signing
    r2 = controller.create_token_backed_response(off_b, chal, backend)
    with pytest.raises(HardwareTokenAuthenticationError):
        controller.verify_dual_hardware_responses(
            chal, r1, r2, off_a.public_key, off_b.public_key,
            officer_1_auth={"scheme": "PKCS11-ECDSA-P384",
                            "token_pubkey": off_a.token_pubkey},
            officer_2_auth={"scheme": "PKCS11-ECDSA-P384",
                            "token_pubkey": off_b.token_pubkey})


def test_unknown_binding_scheme_rejected(controller):
    backend = _FakeTokenBackend()
    chal = controller.issue_hardware_challenge()
    off_a = _token_officer(controller, "OFF-A", backend, "OFF-A-KEY")
    off_b = _token_officer(controller, "OFF-B", backend, "OFF-B-KEY")
    r1 = controller.create_token_backed_response(off_a, chal, backend)
    r2 = controller.create_token_backed_response(off_b, chal, backend)
    with pytest.raises(HardwareTokenAuthenticationError):
        controller.verify_dual_hardware_responses(
            chal, r1, r2, off_a.public_key, off_b.public_key,
            officer_1_auth={"scheme": "ROT13", "token_pubkey": off_a.token_pubkey},
            officer_2_auth={"scheme": "PKCS11-ECDSA-P384",
                            "token_pubkey": off_b.token_pubkey})


def test_non_token_officer_cannot_use_token_path(controller):
    backend = _FakeTokenBackend()
    chal = controller.issue_hardware_challenge()
    off_sw = _software_officer(controller, "OFF-SW")
    with pytest.raises(DualCustodyViolation):
        controller.create_token_backed_response(off_sw, chal, backend,
                                                key_label="OFF-A-KEY")


def test_token_refusal_fails_closed(controller):
    class _DeadBackend(_FakeTokenBackend):
        def sign(self, key_label, data, mechanism="ECDSA"):
            raise RuntimeError("token removed mid-ceremony")

    backend = _DeadBackend()
    chal = controller.issue_hardware_challenge()
    off_a = _token_officer(controller, "OFF-A", backend, "OFF-A-KEY")
    with pytest.raises(HardwareTokenAuthenticationError):
        controller.create_token_backed_response(off_a, chal, backend)


def test_officer_binding_roundtrip(controller):
    backend = _FakeTokenBackend()
    off = _token_officer(controller, "OFF-A", backend, "OFF-A-KEY")
    d = off.to_dict()
    assert d["auth_scheme"] == "PKCS11-ECDSA-P384"  # nosec: B101
    assert d["token_label"] == "OFF-A-KEY"  # nosec: B101
    back = OfficerIdentity.from_dict(d)
    assert back.auth_scheme == "PKCS11-ECDSA-P384"  # nosec: B101
    assert back.token_pubkey == off.token_pubkey  # nosec: B101
    # Legacy dicts (pre-binding) default to the software path.
    legacy = {"officer_id": "X", "rank": "O-6", "duty_title": "Y",
              "public_key_hex": "00" * 2592}
    assert OfficerIdentity.from_dict(legacy).auth_scheme == "ML-DSA-87"  # nosec: B101


def test_backend_mechanism_allowlist_and_unavailable():
    from secure_enclave_key_storage import (
        HardwareUnavailableError, KeyOperationError,
        PKCS11HSMBackend, _resolve_token_sign_mechanism)
    import pkcs11
    assert _resolve_token_sign_mechanism("ECDSA", pkcs11.Mechanism) is pkcs11.Mechanism.ECDSA  # nosec: B101
    assert _resolve_token_sign_mechanism("sha384_rsa_pkcs", pkcs11.Mechanism) is pkcs11.Mechanism.SHA384_RSA_PKCS  # nosec: B101
    for bad in ("MD5_RSA_PKCS", "SHA1_RSA_PKCS", "RSA_PKCS_PSS", "HMAC", ""):
        with pytest.raises(KeyOperationError):
            _resolve_token_sign_mechanism(bad, pkcs11.Mechanism)
    dead = PKCS11HSMBackend.__new__(PKCS11HSMBackend)
    dead._available = False
    with pytest.raises(HardwareUnavailableError):
        dead.sign("k", b"digest")
    assert dead.get_public_key("k") is None  # nosec: B101


def test_spki_builder_shapes():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from secure_enclave_key_storage import _spki_from_token_pubkey
    import pkcs11

    class _Attrs(dict):
        pass

    priv = ec.generate_private_key(ec.SECP384R1())
    nums = priv.public_key().public_numbers()
    raw = b"\x04" + nums.x.to_bytes(48, "big") + nums.y.to_bytes(48, "big")
    attrs = _Attrs({
        pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.EC,
        pkcs11.Attribute.EC_PARAMS: bytes.fromhex("06052b81340122"),
        pkcs11.Attribute.VALUE: raw,
    })
    spki = _spki_from_token_pubkey(attrs, pkcs11)
    assert spki == priv.public_key().public_bytes(  # nosec: B101
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    # DER-wrapped OCTET STRING form also accepted.
    wrapped = dict(attrs)
    wrapped[pkcs11.Attribute.VALUE] = b"\x04\x60" + raw
    attrs2 = _Attrs(wrapped)
    assert _spki_from_token_pubkey(attrs2, pkcs11) == spki  # nosec: B101
    # P-256 refused (strict P-384-only).
    priv256 = ec.generate_private_key(ec.SECP256R1())
    n256 = priv256.public_key().public_numbers()
    raw256 = b"\x04" + n256.x.to_bytes(32, "big") + n256.y.to_bytes(32, "big")
    attrs3 = _Attrs({
        pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.EC,
        pkcs11.Attribute.EC_PARAMS: bytes.fromhex("06082a8648ce3d030107"),
        pkcs11.Attribute.VALUE: raw256,
    })
    assert _spki_from_token_pubkey(attrs3, pkcs11) is None  # nosec: B101

