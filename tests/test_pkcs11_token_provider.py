"""Tests for PKCS#11 hardware token backend and software simulation provider in NC3.

Verifies:
1. SoftwareTokenBackend produces 96-byte raw R||S ECDSA P-384 signatures.
2. Dual-officer token-backed EAM authorization roundtrip using SoftwareTokenBackend.
3. PKCS11HardwareTokenBackend library search and fail-closed absence handling.
4. Production gate: get_default_token_backend() raises HardwareTokenAuthenticationError
   when physical hardware is absent and P2P_PRODUCTION=1.
"""

import os
from unittest.mock import patch
import pytest

from nc3_nuclear_command import (
    NC3CommandController,
    OfficerIdentity,
    HardwareChallenge,
    HardwareTokenAuthenticationError,
    SoftwareTokenBackend,
    PKCS11HardwareTokenBackend,
    get_default_token_backend,
)


def test_software_token_backend_ecdsa_signature_format():
    backend = SoftwareTokenBackend("TEST-SIM-TOKEN")
    assert backend.token_label() == "TEST-SIM-TOKEN"  # nosec: B101

    key_label = "OFFICER-ALPHA-P384"
    backend.register_key(key_label)
    pub_der = backend.get_public_key_der(key_label)
    assert len(pub_der) > 50  # Valid SPKI DER  # nosec: B101

    data_to_sign = b"Test digest to be signed by officer token"
    sig = backend.sign(key_label, data_to_sign, mechanism="ECDSA")
    assert len(sig) == 96  # Exactly 48 bytes R + 48 bytes S for SECP384R1  # nosec: B101


def test_dual_officer_token_backed_eam_roundtrip():
    controller = NC3CommandController()
    backend = SoftwareTokenBackend("AIR-BASE-TOKEN")

    # Setup Officer 1 (token bound)
    label_1 = "OFFICER-1-TOKEN-KEY"
    backend.register_key(label_1)
    pub_der_1 = backend.get_public_key_der(label_1)
    off_1 = OfficerIdentity(
        officer_id="COL_ALPHA",
        rank="O-6",
        duty_title="Strike Commander",
        public_key=b"\x00" * 2592,  # Dummy ML-DSA PK
        auth_scheme="PKCS11-ECDSA-P384",
        token_label=label_1,
        token_pubkey=pub_der_1,
    )

    # Setup Officer 2 (token bound)
    label_2 = "OFFICER-2-TOKEN-KEY"
    backend.register_key(label_2)
    pub_der_2 = backend.get_public_key_der(label_2)
    off_2 = OfficerIdentity(
        officer_id="CAPT_BRAVO",
        rank="O-6",
        duty_title="Executive Officer",
        public_key=b"\x00" * 2592,
        auth_scheme="PKCS11-ECDSA-P384",
        token_label=label_2,
        token_pubkey=pub_der_2,
    )

    challenge = controller.issue_hardware_challenge(expiry_seconds=30.0)

    # Create token-backed responses
    resp_1 = controller.create_token_backed_response(off_1, challenge, backend)
    resp_2 = controller.create_token_backed_response(off_2, challenge, backend)

    assert resp_1.officer_id == "COL_ALPHA"  # nosec: B101
    assert resp_2.officer_id == "CAPT_BRAVO"  # nosec: B101
    assert len(resp_1.auth_signature) == 96  # nosec: B101
    assert len(resp_2.auth_signature) == 96  # nosec: B101

    # Verify dual responses
    ok = controller.verify_dual_hardware_responses(
        challenge=challenge,
        resp_1=resp_1,
        resp_2=resp_2,
        officer_1_pub=b"\x00" * 2592,
        officer_2_pub=b"\x00" * 2592,
        officer_1_auth={"scheme": "PKCS11-ECDSA-P384", "token_pubkey": pub_der_1},
        officer_2_auth={"scheme": "PKCS11-ECDSA-P384", "token_pubkey": pub_der_2},
    )
    assert ok is True  # nosec: B101


def test_pkcs11_backend_absent_fails_closed():
    backend = PKCS11HardwareTokenBackend(library_path="/nonexistent/path/to/pkcs11.so")
    assert backend.is_available() is False  # nosec: B101
    with pytest.raises(HardwareTokenAuthenticationError, match="PKCS#11 hardware token absent"):
        backend.sign("KEY-1", b"digest")


def test_get_default_token_backend_production_gate():
    # In non-production, fallback is allowed
    with patch.dict(os.environ, {"P2P_PRODUCTION": "0", "P2P_FAIL_ON_SOFTWARE_FALLBACK": "0"}):
        with patch.object(PKCS11HardwareTokenBackend, "is_available", return_value=False):
            backend = get_default_token_backend()
            assert isinstance(backend, SoftwareTokenBackend)  # nosec: B101

    # In strict production mode, missing hardware token MUST raise
    with patch.dict(os.environ, {"P2P_PRODUCTION": "1"}):
        with patch.object(PKCS11HardwareTokenBackend, "is_available", return_value=False):
            with pytest.raises(HardwareTokenAuthenticationError, match="Physical PKCS#11 hardware token mandatory"):
                get_default_token_backend()

