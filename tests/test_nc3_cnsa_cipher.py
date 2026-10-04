#!/usr/bin/env python3
"""NC3 PAL bulk cipher: AES-256-GCM seals, legacy ChaCha verifies, tamper fails."""

import os
import secrets
import sys
import unittest

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from nc3_nuclear_command import (
    NC3CommandController,
    _pal_decrypt,
    _pal_encrypt,
)


class TestNC3CNSACipher(unittest.TestCase):
    def test_01_aes_seal_open_roundtrip(self):
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        aad = b"test-eam-id"
        ct = _pal_encrypt(key, nonce, b"PAL-CODE-BRAVO", aad)
        self.assertEqual(_pal_decrypt(key, nonce, ct, aad), b"PAL-CODE-BRAVO")

    def test_02_legacy_chacha_blob_still_opens(self):
        from cryptography.hazmat.primitives.ciphers.aead import (
            ChaCha20Poly1305)
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        aad = b"legacy-eam-id"
        legacy = ChaCha20Poly1305(key).encrypt(nonce, b"PAL-LEGACY", aad)
        self.assertEqual(_pal_decrypt(key, nonce, legacy, aad), b"PAL-LEGACY")

    def test_03_tamper_rejected_both_paths(self):
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        aad = b"tamper-eam"
        good = bytearray(_pal_encrypt(key, nonce, b"X", aad))
        good[5] ^= 0x01
        with self.assertRaises(Exception):
            _pal_decrypt(key, nonce, bytes(good), aad)
        from cryptography.hazmat.primitives.ciphers.aead import (
            ChaCha20Poly1305)
        legacy = bytearray(ChaCha20Poly1305(key).encrypt(nonce, b"Y", aad))
        legacy[5] ^= 0x01
        with self.assertRaises(Exception):
            _pal_decrypt(key, nonce, bytes(legacy), aad)

    def test_04_full_eam_roundtrip_uses_aes(self):
        ctl = NC3CommandController()
        o1 = ctl.generate_officer_credentials("OF-T1-A", "General", "T1")
        o2 = ctl.generate_officer_credentials("OF-T2-B", "Admiral", "T2")
        r1 = ctl.generate_officer_credentials("OF-T3-C", "Colonel", "T3")
        r2 = ctl.generate_officer_credentials("OF-T4-D", "Captain", "T4")
        war_key = secrets.token_bytes(32)
        eam = ctl.create_nuclear_eam(
            directive_code="DIR-CNSA", target_command="CMD-CNSA",
            pal_code="PAL-AES-7741", officer_1=o1, officer_2=o2,
            pal_key=war_key)
        out = ctl.verify_and_decrypt_nuclear_eam(
            eam_data=eam.to_dict(), recipient_officer_1=r1,
            recipient_officer_2=r2, sender_officer_1_pub=o1.public_key,
            sender_officer_2_pub=o2.public_key, pal_key=war_key)
        self.assertEqual(out, "PAL-AES-7741")


    def test_06_twins_delegate_pal_open_to_canonical(self):
        # Regression guard: the legacy twins must NEVER carry a local copy
        # of the PAL cipher again. Seal path lives in nc3 (_pal_encrypt,
        # AES-256-GCM); any twin-local open (e.g. the ChaCha-only block
        # that broke every 2-terminal flash order after the migration)
        # silently breaks seal/open symmetry. Both twins must call the
        # canonical _pal_decrypt inside _verify_and_unseal_nc3_msg.
        import re as _re
        for _twin in ("archive/legacy_prototype/secure_p2.py", "archive/legacy_prototype/secure_p2p.py"):
            _src = open(os.path.join(PROJECT_ROOT, _twin),
                        encoding="utf-8").read()
            _start = _src.find("def _verify_and_unseal_nc3_msg")
            self.assertGreater(_start, 0, f"{_twin}: unseal missing?")
            _tail = _src[_start:]
            _end = _re.search(r"\n    (?:async )?def ", _tail)
            _body = _tail[:_end.start()] if _end else _tail
            self.assertIn("_pal_decrypt(", _body,
                          f"{_twin}: unseal must delegate to canonical opener")
            self.assertNotIn("ChaCha20Poly1305(", _body,
                             f"{_twin}: twin-local PAL cipher forbidden")

    def test_05_strict_mode_refuses_legacy_fallback(self):
        import os as _os
        from cryptography.hazmat.primitives.ciphers.aead import (
            ChaCha20Poly1305)
        from nc3_nuclear_command import DualCustodyViolation
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        aad = b"strict-eam"
        legacy = ChaCha20Poly1305(key).encrypt(nonce, b"OLD", aad)
        _os.environ["P2P_TS_MODE"] = "1"
        try:
            with self.assertRaises(DualCustodyViolation):
                _pal_decrypt(key, nonce, legacy, aad)
        finally:
            _os.environ.pop("P2P_TS_MODE", None)
        # Lab still opens legacy (migration discipline, seal path is AES).
        self.assertEqual(_pal_decrypt(key, nonce, legacy, aad), b"OLD")


if __name__ == "__main__":
    unittest.main()
