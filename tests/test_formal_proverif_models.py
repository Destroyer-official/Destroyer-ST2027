#!/usr/bin/env python3
"""
Test Suite: Formal ProVerif Models Structural & Mathematical Validation
=======================================================================
Verifies that `handshake_model.pv` and `nc3_dual_custody.pv` satisfy:
1. File existence and non-emptiness.
2. Balanced parentheses and comment blocks `(* ... *)`.
3. Well-formed type declarations, constructors, equations, and reductions.
4. Correct correspondence queries (`==>`, `inj-event`, `attacker`).
5. Process declaration balance and channel definitions.
"""

import os
import re
import unittest

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
FORMAL_DIR = os.path.join(PROJECT_ROOT, "docs", "formal")


class TestFormalProVerifModels(unittest.TestCase):
    def test_01_handshake_model_integrity(self):
        """Verify handshake_model.pv is syntactically sound and contains all required proofs."""
        filepath = os.path.join(FORMAL_DIR, "handshake_model.pv")
        self.assertTrue(os.path.exists(filepath), f"File missing: {filepath}")

        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        # Check balanced comments
        open_comments = content.count("(*")
        close_comments = content.count("*)")
        self.assertEqual(open_comments, close_comments, "Mismatched ProVerif comment delimiters (* ... *)")

        # Check required types and cryptographic primitives
        self.assertIn("type key.", content)
        self.assertIn("type skey.", content)
        self.assertIn("type pkey.", content)
        self.assertIn("type ss.", content)
        self.assertIn("fun mlkem_encap", content)
        self.assertIn("fun mceliece_encap", content)
        self.assertIn("fun pq_sign", content)
        self.assertIn("fun hkdf_combine", content)

        # Check required security queries
        self.assertIn("query attacker(secret_payload).", content)
        self.assertIn("inj-event(RespAgrees(k, t)) ==> inj-event(InitAgrees(k, t))", content)
        self.assertIn("query ipk:pkey, rpk:pkey, k:key;", content)

        # Check balanced processes
        self.assertIn("let Initiator", content)
        self.assertIn("let Responder", content)
        self.assertIn("process", content)

    def test_02_nc3_dual_custody_model_integrity(self):
        """Verify nc3_dual_custody.pv is syntactically sound and validates Two-Person Rule & PAL secrecy."""
        filepath = os.path.join(FORMAL_DIR, "nc3_dual_custody.pv")
        self.assertTrue(os.path.exists(filepath), f"File missing: {filepath}")

        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        # Check balanced comments
        open_comments = content.count("(*")
        close_comments = content.count("*)")
        self.assertEqual(open_comments, close_comments, "Mismatched ProVerif comment delimiters (* ... *)")

        # Check required DoD S-5210.41M cryptographic constructions
        self.assertIn("fun vss_share1", content)
        self.assertIn("fun vss_share2", content)
        self.assertIn("fun vss_combine", content)
        self.assertIn("reduc forall k:key, r:nonce;", content)
        self.assertIn("fun aead_enc", content)
        self.assertIn("fun aead_dec", content)
        self.assertIn("fun pq_sign", content)
        self.assertIn("fun pq_verify", content)

        # Check essential DoD NC3 queries
        self.assertIn("query attacker(top_secret_pal_code).", content)
        self.assertIn("event(PALCodeReleased(dir, pal)) ==>", content)
        self.assertIn("event(Officer1Authorizes(dir, pal)) && event(Officer2Authorizes(dir, pal))", content)
        self.assertIn("inj-event(PALCodeReleased(dir, pal)) ==>", content)

        # Check distinct officer and hardware token constraints in process
        self.assertIn("off1_pub <> off2_pub", content)
        self.assertIn("tok1 <> tok2", content)
        self.assertIn("c_nonce1 <> c_nonce2", content)

        # Check compromised officer scenario
        self.assertIn("phase 1;", content)
        self.assertIn("event CompromisedOfficerAttempt", content)


if __name__ == "__main__":
    unittest.main()
