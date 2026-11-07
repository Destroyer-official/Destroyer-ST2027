"""
Unit tests for the Master Defense Audit Scorecard (scripts/run_defense_audit.py).
Verifies:
1. Dynamic gate calculation (no hardcoded '10/10').
2. Failure detection when any gate fails.
3. Completeness enforcement when any expected gate is missing.
"""

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from run_defense_audit import AuditScorecard, EXPECTED_GATES


class TestAuditScorecard(unittest.TestCase):
    def test_all_expected_gates_pass(self):
        card = AuditScorecard(EXPECTED_GATES)
        for gid in EXPECTED_GATES:
            card.record_gate(gid, f"Gate {gid}", True, 10.0, "Verified")

        passed, passed_count, total_count = card.evaluate_completeness()
        self.assertTrue(passed)
        self.assertEqual(passed_count, 10)
        self.assertEqual(total_count, 10)
        summary = card.render_summary()
        self.assertIn("10/10 SATISFIED — ALL GATES VERIFIED", summary)

    def test_failed_gate_detected(self):
        card = AuditScorecard(EXPECTED_GATES)
        for gid in EXPECTED_GATES:
            status = False if gid == "10.1" else True
            card.record_gate(gid, f"Gate {gid}", status, 10.0, "Detail")

        passed, passed_count, total_count = card.evaluate_completeness()
        self.assertFalse(passed)
        self.assertEqual(passed_count, 9)
        self.assertEqual(total_count, 10)
        summary = card.render_summary()
        self.assertIn("DEFENSE DEFICIENCY DETECTED (9/10 passed)", summary)

    def test_missing_gate_detected(self):
        card = AuditScorecard(EXPECTED_GATES)
        # Execute only 8 gates
        for gid in EXPECTED_GATES[:8]:
            card.record_gate(gid, f"Gate {gid}", True, 10.0, "Verified")

        passed, passed_count, total_count = card.evaluate_completeness()
        self.assertFalse(passed)
        self.assertEqual(passed_count, 8)
        self.assertEqual(total_count, 10)
        summary = card.render_summary()
        self.assertIn("DEFENSE DEFICIENCY DETECTED (8/10 passed)", summary)

    def test_persisted_receipt_mldsa_byte_exact_vas(self):
        """Verifies that reading the receipt file from disk and verifying against .sig passes VAS."""
        receipt_file = REPO_ROOT / "compliance_reports" / "defense_master_audit_receipt.json"
        sig_file = Path(str(receipt_file) + ".sig")
        pub_file = Path(str(receipt_file) + ".pub")
        if not (receipt_file.exists() and sig_file.exists() and pub_file.exists()):
            self.skipTest("Receipt and signature not yet generated on disk")

        from pqc_algorithms import LibOQS_MLDSA_87
        signer = LibOQS_MLDSA_87()
        pk = pub_file.read_bytes()
        sig = sig_file.read_bytes()
        doc = receipt_file.read_bytes()
        self.assertTrue(signer.verify(pk, doc, sig), "Persisted receipt bytes must verify against .sig")


if __name__ == "__main__":
    unittest.main()

