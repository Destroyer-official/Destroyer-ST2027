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


if __name__ == "__main__":
    unittest.main()

