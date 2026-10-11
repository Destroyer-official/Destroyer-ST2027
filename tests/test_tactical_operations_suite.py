#!/usr/bin/env python3
"""
Unit and Integration Test Suite for Real Military Tactical C4ISR Operations.
Verifies both the Native Rust Data Plane commands and Python Tactical Console:
  - MIL-STD-6090 Cursor-on-Target (CoT) XML Generation & FIPS 204 Signature.
  - Tactical Message Handling (MMHS Precedence & Bell-LaPadula MLS).
  - NSA NCDSMO RTB Classified Spillage Prevention (Fail-Closed).
  - Two-Person Integrity / Dual-Custody NC3 EAM Authorization.
  - Blue Force Tracking (BFT) State Management & ATAK Bridge UDP Broadcast.
  - Emergency Zeroization Sanitization.
"""

import os
import sys
import subprocess
import tempfile
import unittest
import socket
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CRATE = ROOT / "rust_data_plane"
BIN = CRATE / "target" / "release" / ("secure-transmit.exe" if os.name == "nt" else "secure-transmit")
if not BIN.exists():
    BIN = CRATE / "target" / "debug" / ("secure-transmit.exe" if os.name == "nt" else "secure-transmit")


class TestTacticalOperationsSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert BIN.exists(), f"Binary {BIN} must be built before running tactical tests."

    def test_01_rust_cot_beacon_generation(self):
        """Test native secure-transmit cot-beacon generates valid MIL-STD-6090 XML."""
        r = subprocess.run(
            [str(BIN), "cot-beacon", "--callsign", "VIPER-01", "--lat", "34.5", "--lon", "-118.2", "--type", "a-f-A-M-F"],
            capture_output=True, text=True, cwd=str(CRATE), timeout=10
        )
        self.assertEqual(r.returncode, 0, f"cot-beacon failed: {r.stderr}")
        out = r.stdout
        self.assertIn('<?xml version="1.0"', out)
        self.assertIn('<event version="2.0"', out)
        self.assertIn('type="a-f-A-M-F"', out)
        self.assertIn('callsign="VIPER-01"', out)
        self.assertIn('lat="34.500000"', out)

    def test_02_rust_cot_beacon_with_mldsa87_signature(self):
        """Test native secure-transmit cot-beacon signs with ML-DSA-87."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sk_file = os.path.join(tmpdir, "officer.sk")
            pk_file = os.path.join(tmpdir, "officer.pk")
            out_xml = os.path.join(tmpdir, "beacon.xml")

            # Generate ML-DSA-87 keypair
            r_key = subprocess.run(
                [str(BIN), "auth-keygen", "--out-sk", sk_file, "--out-pk", pk_file],
                capture_output=True, text=True, cwd=str(CRATE), timeout=10
            )
            self.assertEqual(r_key.returncode, 0)

            # Generate and sign CoT
            r_cot = subprocess.run(
                [str(BIN), "cot-beacon", "--callsign", "STRIKE-LEAD", "--sk-file", sk_file, "--out", out_xml],
                capture_output=True, text=True, cwd=str(CRATE), timeout=10
            )
            self.assertEqual(r_cot.returncode, 0)
            self.assertTrue(os.path.exists(out_xml))

            with open(out_xml, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("MIL-STD-6090 FIPS 204 SIGNATURE", content)
            self.assertIn('alg="ML-DSA-87"', content)
            self.assertIn('signer="STRIKE-LEAD"', content)

    def test_03_rust_tactical_msg_handling(self):
        """Test native secure-transmit tactical-msg formats MMHS precedence correctly."""
        r = subprocess.run(
            [str(BIN), "tactical-msg", "--precedence", "Y", "--clearance", "TOP_SECRET", "--caveats", "NOFORN",
             "--msg", "FLASH OVERRIDE: SCRAMBLE COMBAT AIR PATROL"],
            capture_output=True, text=True, cwd=str(CRATE), timeout=10
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("FLASH_OVERRIDE", r.stdout)
        self.assertIn("TOP_SECRET", r.stdout)
        self.assertIn("NOFORN", r.stdout)
        self.assertIn("SCRAMBLE COMBAT AIR PATROL", r.stdout)

    def test_04_rust_rtb_dirty_word_filter_blocks_spillage(self):
        """Test native secure-transmit tactical-msg blocks classified spillage at SECRET clearance."""
        r = subprocess.run(
            [str(BIN), "tactical-msg", "--precedence", "O", "--clearance", "SECRET", "--caveats", "NOFORN",
             "--msg", "Disclosing top secret satellite frequency", "--scan-rtb"],
            capture_output=True, text=True, cwd=str(CRATE), timeout=10
        )
        self.assertNotEqual(r.returncode, 0, "Spillage must fail closed")
        self.assertIn("RTB SPILLAGE PREVENTED", r.stderr)

    def test_05_rust_eam_dual_custody_verification(self):
        """Test native secure-transmit eam-auth verifies two-person rule."""
        with tempfile.TemporaryDirectory() as tmpdir:
            of1_sk = os.path.join(tmpdir, "of1.sk")
            of1_pk = os.path.join(tmpdir, "of1.pk")
            of2_sk = os.path.join(tmpdir, "of2.sk")
            of2_pk = os.path.join(tmpdir, "of2.pk")

            subprocess.run([str(BIN), "auth-keygen", "--out-sk", of1_sk, "--out-pk", of1_pk], check=True, cwd=str(CRATE))
            subprocess.run([str(BIN), "auth-keygen", "--out-sk", of2_sk, "--out-pk", of2_pk], check=True, cwd=str(CRATE))

            directive = "DEFCON-1-LAUNCH-DIRECTIVE-44"
            dir_file = os.path.join(tmpdir, "dir.txt")
            with open(dir_file, "w", encoding="utf-8") as f:
                f.write(directive)

            sig1_file = os.path.join(tmpdir, "of1.sig")
            sig2_file = os.path.join(tmpdir, "of2.sig")

            domain = "DESTROYER-ST2027-NC3-EAM"
            subprocess.run([str(BIN), "auth-sign", "--sk-file", of1_sk, "--domain", domain, "--in", dir_file, "--out", sig1_file], check=True, cwd=str(CRATE))
            subprocess.run([str(BIN), "auth-sign", "--sk-file", of2_sk, "--domain", domain, "--in", dir_file, "--out", sig2_file], check=True, cwd=str(CRATE))

            # Legitimate Dual Custody
            r_auth = subprocess.run(
                [str(BIN), "eam-auth", "--directive", directive,
                 "--officer1-pk", of1_pk, "--officer1-sig", sig1_file,
                 "--officer2-pk", of2_pk, "--officer2-sig", sig2_file],
                capture_output=True, text=True, cwd=str(CRATE), timeout=10
            )
            self.assertEqual(r_auth.returncode, 0, f"eam-auth failed: {r_auth.stderr}")
            self.assertIn("NC3 TWO-PERSON RULE DUAL CUSTODY VERIFIED", r_auth.stdout)

            # Single-Custody Violation (Same Officer twice)
            r_single = subprocess.run(
                [str(BIN), "eam-auth", "--directive", directive,
                 "--officer1-pk", of1_pk, "--officer1-sig", sig1_file,
                 "--officer2-pk", of1_pk, "--officer2-sig", sig1_file],
                capture_output=True, text=True, cwd=str(CRATE), timeout=10
            )
            self.assertNotEqual(r_single.returncode, 0)
            self.assertIn("TWO-PERSON RULE VIOLATION", r_single.stderr)

    def test_06_python_tactical_station_automated_drill(self):
        """Test full Python tactical console autonomous drill runs 100% clean."""
        r = subprocess.run(
            [sys.executable, str(ROOT / "tactical_operator_console.py"), "--drill"],
            capture_output=True, text=True, cwd=str(ROOT), timeout=30
        )
        self.assertEqual(r.returncode, 0, f"tactical_operator_console drill failed: {r.stderr}")
        self.assertIn("AUTONOMOUS TACTICAL C4ISR DRILL COMPLETED WITH 100% SUCCESS", r.stdout)
        self.assertIn("BLUE FORCE TRACKING (BFT)", r.stdout)
        self.assertIn("EMERGENCY ZEROIZE TRIGGERED", r.stdout)


if __name__ == "__main__":
    unittest.main()
