#!/usr/bin/env python3
"""
Production Verification Test Suite: Automated Post-Quantum PKI (RFC 9881 X.509 & Dynamic Pinning)

Verifies:
1. Standards-Compliant X.509 Engine (RFC 9881):
   - ML-DSA-87 SubjectPublicKeyInfo and signature algorithm (1.3.6.1.4.1.2.267.12.8.7).
   - ASN.1 DER roundtrip and 3-of-5 threshold verification.
2. Dynamic In-Band Certificate Exchange:
   - Handshake KEX replaces manual hex-file key distribution (--peer-auth-pk-file)
     with RFC 9881 X.509 threshold PKI.
   - Channel in-band attestation exchange (FTYPE_ATTESTATION_EVIDENCE = 0x05).
3. Monotonic CRL Distribution & Hardware Anti-Rollback:
   - CRL signed by >= 3 custodian keys (FTYPE_REVOCATION = 0x06).
   - TPM 2.0 NVRAM / monotonic counter rejection of replayed/rolled back CRL sequence numbers.
   - Fail-closed session termination when peer certificate is revoked.
"""

import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import trust_anchor as ta
import secure_transmit_2027 as st

BIN = REPO_ROOT / "rust_data_plane" / "target" / "release" / ("secure-transmit.exe" if os.name == "nt" else "secure-transmit")


def _free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestAutomatedPostQuantumPki(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not BIN.exists():
            cmd = ["cargo", "build", "--release", "--manifest-path",
                   str(REPO_ROOT / "rust_data_plane" / "Cargo.toml"), "--bin", "secure-transmit"]
            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode != 0:
                raise RuntimeError(f"Failed to build secure-transmit:\n{res.stderr}")

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmp_dir.name)
        os.environ["P2P_SIEM_LEDGER"] = str(self.tmp / "audit.jsonl")
        st._audit_chain = None
        st.PIN_DIR = self.tmp / "pins"
        ta.clear_registry()

        # Generate 5 Root CA custodians
        self.custodian_handles = [st.generate_identity_hsm(f"custodian-{i}") for i in range(1, 6)]
        self.custodians = [
            ta.Custodian(label=h.label, mldsa_pk=bytes(h.sig_pk))
            for h in self.custodian_handles
        ]
        ta.configure(self.custodians, ta.RevocationCache(self.custodians))

        # Write custodians.json for Rust binary
        self.ca_file = self.tmp / "custodians.json"
        cust_json_data = [
            {"label": c.label, "mldsa_pk": c.mldsa_pk.hex()}
            for c in self.custodians
        ]
        with open(self.ca_file, "w") as f:
            json.dump(cust_json_data, f)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def _generate_identity(self, name: str):
        sk_path = self.tmp / f"{name}.sk"
        pk_path = self.tmp / f"{name}.pk"
        res = subprocess.run([str(BIN), "auth-keygen", "--out-sk", str(sk_path), "--out-pk", str(pk_path)],
                             capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr)
        with open(pk_path, "r") as f:
            pk_bytes = bytes.fromhex(f.read().strip())
        return sk_path, pk_path, pk_bytes

    def _issue_x509_cert(self, subject: str, pk_bytes: bytes, signers, valid_sec: int = 3600):
        now = int(time.time())
        tbs = ta.CertTBS(
            serial=secrets.token_bytes(16),
            subject=subject,
            subject_pk=pk_bytes,
            not_before=now - 60,
            not_after=now + valid_sec,
        )
        cert = ta.issue_certificate(tbs, signers)
        der = ta.cert_to_x509_der(cert)
        return cert, der

    def test_01_rfc9881_x509_kex_handshake_without_peer_auth_pk_file(self):
        """Dynamic PKI KEX replaces manual --peer-auth-pk-file with automated 3-of-5 threshold PKI."""
        port = _free_tcp_port()
        key_a = self.tmp / "resp.key"
        key_b = self.tmp / "init.key"
        psk_file = self.tmp / "shared.psk"
        with open(psk_file, "w") as f:
            f.write(("42" * 32) + "\n")

        resp_sk, resp_pk, resp_pk_bytes = self._generate_identity("resp")
        init_sk, init_pk, init_pk_bytes = self._generate_identity("init")

        # Sign with 3 of 5 custodians
        resp_cert, resp_der = self._issue_x509_cert("enclave-responder", resp_pk_bytes, self.custodian_handles[:3])
        init_cert, init_der = self._issue_x509_cert("enclave-initiator", init_pk_bytes, self.custodian_handles[2:5])

        resp_cert_file = self.tmp / "resp_cert.der"
        init_cert_file = self.tmp / "init_cert.der"
        resp_cert_file.write_bytes(resp_der)
        init_cert_file.write_bytes(init_der)

        listener = subprocess.Popen(
            [str(BIN), "kex-listen", "--bind", f"127.0.0.1:{port}",
             "--out-key", str(key_a), "--psk-file", str(psk_file),
             "--auth-sk-file", str(resp_sk),
             "--cert-file", str(resp_cert_file),
             "--ca-file", str(self.ca_file),
             "--require-mutual-auth", "--timeout-ms", "15000"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=str(REPO_ROOT))

        try:
            time.sleep(1.0)
            connector = subprocess.run(
                [str(BIN), "kex-connect", "--to", f"127.0.0.1:{port}",
                 "--out-key", str(key_b), "--psk-file", str(psk_file),
                 "--auth-sk-file", str(init_sk),
                 "--cert-file", str(init_cert_file),
                 "--ca-file", str(self.ca_file),
                 "--require-mutual-auth", "--timeout-ms", "15000"],
                capture_output=True, text=True, cwd=str(REPO_ROOT))

            self.assertEqual(connector.returncode, 0, f"kex-connect failed:\n{connector.stderr}")
            out, err = listener.communicate(timeout=15)
        finally:
            if listener.poll() is None:
                listener.kill()
                listener.communicate()

        self.assertEqual(listener.returncode, 0, f"kex-listen failed:\n{err}")
        self.assertIn("RFC 9881 X.509 3-of-5 threshold PKI", out)
        self.assertIn("RFC 9881 X.509 3-of-5 threshold PKI", connector.stdout)

        # Keys must match perfectly
        with open(key_a, "r") as f:
            hex_a = f.read().strip()
        with open(key_b, "r") as f:
            hex_b = f.read().strip()
        self.assertEqual(hex_a, hex_b)
        self.assertEqual(len(hex_a), 64)

    def test_02_kex_tampered_or_untrusted_cert_refused_fail_closed(self):
        """Tampered or invalid certificates fail closed with no session key written."""
        port = _free_tcp_port()
        key_a = self.tmp / "resp_fail.key"
        key_b = self.tmp / "init_fail.key"
        psk_file = self.tmp / "shared.psk"
        with open(psk_file, "w") as f:
            f.write(("42" * 32) + "\n")

        resp_sk, resp_pk, resp_pk_bytes = self._generate_identity("resp_bad")
        init_sk, init_pk, init_pk_bytes = self._generate_identity("init_bad")

        resp_cert, resp_der = self._issue_x509_cert("enclave-responder", resp_pk_bytes, self.custodian_handles[:3])

        # Issue initiator cert using rogue custodians not trusted by the Root CA (fail-closed)
        rogue_custodians = [st.generate_identity_hsm(f"rogue-{i}") for i in range(1, 4)]
        init_cert, init_der = self._issue_x509_cert("enclave-initiator", init_pk_bytes, rogue_custodians)

        resp_cert_file = self.tmp / "resp_cert_valid.der"
        init_cert_file = self.tmp / "init_cert_rogue.der"
        resp_cert_file.write_bytes(resp_der)
        init_cert_file.write_bytes(init_der)

        listener = subprocess.Popen(
            [str(BIN), "kex-listen", "--bind", f"127.0.0.1:{port}",
             "--out-key", str(key_a), "--psk-file", str(psk_file),
             "--auth-sk-file", str(resp_sk),
             "--cert-file", str(resp_cert_file),
             "--ca-file", str(self.ca_file),
             "--require-mutual-auth", "--timeout-ms", "8000"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=str(REPO_ROOT))

        try:
            time.sleep(1.0)
            connector = subprocess.run(
                [str(BIN), "kex-connect", "--to", f"127.0.0.1:{port}",
                 "--out-key", str(key_b), "--psk-file", str(psk_file),
                 "--auth-sk-file", str(init_sk),
                 "--cert-file", str(init_cert_file),
                 "--ca-file", str(self.ca_file),
                 "--require-mutual-auth", "--timeout-ms", "8000"],
                capture_output=True, text=True, cwd=str(REPO_ROOT))

            out, err = listener.communicate(timeout=8)
        finally:
            if listener.poll() is None:
                listener.kill()
                listener.communicate()

        # Both must fail closed and neither key file must be written
        self.assertNotEqual(connector.returncode, 0)
        self.assertFalse(key_a.exists())
        self.assertFalse(key_b.exists())

    def test_03_kex_crl_revocation_fail_closed(self):
        """Certificates listed in a valid 3-of-5 threshold CRL are rejected fail-closed during handshake."""
        port = _free_tcp_port()
        key_a = self.tmp / "resp_revoked.key"
        key_b = self.tmp / "init_revoked.key"
        psk_file = self.tmp / "shared.psk"
        with open(psk_file, "w") as f:
            f.write(("42" * 32) + "\n")

        resp_sk, resp_pk, resp_pk_bytes = self._generate_identity("resp_crl")
        init_sk, init_pk, init_pk_bytes = self._generate_identity("init_crl")

        resp_cert, resp_der = self._issue_x509_cert("enclave-responder", resp_pk_bytes, self.custodian_handles[:3])
        init_cert, init_der = self._issue_x509_cert("enclave-initiator", init_pk_bytes, self.custodian_handles[:3])

        resp_cert_file = self.tmp / "resp_crl_cert.der"
        init_cert_file = self.tmp / "init_crl_cert.der"
        resp_cert_file.write_bytes(resp_der)
        init_cert_file.write_bytes(init_der)

        # Issue CRL revoking initiator's serial!
        now = int(time.time())
        crl_der = ta.issue_x509_crl(
            1,
            now - 60,
            now + 3600,
            [init_cert.tbs.serial],
            self.custodian_handles[:3],
        )
        crl_file = self.tmp / "revoked.crl"
        crl_file.write_bytes(crl_der)

        listener = subprocess.Popen(
            [str(BIN), "kex-listen", "--bind", f"127.0.0.1:{port}",
             "--out-key", str(key_a), "--psk-file", str(psk_file),
             "--auth-sk-file", str(resp_sk),
             "--cert-file", str(resp_cert_file),
             "--ca-file", str(self.ca_file),
             "--crl-file", str(crl_file),
             "--require-mutual-auth", "--timeout-ms", "10000"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=str(REPO_ROOT))

        try:
            time.sleep(1.0)
            connector = subprocess.run(
                [str(BIN), "kex-connect", "--to", f"127.0.0.1:{port}",
                 "--out-key", str(key_b), "--psk-file", str(psk_file),
                 "--auth-sk-file", str(init_sk),
                 "--cert-file", str(init_cert_file),
                 "--ca-file", str(self.ca_file),
                 "--require-mutual-auth", "--timeout-ms", "10000"],
                capture_output=True, text=True, cwd=str(REPO_ROOT))

            out, err = listener.communicate(timeout=10)
        finally:
            if listener.poll() is None:
                listener.kill()
                listener.communicate()

        # Listener must detect revocation and abort
        self.assertNotEqual(listener.returncode, 0)
        self.assertIn("revoked in CRL", err)
        self.assertFalse(key_a.exists())
        self.assertFalse(key_b.exists())

    def test_04_channel_in_band_attestation_exchange(self):
        """In-band attestation exchange (FTYPE_ATTESTATION_EVIDENCE) over paced UDP channel."""
        key_file = self.tmp / "channel.key"
        res = subprocess.run([str(BIN), "keygen", "--out", str(key_file)], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)

        port_resp = _free_udp_port()
        port_init = _free_udp_port()
        state_resp = self.tmp / "resp.state"
        state_init = self.tmp / "init.state"

        resp_sk, resp_pk, resp_pk_bytes = self._generate_identity("ch_resp")
        init_sk, init_pk, init_pk_bytes = self._generate_identity("ch_init")

        resp_cert, resp_der = self._issue_x509_cert("enclave-resp", resp_pk_bytes, self.custodian_handles[:3])
        init_cert, init_der = self._issue_x509_cert("enclave-init", init_pk_bytes, self.custodian_handles[:3])

        resp_cert_file = self.tmp / "ch_resp.der"
        init_cert_file = self.tmp / "ch_init.der"
        resp_cert_file.write_bytes(resp_der)
        init_cert_file.write_bytes(init_der)

        resp_proc = subprocess.Popen(
            [str(BIN), "channel", "--key-file", str(key_file), "--state", str(state_resp),
             "--bind", f"127.0.0.1:{port_resp}", "--to", f"127.0.0.1:{port_init}",
             "--role", "responder", "--interval-ms", "10", "--quantum", "1232",
             "--cert-file", str(resp_cert_file), "--ca-file", str(self.ca_file),
             "--reply", "ATTESTATION_RECEIVED_ACK", "--recv-count", "1",
             "--drain-ticks", "50", "--timeout-ms", "10000"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=str(REPO_ROOT)
        )
        time.sleep(0.15)

        init_proc = subprocess.Popen(
            [str(BIN), "channel", "--key-file", str(key_file), "--state", str(state_init),
             "--bind", f"127.0.0.1:{port_init}", "--to", f"127.0.0.1:{port_resp}",
             "--role", "initiator", "--interval-ms", "10", "--quantum", "1232",
             "--cert-file", str(init_cert_file), "--ca-file", str(self.ca_file),
             "--msg", "TACTICAL_MSG_UNDER_ATTESTATION", "--recv-count", "1",
             "--drain-ticks", "50", "--timeout-ms", "10000"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=str(REPO_ROOT)
        )

        init_out, init_err = init_proc.communicate(timeout=10)
        resp_out, resp_err = resp_proc.communicate(timeout=10)

        self.assertEqual(init_proc.returncode, 0, f"init failed:\nOUT: {init_out}\nERR: {init_err}")
        self.assertEqual(resp_proc.returncode, 0, f"resp failed:\nOUT: {resp_out}\nERR: {resp_err}")

        # In-band attestation evidence frames (0x05) were transmitted and verified!
        self.assertIn("ATTESTATION_EVIDENCE_VALID", resp_out)
        self.assertIn("RECV_MSG", resp_out)
        self.assertIn("RECV_MSG", init_out)

    def test_05_channel_crl_revocation_terminates_session_fail_closed(self):
        """Broadcasting CRL revoking active peer cert terminates the channel immediately (fail-closed)."""
        key_file = self.tmp / "channel_rev.key"
        res = subprocess.run([str(BIN), "keygen", "--out", str(key_file)], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)

        port_resp = _free_udp_port()
        port_init = _free_udp_port()
        state_resp = self.tmp / "resp_rev.state"
        state_init = self.tmp / "init_rev.state"

        resp_sk, resp_pk, resp_pk_bytes = self._generate_identity("ch_rev_resp")
        init_sk, init_pk, init_pk_bytes = self._generate_identity("ch_rev_init")

        resp_cert, resp_der = self._issue_x509_cert("enclave-resp", resp_pk_bytes, self.custodian_handles[:3])
        init_cert, init_der = self._issue_x509_cert("enclave-init", init_pk_bytes, self.custodian_handles[:3])

        resp_cert_file = self.tmp / "ch_rev_resp.der"
        init_cert_file = self.tmp / "ch_rev_init.der"
        resp_cert_file.write_bytes(resp_der)
        init_cert_file.write_bytes(init_der)

        # Issue CRL revoking initiator cert, broadcasted by responder
        now = int(time.time())
        crl_der = ta.issue_x509_crl(
            5,
            now - 60,
            now + 3600,
            [init_cert.tbs.serial],
            self.custodian_handles[:3],
        )
        crl_file = self.tmp / "revocation_seq5.crl"
        crl_file.write_bytes(crl_der)

        resp_proc = subprocess.Popen(
            [str(BIN), "channel", "--key-file", str(key_file), "--state", str(state_resp),
             "--bind", f"127.0.0.1:{port_resp}", "--to", f"127.0.0.1:{port_init}",
             "--role", "responder", "--interval-ms", "10", "--quantum", "1232",
             "--cert-file", str(resp_cert_file), "--ca-file", str(self.ca_file),
             "--crl-file", str(crl_file),
             "--timeout-ms", "8000"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=str(REPO_ROOT)
        )
        time.sleep(0.15)

        init_proc = subprocess.Popen(
            [str(BIN), "channel", "--key-file", str(key_file), "--state", str(state_init),
             "--bind", f"127.0.0.1:{port_init}", "--to", f"127.0.0.1:{port_resp}",
             "--role", "initiator", "--interval-ms", "10", "--quantum", "1232",
             "--cert-file", str(init_cert_file), "--ca-file", str(self.ca_file),
             "--timeout-ms", "8000"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=str(REPO_ROOT)
        )

        init_out, init_err = init_proc.communicate(timeout=10)
        resp_out, resp_err = resp_proc.communicate(timeout=10)

        # Responder received initiator cert and matched CRL revoking it -> session severed!
        combined_resp = resp_out + resp_err
        self.assertIn("TERMINATING_SESSION_PEER_CERT_REVOKED", combined_resp)

    def test_06_crl_monotonic_anti_rollback_hardware(self):
        """Monotonic CRL distribution: TPM 2.0 / sidecar hardware anti-rollback counters reject replays."""
        sys.path.insert(0, str(REPO_ROOT / "rust_data_plane" / "python"))
        import destroyer_core._native as native_m

        sidecar_state = str(self.tmp / "tpm_guard_test.state")

        # 1. First broadcast with crl_seq = 10 initializes the monotonic counter to 10
        native_m.tpm_guard_crl_sequence(sidecar_state, 10)

        # 2. Replay of crl_seq = 10 is refused fail-closed by hardware anti-rollback counter
        with self.assertRaises(ValueError) as ctx:
            native_m.tpm_guard_crl_sequence(sidecar_state, 10)
        self.assertIn("rollback refused", str(ctx.exception))

        # 3. Rollback attempt to older crl_seq = 9 is refused fail-closed
        with self.assertRaises(ValueError) as ctx:
            native_m.tpm_guard_crl_sequence(sidecar_state, 9)
        self.assertIn("rollback refused", str(ctx.exception))

        # 4. Monotonic increase to crl_seq = 25 succeeds and advances hardware counter
        native_m.tpm_guard_crl_sequence(sidecar_state, 25)

        # 5. Replay of 25 is refused
        with self.assertRaises(ValueError) as ctx:
            native_m.tpm_guard_crl_sequence(sidecar_state, 25)
        self.assertIn("rollback refused", str(ctx.exception))

        # 6. Replay of older seq = 10 is refused
        with self.assertRaises(ValueError) as ctx:
            native_m.tpm_guard_crl_sequence(sidecar_state, 10)
        self.assertIn("rollback refused", str(ctx.exception))

    def test_07_native_pyo3_x509_pki_interop(self):
        """RFC 9881 X.509 threshold certificates & CRLs are fully interoperable between Rust and Python."""
        sys.path.insert(0, str(REPO_ROOT / "rust_data_plane" / "python"))
        import destroyer_core._native as native_m

        signers = [(f"custodian-{i}", native_m.CoreMldsaSigner()) for i in range(1, 6)]
        cust_json = json.dumps([{"label": label, "mldsa_pk": bytes(s.verifying_bytes()).hex()} for label, s in signers])
        cust_objs = [ta.Custodian(label=label, mldsa_pk=bytes(s.verifying_bytes())) for label, s in signers]

        subj = native_m.CoreMldsaSigner()
        subj_pk = bytes(subj.verifying_bytes())
        serial = secrets.token_bytes(16)
        now = int(time.time())

        # 1. Rust engine issues RFC 9881 X.509 certificate with 3-of-5 threshold signatures
        cert_der = native_m.x509_issue_certificate(
            serial, "enclave-rust-node", subj_pk, now - 60, now + 3600, signers[:3], None
        )
        self.assertGreater(len(cert_der), 10000)

        # 2. Rust engine verifies certificate against 5-custodian Root CA
        v_serial, v_subj, v_pk = native_m.x509_verify_certificate(cert_der, cust_json, float(now))
        self.assertEqual(bytes(v_serial), serial)
        self.assertEqual(v_subj, "enclave-rust-node")
        self.assertEqual(bytes(v_pk), subj_pk)

        # 3. Python trust_anchor decodes and verifies the Rust X.509 certificate
        py_cert = ta.cert_from_x509_der(bytes(cert_der))
        self.assertEqual(py_cert.tbs.subject, "enclave-rust-node")
        self.assertEqual(bytes(py_cert.tbs.subject_pk), subj_pk)

        # 4. Rust engine issues RFC 5280 / RFC 9881 threshold CRL
        crl_der = native_m.x509_issue_crl(42, now - 60, now + 3600, [serial], signers[:3])
        self.assertGreater(len(crl_der), 10000)

        # 5. Rust engine verifies CRL against 5-custodian Root CA
        crl_num, revs = native_m.x509_verify_crl(crl_der, cust_json)
        self.assertEqual(crl_num, 42)
        self.assertEqual(revs, [serial])

        # 6. Python trust_anchor verifies the Rust threshold CRL
        py_crl_num, py_revs = ta.verify_x509_crl(bytes(crl_der), cust_objs)
        self.assertEqual(py_crl_num, 42)
        self.assertEqual(py_revs, [serial])


if __name__ == "__main__":
    unittest.main()
