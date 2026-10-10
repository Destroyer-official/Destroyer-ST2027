"""Standalone Rust binary (Task-1): secure-transmit builds and transfers.

Proves the zero-Python data-plane executor end to end:
  1. cargo build --offline --bin secure-transmit succeeds (frozen Cargo.lock).
  2. `selftest` exits 0 (AEAD roundtrip, tamper reject, replay, MTU).
  3. Live loopback: recv <- send opens exactly the sealed payload.
  4. Wrong frame key: receiver admits the datagram but opens nothing
     (fail-closed timeout, exit 3) — key never negotiates in the binary.
  5. Nonce discipline: seq NEVER comes from `--seq` (refused); repeated
     `send` invocations advance a locked `--state` file monotonically
     (NIST SP 800-38D uniqueness). Key NEVER appears in argv (`--key`
     refused); provision via `--key-file` (0600) or `--key-stdin`.

Scope boundary: Production security core (Noise-XXhfs, ML-KEM-1024,
ML-DSA-87, SPQR ratchet, threshold PKI, AEAD framing) is natively
implemented in pure Rust with strict fail-closed discipline. The Python tree
is maintained intact as the audited reference and backup path.
"""
import os
import re
import shutil
import socket
import subprocess
import unittest

from pathlib import Path

ROOT = Path(__file__).resolve().parent if (Path(__file__).resolve().parent / "destroyer.py").exists() else Path(__file__).resolve().parent.parent
CRATE = ROOT / "rust_data_plane"
BIN = (CRATE / "target" / "debug" /
       ("secure-transmit.exe" if os.name == "nt" else "secure-transmit"))


def _free_udp_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _free_tcp_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _run(*argv, timeout=60, env=None):
    return subprocess.run([str(BIN), *argv], capture_output=True, text=True,
                          timeout=timeout, cwd=str(CRATE), env=env)


def _new_key_file(tmpdir):
    """Run keygen, write hex to a 0600 key file. Returns (hex, keyfile)."""
    import pathlib
    r = _run("keygen")
    assert r.returncode == 0, r.stderr[-500:]
    hexkey = r.stdout.strip()
    assert len(hexkey) == 64
    int(hexkey, 16)
    kf = os.path.join(tmpdir, "frame.key")
    with open(kf, "w") as f:
        f.write(hexkey + "\n")
    try:
        os.chmod(kf, 0o600)
    except OSError:
        pass
    return hexkey, kf


def _seq_of(sent):
    m = re.search(r"sent seq=(\d+)", sent.stderr)
    assert m, sent.stderr[-500:]
    return int(m.group(1))


class TestRustStandaloneBinary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if shutil.which("cargo") is None:
            raise unittest.SkipTest("cargo toolchain absent")
        if os.name != "nt" and not BIN.exists():
            pass  # build step below (re)builds it regardless
        built = subprocess.run(
            ["cargo", "build", "--offline", "--bin", "secure-transmit"],
            capture_output=True, text=True, timeout=600, cwd=str(CRATE))
        assert built.returncode == 0, f"cargo build failed:\n{built.stderr[-2000:]}"
        assert BIN.exists(), "binary missing after successful build"

    def test_01_selftest_green(self):
        r = _run("selftest")
        self.assertEqual(r.returncode, 0, r.stderr[-1000:])
        self.assertIn("replay ok", r.stderr)

    def test_02_keygen_shape(self):
        r = _run("keygen")
        self.assertEqual(r.returncode, 0, r.stderr[-500:])
        key = r.stdout.strip()
        self.assertEqual(len(key), 64)
        int(key, 16)  # raises unless hex

    def test_03_loopback_transfer_opens_exact_payload(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            _hex, kf = _new_key_file(tmp)
            port = _free_udp_port()
            recv_state = os.path.join(tmp, "recv.state")
            send_state = os.path.join(tmp, "send.state")
            recv = subprocess.Popen(
                [str(BIN), "recv", "--key-file", kf, "--state", recv_state,
                 "--bind", f"127.0.0.1:{port}",
                 "--count", "1", "--timeout-ms", "15000"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                cwd=str(CRATE))
            try:
                import time
                time.sleep(1.5)  # let recv bind first (fail-closed otherwise)
                sent = _run("send", "--key-file", kf, "--state", send_state,
                            "--to", f"127.0.0.1:{port}",
                            "--msg", "BINARY-PROOF-7741")
                self.assertEqual(sent.returncode, 0, sent.stderr[-500:])
                seq = _seq_of(sent)
                out, err = recv.communicate(timeout=30)
            finally:
                if recv.poll() is None:
                    recv.kill()
                    recv.communicate()
            self.assertEqual(recv.returncode, 0, err[-1000:])
            self.assertIn(f"seq={seq} BINARY-PROOF-7741", out)

    def test_04_wrong_key_opens_nothing(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            _hex, kf = _new_key_file(tmp)
            wrong = os.path.join(tmp, "wrong.key")
            with open(wrong, "w") as f:
                f.write("ab" * 32 + "\n")
            port = _free_udp_port()
            recv_state = os.path.join(tmp, "recv.state")
            send_state = os.path.join(tmp, "send.state")
            recv = subprocess.Popen(
                [str(BIN), "recv", "--key-file", wrong, "--state", recv_state,
                 "--bind", f"127.0.0.1:{port}",
                 "--count", "1", "--timeout-ms", "6000"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                cwd=str(CRATE))
            try:
                import time
                time.sleep(1.5)
                sent = _run("send", "--key-file", kf, "--state", send_state,
                            "--to", f"127.0.0.1:{port}",
                            "--msg", "MUST-NOT-OPEN")
                self.assertEqual(sent.returncode, 0, sent.stderr[-500:])
                out, err = recv.communicate(timeout=30)
            finally:
                if recv.poll() is None:
                    recv.kill()
                    recv.communicate()
            self.assertEqual(recv.returncode, 3, err[-1000:])  # timeout, opened 0/1
            self.assertNotIn("MUST-NOT-OPEN", out)

    def test_05_send_file_recv_file_roundtrip(self):
        import hashlib
        import tempfile
        payload = bytes(range(256)) * 14  # 3584B -> 3 chunks at 1205B
        self.assertEqual(len(payload), 3584)
        with tempfile.TemporaryDirectory() as tmp:
            _hex, kf = _new_key_file(tmp)
            port = _free_udp_port()
            src = os.path.join(tmp, "in.bin")
            dst = os.path.join(tmp, "out.bin")
            with open(src, "wb") as f:
                f.write(payload)
            recv_state = os.path.join(tmp, "recv.state")
            send_state = os.path.join(tmp, "send.state")
            recv = subprocess.Popen(
                [str(BIN), "recv-file", "--key-file", kf, "--state", recv_state,
                 "--bind", f"127.0.0.1:{port}", "--out", dst,
                 "--count", "3", "--timeout-ms", "15000"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                cwd=str(CRATE))
            try:
                import time
                time.sleep(1.5)
                sent = _run("send-file", "--key-file", kf, "--state", send_state,
                            "--to", f"127.0.0.1:{port}", "--file", src)
                self.assertEqual(sent.returncode, 0, sent.stderr[-500:])
                out, err = recv.communicate(timeout=40)
            finally:
                if recv.poll() is None:
                    recv.kill()
                    recv.communicate()
            self.assertEqual(recv.returncode, 0, err[-1000:])
            want = hashlib.sha256(payload).hexdigest()
            self.assertIn(f"digest={want}", out)
            with open(dst, "rb") as f:
                self.assertEqual(f.read(), payload)

    def test_06_recv_file_wrong_key_writes_nothing(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            _hex, kf = _new_key_file(tmp)
            wrong = os.path.join(tmp, "wrong.key")
            with open(wrong, "w") as f:
                f.write("ab" * 32 + "\n")
            port = _free_udp_port()
            src = os.path.join(tmp, "in.bin")
            dst = os.path.join(tmp, "out.bin")
            with open(src, "wb") as f:
                f.write(b"X" * 64)
            recv_state = os.path.join(tmp, "recv.state")
            send_state = os.path.join(tmp, "send.state")
            recv = subprocess.Popen(
                [str(BIN), "recv-file", "--key-file", wrong, "--state", recv_state,
                 "--bind", f"127.0.0.1:{port}", "--out", dst,
                 "--count", "1", "--timeout-ms", "6000"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                cwd=str(CRATE))
            try:
                import time
                time.sleep(1.5)
                sent = _run("send-file", "--key-file", kf, "--state", send_state,
                            "--to", f"127.0.0.1:{port}", "--file", src)
                self.assertEqual(sent.returncode, 0, sent.stderr[-500:])
                out, err = recv.communicate(timeout=30)
            finally:
                if recv.poll() is None:
                    recv.kill()
                    recv.communicate()
            self.assertEqual(recv.returncode, 4, err[-1000:])
            self.assertFalse(os.path.exists(dst))  # nothing written

    def test_07_recv_file_short_count_refuses_partial(self):
        # Sender emits 1 chunk; receiver demands 2 -> timeout, exit 4, no file.
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            _hex, kf = _new_key_file(tmp)
            port = _free_udp_port()
            src = os.path.join(tmp, "in.bin")
            dst = os.path.join(tmp, "out.bin")
            with open(src, "wb") as f:
                f.write(b"Y" * 64)
            recv_state = os.path.join(tmp, "recv.state")
            send_state = os.path.join(tmp, "send.state")
            recv = subprocess.Popen(
                [str(BIN), "recv-file", "--key-file", kf, "--state", recv_state,
                 "--bind", f"127.0.0.1:{port}", "--out", dst,
                 "--count", "2", "--timeout-ms", "6000"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                cwd=str(CRATE))
            try:
                import time
                time.sleep(1.5)
                _run("send-file", "--key-file", kf, "--state", send_state,
                     "--to", f"127.0.0.1:{port}", "--file", src)
                out, err = recv.communicate(timeout=30)
            finally:
                if recv.poll() is None:
                    recv.kill()
                    recv.communicate()
            self.assertEqual(recv.returncode, 4, err[-1000:])
            self.assertFalse(os.path.exists(dst))

    def test_08_seq_and_key_argv_refused(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            _hex, kf = _new_key_file(tmp)
            st = os.path.join(tmp, "s.bin")
            port = _free_udp_port()
            r1 = _run("send", "--key", "ab" * 32, "--state", st,
                      "--to", f"127.0.0.1:{port}", "--msg", "x")
            self.assertNotEqual(r1.returncode, 0)
            self.assertIn("--key-file", r1.stderr)
            r2 = _run("send", "--key-file", kf, "--state", st,
                      "--to", f"127.0.0.1:{port}", "--msg", "x", "--seq", "1")
            self.assertNotEqual(r2.returncode, 0)
            self.assertIn("--state", r2.stderr)
            r3 = _run("send", "--key-file", kf,
                      "--to", f"127.0.0.1:{port}", "--msg", "x")
            self.assertNotEqual(r3.returncode, 0)
            self.assertIn("--state", r3.stderr)

    def test_repeated_invocations_advance_monotonic_state(self):
        """Verification gate Task 1.3: two `send` runs advance N -> N+1."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            _hex, kf = _new_key_file(tmp)
            st = os.path.join(tmp, "mono.state")
            port = _free_udp_port()
            s1 = _run("send", "--key-file", kf, "--state", st,
                      "--to", f"127.0.0.1:{port}", "--msg", "first")
            self.assertEqual(s1.returncode, 0, s1.stderr[-500:])
            s2 = _run("send", "--key-file", kf, "--state", st,
                      "--to", f"127.0.0.1:{port}", "--msg", "second")
            self.assertEqual(s2.returncode, 0, s2.stderr[-500:])
            n1, n2 = _seq_of(s1), _seq_of(s2)
            self.assertEqual(n2, n1 + 1, f"non-monotonic: {n1} -> {n2}")
            # No execution path allows duplicates: third run advances again.
            s3 = _run("send", "--key-file", kf, "--state", st,
                      "--to", f"127.0.0.1:{port}", "--msg", "third")
            self.assertEqual(_seq_of(s3), n2 + 1)
            # State file is exactly the 48-byte locked record.
            self.assertEqual(os.path.getsize(st), 48)
            # Mismatched key refused against the same state (key binding).
            wrong = os.path.join(tmp, "wrong.key")
            with open(wrong, "w") as f:
                f.write("cd" * 32 + "\n")
            r = _run("send", "--key-file", wrong, "--state", st,
                     "--to", f"127.0.0.1:{port}", "--msg", "evil")
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("different key", r.stderr)

    def test_diode_simplex_fec_transfer(self):
        """Phase 2: Unidirectional Simplex Optical Data Diode transfer with Cauchy-RS FEC."""
        import tempfile, time, hashlib
        with tempfile.TemporaryDirectory() as tmp:
            _hex, kf = _new_key_file(tmp)
            port = _free_udp_port()
            send_state = os.path.join(tmp, "diode_send.state")
            recv_state = os.path.join(tmp, "diode_recv.state")

            src = os.path.join(tmp, "secret_payload.dat")
            dst = os.path.join(tmp, "recovered_payload.dat")

            # Create a 5,000 byte test payload (spans 5 data chunks + parity)
            payload = b"TOP-SECRET-SOVEREIGN-ORDER-2027:" + (b"A" * 4900) + b":TERMINATE"
            with open(src, "wb") as f:
                f.write(payload)
            expected_sha384 = hashlib.sha384(payload).hexdigest()

            recv = subprocess.Popen(
                [str(BIN), "diode-recv", "--key-file", kf, "--state", recv_state,
                 "--bind", f"127.0.0.1:{port}", "--out", dst, "--timeout-ms", "15000"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                cwd=str(CRATE))
            try:
                time.sleep(1.5)  # wait for bind
                sent = _run("diode-send", "--key-file", kf, "--state", send_state,
                            "--to", f"127.0.0.1:{port}", "--file", src,
                            "--parity-ratio", "0.3")
                self.assertEqual(sent.returncode, 0, sent.stderr[-500:])
                self.assertIn("diode-sent", sent.stdout)
                out, err = recv.communicate(timeout=20)
            finally:
                if recv.poll() is None:
                    recv.kill()
                    recv.communicate()

            self.assertEqual(recv.returncode, 0, f"diode-recv failed:\n{err[-1000:]}")
            self.assertIn("diode-recv SUCCESS", out)
            self.assertIn(expected_sha384, out)

            # Verify file on disk matches 100%
            self.assertTrue(os.path.exists(dst))
            with open(dst, "rb") as f:
                recovered = f.read()
            self.assertEqual(recovered, payload)

    def test_stream_chaff_constant_pacing(self):
        """Phase 3: Constant-rate traffic invariance and synthetic chaff emission."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            _hex, kf = _new_key_file(tmp)
            port = _free_udp_port()
            send_state = os.path.join(tmp, "chaff_send.state")

            res = _run("stream-chaff", "--key-file", kf, "--state", send_state,
                       "--to", f"127.0.0.1:{port}", "--interval-ms", "10",
                       "--count", "5", "--quantum", "1232")
            self.assertEqual(res.returncode, 0, res.stderr[-500:])
            self.assertIn("stream-chaff: emitted 5 frames wire=1232B interval=10ms", res.stdout)
            self.assertEqual(os.path.getsize(send_state), 48)

    def test_kex_listen_connect_hybrid_establishment(self):
        """Phase 1: Pure native post-quantum hybrid key exchange (ML-KEM-1024 + X25519)."""
        import tempfile, time
        with tempfile.TemporaryDirectory() as tmp:
            port = _free_tcp_port()
            key_a = os.path.join(tmp, "responder.key")
            key_b = os.path.join(tmp, "initiator.key")
            lab_env = dict(os.environ, P2P_LAB_MODE="1")

            listener = subprocess.Popen(
                [str(BIN), "kex-listen", "--bind", f"127.0.0.1:{port}", "--out-key", key_a, "--timeout-ms", "15000"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=str(CRATE), env=lab_env)
            try:
                time.sleep(1.0)
                connector = _run("kex-connect", "--to", f"127.0.0.1:{port}", "--out-key", key_b, "--timeout-ms", "15000", env=lab_env)
                self.assertEqual(connector.returncode, 0, connector.stderr[-500:])
                out, err = listener.communicate(timeout=15)
            finally:
                if listener.poll() is None:
                    listener.kill()
                    listener.communicate()

            self.assertEqual(listener.returncode, 0, f"kex-listen failed:\n{err[-500:]}")
            self.assertTrue(os.path.exists(key_a))
            self.assertTrue(os.path.exists(key_b))
            self.assertIn("SAS:", out)
            self.assertIn("SAS:", connector.stdout)

            with open(key_a, "r") as f:
                hex_a = f.read().strip()
            with open(key_b, "r") as f:
                hex_b = f.read().strip()

            self.assertEqual(len(hex_a), 64)
            self.assertEqual(len(hex_b), 64)
            self.assertEqual(hex_a, hex_b, "Negotiated keys did not match!")

            # Verify the negotiated key functions seamlessly for authenticated transmission
            udp_port = _free_udp_port()
            st_send = os.path.join(tmp, "kex_send.state")
            st_recv = os.path.join(tmp, "kex_recv.state")

            recv = subprocess.Popen(
                [str(BIN), "recv", "--key-file", key_a, "--state", st_recv, "--bind", f"127.0.0.1:{udp_port}", "--count", "1"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=str(CRATE))
            try:
                time.sleep(1.0)
                sent = _run("send", "--key-file", key_b, "--state", st_send, "--to", f"127.0.0.1:{udp_port}", "--msg", "KEX-VERIFIED")
                self.assertEqual(sent.returncode, 0, sent.stderr[-500:])
                out_recv, err_recv = recv.communicate(timeout=10)
            finally:
                if recv.poll() is None:
                    recv.kill()
                    recv.communicate()

            self.assertEqual(recv.returncode, 0, err_recv[-500:])
            self.assertIn("KEX-VERIFIED", out_recv)

    def test_kex_with_psk_authentication(self):
        """PSK-authenticated quantum-resistant key agreement (RFC 8773 / CNSA 2.0)."""
        import tempfile, time
        with tempfile.TemporaryDirectory() as tmp:
            port = _free_tcp_port()
            key_a = os.path.join(tmp, "responder_psk.key")
            key_b = os.path.join(tmp, "initiator_psk.key")
            psk_hex = "42" * 32
            psk_file = os.path.join(tmp, "shared.psk")
            with open(psk_file, "w") as f:
                f.write(psk_hex + "\n")
            try:
                os.chmod(psk_file, 0o600)
            except OSError:
                pass

            listener = subprocess.Popen(
                [str(BIN), "kex-listen", "--bind", f"127.0.0.1:{port}", "--out-key", key_a,
                 "--psk-file", psk_file, "--timeout-ms", "15000"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=str(CRATE))
            try:
                time.sleep(1.0)
                connector = _run("kex-connect", "--to", f"127.0.0.1:{port}", "--out-key", key_b,
                                 "--psk-file", psk_file, "--timeout-ms", "15000")
                self.assertEqual(connector.returncode, 0, connector.stderr[-500:])
                out, err = listener.communicate(timeout=15)
            finally:
                if listener.poll() is None:
                    listener.kill()
                    listener.communicate()

            self.assertEqual(listener.returncode, 0, f"kex-listen with PSK failed:\n{err[-500:]}")
            with open(key_a, "r") as f:
                hex_a = f.read().strip()
            with open(key_b, "r") as f:
                hex_b = f.read().strip()
            self.assertEqual(hex_a, hex_b)

    def test_kex_mitm_mismatched_psk_rejected(self):
        """Active attacker with wrong PSK cannot complete key confirmation."""
        import tempfile, time
        with tempfile.TemporaryDirectory() as tmp:
            port = _free_tcp_port()
            key_a = os.path.join(tmp, "resp_fail.key")
            key_b = os.path.join(tmp, "init_fail.key")
            psk_a = os.path.join(tmp, "resp.psk")
            with open(psk_a, "w") as f:
                f.write(("11" * 32) + "\n")
            psk_b = os.path.join(tmp, "init.psk")
            with open(psk_b, "w") as f:
                f.write(("22" * 32) + "\n")
            try:
                os.chmod(psk_a, 0o600)
                os.chmod(psk_b, 0o600)
            except OSError:
                pass

            listener = subprocess.Popen(
                [str(BIN), "kex-listen", "--bind", f"127.0.0.1:{port}", "--out-key", key_a,
                 "--psk-file", psk_a, "--timeout-ms", "10000"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=str(CRATE))
            try:
                time.sleep(1.0)
                connector = _run("kex-connect", "--to", f"127.0.0.1:{port}", "--out-key", key_b,
                                 "--psk-file", psk_b, "--timeout-ms", "10000")
                self.assertNotEqual(connector.returncode, 0)
                self.assertIn("mismatch", connector.stderr)
                out, err = listener.communicate(timeout=10)
            finally:
                if listener.poll() is None:
                    listener.kill()
                    listener.communicate()

            self.assertNotEqual(listener.returncode, 0)
            # Neither key file should be written on MITM/mismatch!
            self.assertFalse(os.path.exists(key_a))
            self.assertFalse(os.path.exists(key_b))

    def test_zeroize_cryptographic_media_purge(self):
        """NIST SP 800-88 Rev 1 / DoD 5220.22-M 3-pass emergency zeroization."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            key_path = os.path.join(tmp, "compromised_session.key")
            state_path = os.path.join(tmp, "compromised_session.state")
            extra_path = os.path.join(tmp, "classified_payload.dat")

            # Write secrets to files
            with open(key_path, "w") as f:
                f.write("0123456789abcdef" * 4)
            with open(state_path, "wb") as f:
                f.write(b"STSTATE1" + b"\x99" * 40)
            with open(extra_path, "wb") as f:
                f.write(b"TOP SECRET INTELLIGENCE DATA" * 100)

            self.assertTrue(os.path.exists(key_path))
            self.assertTrue(os.path.exists(state_path))
            self.assertTrue(os.path.exists(extra_path))

            # Run zeroize with --key-file, --state, and --target
            res = _run("zeroize", "--key-file", key_path, "--state", state_path,
                       "--target", extra_path)
            self.assertEqual(res.returncode, 0, res.stderr[-500:])
            self.assertIn("ZEROIZE COMPLETE: 3 file(s)", res.stdout)

            # Assert all files are permanently unlinked
            self.assertFalse(os.path.exists(key_path))
            self.assertFalse(os.path.exists(state_path))
            self.assertFalse(os.path.exists(extra_path))

            # Fail-closed: zeroize on non-existent file must exit non-zero
            res_fail = _run("zeroize", "--target", os.path.join(tmp, "nonexistent.bin"))
            self.assertNotEqual(res_fail.returncode, 0)

    def test_channel_continuous_pacing_and_bidirectional_exchange(self):
        """Phase 6: Full-duplex continuous paced enclave channel with CSPRNG chaff and real message transit."""
        import tempfile, time
        with tempfile.TemporaryDirectory() as tmp:
            _hex, kf = _new_key_file(tmp)
            port_init = _free_udp_port()
            port_resp = _free_udp_port()
            state_init = os.path.join(tmp, "init.state")
            state_resp = os.path.join(tmp, "resp.state")

            # Start responder on port_resp, pointing to port_init
            resp_proc = subprocess.Popen(
                [BIN, "channel", "--key-file", kf, "--state", state_resp,
                 "--bind", f"127.0.0.1:{port_resp}", "--to", f"127.0.0.1:{port_init}",
                 "--role", "responder", "--interval-ms", "15", "--quantum", "1232",
                 "--reply", "TACTICAL_RESPONSE_CONFIRMED", "--recv-count", "1",
                 "--drain-ticks", "6", "--timeout-ms", "8000"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            time.sleep(0.15)

            # Start initiator on port_init, pointing to port_resp
            init_proc = subprocess.Popen(
                [BIN, "channel", "--key-file", kf, "--state", state_init,
                 "--bind", f"127.0.0.1:{port_init}", "--to", f"127.0.0.1:{port_resp}",
                 "--role", "initiator", "--interval-ms", "15", "--quantum", "1232",
                 "--msg", "TACTICAL_COORDINATES_ENCLAVE_ALPHA", "--recv-count", "1",
                 "--drain-ticks", "6", "--timeout-ms", "8000"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )

            init_out, init_err = init_proc.communicate(timeout=10)
            resp_out, resp_err = resp_proc.communicate(timeout=10)

            self.assertEqual(init_proc.returncode, 0, f"Initiator failed:\nOUT: {init_out}\nERR: {init_err}")
            self.assertEqual(resp_proc.returncode, 0, f"Responder failed:\nOUT: {resp_out}\nERR: {resp_err}")

            # Verify initiator received the responder's message
            self.assertIn("RECV_MSG", init_out)
            self.assertIn("TACTICAL_RESPONSE_CONFIRMED", init_out)

            # Verify responder received the initiator's message
            self.assertIn("RECV_MSG", resp_out)
            self.assertIn("TACTICAL_COORDINATES_ENCLAVE_ALPHA", resp_out)

            # Verify state files are intact and 48 bytes
            self.assertEqual(os.path.getsize(state_init), 48)
            self.assertEqual(os.path.getsize(state_resp), 48)

    def test_auth_keygen_sign_verify_cli(self):
        """Native pure-Rust ML-DSA-87 (FIPS 204) CLI keygen, sign, and verify."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            sk_path = os.path.join(tmp, "mldsa.sk")
            pk_path = os.path.join(tmp, "mldsa.pk")
            in_path = os.path.join(tmp, "payload.bin")
            sig_path = os.path.join(tmp, "payload.sig")

            # 1. auth-keygen
            r_gen = _run("auth-keygen", "--out-sk", sk_path, "--out-pk", pk_path)
            self.assertEqual(r_gen.returncode, 0, r_gen.stderr)
            self.assertTrue(os.path.exists(sk_path))
            self.assertTrue(os.path.exists(pk_path))

            # 2. Write payload
            payload = b"COMMAND-ENCLAVE-AUTHORIZATION-TOKEN-0x992B"
            with open(in_path, "wb") as f:
                f.write(payload)

            # 3. auth-sign
            r_sign = _run("auth-sign", "--sk-file", sk_path, "--domain", "TEST-DOMAIN",
                          "--in", in_path, "--out", sig_path)
            self.assertEqual(r_sign.returncode, 0, r_sign.stderr)
            self.assertTrue(os.path.exists(sig_path))

            # 4. auth-verify (honest)
            r_ver = _run("auth-verify", "--pk-file", pk_path, "--domain", "TEST-DOMAIN",
                         "--in", in_path, "--sig-file", sig_path)
            self.assertEqual(r_ver.returncode, 0, r_ver.stderr)
            self.assertIn("VALID", r_ver.stdout)

            # 5. auth-verify (cross-domain mismatch: fail-closed)
            r_bad_dom = _run("auth-verify", "--pk-file", pk_path, "--domain", "WRONG-DOMAIN",
                             "--in", in_path, "--sig-file", sig_path)
            self.assertNotEqual(r_bad_dom.returncode, 0)

            # 6. auth-verify (tampered payload: fail-closed)
            with open(in_path, "wb") as f:
                f.write(b"TAMPERED-PAYLOAD")
            r_bad_pay = _run("auth-verify", "--pk-file", pk_path, "--domain", "TEST-DOMAIN",
                             "--in", in_path, "--sig-file", sig_path)
            self.assertNotEqual(r_bad_pay.returncode, 0)


if __name__ == "__main__":
    unittest.main()


