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

Scope boundary (see src/main.rs header): session-key provisioning (PQ
handshake/PKI/ceremony) stays in the audited Python control plane.
"""
import os
import re
import shutil
import socket
import subprocess
import unittest

ROOT = __import__("pathlib").Path(__file__).resolve().parent
CRATE = ROOT / "rust_data_plane"
BIN = (CRATE / "target" / "debug" /
       ("secure-transmit.exe" if os.name == "nt" else "secure-transmit"))


def _free_udp_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _run(*argv, timeout=60):
    return subprocess.run([str(BIN), *argv], capture_output=True, text=True,
                          timeout=timeout, cwd=str(CRATE))


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


if __name__ == "__main__":
    unittest.main()
