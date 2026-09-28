"""Standalone Rust binary (Task-1): secure-transmit builds and transfers.

Proves the zero-Python data-plane executor end to end:
  1. cargo build --offline --bin secure-transmit succeeds (frozen Cargo.lock).
  2. `selftest` exits 0 (AEAD roundtrip, tamper reject, replay, MTU).
  3. Live loopback: recv <- send opens exactly the sealed payload.
  4. Wrong frame key: receiver admits the datagram but opens nothing
     (fail-closed timeout, exit 3) — key never negotiates in the binary.

Scope boundary (see src/main.rs header): session-key provisioning (PQ
handshake/PKI/ceremony) stays in the audited Python control plane.
"""
import os
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
        key = _run("keygen").stdout.strip()
        port = _free_udp_port()
        recv = subprocess.Popen(
            [str(BIN), "recv", "--key", key, "--bind", f"127.0.0.1:{port}",
             "--count", "1", "--timeout-ms", "15000"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            cwd=str(CRATE))
        try:
            import time
            time.sleep(1.5)  # let recv bind first (fail-closed otherwise)
            sent = _run("send", "--key", key, "--to", f"127.0.0.1:{port}",
                        "--msg", "BINARY-PROOF-7741", "--seq", "4242")
            self.assertEqual(sent.returncode, 0, sent.stderr[-500:])
            out, err = recv.communicate(timeout=30)
        finally:
            if recv.poll() is None:
                recv.kill()
                recv.communicate()
        self.assertEqual(recv.returncode, 0, err[-1000:])
        self.assertIn("seq=4242 BINARY-PROOF-7741", out)

    def test_04_wrong_key_opens_nothing(self):
        key = _run("keygen").stdout.strip()
        wrong = "ab" * 32
        self.assertNotEqual(key, wrong)
        port = _free_udp_port()
        recv = subprocess.Popen(
            [str(BIN), "recv", "--key", wrong, "--bind", f"127.0.0.1:{port}",
             "--count", "1", "--timeout-ms", "6000"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            cwd=str(CRATE))
        try:
            import time
            time.sleep(1.5)
            sent = _run("send", "--key", key, "--to", f"127.0.0.1:{port}",
                        "--msg", "MUST-NOT-OPEN", "--seq", "7")
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
        key = _run("keygen").stdout.strip()
        port = _free_udp_port()
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "in.bin")
            dst = os.path.join(tmp, "out.bin")
            with open(src, "wb") as f:
                f.write(payload)
            recv = subprocess.Popen(
                [str(BIN), "recv-file", "--key", key,
                 "--bind", f"127.0.0.1:{port}", "--out", dst,
                 "--count", "3", "--timeout-ms", "15000"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                cwd=str(CRATE))
            try:
                import time
                time.sleep(1.5)
                sent = _run("send-file", "--key", key,
                            "--to", f"127.0.0.1:{port}", "--file", src,
                            "--seq", "500")
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
        key = _run("keygen").stdout.strip()
        wrong = "ab" * 32
        port = _free_udp_port()
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "in.bin")
            dst = os.path.join(tmp, "out.bin")
            with open(src, "wb") as f:
                f.write(b"X" * 64)
            recv = subprocess.Popen(
                [str(BIN), "recv-file", "--key", wrong,
                 "--bind", f"127.0.0.1:{port}", "--out", dst,
                 "--count", "1", "--timeout-ms", "6000"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                cwd=str(CRATE))
            try:
                import time
                time.sleep(1.5)
                sent = _run("send-file", "--key", key,
                            "--to", f"127.0.0.1:{port}", "--file", src,
                            "--seq", "9")
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
        key = _run("keygen").stdout.strip()
        port = _free_udp_port()
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "in.bin")
            dst = os.path.join(tmp, "out.bin")
            with open(src, "wb") as f:
                f.write(b"Y" * 64)
            recv = subprocess.Popen(
                [str(BIN), "recv-file", "--key", key,
                 "--bind", f"127.0.0.1:{port}", "--out", dst,
                 "--count", "2", "--timeout-ms", "6000"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                cwd=str(CRATE))
            try:
                import time
                time.sleep(1.5)
                _run("send-file", "--key", key,
                     "--to", f"127.0.0.1:{port}", "--file", src, "--seq", "3")
                out, err = recv.communicate(timeout=30)
            finally:
                if recv.poll() is None:
                    recv.kill()
                    recv.communicate()
            self.assertEqual(recv.returncode, 4, err[-1000:])
            self.assertFalse(os.path.exists(dst))


if __name__ == "__main__":
    unittest.main()
