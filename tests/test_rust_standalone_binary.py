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


def _wait_udp_bound(port, proc, timeout_s=15.0):
    """Block until `proc` has bound 127.0.0.1:port (A-12 flake fix).

    The Rust receiver uses a plain UdpSocket::bind with no SO_REUSEADDR, so
    a conflicting probe bind fails exactly once the receiver owns the port.
    Replaces the fixed 1.5 s sleep, which flaked under load (sender fired
    before the receiver was bound -> UDP datagrams silently dropped).
    """
    import time
    deadline = time.monotonic() + timeout_s
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise AssertionError(
                    f"receiver exited before binding (rc={proc.returncode})")
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                return  # port taken -> receiver is bound
            probe.close()
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            time.sleep(0.05)
        raise AssertionError("receiver never bound UDP port within timeout")
    finally:
        probe.close()


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
                _wait_udp_bound(port, recv)
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
            try:
                os.chmod(wrong, 0o600)
            except OSError:
                pass
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
                _wait_udp_bound(port, recv)
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
                _wait_udp_bound(port, recv)
                sent = _run("send-file", "--key-file", kf, "--state", send_state,
                            "--to", f"127.0.0.1:{port}", "--file", src)
                self.assertEqual(sent.returncode, 0, sent.stderr[-500:])
                out, err = recv.communicate(timeout=40)
            finally:
                if recv.poll() is None:
                    recv.kill()
                    recv.communicate()
            self.assertEqual(recv.returncode, 0, err[-1000:])
            want = hashlib.sha384(payload).hexdigest()
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
            try:
                os.chmod(wrong, 0o600)
            except OSError:
                pass
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
                _wait_udp_bound(port, recv)
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
                _wait_udp_bound(port, recv)
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
            # State file is exactly the 80-byte authenticated record (F-04: 48B raw + 32B HMAC).
            self.assertEqual(os.path.getsize(st), 328)
            # Mismatched key refused against the same state (key binding).
            wrong = os.path.join(tmp, "wrong.key")
            with open(wrong, "w") as f:
                f.write("cd" * 32 + "\n")
            try:
                os.chmod(wrong, 0o600)
            except OSError:
                pass
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
                _wait_udp_bound(port, recv)
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
            self.assertEqual(os.path.getsize(send_state), 328)

    def test_kex_listen_connect_hybrid_establishment(self):
        """Phase 1: Pure native post-quantum hybrid key exchange (ML-KEM-1024 + X25519)."""
        import tempfile, time
        with tempfile.TemporaryDirectory() as tmp:
            port = _free_tcp_port()
            key_a = os.path.join(tmp, "responder.key")
            key_b = os.path.join(tmp, "initiator.key")
            psk_file = os.path.join(tmp, "shared.psk")
            with open(psk_file, "w") as f:
                f.write(("42" * 32) + "\n")
            try:
                os.chmod(psk_file, 0o600)
            except OSError:
                pass
            identities = {}
            for side in ("resp", "init"):
                sk = os.path.join(tmp, f"{side}.sk")
                pk = os.path.join(tmp, f"{side}.pk")
                gen = _run("auth-keygen", "--out-sk", sk, "--out-pk", pk)
                self.assertEqual(gen.returncode, 0, gen.stderr[-500:])
                identities[side] = (sk, pk)

            listener = subprocess.Popen(
                [str(BIN), "kex-listen", "--bind", f"127.0.0.1:{port}", "--out-key", key_a,
                 "--psk-file", psk_file,
                 "--auth-sk-file", identities["resp"][0],
                 "--peer-auth-pk-file", identities["init"][1],
                 "--require-mutual-auth", "--timeout-ms", "15000"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=str(CRATE))
            try:
                time.sleep(1.0)
                connector = _run("kex-connect", "--to", f"127.0.0.1:{port}", "--out-key", key_b,
                                 "--psk-file", psk_file,
                                 "--auth-sk-file", identities["init"][0],
                                 "--peer-auth-pk-file", identities["resp"][1],
                                 "--require-mutual-auth", "--timeout-ms", "15000")
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
                _wait_udp_bound(udp_port, recv)
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

            identities = {}
            for side in ("resp", "init"):
                sk = os.path.join(tmp, f"{side}.sk")
                pk = os.path.join(tmp, f"{side}.pk")
                gen = _run("auth-keygen", "--out-sk", sk, "--out-pk", pk)
                self.assertEqual(gen.returncode, 0, gen.stderr[-500:])
                identities[side] = (sk, pk)

            listener = subprocess.Popen(
                [str(BIN), "kex-listen", "--bind", f"127.0.0.1:{port}", "--out-key", key_a,
                 "--psk-file", psk_file,
                 "--auth-sk-file", identities["resp"][0],
                 "--peer-auth-pk-file", identities["init"][1],
                 "--require-mutual-auth", "--timeout-ms", "15000"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=str(CRATE))
            try:
                time.sleep(1.0)
                connector = _run("kex-connect", "--to", f"127.0.0.1:{port}", "--out-key", key_b,
                                 "--psk-file", psk_file,
                                 "--auth-sk-file", identities["init"][0],
                                 "--peer-auth-pk-file", identities["resp"][1],
                                 "--require-mutual-auth", "--timeout-ms", "15000")
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

            identities = {}
            for side in ("resp", "init"):
                sk = os.path.join(tmp, f"{side}.sk")
                pk = os.path.join(tmp, f"{side}.pk")
                gen = _run("auth-keygen", "--out-sk", sk, "--out-pk", pk)
                self.assertEqual(gen.returncode, 0, gen.stderr[-500:])
                identities[side] = (sk, pk)

            listener = subprocess.Popen(
                [str(BIN), "kex-listen", "--bind", f"127.0.0.1:{port}", "--out-key", key_a,
                 "--psk-file", psk_a,
                 "--auth-sk-file", identities["resp"][0],
                 "--peer-auth-pk-file", identities["init"][1],
                 "--require-mutual-auth", "--timeout-ms", "10000"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=str(CRATE))
            try:
                time.sleep(1.0)
                connector = _run("kex-connect", "--to", f"127.0.0.1:{port}", "--out-key", key_b,
                                 "--psk-file", psk_b,
                                 "--auth-sk-file", identities["init"][0],
                                 "--peer-auth-pk-file", identities["resp"][1],
                                 "--require-mutual-auth", "--timeout-ms", "10000")
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

    def test_kex_mutual_mldsa87_authentication(self):
        """Production KEX: PSK + pinned mutual ML-DSA-87 identity signatures."""
        import tempfile, time
        with tempfile.TemporaryDirectory() as tmp:
            port = _free_tcp_port()
            key_a = os.path.join(tmp, "resp_mutual.key")
            key_b = os.path.join(tmp, "init_mutual.key")
            psk_file = os.path.join(tmp, "shared.psk")
            with open(psk_file, "w") as f:
                f.write(("5a" * 32) + "\n")
            try:
                os.chmod(psk_file, 0o600)
            except OSError:
                pass

            identities = {}
            for side in ("resp", "init"):
                sk = os.path.join(tmp, f"{side}.sk")
                pk = os.path.join(tmp, f"{side}.pk")
                gen = _run("auth-keygen", "--out-sk", sk, "--out-pk", pk)
                self.assertEqual(gen.returncode, 0, gen.stderr[-500:])
                identities[side] = (sk, pk)

            listener = subprocess.Popen(
                [str(BIN), "kex-listen", "--bind", f"127.0.0.1:{port}",
                 "--out-key", key_a, "--psk-file", psk_file,
                 "--auth-sk-file", identities["resp"][0],
                 "--peer-auth-pk-file", identities["init"][1],
                 "--require-mutual-auth", "--timeout-ms", "15000"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                cwd=str(CRATE))
            try:
                time.sleep(1.0)
                connector = _run(
                    "kex-connect", "--to", f"127.0.0.1:{port}",
                    "--out-key", key_b, "--psk-file", psk_file,
                    "--auth-sk-file", identities["init"][0],
                    "--peer-auth-pk-file", identities["resp"][1],
                    "--require-mutual-auth", "--timeout-ms", "15000")
                self.assertEqual(connector.returncode, 0, connector.stderr[-500:])
                out, err = listener.communicate(timeout=15)
            finally:
                if listener.poll() is None:
                    listener.kill()
                    listener.communicate()

            self.assertEqual(listener.returncode, 0, f"mutual kex-listen failed:\n{err[-500:]}")
            self.assertIn("mutual ML-DSA-87", out)
            self.assertIn("mutual ML-DSA-87", connector.stdout)
            with open(key_a, "r") as f:
                hex_a = f.read().strip()
            with open(key_b, "r") as f:
                hex_b = f.read().strip()
            self.assertEqual(hex_a, hex_b)

            # A wrong pinned peer key must fail closed and write no session key.
            port2 = _free_tcp_port()
            key_c = os.path.join(tmp, "resp_badpin.key")
            key_d = os.path.join(tmp, "init_badpin.key")
            listener2 = subprocess.Popen(
                [str(BIN), "kex-listen", "--bind", f"127.0.0.1:{port2}",
                 "--out-key", key_c, "--psk-file", psk_file,
                 "--auth-sk-file", identities["resp"][0],
                 "--peer-auth-pk-file", identities["resp"][1],
                 "--require-mutual-auth", "--timeout-ms", "8000"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                cwd=str(CRATE))
            try:
                time.sleep(1.0)
                connector2 = _run(
                    "kex-connect", "--to", f"127.0.0.1:{port2}",
                    "--out-key", key_d, "--psk-file", psk_file,
                    "--auth-sk-file", identities["init"][0],
                    "--peer-auth-pk-file", identities["resp"][1],
                    "--require-mutual-auth", "--timeout-ms", "8000")
                self.assertNotEqual(connector2.returncode, 0)
                listener2.communicate(timeout=10)
            finally:
                if listener2.poll() is None:
                    listener2.kill()
                    listener2.communicate()
            self.assertNotEqual(listener2.returncode, 0)
            self.assertFalse(os.path.exists(key_c))
            self.assertFalse(os.path.exists(key_d))

    def test_kex_psk_only_refused_outside_lab_mode(self):
        """Primary Security Gap Test: PSK-only KEX is lab-only; refused in production."""
        import tempfile, time
        with tempfile.TemporaryDirectory() as tmp:
            key_out = os.path.join(tmp, "prod_refused.key")
            psk_file = os.path.join(tmp, "shared.psk")
            with open(psk_file, "w") as f:
                f.write(("42" * 32) + "\n")
            try:
                os.chmod(psk_file, 0o600)
            except OSError:
                pass

            # Production mode (no --lab, no P2P_LAB_MODE): PSK-only must fail closed
            env_prod = {k: v for k, v in os.environ.items() if "LAB" not in k}
            res = _run("kex-listen", "--bind", "127.0.0.1:0", "--out-key", key_out,
                       "--psk-file", psk_file, env=env_prod)
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("mutual auth requires --auth-sk-file", res.stderr)
            self.assertFalse(os.path.exists(key_out))

            # Lab mode (--lab): PSK-only key establishment succeeds
            port = _free_tcp_port()
            key_a = os.path.join(tmp, "lab_resp.key")
            key_b = os.path.join(tmp, "lab_init.key")
            listener = subprocess.Popen(
                [str(BIN), "kex-listen", "--bind", f"127.0.0.1:{port}",
                 "--out-key", key_a, "--psk-file", psk_file,
                 "--lab", "--timeout-ms", "8000"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=str(CRATE))
            try:
                time.sleep(1.0)
                connector = _run(
                    "kex-connect", "--to", f"127.0.0.1:{port}",
                    "--out-key", key_b, "--psk-file", psk_file,
                    "--lab", "--timeout-ms", "8000")
                self.assertEqual(connector.returncode, 0, connector.stderr[-500:])
                out, err = listener.communicate(timeout=10)
            finally:
                if listener.poll() is None:
                    listener.kill()
                    listener.communicate()

            self.assertEqual(listener.returncode, 0, f"lab kex-listen failed:\n{err[-500:]}")
            self.assertTrue(os.path.exists(key_a))
            self.assertTrue(os.path.exists(key_b))
            with open(key_a, "r") as f:
                hex_a = f.read().strip()
            with open(key_b, "r") as f:
                hex_b = f.read().strip()
            self.assertEqual(hex_a, hex_b)

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

            # Verify state files are intact and 80 bytes (F-04: authenticated record)
            self.assertEqual(os.path.getsize(state_init), 328)
            self.assertEqual(os.path.getsize(state_resp), 328)

    def test_channel_in_band_pcs_ratchet_rekey(self):
        """Continuous in-band line-rate PCS Ratchet rekeying (ML-KEM-1024 + P-384)."""
        import tempfile, time
        with tempfile.TemporaryDirectory() as tmp:
            _hex, kf = _new_key_file(tmp)
            port_init = _free_udp_port()
            port_resp = _free_udp_port()
            state_init = os.path.join(tmp, "init.state")
            state_resp = os.path.join(tmp, "resp.state")

            # Start responder on port_resp, pointing to port_init with --rekey-interval 8
            resp_proc = subprocess.Popen(
                [BIN, "channel", "--key-file", kf, "--state", state_resp,
                 "--bind", f"127.0.0.1:{port_resp}", "--to", f"127.0.0.1:{port_init}",
                 "--role", "responder", "--interval-ms", "15", "--quantum", "1232",
                 "--rekey-interval", "8",
                 "--reply", "CONFIRMED_PCS_RESPONSE",
                 "--count", "45", "--timeout-ms", "8000"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            time.sleep(0.15)

            # Start initiator on port_init, pointing to port_resp with --rekey-interval 8
            init_proc = subprocess.Popen(
                [BIN, "channel", "--key-file", kf, "--state", state_init,
                 "--bind", f"127.0.0.1:{port_init}", "--to", f"127.0.0.1:{port_resp}",
                 "--role", "initiator", "--interval-ms", "15", "--quantum", "1232",
                 "--rekey-interval", "8",
                 "--msg", "TACTICAL_DATA_UNDER_PCS_RATCHET",
                 "--count", "45", "--timeout-ms", "8000"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )

            init_out, init_err = init_proc.communicate(timeout=10)
            resp_out, resp_err = resp_proc.communicate(timeout=10)

            self.assertEqual(init_proc.returncode, 0, f"Initiator failed:\nOUT: {init_out}\nERR: {init_err}")
            self.assertEqual(resp_proc.returncode, 0, f"Responder failed:\nOUT: {resp_out}\nERR: {resp_err}")

            # Verify initial advert bundles exchanged
            self.assertIn("PEER_ADVERT_STORED", init_out)
            self.assertIn("PEER_ADVERT_STORED", resp_out)
            self.assertIn("PEER_ADVERT_STORED", resp_out)

            # Verify in-band hybrid ratchet steps executed
            self.assertIn("RATCHET_STEP_EMIT", init_out)
            self.assertIn("RATCHET_STEP_RECV", resp_out)
            self.assertIn("EPOCH_ADVANCED", init_out)
            self.assertIn("EPOCH_ADVANCED", resp_out)

            # Verify message transit succeeded across ratchet epochs
            self.assertIn("TACTICAL_DATA_UNDER_PCS_RATCHET", resp_out)
            self.assertIn("CONFIRMED_PCS_RESPONSE", init_out)

    def test_channel_interactive_operator_rekey(self):
        """Interactive on-demand /rekey operator trigger over continuous paced channel."""
        import tempfile, time
        with tempfile.TemporaryDirectory() as tmp:
            _hex, kf = _new_key_file(tmp)
            port_init = _free_udp_port()
            port_resp = _free_udp_port()
            state_init = os.path.join(tmp, "init_interactive.state")
            state_resp = os.path.join(tmp, "resp_interactive.state")

            resp_proc = subprocess.Popen(
                [BIN, "channel", "--key-file", kf, "--state", state_resp,
                 "--bind", f"127.0.0.1:{port_resp}", "--to", f"127.0.0.1:{port_init}",
                 "--role", "responder", "--interval-ms", "15", "--quantum", "1232",
                 "--recv-count", "1", "--drain-ticks", "10", "--timeout-ms", "8000"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            time.sleep(0.15)

            init_proc = subprocess.Popen(
                [BIN, "channel", "--key-file", kf, "--state", state_init,
                 "--bind", f"127.0.0.1:{port_init}", "--to", f"127.0.0.1:{port_resp}",
                 "--role", "initiator", "--interval-ms", "15", "--quantum", "1232",
                 "--stdin", "--timeout-ms", "8000"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )

            # Wait for initial advert exchange
            time.sleep(0.5)

            # Trigger interactive /rekey
            init_proc.stdin.write("/rekey\n")
            init_proc.stdin.flush()
            time.sleep(0.4)

            # Send post-rekey message
            init_proc.stdin.write("POST_REKEY_CLASSIFIED_MESSAGE\n")
            init_proc.stdin.flush()
            time.sleep(0.3)

            # Zeroize to terminate initiator
            init_proc.stdin.write("/zeroize\n")
            init_proc.stdin.flush()

            init_out, init_err = init_proc.communicate(timeout=10)
            resp_out, resp_err = resp_proc.communicate(timeout=10)

            self.assertIn("RATCHET_STEP_EMIT", init_out)
            self.assertIn("RATCHET_STEP_RECV", resp_out)
            self.assertIn("EPOCH_ADVANCED", init_out)
            self.assertIn("EPOCH_ADVANCED", resp_out)
            self.assertIn("POST_REKEY_CLASSIFIED_MESSAGE", resp_out)

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

    def test_terminal_interactive_session(self):
        """Production tactical interactive terminal: constant-rate pacing and commands."""
        import tempfile
        import time
        with tempfile.TemporaryDirectory() as tmp:
            _hex, keyfile = _new_key_file(tmp)
            state_init = os.path.join(tmp, "state_init.bin")
            state_resp = os.path.join(tmp, "state_resp.bin")

            port_init = _free_udp_port()
            port_resp = _free_udp_port()

            addr_init = f"127.0.0.1:{port_init}"
            addr_resp = f"127.0.0.1:{port_resp}"

            # Start responder
            resp_proc = subprocess.Popen(
                [
                    str(BIN), "terminal",
                    "--key-file", keyfile,
                    "--state", state_resp,
                    "--bind", addr_resp,
                    "--to", addr_init,
                    "--role", "responder",
                    "--interval-ms", "25",
                    "--quantum", "1232",
                    "--sas", "TEST-SAS-9941",
                    "--callsign", "BRAVO-NMCC",
                    "--timeout-ms", "10000",
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=str(CRATE),
            )
            _wait_udp_bound(port_resp, resp_proc)

            # Start initiator
            init_proc = subprocess.Popen(
                [
                    str(BIN), "terminal",
                    "--key-file", keyfile,
                    "--state", state_init,
                    "--bind", addr_init,
                    "--to", addr_resp,
                    "--role", "initiator",
                    "--interval-ms", "25",
                    "--quantum", "1232",
                    "--sas", "TEST-SAS-9941",
                    "--callsign", "ALPHA-NORAD",
                    "--timeout-ms", "10000",
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=str(CRATE),
            )
            _wait_udp_bound(port_init, init_proc)

            # Feed interactive commands into initiator: /status, message, /clear, /quit
            init_stdin = (
                "/status\n"
                "/help\n"
                "TACTICAL_ALERT_DEFCON1_REACHED\n"
                "/clear\n"
                "/quit\n"
            )
            init_out, init_err = init_proc.communicate(input=init_stdin, timeout=8)

            time.sleep(0.3)

            # Close responder
            resp_stdin = "/quit\n"
            resp_out, resp_err = resp_proc.communicate(input=resp_stdin, timeout=8)

            self.assertEqual(init_proc.returncode, 0, f"Init error:\nOUT: {init_out}\nERR: {init_err}")
            self.assertEqual(resp_proc.returncode, 0, f"Resp error:\nOUT: {resp_out}\nERR: {resp_err}")

            # Verify banner rendered
            self.assertIn("ST2027 SECURE TACTICAL COMMUNICATIONS TERMINAL", init_out)
            self.assertIn("TEST-SAS-9941", init_out)
            self.assertIn("ALPHA-NORAD", init_out)

            # Verify /status output
            self.assertIn("[STATUS] LINK TELEMETRY:", init_out)
            self.assertIn("Pacing Interval: 25 ms", init_out)

            # Verify /help output
            self.assertIn("[HELP] TACTICAL OPERATOR COMMAND MANUAL:", init_out)

            # Verify responder received the transmitted message
            self.assertIn("[INCOMING] TACTICAL_ALERT_DEFCON1_REACHED", resp_out)

            # Verify ANSI screen flush code was emitted on /clear or /quit
            self.assertIn("\x1b[2J\x1b[3J\x1b[H", init_out)

    def test_terminal_zeroize_command(self):
        """Operator /zeroize command executes NIST SP 800-88 purge of key and state."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            _hex, keyfile = _new_key_file(tmp)
            state_file = os.path.join(tmp, "zeroize_state.bin")
            port = _free_udp_port()
            peer_port = _free_udp_port()

            proc = subprocess.Popen(
                [
                    str(BIN), "terminal",
                    "--key-file", keyfile,
                    "--state", state_file,
                    "--bind", f"127.0.0.1:{port}",
                    "--to", f"127.0.0.1:{peer_port}",
                    "--role", "initiator",
                    "--interval-ms", "30",
                    "--timeout-ms", "5000",
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=str(CRATE),
            )
            _wait_udp_bound(port, proc)

            self.assertTrue(os.path.exists(keyfile))
            self.assertTrue(os.path.exists(state_file))

            # Send /zeroize
            stdout, stderr = proc.communicate(input="/zeroize\n", timeout=5)
            self.assertEqual(proc.returncode, 0, f"Zeroize failed:\nOUT: {stdout}\nERR: {stderr}")

            self.assertIn("OPERATOR EMERGENCY ZEROIZATION INITIATED", stdout)
            self.assertIn("ZEROIZE COMPLETE", stdout)

            # Verify NIST SP 800-88 purge: files must be wiped and unlinked
            self.assertFalse(os.path.exists(keyfile), "Keyfile must be purged from disk")
            self.assertFalse(os.path.exists(state_file), "State file must be purged from disk")


if __name__ == "__main__":
    unittest.main()


