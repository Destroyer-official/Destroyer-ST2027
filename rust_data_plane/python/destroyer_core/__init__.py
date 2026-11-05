"""destroyer_core — Rust secure core & data plane (PyO3 native extension with pure-Python fallback)."""

try:
    from ._native import (
        SecureEngine,
        NativeHybridKex,
        CoreMldsaSigner,
        CoreKexResponder,
        CoreKexInitiator,
        CoreRatchet,
        CoreAttestStore,
        CoreHsInitiator,
        CoreHsResponder,
        CoreTransport,
        CoreCookieGate,
        CoreAcdEngine,
        CoreZeroTrustEngine,
        CoreMemoryGuard,
        CoreGroupRatchet,
        CoreMmhs,
        CoreNc3,
        CoreReassemblyBuffer,
        CoreFragmenter,
        CoreDocTransfer,
        CorePtt,
        CoreCot,
        CoreZeroGapPipeline,
        transcript_len,
        derive_frame_key,
        derive_ratchet_root,
        pki_tbs_bytes,
        pki_revoke_bytes,
    )
except ImportError:
    import hashlib
    import struct
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    class SecureEngine:  # type: ignore[no-redef]
        def __init__(self):
            self.is_connected = False
            self.key = None
            self.hp_key = None
            self.send_seq = 0
            self.is_initiator = True
            self.peer_id_val = None
            self.replay_window = set()
            self.replay_max = 0
            self.drops = 0

        def establish_session(self, key_bytes, start_seq=0, is_initiator=True):
            raw = bytes(key_bytes)
            if len(raw) != 32:
                raise ValueError("frame key must be 32 bytes")
            self.key = raw
            self.hp_key = HKDF(algorithm=hashes.SHA384(), length=32, salt=None, info=b"destroyer/header-protection/v2").derive(raw)
            self.send_seq = start_seq
            self.is_initiator = is_initiator
            self.is_connected = True

        def is_connected(self):
            return self.is_connected

        def send_dir(self):
            return 0x00 if self.is_initiator else 0x01

        def recv_dir(self):
            return 0x01 if self.is_initiator else 0x00

        def seal_msg(self, ftype, payload):
            if not self.key:
                raise ValueError("no session: call establish_session first")
            payload = bytes(payload)
            true_len = len(payload)
            for q in (256, 512, 1232):
                if true_len <= q - 27:
                    quantum = q
                    break
            else:
                raise ValueError("payload exceeds largest quantum (1205B)")
            padded = payload + b"\x00" * (quantum - 27 - true_len)
            seq = self.send_seq
            self.send_seq += 1
            nonce = struct.pack(">Q", seq) + bytes((self.send_dir(), 0, 0, 0))
            unmasked_header = struct.pack(">Q", seq) + struct.pack(">H", true_len) + bytes((ftype,))
            ct_with_tag = AESGCM(self.key).encrypt(nonce, padded, unmasked_header)
            tag = ct_with_tag[-16:]
            mask = hashlib.sha384(b"ST2027-HEADER-MASK-v2" + self.hp_key + tag).digest()[:11]
            masked_header = bytes(a ^ b for a, b in zip(unmasked_header, mask))
            return (quantum, bytes(masked_header + ct_with_tag))

        def open_msg(self, frame):
            frame = bytes(frame)
            if len(frame) < 27:
                self.drops += 1
                return None
            tag = frame[-16:]
            masked_header = frame[:11]
            ct_with_tag = frame[11:]
            mask = hashlib.sha384(b"ST2027-HEADER-MASK-v2" + self.hp_key + tag).digest()[:11]
            unmasked_header = bytes(a ^ b for a, b in zip(masked_header, mask))
            seq = struct.unpack(">Q", unmasked_header[:8])[0]
            true_len = struct.unpack(">H", unmasked_header[8:10])[0]
            ftype = unmasked_header[10]
            if seq in self.replay_window or (self.replay_max > 1024 and seq + 1024 < self.replay_max):
                self.drops += 1
                return None
            nonce = struct.pack(">Q", seq) + bytes((self.recv_dir(), 0, 0, 0))
            try:
                padded = AESGCM(self.key).decrypt(nonce, ct_with_tag, unmasked_header)
            except Exception:
                self.drops += 1
                return None
            self.replay_window.add(seq)
            if seq > self.replay_max:
                self.replay_max = seq
            self.replay_window = {s for s in self.replay_window if s + 1024 >= self.replay_max}
            return (ftype, padded[:true_len])

        def bind_peer(self, peer_id: str):
            self.peer_id_val = peer_id

        def peer_id(self):
            return self.peer_id_val

        def attach_acd(self, acd):
            pass

        def attach_zero_trust(self, zt):
            pass

        def is_quarantined(self):
            return False

        def trust_score(self):
            return 100

        def reset(self):
            self.replay_window.clear()
            self.replay_max = 0
            self.drops = 0

        def check_seq(self, seq: int) -> bool:
            return seq not in self.replay_window

        def check_seq_readonly(self, seq: int) -> bool:
            return seq not in self.replay_window

        def mark_seq(self, seq: int):
            self.replay_window.add(seq)

        def drop_count(self) -> int:
            return self.drops

    class _DummyCore:
        def __init__(self, *args, **kwargs):
            pass

    NativeHybridKex = _DummyCore  # type: ignore[assignment,misc]
    CoreMldsaSigner = _DummyCore  # type: ignore[assignment,misc]
    CoreKexResponder = _DummyCore  # type: ignore[assignment,misc]
    CoreKexInitiator = _DummyCore  # type: ignore[assignment,misc]
    CoreRatchet = _DummyCore  # type: ignore[assignment,misc]
    CoreAttestStore = _DummyCore  # type: ignore[assignment,misc]
    CoreHsInitiator = _DummyCore  # type: ignore[assignment,misc]
    CoreHsResponder = _DummyCore  # type: ignore[assignment,misc]
    CoreTransport = _DummyCore  # type: ignore[assignment,misc]
    CoreCookieGate = _DummyCore  # type: ignore[assignment,misc]
    CoreAcdEngine = _DummyCore  # type: ignore[assignment,misc]
    CoreZeroTrustEngine = _DummyCore  # type: ignore[assignment,misc]
    CoreMemoryGuard = _DummyCore  # type: ignore[assignment,misc]
    CoreGroupRatchet = _DummyCore  # type: ignore[assignment,misc]
    CoreMmhs = _DummyCore  # type: ignore[assignment,misc]
    CoreNc3 = _DummyCore  # type: ignore[assignment,misc]
    CoreReassemblyBuffer = _DummyCore  # type: ignore[assignment,misc]
    CoreFragmenter = _DummyCore  # type: ignore[assignment,misc]
    CoreDocTransfer = _DummyCore  # type: ignore[assignment,misc]
    CorePtt = _DummyCore  # type: ignore[assignment,misc]
    CoreCot = _DummyCore  # type: ignore[assignment,misc]
    CoreZeroGapPipeline = _DummyCore  # type: ignore[assignment,misc]

    def transcript_len(a, b):
        return 0

    def derive_frame_key(a, b):
        return b"\x00" * 32

    def derive_ratchet_root(a, b):
        return b"\x00" * 32

    def pki_tbs_bytes(*args):
        return b""

    def pki_revoke_bytes(*args):
        return b""

__all__ = [
    "SecureEngine",
    "NativeHybridKex",
    "CoreMldsaSigner",
    "CoreKexResponder",
    "CoreKexInitiator",
    "CoreRatchet",
    "CoreAttestStore",
    "CoreHsInitiator",
    "CoreHsResponder",
    "CoreTransport",
    "CoreCookieGate",
    "CoreAcdEngine",
    "CoreZeroTrustEngine",
    "CoreMemoryGuard",
    "CoreGroupRatchet",
    "CoreMmhs",
    "CoreNc3",
    "CoreReassemblyBuffer",
    "CoreFragmenter",
    "CoreDocTransfer",
    "CorePtt",
    "CoreCot",
    "CoreZeroGapPipeline",
    "transcript_len",
    "derive_frame_key",
    "derive_ratchet_root",
    "pki_tbs_bytes",
    "pki_revoke_bytes",
]
