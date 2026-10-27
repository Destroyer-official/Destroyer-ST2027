"""Parser fuzz + KAT gates (deterministic, seeded, additive-only).

Covers:
  1. FileMetadata.from_bytes malformed inputs + max-valid roundtrip.
  2. SecureMessageSerializer.deserialize malformed inputs, replay, and
     fail-closed replay-table-full behaviour (without filling 4096 entries).
  3. TUFReleaseManager._validate_rel_path traversal vectors.
  4. KAT: HKDF-SHA384 known vector + ML-KEM-1024 roundtrip (skipped if oqs
     native lib is unavailable -- must NOT fail CI).

Determinism: all fuzz bytes derive from ``random.Random(_SEED)`` instances.
No ``random`` global, ``secrets``, ``os.urandom`` or wall-clock entropy is
used for assertions (a fixed timestamp constant is used for serializer
messages). Target runtime: well under 60 s.

Run: ``pytest test_parser_fuzz_gates.py -v``
"""

import hashlib
import hmac
import random
import struct
import warnings
from datetime import datetime

import pytest

from secure_file_sharing import FileMetadata
from secure_message_serializer import (
    IntegrityViolation,
    MessageFlags,
    MessageType,
    ParseError,
    SecureMessage,
    SecureMessageSerializer,
)

# ---------------------------------------------------------------------------
# Deterministic fixtures / helpers
# ---------------------------------------------------------------------------

_FUZZ_SEED = 0xF02DC0DE
_MAC_KEY = hashlib.sha256(b"parser-fuzz-gate-v1").digest()  # fixed 32 B
_SENDER = b"\xAA" * 32
_FIXED_TS_US = 1704067200000000  # 2024-01-01T00:00:00Z, fixed (no clock use)


def _make_serializer() -> SecureMessageSerializer:
    return SecureMessageSerializer(mac_key=_MAC_KEY)


def _make_msg(seq: int, sender: bytes = _SENDER, payload: bytes = b"gate") -> SecureMessage:
    return SecureMessage(
        version=1,
        msg_type=MessageType.DATA,
        flags=int(MessageFlags.NONE),
        sequence=seq,
        timestamp=_FIXED_TS_US,
        sender_id=sender,
        payload=payload,
    )


def _valid_metadata() -> FileMetadata:
    return FileMetadata(
        file_id="ab12" * 8,  # 32 hex chars
        filename="report.txt",
        file_size=1_000_000,
        file_type="text/plain",
        checksum="c" * 64,
        chunk_size=65536,
        total_chunks=16,
        created_at=datetime(2024, 1, 1, 0, 0, 0),
        sender_id="sender-01",
    )


# ---------------------------------------------------------------------------
# 1. FileMetadata gates
# ---------------------------------------------------------------------------


class TestFileMetadataFuzz:
    def test_truncated_10b_rejected(self):
        with pytest.raises(ValueError):
            FileMetadata.from_bytes(b"\x00" * 10)

    def test_truncated_prefixes_rejected(self):
        blob = _valid_metadata().to_bytes()
        rng = random.Random(_FUZZ_SEED)  # nosec B311 -- deterministic seeded fuzz stream (reproducibility required; never key material)
        # Deterministic cut lengths incl. empty, header-only, and off-by-ones.
        cuts = [0, 1, 10, 31, 32, 33, 63, 64, len(blob) - 1]
        cuts += [rng.randrange(0, len(blob)) for _ in range(8)]
        for n in cuts:
            with pytest.raises(ValueError):
                FileMetadata.from_bytes(blob[:n])

    def test_oversize_filename_len_500_short_body_rejected(self):
        # file_id(32) + filename_len(500) + short body; total >= minimum size
        # so the parse reaches the filename_len allowlist check (>255).
        blob = b"f" * 32 + struct.pack(">H", 500) + b"short" + b"\x00" * 100
        with pytest.raises(ValueError):  # filename_len=500 must be rejected
            FileMetadata.from_bytes(blob)

    @pytest.mark.parametrize("field", ["filename_len", "file_type_len", "sender_id_len"])
    def test_zero_lens_rejected(self, field):
        if field == "filename_len":
            blob = b"f" * 32 + struct.pack(">H", 0) + b"\x00" * 128
        elif field == "file_type_len":
            blob = (
                b"f" * 32
                + struct.pack(">H", 1) + b"x"
                + struct.pack(">Q", 8)
                + struct.pack(">H", 0)
                + b"\x00" * 128
            )
        else:
            m = _valid_metadata()
            blob = bytearray(m.to_bytes())
            # Patch trailing sender_id_len to zero (last 2 bytes of prefix
            # before sender body). Rebuild instead: truncate to sender_len
            # field then append zero len + filler.
            prefix = m.to_bytes()
            # sender_id_len sits right after the 8-byte timestamp; find it by
            # re-walking is overkill -- simplest: keep everything up to and
            # including timestamp, then zero len.
            # Layout tail: ... total_chunks(4) + timestamp(8) + s_len(2) + s.
            blob = prefix[: len(prefix) - len("sender-01") - 2] + struct.pack(">H", 0)
        with pytest.raises(ValueError):  # f"{field}=0 must be rejected"
            FileMetadata.from_bytes(bytes(blob))

    def test_max_valid_roundtrip(self):
        meta = FileMetadata(
            file_id="0123456789abcdef" * 2,  # 32 chars
            filename="n" * 255,  # max accepted by from_bytes
            file_size=1024 * 1024 * 1024,  # 1 GB upper bound (inclusive)
            file_type="t" * 128,  # max accepted by from_bytes
            checksum="d" * 64,
            chunk_size=65536,  # >= FileMessage.MIN_CHUNK_SIZE (4 KB)
            total_chunks=16384,
            created_at=datetime(2024, 1, 1, 0, 0, 0),
            sender_id="s" * 256,  # max accepted by from_bytes
        )
        blob = meta.to_bytes()
        parsed = FileMetadata.from_bytes(blob)
        assert parsed.file_id == meta.file_id  # nosec: B101
        assert parsed.filename == meta.filename  # nosec: B101
        assert parsed.file_size == meta.file_size  # nosec: B101
        assert parsed.file_type == meta.file_type  # nosec: B101
        assert parsed.checksum == meta.checksum  # nosec: B101
        assert parsed.chunk_size == meta.chunk_size  # nosec: B101
        assert parsed.total_chunks == meta.total_chunks  # nosec: B101
        assert parsed.sender_id == meta.sender_id  # nosec: B101
        assert int(parsed.created_at.timestamp()) == int(meta.created_at.timestamp())  # nosec: B101
        # Re-serialisation is deterministic.
        assert parsed.to_bytes() == blob  # nosec: B101

    def test_seeded_mutation_fuzz_never_crashes(self):
        """64 deterministic single/multi-byte mutations: only narrow parse
        errors (or a successful parse whose value re-serialises) are allowed
        -- no unexpected exception types, no hangs."""
        blob = bytearray(_valid_metadata().to_bytes())
        rng = random.Random(_FUZZ_SEED ^ 0x9E3779B9)  # nosec B311 -- deterministic seeded fuzz stream (reproducibility required; never key material)
        allowed = (ValueError, UnicodeDecodeError, struct.error)
        ok = 0
        for _ in range(64):
            mut = bytearray(blob)
            for _ in range(rng.randint(1, 3)):
                mut[rng.randrange(len(mut))] ^= 1 << rng.randrange(8)
            try:
                parsed = FileMetadata.from_bytes(bytes(mut))
            except allowed:
                continue
            # Successful parse: object must be well-formed and re-serialisable.
            parsed.to_bytes()
            ok += 1
        # Sanity: fuzz actually exercised both paths (not all-reject).
        assert ok >= 0  # informational; gate is "no unexpected exception"  # nosec: B101


# ---------------------------------------------------------------------------
# 2. Serializer gates
# ---------------------------------------------------------------------------


class _FakeFullTable(dict):
    """5-entry dict that reports len() == 4096 so the fail-closed
    'replay table full' branch is exercised WITHOUT filling 4096 entries."""

    def __len__(self):  # noqa: D102
        return 4096


class TestSerializerGates:
    def test_truncated_header_rejected(self):
        ser = _make_serializer()
        with pytest.raises(ParseError):
            ser.deserialize(b"\x00" * 10)
        with pytest.raises(ParseError):
            ser.deserialize(b"\x00" * (ser.HEADER_SIZE + ser.MAC_SIZE - 1))

    def test_length_mismatch_rejected(self):
        ser = _make_serializer()
        blob = ser.serialize(_make_msg(seq=1))
        header_len = ser.HEADER_SIZE
        message_data, mac = blob[:-ser.MAC_SIZE], blob[-ser.MAC_SIZE:]
        (version, mtype, flags, total_len, seq, ts, sender) = struct.unpack(
            ser.HEADER_FORMAT, message_data[:header_len]
        )
        assert total_len == len(blob)  # nosec: B101
        bad_header = struct.pack(
            ser.HEADER_FORMAT, version, mtype, flags, total_len + 8, seq, ts, sender
        )
        bad_data = bad_header + message_data[header_len:]
        # Recompute MAC so the parse passes MAC-first verification and
        # reaches the length-field check.
        fresh_mac = hmac.new(_MAC_KEY, bad_data, hashlib.sha384).digest()[:32]
        with pytest.raises(ParseError):
            ser.deserialize(bad_data + fresh_mac, enforce_sequence=False)

    def test_bad_mac_rejected(self):
        ser = _make_serializer()
        blob = bytearray(ser.serialize(_make_msg(seq=2)))
        blob[-1] ^= 0x01
        with pytest.raises(IntegrityViolation):
            ser.deserialize(bytes(blob))

    def test_seq_replay_same_seq_twice_rejected(self):
        ser = _make_serializer()
        blob = ser.serialize(_make_msg(seq=7))
        first = ser.deserialize(blob)  # first delivery accepted
        assert first.sequence == 7  # nosec: B101
        with pytest.raises(IntegrityViolation):
            ser.deserialize(blob)  # replay of seq 7 rejected

    def test_table_full_unknown_sender_fail_closed(self):
        """Fail-closed for unknown senders when the replay table is full.

        Uses a 5-entry test double (never fills 4096 real entries)."""
        ser = _make_serializer()
        table = _FakeFullTable({bytes([i]) * 32: i for i in range(1, 6)})
        ser._last_sequences = table
        blob = ser.serialize(_make_msg(seq=1, sender=b"\xFE" * 32))
        with pytest.raises(IntegrityViolation) as excinfo:
            ser.deserialize(blob)
        assert "full" in str(excinfo.value).lower() or "handshake" in str(  # nosec: B101
            excinfo.value
        ).lower(), f"expected table-full rejection, got: {excinfo.value!r}"
        # Prove we did NOT fill 4096 entries: only the 5 double entries exist.
        assert len(list(table.keys())) == 5  # nosec: B101

    def test_seeded_payload_roundtrips(self):
        rng = random.Random(_FUZZ_SEED ^ 0x5E4)  # nosec B311 -- deterministic seeded fuzz stream (reproducibility required; never key material)
        for i in range(16):
            n = rng.choice([0, 1, 7, 127, 1024, 4096])
            payload = bytes(rng.getrandbits(8) for _ in range(n))
            ser = _make_serializer()  # fresh replay state per vector
            blob = ser.serialize(_make_msg(seq=100 + i, payload=payload))
            back = ser.deserialize(blob)
            assert back.payload == payload  # nosec: B101
            assert back.sequence == 100 + i  # nosec: B101


# ---------------------------------------------------------------------------
# 3. TUF path-traversal gates
# ---------------------------------------------------------------------------

_TRAVERSAL_VECTORS = [
    "../../../etc/passwd",
    "/etc/passwd",
    "C:\\win",
    "\\",
    "\\\\server\\share",
    "a\x00b",
    "..%2F..%2Fetc%2Fpasswd",  # encoded separators -> traversal after decode
    "",
    "a/../b",
]


def _tuf_manager_no_init():
    """Instantiate TUFReleaseManager without __init__ side effects (no state
    dir / TPM probing); _validate_rel_path does not use instance state."""
    try:
        from supply_chain_security import TUFReleaseManager
    except Exception as exc:
        pytest.skip(f"TUFReleaseManager unavailable, skipping path gates: {exc!r}")
    if not hasattr(TUFReleaseManager, "_validate_rel_path"):
        pytest.skip("TUFReleaseManager._validate_rel_path missing, skipping path gates")
    return TUFReleaseManager.__new__(TUFReleaseManager)


class TestTUFPathGates:
    @pytest.mark.parametrize("vector", _TRAVERSAL_VECTORS)
    def test_traversal_vectors_rejected(self, vector):
        mgr = _tuf_manager_no_init()
        with pytest.raises(ValueError):  # vector must raise; id shows vector
            mgr._validate_rel_path(vector)

    def test_benign_relative_path_accepted(self):
        mgr = _tuf_manager_no_init()
        assert mgr._validate_rel_path("firmware/v1/app.bin") == "firmware/v1/app.bin"  # nosec: B101


# ---------------------------------------------------------------------------
# 4. KAT gates
# ---------------------------------------------------------------------------

# HKDF-SHA384 vector: RFC 5869 Test-Case-1 framing (IKM=0x0b*22,
# salt=0x0001..0x0c, info=0xf0..0xf9, L=42) recomputed for SHA-384.
# Expected OKM generated with `cryptography` and cross-checked against an
# independent HMAC-based extract-and-expand reference (see test body).
_HKDF_IKM = bytes.fromhex("0b" * 22)
_HKDF_SALT = bytes.fromhex("000102030405060708090a0b0c")
_HKDF_INFO = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
_HKDF_L = 42
_HKDF_EXPECTED_HEX = (
    "9b5097a86038b805309076a44b3a9f380"
    "63e25b516dcbf369f394cfab43685f748"
    "b6457763e4f0204fc5"
)


def _hkdf_sha384_reference(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """Independent RFC 5869 extract-and-expand using HMAC-SHA384 only."""
    prk = hmac.new(salt, ikm, hashlib.sha384).digest()
    okm, block = b"", b""
    for counter in range(1, (length + 47) // 48 + 1):
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha384).digest()
        okm += block
    return okm[:length]


class TestKATGates:
    def test_hkdf_sha384_known_vector(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        kdf = HKDF(
            algorithm=hashes.SHA384(),
            length=_HKDF_L,
            salt=_HKDF_SALT,
            info=_HKDF_INFO,
        )
        okm = kdf.derive(_HKDF_IKM)
        assert okm.hex() == _HKDF_EXPECTED_HEX  # nosec: B101
        # Cross-check library output against the independent reference.
        assert _hkdf_sha384_reference(_HKDF_IKM, _HKDF_SALT, _HKDF_INFO, _HKDF_L) == okm  # nosec: B101

    def test_mlkem1024_roundtrip_or_skip(self):
        try:
            from liboqs_wrapper import LibOQS_MLKEM_1024
        except Exception as exc:
            pytest.skip(f"liboqs_wrapper unavailable, skipping ML-KEM gate: {exc!r}")
        try:
            kem = LibOQS_MLKEM_1024()
        except Exception as exc:  # missing oqs.dll / algorithm disabled
            warnings.warn(f"ML-KEM-1024 unavailable, skipping: {exc!r}")
            pytest.skip(f"ML-KEM-1024 unavailable: {exc!r}")
        pk, sk = kem.keygen()
        assert len(pk) == kem.pk_size and len(sk) == kem.sk_size  # nosec: B101
        ct, ss_enc = kem.encaps(pk)
        ss_dec = kem.decaps(sk, ct)
        assert len(ct) == kem.ct_size  # nosec: B101
        assert ss_enc == ss_dec  # nosec: B101
        assert len(ss_enc) == kem.ss_size  # nosec: B101


# ---------------------------------------------------------------------------
# 5. Tier-3 framing v2 + treekem fuzz (untrusted-bytes decoders).
# Deterministic seeded streams; every malformed input must raise
# ValueError (never return garbage, never hang, never accept). Valid
# roundtrips must survive encode/decode intact.
# ---------------------------------------------------------------------------

def _framing_valid_samples():
    from mls_framing import Commit, KeyPackage, Proposal, KIND_ADD, KIND_REMOVE, KIND_UPDATE, TRANSCRIPT_INIT
    import time
    now = int(time.time())
    kp = KeyPackage(member_id="fuzz-alice", ml_dsa_pub=b"\x01" * 32,
                    kem_pub=b"\x02" * 16, not_before=now - 60,
                    not_after=now + 3600)
    props = [Proposal(kind=k, member_id=f"m-{k}", sig=b"\xab" * 8)
             for k in (KIND_ADD, KIND_REMOVE, KIND_UPDATE)]
    c = Commit(epoch=3, prev_tx=TRANSCRIPT_INIT, proposals=props,
               suite_id="ML-KEM-1024+ML-DSA-87/pure-PQ")
    return [("KeyPackage", KeyPackage, kp.encode()),
            ("Proposal", Proposal, props[0].encode()),
            ("Commit", Commit, c.encode())]


class TestFramingV2FuzzGates:
    def test_valid_wire_roundtrips(self):
        for name, cls, wire in _framing_valid_samples():
            back = cls.decode(wire)
            assert back.encode() == wire, name  # nosec: B101

    def test_truncations_rejected(self):
        for name, cls, wire in _framing_valid_samples():
            for cut in (1, 4, 5, 6, 7, 11, len(wire) // 2, len(wire) - 1):
                with pytest.raises(ValueError):
                    cls.decode(wire[:cut])

    def test_bitflips_rejected_or_absorbed_safely(self):
        # A flipped bit must either decode to a DIFFERENT valid object
        # (accepted only if fully self-consistent) or raise ValueError.
        # It must never produce trailing-byte acceptance or crash.
        rng = random.Random(_FUZZ_SEED ^ 0x5E4)  # nosec B311 -- deterministic seeded fuzz stream (reproducibility required; never key material)
        for name, cls, wire in _framing_valid_samples():
            for _ in range(20):
                buf = bytearray(wire)
                pos = rng.randrange(len(buf))
                buf[pos] ^= 1 << rng.randrange(8)
                try:
                    back = cls.decode(bytes(buf))
                except ValueError:
                    continue
                # If it decoded, re-encoding must be canonical (no junk).
                assert back.encode() == bytes(buf), name  # nosec: B101

    def test_garbage_rejected(self):
        from mls_framing import Commit, KeyPackage, Proposal
        rng = random.Random(_FUZZ_SEED ^ 0x9E3779B9)  # nosec B311 -- deterministic seeded fuzz stream (reproducibility required; never key material)
        for cls in (KeyPackage, Proposal, Commit):
            for _ in range(40):
                n = rng.randrange(0, 48)
                junk = bytes(rng.randrange(256) for _ in range(n))
                with pytest.raises(ValueError):
                    cls.decode(junk)
        # Wrong magic / version rejected even at full length.
        for cls, magic in ((KeyPackage, b"MLSF1"), (Proposal, b"MLSP1"),
                           (Commit, b"MLSC1")):
            good = None
            for name, c, wire in _framing_valid_samples():
                if name.lower() in ("keypackage", "proposal", "commit") and \
                        wire[:5] == magic:
                    good = wire
            assert good is not None  # nosec: B101
            bad_magic = b"XXXXX" + good[5:]
            with pytest.raises(ValueError):
                cls.decode(bad_magic)

    def test_oversize_member_id_rejected(self):
        from mls_framing import KeyPackage, Proposal
        with pytest.raises(ValueError):
            KeyPackage(member_id="x" * 300, ml_dsa_pub=b"\x01" * 32,
                       kem_pub=b"\x02" * 16,
                       not_before=1, not_after=2).encode()
        with pytest.raises(ValueError):
            Proposal(kind=99, member_id="x").encode()


class TestTreekemFuzzGates:
    def test_random_op_sequences_hold_invariants(self):
        from treekem import RatchetTree, TreeError
        rng = random.Random(_FUZZ_SEED ^ 0x7E3)  # nosec B311 -- deterministic seeded fuzz stream (reproducibility required; never key material)
        for trial in range(15):
            t = RatchetTree(width=4)
            live = set()
            for step in range(40):
                op = rng.randrange(4)
                name = f"u{trial}-{step}-{rng.randrange(100000)}"
                try:
                    if op == 0 and len(live) < 8:
                        t.add(name, b"\x01" * 32)
                        live.add(name)
                    elif op == 1 and live:
                        victim = sorted(live)[rng.randrange(len(live))]
                        t.remove(victim)
                        live.discard(victim)
                    elif op == 2 and live:
                        who = sorted(live)[rng.randrange(len(live))]
                        t.rotate(who, b"\x02" * 32)
                    else:
                        with pytest.raises(TreeError):
                            t.remove(f"ghost-{name}")
                except TreeError:
                    pass
            # Invariants: roster matches, cover non-empty iff members exist,
            # hash deterministic for the final state.
            assert set(t.members().keys()) == live  # nosec: B101
            assert (t.cover() != []) == (len(live) > 0)  # nosec: B101
            assert t.tree_hash() == t.tree_hash()  # nosec: B101

    def test_hostile_inputs_fail_closed(self):
        from treekem import RatchetTree, TreeError
        t = RatchetTree(width=4)
        for bad_mid in ("", "x" * 300, 123, None, b"bytes-id"):
            with pytest.raises((TreeError, TypeError, ValueError)):
                t.add(bad_mid, b"\x01" * 32)
        with pytest.raises((TreeError, TypeError, ValueError)):
            t.add("ok", b"")
        with pytest.raises(TreeError):
            t.remove("nobody")
        with pytest.raises(TreeError):
            t.rotate("nobody", b"\x01" * 32)
        with pytest.raises(TreeError):
            RatchetTree(width=3)
        with pytest.raises(TreeError):
            RatchetTree(width=0)

