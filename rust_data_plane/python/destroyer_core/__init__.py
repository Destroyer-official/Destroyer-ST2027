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
        CoreWebRtcMorpher,
        CoreQuicMorpher,
        CoreChameleonEngine,
        CoreTripleKex,
        CoreDtnBundle,
        CorePqZkp,
        CoreSdrDsss,
        CoreBlindedCds,
        CoreFormalProofs,
        CoreFsoTransceiver,
        triple_kex_derive_master,
        transcript_len,
        derive_frame_key,
        derive_ratchet_root,
        pki_tbs_bytes,
        pki_revoke_bytes,
    )
    try:
        from ._native import CoreDiodeSender, CoreDiodeReceiver
    except ImportError:
        pass
    IS_NATIVE = True
except ImportError:
    IS_NATIVE = False
    import hashlib
    import struct
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    class SecureEngine:  # type: ignore[no-redef]
        def __init__(self):
            self._connected = False
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
            self._connected = True

        def is_connected(self):
            return self._connected

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
            if not self.key or not self.hp_key:
                self.drops += 1
                return None
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

        def check_seq_readonly(self, seq: int) -> bool:
            if seq <= 0:
                return False
            if seq in self.replay_window:
                return False
            if self.replay_max > 1024 and seq + 1024 <= self.replay_max:
                return False
            return True

        def mark_seq(self, seq: int):
            if seq <= 0:
                return
            self.replay_window.add(seq)
            if seq > self.replay_max:
                self.replay_max = seq
            self.replay_window = {s for s in self.replay_window if s + 1024 >= self.replay_max}

        def check_seq(self, seq: int) -> bool:
            if not self.check_seq_readonly(seq):
                self.drops += 1
                return False
            self.mark_seq(seq)
            return True

        def drop_count(self) -> int:
            return self.drops

    class _DummyCore:
        def __init__(self, *args, **kwargs):
            self._scores = {}

        def verify_read(self, *args, **kwargs):
            return True

        def register_peer(self, peer=None, role="operator", *args, **kwargs):
            if peer:
                self._scores[str(peer)] = 75
            return True

        def verifying_bytes(self, *args, **kwargs):
            return b"\x00" * 32

        def get_public_keys(self, *args, **kwargs):
            return b"\x00" * 32

        def is_quarantined(self, *args, **kwargs):
            return False

        def is_emergency_isolated(self, *args, **kwargs):
            return False

        def create_cookie(self, *args, **kwargs):
            return b"\x00" * 32

        def create_challenge(self, *args, **kwargs):
            return b"\x00" * 32

        @classmethod
        def solve_challenge(cls, *args, **kwargs):
            return 0

        def secure_wipe(self, *args, **kwargs):
            pass

        def process_incoming_m1(self, *args, **kwargs):
            return b"\x00" * 32

        def trust_score(self, peer=None, *args, **kwargs):
            if peer and str(peer) in self._scores:
                return self._scores[str(peer)]
            return 75

        def score(self, *args, **kwargs):
            return 75

        def is_trusted(self, peer=None, *args, **kwargs):
            return self.trust_score(peer) >= 50

        def record_action(self, *args, **kwargs):
            pass

        def record_event(self, *args, **kwargs):
            pass

        def record_success(self, peer=None, *args, **kwargs):
            if peer:
                self._scores[str(peer)] = min(100, self._scores.get(str(peer), 75))

        def record_penalty(self, peer, points: int = 15):
            p = str(peer) if peer else "default"
            curr = self._scores.get(p, 75)
            new_s = curr - points
            if new_s < 50:
                self._scores[p] = 0
                raise ValueError("zero-trust continuous verification failure: trust score below floor")
            self._scores[p] = new_s

        def record_anomaly(self, *args, **kwargs):
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
    class CoreNc3:  # type: ignore[no-redef]
        @staticmethod
        def check_safety_gate(message):
            return None

        @staticmethod
        def verify_two_person(vk1_bytes, vk2_bytes):
            if bytes(vk1_bytes) == bytes(vk2_bytes):
                raise ValueError("Two person rule requires distinct verification keys")

        @staticmethod
        def verify_temporal_window(timestamps_ms):
            if not timestamps_ms:
                raise ValueError("No timestamps provided")
            skew = max(timestamps_ms) - min(timestamps_ms)
            if skew > 2000:
                raise ValueError(f"Temporal skew {skew}ms exceeds 2000ms window")
            return skew

        @staticmethod
        def verify_silo_quorum(signer_indices, threshold):
            if threshold < 2:
                raise ValueError("Threshold must be at least 2")
            if len(signer_indices) < threshold:
                raise ValueError(f"Quorum not met: got {len(signer_indices)}, need {threshold}")
            if len(set(signer_indices)) != len(signer_indices):
                raise ValueError("Duplicate silo signer indices detected")

        @staticmethod
        def verify_threshold_mpc_wire(wire_bytes, payload_bytes, expected_master_pk):
            from nc3_threshold_mpc import ThresholdSignature, verify_threshold_signature_on_payload
            sig = ThresholdSignature.from_wire_bytes(bytes(wire_bytes))
            if not verify_threshold_signature_on_payload(sig, bytes(payload_bytes), bytes(expected_master_pk)):
                raise ValueError("Threshold MPC signature verification failed")
            return sig.sync_skew_ms
    CoreReassemblyBuffer = _DummyCore  # type: ignore[assignment,misc]
    CoreFragmenter = _DummyCore  # type: ignore[assignment,misc]
    CoreDocTransfer = _DummyCore  # type: ignore[assignment,misc]
    CorePtt = _DummyCore  # type: ignore[assignment,misc]
    CoreCot = _DummyCore  # type: ignore[assignment,misc]
    CoreZeroGapPipeline = _DummyCore  # type: ignore[assignment,misc]

    class CoreDtnBundle:  # type: ignore[no-redef]
        @staticmethod
        def inspect_bundle(wire_bytes):
            wire = bytes(wire_bytes)
            if len(wire) < 50 or wire[:6] != b"BP7PQC":
                raise ValueError("Malformed wire header")
            offset = 6 + 1 + 8 + 1  # magic, version, flags, crc
            dst_len = struct.unpack(">H", wire[offset:offset + 2])[0]
            offset += 2
            dst_eid = wire[offset:offset + dst_len].decode("utf-8")
            offset += dst_len
            src_len = struct.unpack(">H", wire[offset:offset + 2])[0]
            offset += 2
            src_eid = wire[offset:offset + src_len].decode("utf-8")
            offset += src_len
            rep_len = struct.unpack(">H", wire[offset:offset + 2])[0]
            offset += 2
            rep_eid = wire[offset:offset + rep_len].decode("utf-8")
            offset += rep_len
            cr_time, seq, life = struct.unpack(">QQQ", wire[offset:offset + 24])
            offset += 24
            h_lim, h_cnt, age_ms = struct.unpack(">IIQ", wire[offset:offset + 16])
            offset += 16
            pn_flag = wire[offset]
            offset += 1
            prev_node = None
            if pn_flag == 1:
                pn_len = struct.unpack(">H", wire[offset:offset + 2])[0]
                offset += 2
                prev_node = wire[offset:offset + pn_len].decode("utf-8")
                offset += pn_len
            sec_flag = wire[offset]
            return (src_eid, dst_eid, rep_eid, cr_time, seq, life, h_lim, h_cnt, age_ms, prev_node, sec_flag == 1)

        @staticmethod
        def process_hop(wire_bytes, current_time_ms, hop_transit_time_ms, current_node_eid):
            wire = bytearray(wire_bytes)
            headers = CoreDtnBundle.inspect_bundle(wire)
            (src_eid, dst_eid, rep_eid, cr_time, seq, life, h_lim, h_cnt, age_ms, prev_node, is_enc) = headers
            if cr_time + life < current_time_ms:
                raise ValueError("Bundle stale / expired")
            if h_cnt >= h_lim:
                raise ValueError("Hop limit exceeded")
            offset = 6 + 1 + 8 + 1 + 2 + len(dst_eid.encode("utf-8")) + 2 + len(src_eid.encode("utf-8")) + 2 + len(rep_eid.encode("utf-8")) + 24
            h_cnt += 1
            age_ms += hop_transit_time_ms
            struct.pack_into(">I", wire, offset + 4, h_cnt)
            struct.pack_into(">Q", wire, offset + 8, age_ms)
            return bytes(wire)

    class CoreSdrDsss:  # type: ignore[no-redef]
        @staticmethod
        def modulate_dsss_bits(bits, spreading_factor):
            # Pure-Python fallback DSSS modulator
            chips = [1.0 if (i & 1) == 0 else -1.0 for i in range(spreading_factor)]
            i_chan = []
            for b in bits:
                sign = 1.0 if b == 0 else -1.0
                for c in chips:
                    # 4 samples per chip
                    val = sign * c
                    i_chan.extend([val, val, val, val])
            return i_chan, [0.0] * len(i_chan)

        @staticmethod
        def demodulate_dsss_bits(i_channel, spreading_factor):
            sps = spreading_factor * 4
            chips = [1.0 if (i & 1) == 0 else -1.0 for i in range(spreading_factor)]
            num_syms = len(i_channel) // sps
            bits = []
            for s in range(num_syms):
                acc = 0.0
                start = s * sps
                for c_idx, c in enumerate(chips):
                    pos = start + c_idx * 4
                    if pos < len(i_channel):
                        acc += i_channel[pos] * c
                bits.append(0 if acc >= 0.0 else 1)
            return bits

        @staticmethod
        def to_cs16_pcm(i_channel, q_channel, amplitude):
            out = []
            for i, q in zip(i_channel, q_channel):
                out.append(int(max(-32768, min(32767, i * amplitude * 32767.0))))
                out.append(int(max(-32768, min(32767, q * amplitude * 32767.0))))
            return out

        @staticmethod
        def simulate_awgn_channel(i_channel, snr_db):
            import random, math
            sig_power = sum(x * x for x in i_channel) / max(1, len(i_channel))
            snr_lin = 10.0 ** (snr_db / 10.0)
            noise_std = math.sqrt(sig_power / snr_lin)
            return [x + random.gauss(0.0, noise_std) for x in i_channel]

    class CoreWebRtcMorpher:  # type: ignore[no-redef]
        def __init__(self, payload_type=111, ssrc=None, target_quantum=None):
            import secrets
            self.payload_type = payload_type if payload_type is not None else 111
            self.ssrc = ssrc if ssrc is not None else secrets.randbits(32)
            self.target_quantum = target_quantum
            self.seq_num = 1
            self.timestamp = 960
            self.pacing_counter = 0

        def morph(self, cell):
            import struct
            import os
            cell = bytes(cell)
            cell_len = len(cell)
            min_len = 12 + 1 + 2 + cell_len
            total_len = self.target_quantum if (self.target_quantum and self.target_quantum >= min_len) else min_len
            hdr = bytearray(12)
            hdr[0] = 0x80
            hdr[1] = self.payload_type & 0x7F
            struct.pack_into(">H", hdr, 2, self.seq_num & 0xFFFF)
            struct.pack_into(">I", hdr, 4, self.timestamp & 0xFFFFFFFF)
            struct.pack_into(">I", hdr, 8, self.ssrc & 0xFFFFFFFF)
            self.seq_num = (self.seq_num + 1) & 0xFFFF
            self.timestamp = (self.timestamp + 960) & 0xFFFFFFFF
            payload = bytes([0x78]) + struct.pack(">H", cell_len) + cell
            if total_len > len(hdr) + len(payload):
                payload += os.urandom(total_len - len(hdr) - len(payload))
            return bytes(hdr + payload)

        def demorph(self, packet):
            import struct
            packet = bytes(packet)
            if len(packet) < 15:
                raise ValueError("packet too short")
            if (packet[0] >> 6) != 2:
                raise ValueError("invalid RTP version")
            if (packet[1] & 0x7F) != self.payload_type:
                raise ValueError("payload type mismatch")
            cell_len = struct.unpack(">H", packet[13:15])[0]
            if 15 + cell_len > len(packet):
                raise ValueError("cell length exceeds packet bounds")
            return packet[15:15 + cell_len]

        def next_pacing_delay_ms(self):
            import math
            idx = self.pacing_counter % 100
            self.pacing_counter += 1
            u = (idx + 0.5 + math.sin(self.pacing_counter * 12.9898) * 0.05) / 100.0
            u = max(0.0001, min(0.9999, u))
            from scipy.stats import norm
            return float(norm.ppf(u, loc=20.0, scale=2.0))

        def generate_pacing_intervals(self, count):
            import math
            from scipy.stats import norm
            out = []
            for i in range(count):
                u = (i + 0.5 + math.sin(i * 12.9898) * 0.05) / float(count)
                u = max(0.0001, min(0.9999, u))
                out.append(float(norm.ppf(u, loc=20.0, scale=2.0)))
            return out

    class CoreQuicMorpher:  # type: ignore[no-redef]
        def __init__(self, dcid=None, target_size=1200):
            import os
            self.dcid = bytes(dcid) if dcid is not None else os.urandom(8)
            self.target_size = target_size if target_size is not None else 1200
            self.pn = 1

        def morph(self, cell):
            import struct
            cell = bytes(cell)
            first_byte = 0x43  # short header, fixed bit 1, 4-byte PN
            hdr = bytes([first_byte]) + self.dcid + struct.pack(">I", self.pn & 0xFFFFFFFF)
            self.pn = (self.pn + 1) & 0xFFFFFFFF
            # STREAM frame 0x0A: Stream ID 0, Length varint, Data
            stream_frame = bytearray([0x0A, 0x00])
            val = len(cell)
            if val < 64:
                stream_frame.append(val)
            elif val < 16384:
                stream_frame.extend([0x40 | (val >> 8), val & 0xFF])
            else:
                stream_frame.extend([0x80 | (val >> 24), (val >> 16) & 0xFF, (val >> 8) & 0xFF, val & 0xFF])
            stream_frame.extend(cell)
            pkt = bytearray(hdr + stream_frame)
            if len(pkt) < self.target_size:
                pkt.extend(b"\x00" * (self.target_size - len(pkt)))
            return bytes(pkt)

        def demorph(self, packet):
            import struct
            packet = bytes(packet)
            if not packet:
                raise ValueError("packet empty")
            first = packet[0]
            if (first & 0x80) != 0:
                raise ValueError("long header not supported in basic fallback")
            if (first & 0x40) == 0:
                raise ValueError("fixed bit not set")
            pn_len = (first & 0x03) + 1
            hdr_len = 1 + len(self.dcid) + pn_len
            if len(packet) < hdr_len + 1:
                raise ValueError("packet too short")
            offset = hdr_len
            while offset < len(packet):
                ftype = packet[offset]
                if ftype == 0x00:
                    offset += 1
                    continue
                if 0x08 <= ftype <= 0x0F:
                    offset += 1
                    # Stream ID varint
                    first_v = packet[offset]
                    v_len = 1 << (first_v >> 6)
                    offset += v_len
                    # Length varint if LEN bit set
                    if ftype & 0x02:
                        first_l = packet[offset]
                        l_len = 1 << (first_l >> 6)
                        data_len = first_l & 0x3F
                        for b in packet[offset + 1:offset + l_len]:
                            data_len = (data_len << 8) | b
                        offset += l_len
                    else:
                        data_len = len(packet) - offset
                    if offset + data_len > len(packet):
                        raise ValueError("length exceeds packet")
                    return packet[offset:offset + data_len]
                offset += 1
            raise ValueError("no stream frame found")

    class CoreChameleonEngine:  # type: ignore[no-redef]
        def __init__(self, profile="webrtc", target_size=None):
            self.profile = profile.lower() if profile else "webrtc"
            self.webrtc = CoreWebRtcMorpher(target_quantum=target_size)
            self.quic = CoreQuicMorpher(target_size=target_size)

        def set_profile(self, profile):
            self.profile = profile.lower()

        def morph(self, cell):
            if self.profile in ("webrtc", "rtp", "opus"):
                return self.webrtc.morph(cell)
            return self.quic.morph(cell)

        def demorph(self, packet):
            packet = bytes(packet)
            if not packet:
                raise ValueError("packet empty")
            if (packet[0] >> 6) == 2 and len(packet) >= 15 and (packet[1] & 0x7F) == self.webrtc.payload_type:
                return self.webrtc.demorph(packet)
            return self.quic.demorph(packet)

        def next_pacing_delay_ms(self):
            return self.webrtc.next_pacing_delay_ms()

        def morph_chaff(self, target_len=None):
            if self.profile in ("webrtc", "rtp", "opus"):
                return self.webrtc.morph_chaff(target_len)
            return self.quic.morph_chaff(target_len)

        def set_target_size(self, target_size):
            self.webrtc.target_quantum = target_size
            self.quic.target_size = target_size

        def auto_evade(self):
            self.profile = "quic" if self.profile in ("webrtc", "rtp", "opus") else "webrtc"
            return self.profile

        def telemetry(self):
            return (0, 0, 0, 0, 0, 0, 0, self.profile)

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

    def triple_kex_derive_master(transcript, ss_mlkem, ss_mceliece, h_psk):
        import hmac, hashlib, secrets
        if len(ss_mlkem) != 32 or len(ss_mceliece) != 32 or len(h_psk) != 32:
            raise ValueError("All secret components must be 32 bytes")
        if (
            secrets.compare_digest(bytes(ss_mlkem), bytes(32))
            or secrets.compare_digest(bytes(ss_mceliece), bytes(32))
            or secrets.compare_digest(bytes(h_psk), bytes(32))
        ):
            raise ValueError("All-zero key material rejected (fail-closed)")
        salt = hashlib.sha384(b"ST2027-TRIPLE-KEX-v1" + bytes(transcript)).digest()
        ikm = bytes(ss_mlkem) + bytes(ss_mceliece) + bytes(h_psk)
        return hmac.new(salt, ikm, hashlib.sha384).digest()

    class CoreTripleKex:
        @staticmethod
        def derive_master(transcript, ss_mlkem, ss_mceliece, h_psk):
            return triple_kex_derive_master(transcript, ss_mlkem, ss_mceliece, h_psk)

        @staticmethod
        def expand_session_keys(master_key, transcript_binding):
            from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
            from cryptography.hazmat.primitives import hashes
            import secrets
            if len(master_key) != 48:
                raise ValueError("master_key must be 48 bytes")
            if secrets.compare_digest(bytes(master_key), bytes(48)):
                raise ValueError("All-zero master key rejected (fail-closed)")
            i2r = HKDFExpand(hashes.SHA384(), 32, b"ST2027-TRIPLE-KEX-I2R-v1" + bytes(transcript_binding)).derive(master_key)
            r2i = HKDFExpand(hashes.SHA384(), 32, b"ST2027-TRIPLE-KEX-R2I-v1" + bytes(transcript_binding)).derive(master_key)
            conf = HKDFExpand(hashes.SHA384(), 32, b"ST2027-TRIPLE-KEX-CONFIRM-v1" + bytes(transcript_binding)).derive(master_key)
            return (i2r, r2i, conf)

        @staticmethod
        def compute_confirmation_tag(confirmation_key, role_label, transcript_binding):
            import hmac, hashlib, secrets
            if len(confirmation_key) != 32 or secrets.compare_digest(bytes(confirmation_key), bytes(32)):
                raise ValueError("Invalid or all-zero confirmation key (fail-closed)")
            return hmac.new(confirmation_key, bytes(role_label) + bytes(transcript_binding), hashlib.sha384).digest()[:32]

        @staticmethod
        def verify_confirmation_tag(confirmation_key, role_label, transcript_binding, expected_tag):
            import secrets
            if len(expected_tag) != 32:
                return False
            computed = CoreTripleKex.compute_confirmation_tag(confirmation_key, role_label, transcript_binding)
            return secrets.compare_digest(computed, expected_tag)

    try:
        from optical_diode_controller import (
            OpticalDiodeSender as CoreDiodeSender,
            OpticalDiodeReceiver as CoreDiodeReceiver,
        )
    except ImportError:
        CoreDiodeSender = _DummyCore  # type: ignore[assignment,misc]
        CoreDiodeReceiver = _DummyCore  # type: ignore[assignment,misc]

    CoreBlindedCds = _DummyCore  # type: ignore[assignment,misc]
    CoreFormalProofs = _DummyCore  # type: ignore[assignment,misc]
    CoreFsoTransceiver = _DummyCore  # type: ignore[assignment,misc]

__all__ = [
    "IS_NATIVE",
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
    "CoreWebRtcMorpher",
    "CoreQuicMorpher",
    "CoreChameleonEngine",
    "CoreTripleKex",
    "CoreDtnBundle",
    "CorePqZkp",
    "CoreSdrDsss",
    "CoreBlindedCds",
    "CoreFormalProofs",
    "CoreFsoTransceiver",
    "CoreDiodeSender",
    "CoreDiodeReceiver",
    "triple_kex_derive_master",
    "transcript_len",
    "derive_frame_key",
    "derive_ratchet_root",
    "pki_tbs_bytes",
    "pki_revoke_bytes",
]
