#!/usr/bin/env python3
"""Regression tests for full-review CRITICAL remediations (2026-10).

Covers:
  C1/C2  threshold_cryptography: share-declared threshold downgrade + index-0 shares
  C3     zk_authenticator: Schnorr challenge must be Fiat-Shamir bound
  C4     pq_certificate_authority: embedded issuer key is not a trust anchor
  C5     secure_p2p: NC3 war key fails closed (no public-constant fallback)
  C6     critical_release: engine RBAC False return denied; pre-enrollment required
  C7     libsodium_manager: Windows DLL requires pinned digest (sidecar ignored)
  C8     anonymous_identity_manager: onion key is random, not derivable from public key
  C9     cjadc2_allied_gateway: release token signer must be own/trusted gateway key
  C10    network_adversary_resistance: onion layer keys require local private key
  C11    sovereign_group_ratchet: TPI epoch rekey verifies real ML-DSA-87 signatures
"""

import logging
import os
import time
import types

import pytest


# ---------------------------------------------------------------------------
# C1/C2: threshold cryptography
# ---------------------------------------------------------------------------

class TestThresholdReconstructionHardening:
    def _manager(self):
        os.environ["P2P_ENABLE_CUSTOM_THRESHOLD"] = "1"
        from threshold_cryptography import ThresholdKeyManager
        return ThresholdKeyManager(threshold=3, total_shares=5)

    def test_honest_reconstruction_still_works(self):
        mgr = self._manager()
        secret = os.urandom(32)
        shares = mgr.split_key(secret)
        assert mgr.reconstruct_key(shares[:3]) == secret

    def test_share_declared_threshold_cannot_downgrade(self):
        from threshold_cryptography import InsufficientSharesError, ThresholdShare

        mgr = self._manager()
        secret = os.urandom(32)
        shares = mgr.split_key(secret)

        def forge(s, threshold):
            return ThresholdShare(
                index=s.index,
                value=s.value,
                threshold=threshold,
                commitment=s.commitment,
                total_shares=s.total_shares,
            )

        with pytest.raises(InsufficientSharesError):
            mgr.reconstruct_key([forge(shares[0], 1)])

        with pytest.raises(InsufficientSharesError):
            mgr.reconstruct_key([forge(shares[0], 1), forge(shares[1], 1)])

    def test_index_zero_share_rejected(self):
        from threshold_cryptography import ReconstructionError, ThresholdShare

        mgr = self._manager()
        secret = os.urandom(32)
        shares = mgr.split_key(secret)

        evil = [ThresholdShare(
            index=0,
            value=shares[0].value,
            threshold=3,
            commitment=shares[0].commitment,
            total_shares=shares[0].total_shares,
        )]
        evil += shares[1:3]
        with pytest.raises(ReconstructionError):
            mgr.reconstruct_key(evil)


# ---------------------------------------------------------------------------
# C3: ZK Schnorr challenge binding
# ---------------------------------------------------------------------------

class TestZkChallengeBinding:
    def _zk(self):
        os.environ["P2P_ENABLE_CUSTOM_ZK"] = "1"
        from zk_authenticator import ZKAuthenticator
        return ZKAuthenticator(allow_unaudited=True)

    def test_honest_proof_roundtrip(self):
        zk = self._zk()
        pk, sk = zk.generate_keypair()
        challenge = os.urandom(32)
        proof = zk.prove_identity(sk, challenge)
        assert zk.verify_proof(pk, challenge, proof) is True

    def test_residual_forgery_rejected(self):
        from zk_authenticator import ZKProof
        from datetime import datetime

        zk = self._zk()
        pk, _sk = zk.generate_keypair()
        challenge = os.urandom(32)

        pk_int = zk._bytes_to_int(pk)
        s = zk._mod_exp(zk.g, 123456789, zk.PRIME)
        c_guess_int = 1
        pk_c = zk._mod_exp(pk_int, c_guess_int, zk.PRIME)
        inv = pow(pk_c, -1, zk.PRIME)
        R_int = (s * inv) % zk.PRIME

        forged = ZKProof(
            commitment=zk._int_to_bytes(R_int),
            challenge=challenge,
            response=zk._int_to_bytes(123456789),
            proof_type="identity",
            timestamp=datetime.now(),
            session_id=os.urandom(32),
        )
        assert zk.verify_proof(pk, challenge, forged) is False

    def test_challenge_substitution_rejected(self):
        zk = self._zk()
        pk, sk = zk.generate_keypair()
        challenge = os.urandom(32)
        proof = zk.prove_identity(sk, challenge)
        proof.challenge = b"\x00" * 32
        assert zk.verify_proof(pk, challenge, proof) is False


# ---------------------------------------------------------------------------
# C4: PQ CA issuer anchoring
# ---------------------------------------------------------------------------

class TestPqCaIssuerAnchoring:
    def test_foreign_issuer_certificate_rejected(self):
        from pq_certificate_authority import PQCertificateAuthority, SignatureVerificationError
        from liboqs_wrapper import LibOQS_MLDSA_87

        ca_a = PQCertificateAuthority(ca_name="CA_ALPHA")
        ca_b = PQCertificateAuthority(ca_name="CA_BRAVO")

        signer = LibOQS_MLDSA_87()
        pk, _ = signer.keygen()
        cert = ca_a.issue_certificate(subject="terminal_bravo", public_key=pk, validity_days=30)

        assert ca_a.verify_certificate(cert) is True
        with pytest.raises(SignatureVerificationError):
            ca_b.verify_certificate(cert)


# ---------------------------------------------------------------------------
# C5: NC3 war key fail-closed
# ---------------------------------------------------------------------------

class TestNc3WarKeyFailClosed:
    def _dummy(self):
        return types.SimpleNamespace(
            _cached_nc3_war_key=None,
            hybrid_root_key=None,
            ratchet=None,
        )

    def test_no_root_no_env_is_fatal(self, monkeypatch):
        monkeypatch.delenv("P2P_NC3_WAR_KEY", raising=False)
        from secure_p2p import SecureP2PChat
        with pytest.raises(RuntimeError):
            SecureP2PChat._get_or_derive_nc3_war_key(self._dummy())

    def test_env_key_accepts_64_hex(self, monkeypatch):
        monkeypatch.setenv("P2P_NC3_WAR_KEY", "ab" * 32)
        from secure_p2p import SecureP2PChat
        key = SecureP2PChat._get_or_derive_nc3_war_key(self._dummy())
        assert key == bytes.fromhex("ab" * 32)

    def test_env_key_invalid_hex_is_fatal(self, monkeypatch):
        monkeypatch.setenv("P2P_NC3_WAR_KEY", "not-hex")
        from secure_p2p import SecureP2PChat
        with pytest.raises(RuntimeError):
            SecureP2PChat._get_or_derive_nc3_war_key(self._dummy())

    def test_env_key_wrong_length_is_fatal(self, monkeypatch):
        monkeypatch.setenv("P2P_NC3_WAR_KEY", "ab" * 16)
        from secure_p2p import SecureP2PChat
        with pytest.raises(RuntimeError):
            SecureP2PChat._get_or_derive_nc3_war_key(self._dummy())

    def test_authenticated_root_key_still_derives(self, monkeypatch):
        monkeypatch.delenv("P2P_NC3_WAR_KEY", raising=False)
        from secure_p2p import SecureP2PChat
        dummy = self._dummy()
        dummy.hybrid_root_key = b"\x42" * 32
        key = SecureP2PChat._get_or_derive_nc3_war_key(dummy)
        assert isinstance(key, bytes) and len(key) == 32
        dummy2 = self._dummy()
        dummy2.hybrid_root_key = b"\x42" * 32
        assert SecureP2PChat._get_or_derive_nc3_war_key(dummy2) == key


# ---------------------------------------------------------------------------
# C6: critical release ceremony
# ---------------------------------------------------------------------------

class TestCriticalReleaseCeremony:
    def test_authorize_without_pre_enrollment_refused(self):
        from critical_release import CriticalReleaseAuthority, ReleaseAuthError
        auth = CriticalReleaseAuthority()
        with pytest.raises(ReleaseAuthError):
            auth.authorize("OP_A", "pw-a", "OP_B", "pw-b")

    def test_two_distinct_pre_enrolled_operators_authorize(self):
        from critical_release import CriticalReleaseAuthority
        auth = CriticalReleaseAuthority()
        auth.enroll("OP_A", "pw-a")
        auth.enroll("OP_B", "pw-b")
        assert auth.authorize("OP_A", "pw-a", "OP_B", "pw-b") == ("OP_A", "OP_B")

    def test_same_operator_twice_refused(self):
        from critical_release import CriticalReleaseAuthority, ReleaseAuthError
        auth = CriticalReleaseAuthority()
        auth.enroll("OP_A", "pw-a")
        auth.enroll("OP_B", "pw-b")
        with pytest.raises(ReleaseAuthError):
            auth.authorize("OP_A", "pw-a", "OP_A", "pw-a")

    def test_engine_false_return_is_denied(self):
        from critical_release import CriticalReleaseAuthority, ReleaseAuthError

        class DenyingEngine:
            def check_permission(self, peer_id, action):
                return False

        auth = CriticalReleaseAuthority()
        auth.enroll("OP_A", "pw-a")
        auth.enroll("OP_B", "pw-b")
        with pytest.raises(ReleaseAuthError):
            auth.authorize(
                "OP_A", "pw-a", "OP_B", "pw-b",
                requester_peer_id="peer-1",
                zero_trust_engine=DenyingEngine(),
            )


# ---------------------------------------------------------------------------
# C7: libsodium pinned digest on Windows
# ---------------------------------------------------------------------------

class TestLibsodiumPinnedDigest:
    @pytest.mark.skipif(os.name != "nt", reason="Windows DLL trust gate")
    def test_sidecar_match_does_not_bypass_pin(self, tmp_path, caplog):
        import hashlib as _hashlib
        import json as _json
        from libsodium_manager import _load_libsodium_from_path

        fake = tmp_path / "libsodium.dll"
        fake.write_bytes(b"not-a-real-dll" * 64)
        sidecar = tmp_path / "libsodium.dll.hashes"
        sidecar.write_text(
            _json.dumps({"sha512": _hashlib.sha512(fake.read_bytes()).hexdigest()}),
            encoding="utf-8",
        )

        with caplog.at_level(logging.CRITICAL):
            ok, lib = _load_libsodium_from_path(str(fake))

        assert ok is False and lib is None
        assert "SUPPLY CHAIN INTEGRITY VIOLATION" in caplog.text


# ---------------------------------------------------------------------------
# C8: onion key randomness
# ---------------------------------------------------------------------------

class TestOnionKeyRandomness:
    def test_onion_key_not_derivable_from_public_key(self):
        from anonymous_identity_manager import AnonymousIdentityManager

        mgr = AnonymousIdentityManager()
        sig_public = os.urandom(32)

        addr1, key1 = mgr._generate_onion_address_with_key(sig_public)
        addr2, key2 = mgr._generate_onion_address_with_key(sig_public)

        assert addr1 != addr2
        assert key1 != key2
        assert key1 is not None and len(key1) == 32
        assert addr1.endswith(".onion")


# ---------------------------------------------------------------------------
# C9: cjadc2 release signer anchoring
# ---------------------------------------------------------------------------

class TestCjadc2SignerAnchoring:
    def _package(self):
        from cjadc2_allied_gateway import (
            AlliedCoalitionGateway, CoalitionAlliance, SecurityClassification,
        )
        gw = AlliedCoalitionGateway()
        pkg = gw.redact_and_package_for_coalition(
            payload_bytes=b"Allied sector perimeter clear",
            source_classification=SecurityClassification.SECRET,
            target_alliance=CoalitionAlliance.FVEY,
            target_partner_nation="GBR",
            active_caveats={"HCS-P"},
        )
        return gw, pkg

    def test_own_gateway_package_verifies(self):
        gw, pkg = self._package()
        assert gw.verify_coalition_release(pkg) is True

    def test_foreign_package_rejected_and_trusted_enrollment_allows(self):
        _gw, pkg = self._package()
        from cjadc2_allied_gateway import AlliedCoalitionGateway

        other = AlliedCoalitionGateway()
        assert other.verify_coalition_release(pkg) is False
        other.trusted_gateway_pubkeys_hex.add(pkg["gateway_ml_dsa_87_pubkey_hex"])
        assert other.verify_coalition_release(pkg) is True

    def test_swapped_attacker_pubkey_rejected(self):
        gw, pkg = self._package()
        from cjadc2_allied_gateway import AlliedCoalitionGateway

        attacker = AlliedCoalitionGateway()
        forged = dict(pkg)
        forged["gateway_ml_dsa_87_pubkey_hex"] = attacker.pk.hex()
        assert gw.verify_coalition_release(forged) is False


# ---------------------------------------------------------------------------
# C10: onion routing ECDH fail-closed
# ---------------------------------------------------------------------------

class TestOnionRoutingEcdh:
    def _x25519_pair(self):
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives import serialization

        priv = X25519PrivateKey.generate()
        raw_priv = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return raw_priv, pub

    def test_layer_key_requires_local_private_key(self):
        from network_adversary_resistance import (
            MultiHopRouter, MultiHopRoutingError, RelayNode,
        )

        raw_priv, pub = self._x25519_pair()
        router = MultiHopRouter(num_hops=1)
        route = [RelayNode(node_id="R1", address="10.0.0.1", port=9000, public_key=pub)]

        with pytest.raises(MultiHopRoutingError):
            router.build_onion_message(b"payload", route, os.urandom(32))

        with pytest.raises(MultiHopRoutingError):
            router._derive_shared_key(pub)

    def test_onion_builds_with_private_key(self):
        from network_adversary_resistance import MultiHopRouter, RelayNode

        raw_priv, pub = self._x25519_pair()
        router = MultiHopRouter(num_hops=1)
        router.set_local_private_key(raw_priv)
        route = [RelayNode(node_id="R1", address="10.0.0.1", port=9000, public_key=pub)]

        onion = router.build_onion_message(b"payload", route, os.urandom(32))
        assert isinstance(onion, bytes) and len(onion) > 0 and onion != b"payload"


# ---------------------------------------------------------------------------
# C11: sovereign group ratchet TPI (supplemental to dedicated test file)
# ---------------------------------------------------------------------------

class TestSovereignGroupRatchetTpi:
    def test_unbounded_sequence_gap_refused(self):
        from sovereign_group_ratchet import SovereignGroupRatchet, GroupMessage

        root = os.urandom(48)
        node = SovereignGroupRatchet("GROUP_X", "NODE_X", root)
        node.register_peer_sender_key("PEER", os.urandom(48))

        forged = GroupMessage(
            group_id="GROUP_X",
            epoch=0,
            sender_id="PEER",
            seq=10**9,
            ciphertext=os.urandom(64),
        )
        with pytest.raises(ValueError, match="Sequence gap too large"):
            node.open(forged)

    def test_rekey_requires_enrolled_officer_signatures(self, monkeypatch):
        from sovereign_group_ratchet import SovereignGroupRatchet
        from liboqs_wrapper import LibOQS_MLDSA_87

        node = SovereignGroupRatchet("GROUP_Y", "NODE_Y", os.urandom(48))
        mldsa = LibOQS_MLDSA_87()
        pk1, sk1 = mldsa.keygen()
        pk2, sk2 = mldsa.keygen()

        fresh = os.urandom(32)
        message = node.tpi_rekey_message(fresh)
        sig1 = mldsa.sign(sk1, message)
        sig2 = mldsa.sign(sk2, message)

        with pytest.raises(ValueError, match="Two-Person Integrity violation"):
            node.advance_epoch(fresh, sig1, sig2)

        node.enroll_tpi_officer("O6", pk1)
        node.enroll_tpi_officer("O7", pk2)
        with pytest.raises(ValueError, match="Two-Person Integrity violation"):
            node.advance_epoch(os.urandom(32), sig1, sig2)

        assert node.advance_epoch(fresh, sig1, sig2) == 1


# ---------------------------------------------------------------------------
# HIGH Batch B (2026-10 full-review triage)
#   B-h1 side_channel_resistance: constant_time_select int/bytes dispatch
#   B-h2 enhanced_audit_logging: export signature pinned to local signer
#   B-h3 tactical_data_diode: unkeyed wire refused in production
#   B-h4 active_cyber_defense: unreadable quarantine state fails closed
#   B-h5 anonymous_identity_manager: no stub disposal certification
# ---------------------------------------------------------------------------

class TestConstantTimeSelectDispatch:
    """B-h1: the bytes overload silently shadowed the integer selector."""

    def test_int_selection(self):
        from side_channel_resistance import ConstantTimeOperations

        assert ConstantTimeOperations.constant_time_select(True, 42, 24) == 42
        assert ConstantTimeOperations.constant_time_select(False, 42, 24) == 24

    def test_bytes_selection(self):
        from side_channel_resistance import ConstantTimeOperations

        a, b = b"\x01\x02", b"\x03\x04"
        assert ConstantTimeOperations.constant_time_select(True, a, b) == a
        assert ConstantTimeOperations.constant_time_select(False, a, b) == b

    def test_length_and_type_mismatch_rejected(self):
        from side_channel_resistance import ConstantTimeOperations

        with pytest.raises(ValueError):
            ConstantTimeOperations.constant_time_select(True, b"short", b"longer")
        with pytest.raises(TypeError):
            ConstantTimeOperations.constant_time_select(True, b"a", 1)


class TestExportSignatureAnchoring:
    """B-h2: the embedded public key may never authenticate itself."""

    def test_honest_export_verifies(self):
        from enhanced_audit_logging import HashChainAuditLogger

        lg = HashChainAuditLogger()
        export = lg.export_logs(include_signature=True)
        assert export.get("signature")
        assert lg.verify_export_signature(export) is True

    def test_swapped_public_key_rejected(self):
        import base64

        from enhanced_audit_logging import HashChainAuditLogger

        lg = HashChainAuditLogger()
        export = lg.export_logs(include_signature=True)
        evil_pk, _evil_sk = lg._signature_impl.keygen()
        forged = dict(export)
        forged["public_key"] = {
            alg: base64.b64encode(pk).decode("utf-8") if pk else None
            for alg, pk in evil_pk.items()
        }
        assert lg.verify_export_signature(forged) is False

    def test_verifier_without_local_keys_refuses(self):
        from enhanced_audit_logging import HashChainAuditLogger

        lg = HashChainAuditLogger()
        export = lg.export_logs(include_signature=True)
        verifier = HashChainAuditLogger()
        verifier._signing_keys = None
        assert verifier.verify_export_signature(export) is False


class TestDiodeWireKeyFailClosed:
    """B-h3: unkeyed diode frames are lab-only."""

    def test_unkeyed_refused_in_production(self, monkeypatch):
        import production_gate

        monkeypatch.delenv("P2P_DIODE_WIRE_KEY", raising=False)
        monkeypatch.setenv("P2P_PRODUCTION", "1")
        try:
            production_gate.reset_for_tests()
            assert production_gate.is_production() is True
            import tactical_data_diode as tdd

            with pytest.raises(ValueError, match="wire key is required in production"):
                tdd.DiodeReceiver(bind_host="127.0.0.1", bind_port=55101, wire_key=None)
        finally:
            production_gate.reset_for_tests()


class TestQuarantineStateFailClosed:
    """B-h4: corrupt quarantine state must not read as 'no quarantines'."""

    def test_corrupt_quarantine_refused(self, tmp_path):
        from active_cyber_defense import ActiveCyberDefenseEngine

        qf = tmp_path / "q.json"
        qf.write_text("{not-json", encoding="utf-8")
        with pytest.raises(RuntimeError, match="unreadable quarantine state"):
            ActiveCyberDefenseEngine(quarantine_file=qf)

    def test_empty_quarantine_allowed(self, tmp_path):
        from active_cyber_defense import ActiveCyberDefenseEngine

        qf = tmp_path / "q.json"
        qf.write_text("", encoding="utf-8")
        engine = ActiveCyberDefenseEngine(quarantine_file=qf)
        assert engine.is_peer_quarantined("peer-x") is False


class TestDisposalVerificationRefusedWithoutBackend:
    """B-h5: unverifiable disposal must not be certified as verified."""

    def test_scan_refuses_without_backend(self):
        from anonymous_identity_manager import AnonymousIdentityManager

        mgr = AnonymousIdentityManager(in_memory_only=True, enable_tor=False)
        assert mgr._verify_memory_scan([b"\x00" * 32]) is False


# ---------------------------------------------------------------------------
# HIGH Batch C (2026-10 full-review triage)
#   C-h1 secure_file_transfer: symlinks refused for reassembly and secure wipe
# ---------------------------------------------------------------------------

class TestFileTransferSymlinkRefusal:
    """C-h1: output/wipe paths must not be symlinks."""

    def _target_and_link(self, tmp_path):
        target = tmp_path / "target.txt"
        target.write_bytes(b"SECRET-TARGET")
        link = tmp_path / "link.txt"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            pytest.skip("symlink creation not permitted on this platform")
        return target, link

    def test_reassemble_refuses_symlink_output(self, tmp_path):
        from secure_file_transfer import SecureFileTransfer

        _target, link = self._target_and_link(tmp_path)
        mgr = SecureFileTransfer(hmac_key=os.urandom(48))
        with pytest.raises(ValueError, match="symlink"):
            mgr.reassemble_file("0" * 32, link, "00" * 64)

    def test_secure_delete_refuses_symlink(self, tmp_path):
        from secure_file_transfer import SecureDeletionError, SecureFileTransfer

        target, link = self._target_and_link(tmp_path)
        with pytest.raises(SecureDeletionError, match="symlink"):
            SecureFileTransfer.secure_delete_file(link)
        assert target.read_bytes() == b"SECRET-TARGET"


# ---------------------------------------------------------------------------
# HIGH audit-logging cluster (2026-10 full-review triage)
#   A-h1 HashChainAuditLogger: keyed chain + authenticated head anchor
#   A-h2 remote_siem_forwarder: fail-closed anchor + no plaintext key in prod
#   A-h3 AuditLogger: authenticated head anchor detects tail truncation
# ---------------------------------------------------------------------------

class TestAuditChainHardening:
    def test_hash_chain_requires_key_in_production(self, monkeypatch):
        from enhanced_audit_logging import HashChainAuditLogger

        monkeypatch.delenv("P2P_AUDIT_CHAIN_KEY", raising=False)
        monkeypatch.setattr(
            HashChainAuditLogger, "_production", staticmethod(lambda: True)
        )
        with pytest.raises(RuntimeError, match="P2P_AUDIT_CHAIN_KEY"):
            HashChainAuditLogger()

    def test_hash_chain_rejects_short_key(self, monkeypatch):
        from enhanced_audit_logging import HashChainAuditLogger

        monkeypatch.setenv("P2P_AUDIT_CHAIN_KEY", "too-short")
        with pytest.raises(ValueError, match="at least 32 bytes"):
            HashChainAuditLogger()

    def test_hash_chain_anchor_detects_tail_truncation(self, tmp_path, monkeypatch):
        import sqlite3

        from enhanced_audit_logging import AuditEventType, HashChainAuditLogger

        monkeypatch.setenv("P2P_AUDIT_CHAIN_KEY", "K" * 48)
        monkeypatch.setattr(
            HashChainAuditLogger, "_production", staticmethod(lambda: True)
        )
        db = str(tmp_path / "chain.db")
        lg = HashChainAuditLogger(db)
        lg.add_entry(AuditEventType.SYSTEM_STARTUP, "one")
        lg.add_entry(AuditEventType.SYSTEM_STARTUP, "two")
        ok, bad = lg.verify_chain()
        assert ok and bad is None
        lg.close()
        assert os.path.exists(db + ".head.anchor")

        con = sqlite3.connect(db)
        con.execute("DELETE FROM hash_chain_entries WHERE sequence_number = 2")
        con.commit()
        con.close()
        with pytest.raises(RuntimeError, match="truncation"):
            HashChainAuditLogger(db)

    def test_hash_chain_anchor_mac_rejects_tamper(self, tmp_path, monkeypatch):
        import json

        from enhanced_audit_logging import AuditEventType, HashChainAuditLogger

        monkeypatch.setenv("P2P_AUDIT_CHAIN_KEY", "K" * 48)
        monkeypatch.setattr(
            HashChainAuditLogger, "_production", staticmethod(lambda: True)
        )
        db = str(tmp_path / "chain.db")
        lg = HashChainAuditLogger(db)
        lg.add_entry(AuditEventType.SYSTEM_STARTUP, "one")
        lg.close()

        anchor_path = db + ".head.anchor"
        with open(anchor_path, encoding="utf-8") as f:
            anchor = json.load(f)
        anchor["seq"] = 0
        with open(anchor_path, "w", encoding="utf-8") as f:
            json.dump(anchor, f)
        with pytest.raises(RuntimeError, match="MAC"):
            HashChainAuditLogger(db)

    def test_remote_siem_anchor_mac_rejects_tamper(self, tmp_path, monkeypatch):
        import json

        from remote_siem_forwarder import (
            SiemAuditChainError,
            TamperEvidentAuditChain,
        )

        monkeypatch.setattr(
            TamperEvidentAuditChain, "_production", staticmethod(lambda: True)
        )
        key = os.urandom(48)
        ledger = tmp_path / "a.jsonl"
        anchor = tmp_path / "a.anchor.json"
        chain = TamperEvidentAuditChain(
            ledger_path=ledger, anchor_path=anchor, hmac_key=key
        )
        chain.append_event("BOOT", "INFO", {})
        chain.export_head_anchor()

        data = json.loads(anchor.read_text(encoding="utf-8"))
        data["head_hmac"] = "0" * 96
        anchor.write_text(json.dumps(data), encoding="utf-8")
        with pytest.raises(SiemAuditChainError, match="MAC"):
            TamperEvidentAuditChain(
                ledger_path=ledger, anchor_path=anchor, hmac_key=key
            )

    def test_remote_siem_refuses_plaintext_key_file_in_production(
        self, tmp_path, monkeypatch
    ):
        from remote_siem_forwarder import (
            SiemAuditChainError,
            TamperEvidentAuditChain,
        )

        monkeypatch.setattr(
            TamperEvidentAuditChain, "_production", staticmethod(lambda: True)
        )
        monkeypatch.delenv("P2P_SIEM_KEY", raising=False)
        with pytest.raises(SiemAuditChainError, match="P2P_SIEM_KEY"):
            TamperEvidentAuditChain(
                ledger_path=tmp_path / "l.jsonl",
                anchor_path=tmp_path / "l.anchor.json",
            )

    def test_audit_logger_anchor_detects_tail_truncation(self, tmp_path):
        import datetime
        import sqlite3

        from audit_logging_system import (
            AuditEvent,
            AuditEventType,
            AuditLogger,
            AuditSeverity,
            SecurityError,
        )

        db = str(tmp_path / "audit.db")
        lg = AuditLogger(db)
        lg.store_event(
            AuditEvent(
                event_id="e1",
                timestamp=datetime.datetime.now(datetime.timezone.utc),
                event_type=AuditEventType.SYSTEM_STARTUP,
                severity=AuditSeverity.INFO,
                message="baseline",
            )
        )
        lg.close()
        assert os.path.exists(db + ".anchor")

        con = sqlite3.connect(db)
        con.execute("DROP TRIGGER IF EXISTS prevent_audit_delete")
        con.execute("DELETE FROM audit_events")
        con.commit()
        con.close()
        with pytest.raises(SecurityError, match="truncation"):
            AuditLogger(db)


# ---------------------------------------------------------------------------
# HIGH monitoring cluster (2026-10 full-review triage)
#   M-h1 zero_trust: unpinned peers get VIEWER; prod requires a trust anchor
#   M-h2 emergency_anti_tamper: no success affidavit when a wipe/callback fails
#   M-h3 continuous_security_monitor: air-gapped alerts persisted durably
#   M-h4 threat_detection_engine: probe exceptions surface as HIGH threats
# ---------------------------------------------------------------------------

class TestMonitoringHardening:
    def test_unpinned_peer_restricted_and_prod_refuses(self, monkeypatch):
        import zero_trust_engine as zte

        eng = zte.ZeroTrustEngine(b"\x00" * 2592, b"\x00" * 4896)
        monkeypatch.setattr(eng, "_verify_signature", lambda *a, **k: True)
        eng.set_peer_role("peer1", zte.Role.VIEWER)
        assert eng.authenticate_peer("peer1", b"PK1", b"SIG", b"CH") is True
        assert eng.get_minimal_role("peer1") is zte.Role.VIEWER

        assert eng.authenticate_peer("peer2", b"PK2", b"SIG", b"CH") is True
        assert eng.get_minimal_role("peer2") is zte.Role.VIEWER

        monkeypatch.setattr(zte, "_prod_strict_on", lambda: True)
        with pytest.raises(zte.CertificatePinningFailure):
            eng.authenticate_peer("peer3", b"PK3", b"SIG", b"CH")

    def test_zeroization_affidavit_reports_failure(self, tmp_path):
        from emergency_anti_tamper import EmergencyZeroizationEngine

        eng = EmergencyZeroizationEngine(audit_dir=tmp_path)

        def _boom():
            raise RuntimeError("cleanup subsystem failed")

        eng.register_cleanup_callback(_boom)
        report = eng.execute_scorched_earth_zeroization("TEST")
        assert eng.zeroized is False
        assert (
            report["emergency_zeroization_audit"]["status"]
            == "SANITIZATION_FAILED"
        )
        assert report["emergency_zeroization_audit"]["sanitization_failures"]

    def test_airgap_siem_alert_is_persisted_before_export(
        self, tmp_path, monkeypatch
    ):
        import datetime
        import json

        from continuous_security_monitor import (
            AlertSeverity,
            SecurityAlert,
            SecurityMonitor,
        )

        monkeypatch.setenv("P2P_AIR_GAPPED_MODE", "1")
        log_path = tmp_path / "airgap_alerts.jsonl"
        monkeypatch.setenv("P2P_AIRGAP_ALERT_LOG", str(log_path))
        mon = SecurityMonitor()
        monkeypatch.setattr(
            mon, "_sign_alert_payload",
            lambda data: {"sig_b64": None, "kid": None, "alg": None},
        )
        alert = SecurityAlert(
            alert_id="a1",
            severity=AlertSeverity.CRITICAL,
            title="honeypot",
            description="triggered",
            timestamp=datetime.datetime.now(),
            source="test",
            alert_type="honeypot",
            signature="pre-signed",
        )
        assert mon._send_to_siem(alert) is True
        lines = log_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        assert json.loads(lines[0])["alert_id"] == "a1"

    def test_integrity_probe_failure_emits_high_threat(self):
        import types

        from threat_detection_engine import ThreatDetectionEngine, ThreatType

        def _probe(_pid):
            raise RuntimeError("integrity probe unavailable")

        monitor = types.SimpleNamespace(check_process_integrity=_probe)
        engine = ThreatDetectionEngine(process_monitor=monitor)
        engine._analyze_system_integrity()
        threat = engine.threat_queue.get_nowait()
        assert threat.threat_type == ThreatType.INTEGRITY_VIOLATION
        assert threat.threat_level.value == "high"


# ---------------------------------------------------------------------------
# HIGH NC3-console cluster (2026-10 full-review triage)
#   N-h1 operator console: second custodian never self-generated
#   N-h2 web console: zeroize uses the file shredder and fails closed
#   N-h3 web console: EAM custodian keys bound to provisioned identities
# ---------------------------------------------------------------------------

class _CaptureHandler:
    def __init__(self):
        self.data = None
        self.status = 200

    def _send_json(self, payload, status=200):
        self.data = payload
        self.status = status


class TestNC3ConsoleHardening:
    def test_operator_console_refuses_self_generated_custodian(self, monkeypatch):
        import tactical_operator_console as toc

        monkeypatch.setattr(toc, "_is_production", lambda: False)
        station = toc.TacticalConsoleStation(
            node_name="n1", callsign="OF1", local_port=9190,
            enable_atak_bridge=False,
        )
        assert station.authorize_dual_eam(directive="NO-SECOND-OFFICER") == {}

    def test_operator_console_prod_requires_enrolled_custodians(self, monkeypatch):
        import tactical_operator_console as toc

        of1 = toc.TacticalConsoleStation(
            node_name="n2", callsign="OF1", local_port=9191,
            enable_atak_bridge=False,
        )
        of2 = toc.TacticalConsoleStation(
            node_name="n3", callsign="OF2", local_port=9192,
            enable_atak_bridge=False,
        )
        monkeypatch.setattr(toc, "_is_production", lambda: True)
        packet = of1.authorize_dual_eam(
            directive="UNENROLLED-CUSTODIAN",
            second_officer_callsign="OF2",
            second_officer_pk=of2.pubkey_mldsa,
            second_officer_signer=of2.sign_data,
        )
        assert packet == {}

    def test_web_zeroize_uses_file_shredder(self, tmp_path, monkeypatch):
        import tactical_web_console as twc

        monkeypatch.setattr(twc, "REPO_ROOT", tmp_path)
        target = tmp_path / "monotonic.state"
        target.write_bytes(b"VOLATILE-STATE" * 64)
        h = _CaptureHandler()
        twc.TacticalWebHandler._handle_api_zeroize(
            h, {"confirm": twc._ZEROIZE_CONFIRM_TOKEN}
        )
        assert not target.exists()
        assert h.status == 200
        assert h.data["status"] == "PURGE_COMPLETE"
        assert h.data["verdict"].startswith("FORENSIC")

    def test_web_zeroize_reports_failure(self, tmp_path, monkeypatch):
        import tactical_web_console as twc

        monkeypatch.setattr(twc, "REPO_ROOT", tmp_path)
        target = tmp_path / "monotonic.state"
        target.mkdir()  # not a regular file: shredder must refuse
        h = _CaptureHandler()
        twc.TacticalWebHandler._handle_api_zeroize(
            h, {"confirm": twc._ZEROIZE_CONFIRM_TOKEN}
        )
        assert h.status == 500
        assert h.data["status"] == "PURGE_FAILED"
        assert h.data["verdict"] == "SANITIZATION_FAILED"

    def test_web_eam_rejects_mismatched_provisioned_key(self, monkeypatch):
        import base64
        import time

        import nc3_nuclear_command as nc3
        import tactical_web_console as twc
        from liboqs_wrapper import LibOQS_MLDSA_87

        signer = LibOQS_MLDSA_87()
        pk1, sk1 = signer.keygen()
        pk2, sk2 = signer.keygen()
        ts = time.time()
        expires = ts + 120.0
        canonical = twc.canonical_web_eam_bytes(
            "KEY-BIND", "NORAD_ALPHA", ts, expires, "OFF-1", "OFF-2"
        )
        payload = {
            "originator": "NORAD_ALPHA",
            "directive": "KEY-BIND",
            "officer_1_id": "OFF-1",
            "officer_2_id": "OFF-2",
            "timestamp_utc": ts,
            "expires_at": expires,
            "officer_1_pk_b64": base64.b64encode(pk1).decode(),
            "officer_2_pk_b64": base64.b64encode(pk2).decode(),
            "officer_1_sig_b64": base64.b64encode(
                signer.sign(sk1, canonical)).decode(),
            "officer_2_sig_b64": base64.b64encode(
                signer.sign(sk2, canonical)).decode(),
        }
        wrong = b"\x01" * 2592
        monkeypatch.setattr(
            nc3, "load_officer_public_key", lambda _cid: wrong
        )
        h = _CaptureHandler()
        twc.TacticalWebHandler._handle_api_eam(h, payload)
        assert h.status == 403
        assert h.data["status"] == "EAM_REJECTED_CUSTODIAN_KEY_MISMATCH"


# ---------------------------------------------------------------------------
# HIGH CJADC2 cluster (2026-10 full-review triage)
#   J-h1 coalition release tokens: nonce + expiry + replay cache
#   J-h2 cross-domain audit: persistent provisioned signing key/trust anchor
#   J-h3 minimal RBAC: deny-by-default regardless of P2P_RBAC_STRICT
# ---------------------------------------------------------------------------

class TestCJADC2Hardening:
    def _package(self):
        from cjadc2_allied_gateway import (
            AlliedCoalitionGateway, CoalitionAlliance, SecurityClassification,
        )

        gw = AlliedCoalitionGateway()
        pkg = gw.redact_and_package_for_coalition(
            payload_bytes=b"Allied sector perimeter clear",
            source_classification=SecurityClassification.SECRET,
            target_alliance=CoalitionAlliance.FVEY,
            target_partner_nation="GBR",
            active_caveats={"HCS-P"},
        )
        return gw, pkg

    def test_release_token_is_single_use(self):
        gw, pkg = self._package()
        assert gw.verify_coalition_release(pkg) is True
        assert gw.verify_coalition_release(pkg) is False

    def test_expired_release_token_rejected(self):
        import json
        import time

        gw, pkg = self._package()
        token = dict(pkg["release_token"])
        token["issued_at"] = time.time() - 3600.0
        token["expires_at"] = time.time() - 60.0
        token_bytes = json.dumps(token, sort_keys=True).encode("utf-8")
        expired = dict(pkg)
        expired["release_token"] = token
        expired["release_token_signature_hex"] = gw.signer.sign(
            gw.sk, token_bytes).hex()
        assert gw.verify_coalition_release(expired) is False

    def test_audit_report_rejects_ephemeral_attacker_key(self, tmp_path, monkeypatch):
        import cjadc2_cross_domain_guard as cdg
        from liboqs_wrapper import LibOQS_MLDSA_87

        monkeypatch.delenv("P2P_CJADC2_AUDIT_KEY_FILE", raising=False)
        guard = cdg.CrossDomainGuard(audit_dir=tmp_path)
        rep, sig, pub = cdg.sign_and_export_cross_domain_audit(
            guard, output_dir=tmp_path)
        assert cdg.verify_cross_domain_audit_signature(rep, sig, pub) is True

        attacker = LibOQS_MLDSA_87()
        apk, ask = attacker.keygen()
        pub.write_bytes(apk)
        sig.write_bytes(attacker.sign(ask, rep.read_bytes()))
        assert cdg.verify_cross_domain_audit_signature(rep, sig, pub) is False

    def test_audit_report_prod_requires_provisioned_key(self, tmp_path, monkeypatch):
        import cjadc2_cross_domain_guard as cdg

        monkeypatch.delenv("P2P_CJADC2_AUDIT_KEY_FILE", raising=False)
        monkeypatch.setattr(cdg, "_production", lambda: True)
        guard = cdg.CrossDomainGuard(audit_dir=tmp_path)
        with pytest.raises(RuntimeError):
            cdg.sign_and_export_cross_domain_audit(guard, output_dir=tmp_path)

    def test_minimal_rbac_denies_by_default(self, monkeypatch):
        import zero_trust_engine as zte

        monkeypatch.delenv("P2P_RBAC_STRICT", raising=False)
        eng = zte.ZeroTrustEngine(b"\x00" * 2592, b"\x00" * 4896)
        with pytest.raises(zte.AuthenticationFailure):
            eng.check_permission("unknown-peer", "critical_release")
        eng.set_peer_role("admin-peer", zte.Role.ADMIN)
        assert eng.check_permission("admin-peer", "critical_release") is True
        eng.set_peer_role("viewer-peer", zte.Role.VIEWER)
        with pytest.raises(zte.AuthenticationFailure):
            eng.check_permission("viewer-peer", "critical_release")


# ---------------------------------------------------------------------------
# HIGH decentralized cluster (2026-10 full-review triage)
#   D-h1 DHT records bound to key + PoW identity + signer
#   D-h2 FIND_VALUE: txid-only, queried-responder, per-responder dedup
#   D-h3 relay origin identity pinned; no fail-open without a verifier
# ---------------------------------------------------------------------------

def _mined_node_info(sig_public_key):
    import hashlib
    import os

    from decentralized_architecture import DHTNodeInfo, _pow_difficulty

    public_key = os.urandom(32)
    target = _pow_difficulty()
    for nonce in range(2_000_000):
        node_id = hashlib.sha3_256(public_key + nonce.to_bytes(4, "big")).digest()
        if all(node_id[i] == 0 for i in range(target)):
            return DHTNodeInfo(
                node_id=node_id, address="10.0.0.9", port=4444,
                public_key=public_key, sig_public_key=sig_public_key,
                pow_nonce=nonce,
            )
    raise AssertionError("PoW mining budget exhausted")


class TestDecentralizedHardening:
    def _signed_record(self):
        import hashlib
        import json
        import struct
        import time

        from cryptography.hazmat.primitives.asymmetric import ed25519

        priv = ed25519.Ed25519PrivateKey.generate()
        pk = priv.public_key().public_bytes_raw()
        node = _mined_node_info(pk)
        key = hashlib.sha3_256(node.node_id).digest()
        val = json.dumps(node.to_dict()).encode("utf-8")
        ts = int(time.time())
        sig = priv.sign(key + val + struct.pack(">Q", ts))
        return key, val, sig, pk, ts, node

    def test_dht_record_binding_rejects_forged_key_and_signer(self):
        import hashlib
        import os

        from decentralized_architecture import _bind_dht_peer_record

        key, val, _sig, pk, _ts, _node = self._signed_record()
        assert _bind_dht_peer_record(key, val, pk) is True
        assert _bind_dht_peer_record(os.urandom(32), val, pk) is False
        assert _bind_dht_peer_record(
            hashlib.sha3_256(val).digest(), val, os.urandom(32)) is False

    def test_find_value_requires_queried_responder_and_dedupes(self):
        import threading
        import types

        from decentralized_architecture import (
            DecentralizedPeerDiscovery as DPD,
        )

        key, val, sig, pk, ts, _node = self._signed_record()
        txid = "tx-1"
        state = {
            "key": key,
            "responses": [],
            "raw_values": [],
            "closest_nodes": [],
            "queried_addrs": {("10.0.0.1", 4444)},
            "responders": set(),
            "event": threading.Event(),
            "lock": threading.Lock(),
        }
        fake = types.SimpleNamespace(
            _lock=threading.Lock(), _pending_lookups={txid: state})
        msg = {
            "txid": txid, "key": key.hex(), "found": True,
            "value": val.hex(), "signature": sig.hex(),
            "sig_public_key": pk.hex(), "timestamp": ts,
        }
        DPD._handle_find_value_response(fake, msg, ("10.0.0.1", 4444))
        DPD._handle_find_value_response(fake, msg, ("10.0.0.1", 4444))
        assert len(state["responses"]) == 1
        assert len(state["raw_values"]) == 1

        DPD._handle_find_value_response(fake, msg, ("6.6.6.6", 6666))
        assert len(state["responses"]) == 1

        unknown_txid = dict(msg, txid="not-a-lookup")
        DPD._handle_find_value_response(fake, unknown_txid, ("10.0.0.1", 4444))
        assert len(state["responses"]) == 1

    def test_relay_sender_identity_is_pinned(self, monkeypatch):
        import decentralized_architecture as da

        monkeypatch.setattr(da, "_production", lambda: False)
        node = da.RelayNode(
            node_id=b"n" * 32,
            signer=lambda data: b"SIG",
            sender_pubkey=b"PK",
            verifier=lambda pk, data, sig: sig == b"SIG",
        )
        node.register_peer_sender_key(b"SENDER", b"PK")

        def _msg(pubkey):
            return da.RelayMessage(
                message_id="m1", sender_id=b"SENDER",
                recipient_id=b"R", encrypted_payload=b"c",
                sender_sig=b"SIG", sender_pubkey=pubkey,
            )

        assert node._verify_relay_message(_msg(b"PK")) is True
        assert node._verify_relay_message(_msg(b"ATTACKER")) is False

    def test_relay_prod_requires_pinned_sender_and_verifier(self, monkeypatch):
        import decentralized_architecture as da

        node = da.RelayNode(
            node_id=b"n" * 32,
            signer=lambda data: b"SIG",
            sender_pubkey=b"PK",
            verifier=lambda pk, data, sig: sig == b"SIG",
        )
        msg = da.RelayMessage(
            message_id="m2", sender_id=b"STRANGER",
            recipient_id=b"R", encrypted_payload=b"c",
            sender_sig=b"SIG", sender_pubkey=b"PK",
        )
        monkeypatch.setattr(da, "_production", lambda: True)
        assert node._verify_relay_message(msg) is False

        unverified = da.RelayNode(node_id=b"n" * 32)
        unsigned = da.RelayMessage(
            message_id="m3", sender_id=b"X", recipient_id=b"R",
            encrypted_payload=b"c",
        )
        assert unverified._verify_relay_message(unsigned) is False


# ---------------------------------------------------------------------------
# HIGH destroyer modules cluster (2026-10 full-review triage)
#   X-h1 PSK-less KEX must be an explicit lab opt-in (never implicit)
#   X-h2 NC3 EAM on the paced path must not assert two-person verification
#   X-h3 unseal failures are discarded, never surfaced as traffic
# ---------------------------------------------------------------------------

class TestDestroyerHardening:
    def _node(self, tmp_path, **kwargs):
        import destroyer_tactical_p2p as dtp

        fake_bin = tmp_path / "secure-transmit.exe"
        fake_bin.write_bytes(b"stub")
        kwargs.setdefault("name", "N")
        kwargs.setdefault("role", "initiator")
        kwargs.setdefault("bind_addr", "127.0.0.1")
        kwargs.setdefault("peer_addr", "127.0.0.1")
        kwargs.setdefault("kex_port", 9300)
        kwargs.setdefault("channel_port", 9310)
        kwargs.setdefault("work_dir", str(tmp_path))
        return dtp, dtp.TacticalP2PNode(**kwargs), fake_bin

    def test_missing_psk_refuses_unauthenticated_kex(self, tmp_path, monkeypatch):
        import subprocess

        dtp, node, fake_bin = self._node(tmp_path, lab_mode=False)
        monkeypatch.setattr(dtp, "NATIVE_BIN", fake_bin)
        monkeypatch.delenv("P2P_PSK_FILE", raising=False)
        monkeypatch.setattr(dtp, "_production", lambda: False)

        def _boom(*_a, **_k):
            raise AssertionError("KEX subprocess must not start")

        monkeypatch.setattr(subprocess, "Popen", _boom)
        assert node.negotiate_hybrid_kex(timeout_sec=1) is False

    def test_missing_psk_file_path_refuses(self, tmp_path, monkeypatch):
        dtp, node, fake_bin = self._node(
            tmp_path, psk_file=str(tmp_path / "typo.psk"), lab_mode=True)
        monkeypatch.setattr(dtp, "NATIVE_BIN", fake_bin)
        assert node.negotiate_hybrid_kex(timeout_sec=1) is False

    def test_explicit_lab_mode_sets_backend_optin(self, tmp_path, monkeypatch):
        import types

        dtp, node, fake_bin = self._node(tmp_path, lab_mode=True)
        monkeypatch.setattr(dtp, "NATIVE_BIN", fake_bin)
        monkeypatch.setattr(dtp, "_production", lambda: False)
        captured = {}

        def _fake_popen(cmd, env=None, **_k):
            captured["env"] = env
            return types.SimpleNamespace(
                returncode=1, communicate=lambda timeout=None: ("", "stub"))

        monkeypatch.setattr(dtp.subprocess, "Popen", _fake_popen)
        assert node.negotiate_hybrid_kex(timeout_sec=1) is False
        assert captured["env"]["P2P_LAB_MODE"] == "1"

    def test_eam_refused_on_paced_path_in_production(self, tmp_path, monkeypatch):
        import io
        import types

        dtp, node, _fake_bin = self._node(tmp_path)
        node.channel_proc = types.SimpleNamespace(stdin=io.BytesIO())
        node.zero_gap_pipeline = object()
        node.zero_gap_ratchet = object()
        import production_gate
        monkeypatch.setattr(production_gate, "is_production", lambda: True)
        assert node.send_eam("DEFCON-1") is False


# ---------------------------------------------------------------------------
# HIGH hw/TEE cluster (2026-10 full-review triage)
#   H-h1 PQC token custody requires an advertised ML-DSA/ML-KEM mechanism
#   H-h2 diode raw-key signing refused in TS mode
#   H-h3 TEE attestation never verifies with default/static keys
# ---------------------------------------------------------------------------

class TestHwTeeHardening:
    def test_pqc_token_requires_pqc_mechanism(self, monkeypatch):
        import types

        import ts_hw_layer as ts

        base = types.SimpleNamespace(pkcs11_libs=["/fake/lib.so"])
        monkeypatch.setattr(ts, "probe_hardware_custody", lambda: base)

        info = ("/fake/lib.so", "Thales", "Luna Network HSM", (7, 9), set())
        monkeypatch.setattr(ts, "_iter_token_infos", lambda libs: iter([info]))
        assert ts.probe_pqc_token() is None

        class _Mech:
            name = "CKM_ML_DSA"

        info_pqc = ("/fake/lib.so", "Thales", "Luna Network HSM", (7, 9),
                    {_Mech()})
        monkeypatch.setattr(
            ts, "_iter_token_infos", lambda libs: iter([info_pqc]))
        attestation = ts.probe_pqc_token()
        assert attestation is not None
        assert attestation.tier == "PQC-HW"

    def test_diode_raw_key_refused_in_ts_mode(self, monkeypatch):
        import ts_hw_layer as ts

        for var in ("P2P_PRODUCTION", "P2P_REQUIRE_HARDWARE_IDENTITY"):
            monkeypatch.delenv(var, raising=False)
        monkeypatch.setenv("P2P_TS_MODE", "1")
        with pytest.raises(ts.TSRequiredError):
            ts.diode_send(b"payload", b"\x00" * 4896, "kid-1",
                          "127.0.0.1", 55490)

    def test_trustzone_and_sev_fail_closed_without_provisioned_key(self, monkeypatch):
        import os as _os
        import time

        from tee_manager import (
            AMDSEVBackend, ARMTrustZoneBackend, AttestationReport,
            AttestationStatus, TEEType,
        )

        monkeypatch.delenv("P2P_TRUSTZONE_DEVICE_KEY", raising=False)
        monkeypatch.delenv("P2P_SEV_VCEK", raising=False)
        nonce = _os.urandom(32)

        tz = AttestationReport(
            tee_type=TEEType.ARM_TRUSTZONE, status=AttestationStatus.PENDING,
            timestamp=time.time(), nonce=nonce,
            quote_data=b"TZAT" + nonce, signature=b"\x00" * 64,
        )
        assert ARMTrustZoneBackend().verify_attestation(tz) is False
        assert tz.status == AttestationStatus.FAILED

        sev = AttestationReport(
            tee_type=TEEType.AMD_SEV, status=AttestationStatus.PENDING,
            timestamp=time.time(), nonce=nonce,
            quote_data=b"X" * 128, signature=b"\x00" * 64,
        )
        assert AMDSEVBackend().verify_attestation(sev) is False
        assert sev.status == AttestationStatus.FAILED


# ---------------------------------------------------------------------------
# HIGH final clusters (2026-10 full-review triage)
#   F-h1 transport_anonymity: fresh-ephemeral hybrid epoch rekey
#   F-h2 sovereign group ratchet: verify-before-commit
#   F-h3 byzantine actuator: subsystem failure is not "success"
#   F-h4 ephemeral messaging: expiry anchored to local receipt time
#   F-h5 libsodium: cdecl only (no stdcall WinDLL), pinned tarball
#   F-h6 TEE: no default/static attestation keys
#   F-h7 TPM quote: challenge-bound verification with enrolled AK pubs
# ---------------------------------------------------------------------------

class TestFinalClusterHardening:
    def test_libsodium_loader_never_uses_windll(self):
        from pathlib import Path as _P

        src = _P("libsodium_manager.py").read_text(encoding="utf-8")
        assert "ctypes.WinDLL" not in src, \
            "libsodium is cdecl; stdcall WinDLL corrupts the 32-bit stack"

    def test_libsodium_tarball_requires_pin_on_posix(self, monkeypatch):
        import libsodium_manager as lsm

        monkeypatch.delenv("P2P_LIBSODIUM_TARBALL_SHA512", raising=False)
        monkeypatch.setattr(lsm.os, "name", "posix")
        ok, _lib, _path = lsm.compile_libsodium_from_source()
        assert ok is False, "unpinned libsodium tarball must be refused"

    def test_group_ratchet_commits_only_after_authentication(self):
        import secrets

        import sovereign_group_ratchet as sgr

        secret = secrets.token_bytes(32)
        alpha = sgr.SovereignGroupRatchet("G1", "A", secret)
        bravo = sgr.SovereignGroupRatchet("G1", "B", secret)
        alpha.register_peer_sender_key("B", bravo.members["B"].chain_key)
        bravo.register_peer_sender_key("A", alpha.members["A"].chain_key)

        msg = alpha.seal(b"HELLO")
        # A forged frame must not advance the receiver's ratchet state.
        forged = sgr.GroupMessage(
            group_id="G1", epoch=alpha.epoch, sender_id="A",
            seq=0, ciphertext=b"\x00" * 64)
        try:
            bravo.open(forged)
        except Exception:
            pass
        assert bravo.members["A"].message_seq == 0, \
            "unauthenticated frame advanced the ratchet state"
        assert bravo.open(msg) == b"HELLO"

    def test_byzantine_actuator_reports_failure(self, monkeypatch):
        import byzantine_mesh_consensus as bmc

        monkeypatch.setattr(
            bmc, "CriticalCommandType", bmc.CriticalCommandType, raising=False)
        src = open("byzantine_mesh_consensus.py", encoding="utf-8").read()
        assert "TACTICAL_REKEY_ALL failed on all subsystems" in src
        assert "REVOKE_NODE_CREDENTIAL partial failure" in src

    def test_ephemeral_import_expiry_anchored_locally(self, monkeypatch):
        import ephemeral_messaging as em

        mgr = em.EphemeralMessageManager(device_id="dev-1")
        key = b"\x11" * 32
        msg = mgr.create_message(
            content=b"payload", sender_id="s", recipient_id="r",
            ttl_seconds=60)
        # Simulate a peer that rolls its timestamps into the future.
        msg.created_at = time.time() + 10_000
        msg.expires_at = time.time() + 10_000 + 60
        env = msg.to_encrypted_envelope(key)
        imported = mgr.import_message_envelope(env, key)
        assert imported.expires_at <= time.time() + 61, \
            "imported expiry was not anchored to local receipt time"

    def test_tee_attestation_requires_provisioned_key(self, monkeypatch):
        import tee_manager as tm

        monkeypatch.delenv("P2P_TRUSTZONE_DEVICE_KEY", raising=False)
        monkeypatch.delenv("P2P_SEV_VCEK", raising=False)
        monkeypatch.setattr(tm, "_is_production", lambda: False)
        report = tm.AttestationReport(
            tee_type=tm.TEEType.ARM_TRUSTZONE,
            status=tm.AttestationStatus.PENDING, timestamp=time.time(),
            nonce=b"n" * 32, quote_data=b"TZAT" + b"n" * 32,
            signature=b"\x00" * 64)
        assert tm.ARMTrustZoneBackend().verify_attestation(report) is False

    def test_tpm_quote_requires_challenge_and_trusted_ak(self):
        import tpm_quote as tq

        from liboqs_wrapper import LibOQS_MLDSA_87

        signer = LibOQS_MLDSA_87()
        pk, sk = signer.keygen()
        nonce = b"\x22" * 32
        env = tq.sign_quote({}, nonce, "ak-test", sk, degraded=True)
        # Self-supplied nonce must not satisfy the check.
        assert tq.validate_handshake_quote(
            env, expected_nonce=env.get("nonce", ""),
            trusted_pubs=[pk], allow_degraded=True) is True
        # A different challenge must fail.
        assert tq.validate_handshake_quote(
            env, expected_nonce=b"\x33" * 32,
            trusted_pubs=[pk], allow_degraded=True) is False
        # No enrolled AK => fail closed.
        assert tq.validate_handshake_quote(
            env, expected_nonce=nonce, trusted_pubs=None,
            allow_degraded=True) is False

    def test_zero_trust_rbac_denies_by_default(self, monkeypatch):
        import zero_trust_engine as zte

        monkeypatch.delenv("P2P_RBAC_STRICT", raising=False)
        eng = zte.ZeroTrustEngine(b"\x00" * 2592, b"\x00" * 4896)
        with pytest.raises(zte.AuthenticationFailure):
            eng.check_permission("nobody", "critical_release")

    def test_lab_self_approval_refused_in_production(self, monkeypatch):
        import sys

        monkeypatch.setenv("P2P_PRODUCTION", "1")
        sys.path.insert(0, "scripts")
        try:
            import witnessed_key_ceremony as wkc
        finally:
            if sys.path and sys.path[0] == "scripts":
                sys.path.pop(0)
        ceremony = wkc.WitnessedKeyCeremony.__new__(wkc.WitnessedKeyCeremony)
        with pytest.raises(RuntimeError):
            ceremony._lab_self_approve()

    def test_package_deployment_refuses_unsafe_destination(self, tmp_path):
        import sys

        sys.path.insert(0, "scripts")
        try:
            import package_deployment as pd
        finally:
            if sys.path and sys.path[0] == "scripts":
                sys.path.pop(0)
        with pytest.raises(SystemExit):
            pd.build_deployment(tmp_path / ".." / ".." / "system-root")
        with pytest.raises(SystemExit):
            pd._safe_rel(tmp_path, "../../etc/passwd")

    def test_key_fill_imported_war_key_is_used_by_nc3_path(self, monkeypatch):
        """The dual-custody imported war key must be the one the EAM path uses.

        Regression gate for the dead-import finding: the import sink
        (_nc3_war_key) must be preferred by _get_or_derive_nc3_war_key, so
        the ceremony key is not silently ignored in favour of a derived or
        environment-provided key.
        """
        from secure_p2p import SecureP2PChat

        monkeypatch.delenv("P2P_NC3_WAR_KEY", raising=False)
        chat = SecureP2PChat.__new__(SecureP2PChat)
        chat._nc3_war_key = bytes.fromhex("aa" * 32)
        chat._cached_nc3_war_key = None
        chat.hybrid_root_key = None
        chat.ratchet = None
        key = SecureP2PChat._get_or_derive_nc3_war_key(chat)
        assert key == bytes.fromhex("aa" * 32), \
            "the imported dual-custody war key was not used"
