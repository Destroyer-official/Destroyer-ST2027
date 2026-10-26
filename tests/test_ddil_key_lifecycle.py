# Destroyer-ST2027 Military Production Hardening Release (2026-10-26)
# NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204
import json
import secrets
import unittest
import uuid

from cjadc2_tactical_cot import CoTEventType, TacticalCoTEvent
from liboqs_wrapper import LibOQS_MLDSA_87
from tactical_mesh_ddil import (
    TacticalKeyring,
    _bundle_aad,
    _derive_bundle_key,
    create_bpsec_bundle,
    decrypt_bpsec_bundle,
    get_tactical_keyring,
)


class TestDDILKeyLifecycle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signer = LibOQS_MLDSA_87()
        cls.pk, cls.sk = cls.signer.keygen()

    def setUp(self):
        self.ring = get_tactical_keyring()
        self.suffix = uuid.uuid4().hex[:10]
        self.sender = f"COMMAND_{self.suffix}"
        self.recipient = f"OUTPOST_{self.suffix}"

    def tearDown(self):
        self.ring.remove_epoch_keys(self.sender)
        self.ring.remove_epoch_keys(self.recipient)

    def _bundle(self, root_key=None, recipient=None, epoch=1, seq=7):
        return create_bpsec_bundle(
            sender_id=self.sender,
            recipient_id=recipient or self.recipient,
            seq=seq,
            payload_plaintext=b"TACTICAL_EPOCH_KEY_LIFECYCLE",
            sender_sk=self.sk,
            sender_pk=self.pk,
            symmetric_key=root_key,
            key_epoch=epoch,
        )

    def test_derived_keys_are_bound_to_peer_sequence_and_epoch(self):
        root = secrets.token_bytes(32)
        base = _derive_bundle_key(root, "A", "B", 1, 1)
        self.assertEqual(len(base), 32)
        self.assertNotEqual(base, root)
        self.assertNotEqual(base, _derive_bundle_key(root, "A", "C", 1, 1))
        self.assertNotEqual(base, _derive_bundle_key(root, "A", "B", 2, 1))
        self.assertNotEqual(base, _derive_bundle_key(root, "A", "B", 1, 2))

    def test_keyring_resolves_and_decrypts_without_external_key(self):
        root = secrets.token_bytes(32)
        key_id = self.ring.register_epoch_key(self.recipient, root, 1)
        bundle = self._bundle()
        self.assertEqual(bundle.key_epoch, 1)
        self.assertEqual(bundle.encryption_key_id, key_id)
        self.assertEqual(
            decrypt_bpsec_bundle(bundle, expected_sender_pk=self.pk),
            b"TACTICAL_EPOCH_KEY_LIFECYCLE",
        )

    def test_wrong_epoch_root_is_rejected_by_key_id(self):
        root = secrets.token_bytes(32)
        self.ring.register_epoch_key(self.recipient, root, 1)
        bundle = self._bundle()
        with self.assertRaisesRegex(ValueError, "key ID mismatch"):
            decrypt_bpsec_bundle(
                bundle,
                symmetric_key=secrets.token_bytes(32),
                expected_sender_pk=self.pk,
            )

    def test_missing_pre_pinned_key_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "no pre-pinned DDIL epoch key"):
            self._bundle()

    def test_rotation_keeps_recent_epochs_and_retires_old_ones(self):
        first_root = secrets.token_bytes(32)
        _, first_id = self.ring.rotate_epoch_key(self.recipient, first_root)
        first_bundle = self._bundle()

        second_epoch, second_id = self.ring.rotate_epoch_key(self.recipient)
        second_bundle = self._bundle()
        self.assertEqual(second_epoch, 2)
        self.assertEqual(second_bundle.key_epoch, 2)
        self.assertNotEqual(first_id, second_id)
        self.assertEqual(
            decrypt_bpsec_bundle(first_bundle, expected_sender_pk=self.pk),
            b"TACTICAL_EPOCH_KEY_LIFECYCLE",
        )
        self.assertEqual(
            decrypt_bpsec_bundle(second_bundle, expected_sender_pk=self.pk),
            b"TACTICAL_EPOCH_KEY_LIFECYCLE",
        )

        for _ in range(TacticalKeyring.EPOCH_RETENTION):
            self.ring.rotate_epoch_key(self.recipient)
        self.assertIsNone(self.ring.get_epoch_key_by_id(first_id))
        with self.assertRaisesRegex(ValueError, "no DDIL epoch key available"):
            decrypt_bpsec_bundle(first_bundle, expected_sender_pk=self.pk)
        self.assertEqual(
            decrypt_bpsec_bundle(
                first_bundle,
                symmetric_key=first_root,
                expected_sender_pk=self.pk,
            ),
            b"TACTICAL_EPOCH_KEY_LIFECYCLE",
        )

    def test_wipe_removes_keyring_material(self):
        root = secrets.token_bytes(32)
        key_id = self.ring.register_epoch_key(self.recipient, root, 1)
        bundle = self._bundle()
        self.ring.wipe_epoch_keys()
        self.assertIsNone(self.ring.get_epoch_key_by_id(key_id))
        with self.assertRaisesRegex(ValueError, "no DDIL epoch key available"):
            decrypt_bpsec_bundle(bundle, expected_sender_pk=self.pk)

    def test_remove_epoch_key_wipes_underlying_buffer(self):
        root = bytearray(secrets.token_bytes(32))
        key_id = self.ring.register_epoch_key(self.recipient, bytes(root), 5)
        internal_buf = self.ring._epoch_by_node[self.recipient][5][0]
        self.assertEqual(bytes(internal_buf), bytes(root))
        removed = self.ring.remove_epoch_key(self.recipient, 5)
        self.assertTrue(removed)
        self.assertEqual(bytes(internal_buf), b"\x00" * 32)
        self.assertIsNone(self.ring.get_epoch_key(self.recipient, 5))
        self.assertIsNone(self.ring.get_epoch_key_by_id(key_id))

    def test_legacy_aad_is_stable(self):
        self.assertEqual(
            _bundle_aad("SENDER", "RECIPIENT", 9, 0, None),
            b"SENDERRECIPIENT",
        )

    def test_cot_bundle_uses_same_epoch_derivation(self):
        root = secrets.token_bytes(32)
        event = TacticalCoTEvent(
            event_type=CoTEventType.FRIENDLY_GROUND_COMBAT,
            lat=34.55,
            lon=43.12,
            callsign="VIPER_01",
        )
        bundle = event.to_ddil_bundle(
            self.sender,
            self.recipient,
            seq=21,
            symmetric_key=root,
            key_epoch=3,
        )
        bundle.sign_bundle(self.signer, self.sk, self.pk)
        recovered = decrypt_bpsec_bundle(
            bundle, symmetric_key=root, expected_sender_pk=self.pk
        )
        self.assertEqual(
            recovered,
            json.dumps(event.to_compact_json()).encode("utf-8"),
        )

    def test_cot_bundle_resolves_keyring_epoch(self):
        root = secrets.token_bytes(32)
        self.ring.register_epoch_key(self.recipient, root, 2)
        event = TacticalCoTEvent(
            event_type=CoTEventType.FRIENDLY_GROUND_COMBAT,
            lat=34.55,
            lon=43.12,
            callsign="VIPER_02",
        )
        bundle = event.to_ddil_bundle(self.sender, self.recipient, seq=22)
        self.assertEqual(bundle.key_epoch, 2)
        bundle.sign_bundle(self.signer, self.sk, self.pk)
        self.assertEqual(
            decrypt_bpsec_bundle(bundle, expected_sender_pk=self.pk),
            json.dumps(event.to_compact_json()).encode("utf-8"),
        )


if __name__ == "__main__":
    unittest.main()
