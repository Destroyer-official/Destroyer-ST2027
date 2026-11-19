#!/usr/bin/env python3
"""
tests/test_dtn_zero_rtt_mesh.py
===============================
Comprehensive verification suite for Phase G: Asynchronous DTN & 0-RTT Post-Quantum Mesh.
Validates RFC 9171 BPv7, 0-RTT ML-KEM-1024 + ML-DSA-87 envelopes, CGR, PRoPHET, and custody transfer.
"""

import os
import sys
import time
import secrets
import unittest
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from network.dtn_mesh_router import (
    DtnMeshRouter,
    DtnPriority,
    CustodyStatus,
    BundleStore,
    ContactGraphRouter,
    ContactPlanEntry,
    ProphetRouter,
    DtnBundleRecord,
    HopLimitExceededError,
    BundleExpiredError,
    BundleTamperedError,
    current_dtn_time_ms,
)
from destroyer_core import CoreDtnBundle, IS_NATIVE


class TestDtnZeroRttMesh(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node_ground = DtnMeshRouter("dtn://ground-nmcc")
        cls.node_sat = DtnMeshRouter("dtn://sat-relay-01")
        cls.node_sub = DtnMeshRouter("dtn://sub-titan-04")

    # =========================================================================
    # 1. 0-RTT Post-Quantum Envelope Tests
    # =========================================================================

    def test_01_0rtt_bundle_creation_and_delivery_roundtrip(self):
        """Verify 0-RTT ML-KEM-1024 encryption and local delivery."""
        payload = b"CRITICAL-FLASH-ORDER-4096-ALPHA"
        bundle_rec = self.node_ground.create_and_send_0rtt_bundle(
            destination_eid=self.node_sub.node_eid,
            payload=payload,
            recipient_mlkem_pk=self.node_sub.mlkem_pk,
            priority=DtnPriority.EMERGENCY_NC3,
        )
        self.assertIsNotNone(bundle_rec)
        self.assertTrue(len(bundle_rec.wire_bytes) > 8000)  # PQC signatures & ciphertexts

        # Simulate transmission to destination
        delivered, plaintext = self.node_sub.receive_bundle(
            bundle_rec.wire_bytes,
            ingress_node_eid=self.node_ground.node_eid,
        )
        self.assertTrue(delivered)
        self.assertEqual(plaintext, payload)

    def test_02_0rtt_simplex_security_no_interactive_handshake(self):
        """Verify simplex 0-RTT delivery without any reverse communication channel."""
        fresh_sub = DtnMeshRouter("dtn://deep-sub-simplex")
        secret_msg = b"SUBTERRANEAN-ONE-WAY-TRANSMISSION-TEST"

        bundle = self.node_ground.create_and_send_0rtt_bundle(
            destination_eid=fresh_sub.node_eid,
            payload=secret_msg,
            recipient_mlkem_pk=fresh_sub.mlkem_pk,
            priority=DtnPriority.FLASH,
        )

        # Receiver has zero prior knowledge of sender session state
        delivered, decrypted = fresh_sub.receive_bundle(
            bundle.wire_bytes,
            ingress_node_eid="dtn://optical-diode-uplink",
        )
        self.assertTrue(delivered)
        self.assertEqual(decrypted, secret_msg)

    def test_03_bundle_tampered_ciphertext_fails_closed(self):
        """Verify that any modification to ciphertext in flight causes AEAD verification to fail."""
        payload = b"SECRET-COMMAND-DO-NOT-CORRUPT"
        bundle = self.node_ground.create_and_send_0rtt_bundle(
            destination_eid=self.node_sub.node_eid,
            payload=payload,
            recipient_mlkem_pk=self.node_sub.mlkem_pk,
        )

        tampered_wire = bytearray(bundle.wire_bytes)
        # Flip a bit in the encrypted payload area
        tampered_wire[-5000] ^= 0x01

        with self.assertRaises(BundleTamperedError):
            self.node_sub.receive_bundle(bytes(tampered_wire), ingress_node_eid=self.node_ground.node_eid)

    def test_04_bundle_tampered_mldsa_signature_fails_closed(self):
        """Verify that forged or altered ML-DSA-87 signatures fail closed."""
        bundle = self.node_ground.create_and_send_0rtt_bundle(
            destination_eid=self.node_sub.node_eid,
            payload=b"AUTHENTICATED-DATA",
            recipient_mlkem_pk=self.node_sub.mlkem_pk,
        )

        tampered_wire = bytearray(bundle.wire_bytes)
        # Flip a bit in the ML-DSA-87 signature (last bytes)
        tampered_wire[-10] ^= 0xFF

        with self.assertRaises(BundleTamperedError):
            self.node_sub.receive_bundle(bytes(tampered_wire), ingress_node_eid=self.node_ground.node_eid)

    def test_05_bundle_tampered_primary_header_fails_closed(self):
        """Verify that tampering with destination EID in primary header breaks signature binding."""
        bundle = self.node_ground.create_and_send_0rtt_bundle(
            destination_eid=self.node_sub.node_eid,
            payload=b"HEADER-INTEGRITY-TEST",
            recipient_mlkem_pk=self.node_sub.mlkem_pk,
        )

        tampered_wire = bytearray(bundle.wire_bytes)
        # Corrupt flag byte
        tampered_wire[8] ^= 0xFF

        with self.assertRaises(BundleTamperedError):
            self.node_sub.receive_bundle(bytes(tampered_wire), ingress_node_eid=self.node_ground.node_eid)

    # =========================================================================
    # 2. Hop Limits & Lifetime Expiration Tests
    # =========================================================================

    def test_06_hop_limit_enforcement_drops_loops(self):
        """Verify bundle is dropped when hop count reaches hop limit."""
        relay_node = DtnMeshRouter("dtn://loop-relay")
        bundle = self.node_ground.create_and_send_0rtt_bundle(
            destination_eid="dtn://far-station",
            payload=b"LOOP-TEST",
            recipient_mlkem_pk=self.node_sub.mlkem_pk,
            hop_limit=2,
        )

        # Hop 1
        delivered, _ = relay_node.receive_bundle(bundle.wire_bytes, ingress_node_eid="node-0")
        self.assertFalse(delivered)

        # Hop 2
        fwd_rec = relay_node.storage.get(bundle.bundle_id)
        self.assertIsNotNone(fwd_rec)
        delivered, _ = relay_node.receive_bundle(fwd_rec.wire_bytes, ingress_node_eid="node-1")
        self.assertFalse(delivered)

        # Hop 3 -> Should exceed hop limit (2) and raise HopLimitExceededError
        fwd_rec2 = relay_node.storage.get(bundle.bundle_id)
        with self.assertRaises(HopLimitExceededError):
            relay_node.receive_bundle(fwd_rec2.wire_bytes, ingress_node_eid="node-2")

    def test_07_lifetime_expiration_prunes_and_drops(self):
        """Verify expired bundles are refused and pruned from store."""
        store = BundleStore()
        now_ms = current_dtn_time_ms()

        # Add valid bundle
        rec_valid = DtnBundleRecord(
            bundle_id="valid-1",
            source_eid="src",
            destination_eid="dst",
            report_to_eid="rep",
            creation_time_ms=now_ms,
            sequence=1,
            lifetime_ms=60_000,
            priority=DtnPriority.PRIORITY,
            hop_limit=10,
            hop_count=0,
            age_ms=0,
            previous_node=None,
            is_encrypted=True,
            wire_bytes=b"valid",
            received_time_ms=now_ms,
        )
        store.add(rec_valid)

        # Add expired bundle
        rec_expired = DtnBundleRecord(
            bundle_id="expired-1",
            source_eid="src",
            destination_eid="dst",
            report_to_eid="rep",
            creation_time_ms=now_ms - 20_000,
            sequence=2,
            lifetime_ms=10_000,
            priority=DtnPriority.ROUTINE,
            hop_limit=10,
            hop_count=0,
            age_ms=0,
            previous_node=None,
            is_encrypted=True,
            wire_bytes=b"expired",
            received_time_ms=now_ms - 20_000,
        )
        store.add(rec_expired)

        # Prune
        purged = store.prune_expired(now_ms)
        self.assertIn("expired-1", purged)
        self.assertNotIn("valid-1", purged)
        self.assertEqual(len(store), 1)

    # =========================================================================
    # 3. Multi-Priority Queue & Quota Tests
    # =========================================================================

    def test_08_multi_priority_queueing_emergency_nc3_preemption(self):
        """Verify that EMERGENCY_NC3 bundles are popped ahead of ROUTINE and FLASH bundles."""
        store = BundleStore()
        now_ms = current_dtn_time_ms()

        # Insert Routine first
        store.add(DtnBundleRecord(
            bundle_id="b-routine",
            source_eid="src",
            destination_eid="dst",
            report_to_eid="rep",
            creation_time_ms=now_ms,
            sequence=1,
            lifetime_ms=60_000,
            priority=DtnPriority.ROUTINE,
            hop_limit=10,
            hop_count=0,
            age_ms=0,
            previous_node=None,
            is_encrypted=False,
            wire_bytes=b"routine",
            received_time_ms=now_ms,
        ))

        # Insert Flash second
        store.add(DtnBundleRecord(
            bundle_id="b-flash",
            source_eid="src",
            destination_eid="dst",
            report_to_eid="rep",
            creation_time_ms=now_ms + 10,
            sequence=2,
            lifetime_ms=60_000,
            priority=DtnPriority.FLASH,
            hop_limit=10,
            hop_count=0,
            age_ms=0,
            previous_node=None,
            is_encrypted=False,
            wire_bytes=b"flash",
            received_time_ms=now_ms + 10,
        ))

        # Insert Emergency NC3 third
        store.add(DtnBundleRecord(
            bundle_id="b-nc3",
            source_eid="src",
            destination_eid="dst",
            report_to_eid="rep",
            creation_time_ms=now_ms + 20,
            sequence=3,
            lifetime_ms=60_000,
            priority=DtnPriority.EMERGENCY_NC3,
            hop_limit=10,
            hop_count=0,
            age_ms=0,
            previous_node=None,
            is_encrypted=False,
            wire_bytes=b"nc3",
            received_time_ms=now_ms + 20,
        ))

        # Pop order must be: NC3 (0), FLASH (1), ROUTINE (4)
        first = store.pop_highest_priority()
        second = store.pop_highest_priority()
        third = store.pop_highest_priority()

        self.assertEqual(first.bundle_id, "b-nc3")
        self.assertEqual(second.bundle_id, "b-flash")
        self.assertEqual(third.bundle_id, "b-routine")

    def test_09_storage_quota_pressure_eviction_protects_nc3(self):
        """Verify that under storage pressure, routine bundles are evicted while NC3 is kept."""
        store = BundleStore(max_storage_bundles=2)
        now_ms = current_dtn_time_ms()

        # Add NC3 bundle
        store.add(DtnBundleRecord(
            bundle_id="nc3-keeper",
            source_eid="src",
            destination_eid="dst",
            report_to_eid="rep",
            creation_time_ms=now_ms,
            sequence=1,
            lifetime_ms=60000,
            priority=DtnPriority.EMERGENCY_NC3,
            hop_limit=10,
            hop_count=0,
            age_ms=0,
            previous_node=None,
            is_encrypted=False,
            wire_bytes=b"1",
            received_time_ms=now_ms,
        ))

        # Add Routine bundle
        store.add(DtnBundleRecord(
            bundle_id="routine-victim",
            source_eid="src",
            destination_eid="dst",
            report_to_eid="rep",
            creation_time_ms=now_ms + 1,
            sequence=2,
            lifetime_ms=60000,
            priority=DtnPriority.ROUTINE,
            hop_limit=10,
            hop_count=0,
            age_ms=0,
            previous_node=None,
            is_encrypted=False,
            wire_bytes=b"2",
            received_time_ms=now_ms + 1,
        ))

        # Add another priority bundle; capacity is 2 so routine must be evicted
        store.add(DtnBundleRecord(
            bundle_id="flash-new",
            source_eid="src",
            destination_eid="dst",
            report_to_eid="rep",
            creation_time_ms=now_ms + 2,
            sequence=3,
            lifetime_ms=60000,
            priority=DtnPriority.FLASH,
            hop_limit=10,
            hop_count=0,
            age_ms=0,
            previous_node=None,
            is_encrypted=False,
            wire_bytes=b"3",
            received_time_ms=now_ms + 2,
        ))

        self.assertIsNotNone(store.get("nc3-keeper"))
        self.assertIsNotNone(store.get("flash-new"))
        self.assertIsNone(store.get("routine-victim"))

    # =========================================================================
    # 4. Routing Engines (CGR & PRoPHET) Tests
    # =========================================================================

    def test_10_contact_graph_routing_scheduled_ephemeris_path(self):
        """Verify Dijkstra shortest arrival computation across scheduled satellite contacts."""
        cgr = ContactGraphRouter()
        t0 = 1000

        # Ground -> LEO-Sat (Pass 1: t=1200 to 1800)
        cgr.add_contact(ContactPlanEntry("c1", "ground", "sat-leo", 1200, 1800, 1000000))
        # LEO-Sat -> GEO-Sat (Pass 2: t=1500 to 2200)
        cgr.add_contact(ContactPlanEntry("c2", "sat-leo", "sat-geo", 1500, 2200, 500000))
        # GEO-Sat -> Submarine (Pass 3: t=1900 to 2500)
        cgr.add_contact(ContactPlanEntry("c3", "sat-geo", "sub", 1900, 2500, 250000))

        route = cgr.compute_route("ground", "sub", current_time_ms=t0)
        self.assertIsNotNone(route)
        self.assertEqual(len(route), 3)
        self.assertEqual(route[0].contact_id, "c1")
        self.assertEqual(route[1].contact_id, "c2")
        self.assertEqual(route[2].contact_id, "c3")

    def test_11_prophet_routing_encounter_predictability(self):
        """Verify PRoPHET delivery predictability calculations and transitive updates."""
        prophet = ProphetRouter("node-A", p_encounter_init=0.8, p_transitivity_factor=0.5)

        # Encounter node B
        prophet.record_encounter("node-B")
        p_ab = prophet.get_predictability("node-B")
        self.assertAlmostEqual(p_ab, 0.8, places=3)

        # Update transitivity: B knows C with P(B, C) = 0.6
        prophet.update_transitivity("node-B", {"node-C": 0.6})
        p_ac = prophet.get_predictability("node-C")
        # P(A, C) = P(A, B) * P(B, C) * beta = 0.8 * 0.6 * 0.5 = 0.24
        self.assertAlmostEqual(p_ac, 0.24, places=3)

        # Forwarding decision
        self.assertTrue(prophet.should_forward("node-C", candidate_node_p=0.5))
        self.assertFalse(prophet.should_forward("node-C", candidate_node_p=0.1))

    # =========================================================================
    # 5. Store-and-Forward Mesh & Fast-Path Integration
    # =========================================================================

    def test_12_multi_hop_store_and_forward_custody_transfer(self):
        """Verify multi-hop store-and-forward traversal: Ground -> Sat -> Sub."""
        ground = DtnMeshRouter("dtn://silo-alpha")
        sat_relay = DtnMeshRouter("dtn://orbital-sat-relay")
        sub_dest = DtnMeshRouter("dtn://ssbn-sub-dest")

        order = b"EXECUTE-STRATEGIC-OPTION-ROMEO"
        bundle = ground.create_and_send_0rtt_bundle(
            destination_eid=sub_dest.node_eid,
            payload=order,
            recipient_mlkem_pk=sub_dest.mlkem_pk,
            priority=DtnPriority.EMERGENCY_NC3,
            hop_limit=10,
        )

        # Hop 1: Ground -> Sat Relay
        delivered_sat, _ = sat_relay.receive_bundle(bundle.wire_bytes, ingress_node_eid=ground.node_eid)
        self.assertFalse(delivered_sat)  # Stored for forward, not delivered locally

        sat_stored = sat_relay.storage.get(bundle.bundle_id)
        self.assertIsNotNone(sat_stored)
        self.assertEqual(sat_stored.hop_count, 1)

        # Hop 2: Sat Relay -> Sub Destination
        delivered_sub, decrypted_payload = sub_dest.receive_bundle(
            sat_stored.wire_bytes,
            ingress_node_eid=sat_relay.node_eid,
        )
        self.assertTrue(delivered_sub)
        self.assertEqual(decrypted_payload, order)

    def test_13_deduplication_anti_replay_cache(self):
        """Verify that identical replayed bundles are rejected by the bundle store."""
        store = BundleStore()
        rec = DtnBundleRecord(
            bundle_id="unique-b-1",
            source_eid="s",
            destination_eid="d",
            report_to_eid="r",
            creation_time_ms=1000,
            sequence=1,
            lifetime_ms=10000,
            priority=DtnPriority.ROUTINE,
            hop_limit=5,
            hop_count=0,
            age_ms=0,
            previous_node=None,
            is_encrypted=False,
            wire_bytes=b"data",
            received_time_ms=1000,
        )
        self.assertTrue(store.add(rec))
        self.assertFalse(store.add(rec))  # Second attempt returns False (duplicate)

    def test_14_native_rust_core_dtn_bundle_fast_path(self):
        """Verify native Rust CoreDtnBundle methods execute and match expectations."""
        self.assertTrue(IS_NATIVE)

        # Inspect headers of a newly minted bundle
        bundle = self.node_ground.create_and_send_0rtt_bundle(
            destination_eid="dtn://target-inspect",
            payload=b"NATIVE-FAST-PATH-DATA",
            recipient_mlkem_pk=self.node_sub.mlkem_pk,
        )

        headers = CoreDtnBundle.inspect_bundle(bundle.wire_bytes)
        src, dst, rep, cr_ms, seq, life, h_lim, h_cnt, age, prev, is_enc = headers
        self.assertEqual(src, self.node_ground.node_eid)
        self.assertEqual(dst, "dtn://target-inspect")
        self.assertEqual(h_cnt, 0)
        self.assertTrue(is_enc)


if __name__ == "__main__":
    unittest.main()
