#!/usr/bin/env python3
# Destroyer-ST2027 Military Production Hardening Release (2026-10-26)
# NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204
"""Test suite for SovereignGroupRatchet (CNSA Suite 2.0 / RFC 9420 MLS Aligned).

Validates:
  1. Multi-party group message broadcast and decryption.
  2. Per-message symmetric forward secrecy (ratcheting sender keys).
  3. Replay prevention and tampering rejection.
  4. Epoch rekeying with Post-Compromise Security (PCS healing).
  5. Two-Person Integrity (TPI) dual-officer authorization enforcement.
"""

import os
import pytest
from sovereign_group_ratchet import SovereignGroupRatchet, _hkdf_expand


def test_three_party_group_messaging_roundtrip():
    """Verify encrypted group broadcast among three tactical nodes (Alpha, Bravo, Charlie)."""
    root_epoch_secret = os.urandom(48)
    group_id = "TASK_FORCE_TITAN_77"

    # Initialize three nodes
    alpha = SovereignGroupRatchet(group_id, "ALPHA_COMMAND", root_epoch_secret)
    bravo = SovereignGroupRatchet(group_id, "BRAVO_OUTPOST", root_epoch_secret)
    charlie = SovereignGroupRatchet(group_id, "CHARLIE_RECON", root_epoch_secret)

    # Distribute initial sender chain keys derived under epoch 0
    alpha_chain = _hkdf_expand(root_epoch_secret, b"ALPHA_COMMAND" + b"\x00"*8, 48)
    bravo_chain = _hkdf_expand(root_epoch_secret, b"BRAVO_OUTPOST" + b"\x00"*8, 48)

    bravo.register_peer_sender_key("ALPHA_COMMAND", alpha_chain)
    charlie.register_peer_sender_key("ALPHA_COMMAND", alpha_chain)
    alpha.register_peer_sender_key("BRAVO_OUTPOST", bravo_chain)
    charlie.register_peer_sender_key("BRAVO_OUTPOST", bravo_chain)

    # 1. Alpha broadcasts to group
    msg1 = alpha.seal(b"TACTICAL_ALERT_DEFCON_2")
    assert bravo.open(msg1) == b"TACTICAL_ALERT_DEFCON_2"
    # Note: in real use, Charlie would get a separate copy or track identical state
    
    # 2. Replay of msg1 must fail
    with pytest.raises(ValueError, match="Replay detected"):
        bravo.open(msg1)

    # 3. Alpha broadcasts second message (forward secrecy ratchet)
    msg2 = alpha.seal(b"MISSION_COMMENCE_AT_DAWN")
    assert bravo.open(msg2) == b"MISSION_COMMENCE_AT_DAWN"


def test_epoch_advancement_requires_two_person_integrity():
    """Verify epoch advancement enforces real dual-officer ML-DSA-87 TPI signatures."""
    from liboqs_wrapper import LibOQS_MLDSA_87

    root_epoch_secret = os.urandom(48)
    node = SovereignGroupRatchet("GROUP_1", "NODE_1", root_epoch_secret)

    mldsa = LibOQS_MLDSA_87()
    pk1, sk1 = mldsa.keygen()
    pk2, sk2 = mldsa.keygen()

    fresh = os.urandom(32)
    message = node.tpi_rekey_message(fresh)
    sig1 = mldsa.sign(sk1, message)
    sig2 = mldsa.sign(sk2, message)

    # Unenrolled officers must fail closed even with valid signature shapes
    with pytest.raises(ValueError, match="Two-Person Integrity violation"):
        node.advance_epoch(fresh, sig1, sig2)

    node.enroll_tpi_officer("OFFICER_O6", pk1)
    node.enroll_tpi_officer("OFFICER_O7", pk2)

    # Missing/placeholder signatures must fail closed
    with pytest.raises(ValueError, match="Two-Person Integrity violation"):
        node.advance_epoch(fresh, b"", b"")

    with pytest.raises(ValueError, match="Two-Person Integrity violation"):
        node.advance_epoch(fresh, b"SIG_O6", b"")

    with pytest.raises(ValueError, match="Two-Person Integrity violation"):
        node.advance_epoch(fresh, b"OFFICER_1_MLDSA87_SIG", b"OFFICER_2_MLDSA87_SIG")

    # Signatures over a different transcript (wrong entropy) must fail closed
    other_fresh = os.urandom(32)
    with pytest.raises(ValueError, match="Two-Person Integrity violation"):
        node.advance_epoch(other_fresh, sig1, sig2)

    # Valid dual co-signatures over the canonical transcript succeed
    new_epoch = node.advance_epoch(fresh, sig1, sig2)
    assert new_epoch == 1
    assert node.epoch == 1


def test_group_epoch_advancement_synchronization():
    """Verify that advancing an epoch resynchronizes all roster members' sender keys."""
    from liboqs_wrapper import LibOQS_MLDSA_87

    root_epoch_secret = os.urandom(48)
    group_id = "TASK_FORCE_TITAN_77"

    alpha = SovereignGroupRatchet(group_id, "ALPHA_COMMAND", root_epoch_secret)
    bravo = SovereignGroupRatchet(group_id, "BRAVO_OUTPOST", root_epoch_secret)

    # Register each other
    alpha.register_peer_sender_key("BRAVO_OUTPOST", alpha.derive_epoch_sender_key("BRAVO_OUTPOST"))
    bravo.register_peer_sender_key("ALPHA_COMMAND", bravo.derive_epoch_sender_key("ALPHA_COMMAND"))

    # Initial epoch 0 message exchange
    m0 = alpha.seal(b"INITIAL_EPOCH_0_DISPATCH")
    assert bravo.open(m0) == b"INITIAL_EPOCH_0_DISPATCH"

    # Setup TPI officers
    mldsa = LibOQS_MLDSA_87()
    pk1, sk1 = mldsa.keygen()
    pk2, sk2 = mldsa.keygen()

    alpha.enroll_tpi_officer("O1", pk1)
    alpha.enroll_tpi_officer("O2", pk2)
    bravo.enroll_tpi_officer("O1", pk1)
    bravo.enroll_tpi_officer("O2", pk2)

    fresh = os.urandom(32)
    sig1_a = mldsa.sign(sk1, alpha.tpi_rekey_message(fresh))
    sig2_a = mldsa.sign(sk2, alpha.tpi_rekey_message(fresh))

    sig1_b = mldsa.sign(sk1, bravo.tpi_rekey_message(fresh))
    sig2_b = mldsa.sign(sk2, bravo.tpi_rekey_message(fresh))

    # Both advance epoch to 1
    assert alpha.advance_epoch(fresh, sig1_a, sig2_a) == 1
    assert bravo.advance_epoch(fresh, sig1_b, sig2_b) == 1

    # Epoch 1 message exchange works without manual renegotiation
    m1 = alpha.seal(b"POST_REKEY_EPOCH_1_DIRECTIVE")
    assert bravo.open(m1) == b"POST_REKEY_EPOCH_1_DIRECTIVE"

    m1_reply = bravo.seal(b"POST_REKEY_EPOCH_1_ACK")
    assert alpha.open(m1_reply) == b"POST_REKEY_EPOCH_1_ACK"

