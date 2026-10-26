# Destroyer-ST2027 Military Production Hardening Release (2026-10-26)
# NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204
"""FALCON/hybrid bundle serialization consistency (A-14, 2026-10-16).

Root cause class: bundle signing selects signature components from the DSS
mode, while public-key serialization filtered components via a separate mode
lookup on an adapter (MLDSA_SLHDSA_HybridSignature) that exposed no ``mode``
and silently defaulted to 'fast'. Under 'secure'/'dual' configurations the
published bundle could omit a component the signature carried, so the
in-emit self-verification (which uses the unfiltered in-memory key) passed
while peer verification failed — the "environment-dependent self-verify
quirk" recorded in test_combiner_downgrade_guard.py's header.

Fixes pinned here:
  1. MLDSA_SLHDSA_HybridSignature.mode now delegates to the implementation
     (single source of truth: what is signed is what is serialized).
  2. get_public_bundle enforces sig-components ⊆ public-key-components
     fail-closed before publishing (A-14 emit gate).
  3. verify_public_bundle rejects bundles whose signature carries components
     absent from the advertised public key (precise audit log, no opaque
     KeyError-driven reject).

The 2026-10-16 audit could not reproduce the original reject on any reachable
path; these tests pin the invariant so the divergence class cannot return.
"""

import base64
import json

import pytest

EXPECTED_COMPONENTS = {
    "fast": {"mldsa"},
    "secure": {"slhdsa"},
    "dual": {"mldsa", "slhdsa"},
}


def _fresh_kex(identity):
    from hybrid_kex import HybridKeyExchange

    return HybridKeyExchange(identity=identity, ephemeral=True, in_memory_only=True)


def test_native_falcon_bundle_roundtrip():
    """Default (native Falcon-1024) path: emit, self-verify, peer-verify."""
    kex = _fresh_kex("a14_native")
    assert isinstance(kex.falcon_public_key, (bytes, bytearray))
    bundle = kex.get_public_bundle()
    assert bundle.get("bundle_signature"), "bundle must be signed"  # nosec: B101
    # Legacy single-key format is raw base64, not a component JSON dict.
    assert not bundle["falcon_public_key"].startswith("{")  # nosec: B101
    assert kex.verify_public_bundle(bundle) is True  # nosec: B101

    peer = _fresh_kex("a14_native_peer")
    assert peer.verify_public_bundle(bundle) is True  # nosec: B101

    tampered = dict(bundle)
    tampered["identity"] = "a14_native_evil"
    assert peer.verify_public_bundle(tampered) is False  # nosec: B101


@pytest.mark.parametrize("mode", ["fast", "secure", "dual"])
def test_bundle_serialization_matches_signature_components(mode):
    """Serialized public components == signature components == mode set."""
    from pqc_algorithms import EnhancedFALCON_1024

    kex = _fresh_kex(f"a14_{mode}")
    kex.dss.impl = EnhancedFALCON_1024(mode=mode)
    pk, sk = kex.dss.impl.base_signature.keygen()
    assert isinstance(pk, dict)  # nosec: B101
    kex.falcon_public_key = pk
    kex.falcon_private_key = sk

    assert kex.dss.mode == mode  # nosec: B101

    bundle = kex.get_public_bundle()
    pub_comps = set(json.loads(bundle["falcon_public_key"]).keys())
    sig_comps = set(json.loads(bundle["bundle_signature"]).keys())
    assert pub_comps == EXPECTED_COMPONENTS[mode]  # nosec: B101
    assert sig_comps == EXPECTED_COMPONENTS[mode]  # nosec: B101

    peer = _fresh_kex(f"a14_{mode}_peer")
    assert peer.verify_public_bundle(bundle) is True  # nosec: B101


def test_emit_gate_refuses_peer_unverifiable_bundle():
    """A public key missing a signed component must never be published."""
    from pqc_algorithms import EnhancedFALCON_1024

    kex = _fresh_kex("a14_emit_gate")
    kex.dss.impl = EnhancedFALCON_1024(mode="dual")
    pk, sk = kex.dss.impl.base_signature.keygen()
    # Private half keeps both components (dual signing succeeds) but the
    # advertised public half is crippled: serialization would omit 'slhdsa'.
    kex.falcon_public_key = {"mldsa": pk["mldsa"]}
    kex.falcon_private_key = sk

    with pytest.raises(ValueError):
        kex.get_public_bundle()


def test_verify_gate_rejects_signature_components_absent_from_public_key():
    """Verify rejects (with containment check) sig components ⊆ pub components."""
    from pqc_algorithms import EnhancedFALCON_1024

    kex = _fresh_kex("a14_verify_gate")
    kex.dss.impl = EnhancedFALCON_1024(mode="dual")
    pk, sk = kex.dss.impl.base_signature.keygen()
    kex.falcon_public_key = pk
    kex.falcon_private_key = sk
    bundle = kex.get_public_bundle()

    # Strip 'slhdsa' from the advertised public key while the signature
    # (and its transcript) stay untouched.
    pub_dict = json.loads(bundle["falcon_public_key"])
    del pub_dict["slhdsa"]
    bad = dict(bundle)
    bad["falcon_public_key"] = json.dumps(pub_dict)

    peer = _fresh_kex("a14_verify_gate_peer")
    assert peer.verify_public_bundle(bad) is False  # nosec: B101
    # Sanity: the pristine bundle verifies on the same peer instance.
    assert peer.verify_public_bundle(bundle) is True  # nosec: B101


def test_b64_roundtrip_of_components_stable():
    """Serialized components decode to the exact in-memory key bytes."""
    from pqc_algorithms import EnhancedFALCON_1024

    kex = _fresh_kex("a14_b64")
    kex.dss.impl = EnhancedFALCON_1024(mode="fast")
    pk, sk = kex.dss.impl.base_signature.keygen()
    kex.falcon_public_key = pk
    kex.falcon_private_key = sk
    bundle = kex.get_public_bundle()

    decoded = {k: base64.b64decode(v)
               for k, v in json.loads(bundle["falcon_public_key"]).items()}
    assert decoded == {k: pk[k] for k in EXPECTED_COMPONENTS["fast"]}  # nosec: B101
