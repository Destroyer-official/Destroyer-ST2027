#!/usr/bin/env python3
"""Truth-in-claims gates (Phase 4): documentation is audited like code.

4.1: README carries zero false accreditation claims (badges, counts,
     maturity ratings). The exact evaluation-boundary sentence is present.
4.2: Formal-verification attribution matches rust_data_plane/tests/
     kani_harness.rs exactly: 5 #[kani::proof] harnesses by name (defined;
     execution requires the Kani + CBMC toolchain) plus 7 deterministic
     property doubles by name (executed green under cargo test).
4.3: Physical-boundary disclosures (Python bytes hygiene, Tor vs global
     passive adversary) are present in README and
     SYSTEM_SECURITY_DOCUMENTATION.md.

All primitives under test here are text audits (no crypto); the code they
describe is covered by the suites they cite.
"""

import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent if (Path(__file__).resolve().parent / 'destroyer.py').exists() else Path(__file__).resolve().parent.parent
README = (ROOT / "README.md").read_text(encoding="utf-8")
_sysvol_path = ROOT / "docs" / "SYSTEM_SECURITY_DOCUMENTATION.md"
if not _sysvol_path.exists():
    _sysvol_path = ROOT / "SYSTEM_SECURITY_DOCUMENTATION.md"
SYSVOL = _sysvol_path.read_text(encoding="utf-8")
FORMAL_README = (ROOT / "docs" / "formal" / "README.md").read_text(encoding="utf-8")
KANI_SRC = (ROOT / "rust_data_plane" / "tests" / "kani_harness.rs").read_text(
    encoding="utf-8")

HONESTY_SENTENCE = (
    "This software is an engineering baseline designed to meet the "
    "technical specifications of CNSA 2.0. It has not undergone accredited "
    "laboratory evaluation (FIPS 140-3 CMVP / Common Criteria) and does "
    "not possess a government Authority to Operate (ATO)."
)
MEMORY_DISCLOSURE = (
    "Python immutable `bytes` objects cannot be wiped deterministically "
    "due to runtime garbage collector copies. High-assurance operational "
    "deployments must execute via the standalone native Rust data-plane "
    "(`secure-transmit`)."
)
TRAFFIC_DISCLOSURE = (
    "Constant-rate traffic shaping (50ms interval) provides statistical "
    "masking against localized ISP/packet sniffers. It does not provide "
    "mathematical security against a global passive adversary with full "
    "autonomous network vantage points."
)

# Badge/claim fragments that assert UNEARNED accreditation. (FIPS 140-3
# Level 3/4 and EAL4+ may appear ONLY with an explicit design-target /
# not-certified qualifier, and maturity-level achievement claims never.)
FORBIDDEN_BADGE_FRAGMENTS = [
    "DoD_Zero_Trust_Level_4",
    "Zero Trust Architecture Maturity Level 4",
    "Kani_CBMC_Verified",
    "227%2F227",
    "227 PASSED",
    "227 automated tests",
    "163 / 163 PASSED",
    "64 / 64 PASSED",
    "29 Kani Formal Harnesses",
    "29 formal Kani",
    "24 Property Tests",
    "24 automated property",
]

KANI_PROOFS = [
    "kani_frame_split_reassemble_roundtrip",
    "kani_nonce_domain_separation",
    "kani_replay_window_monotonic",
    "kani_max_stream_bytes_cap",
    "kani_nostd_frame_parse_never_panics",
]
PROPERTY_DOUBLES = [
    "frame_split_reassemble_roundtrip_bounded",
    "nonce_domain_separation",
    "replay_window_monotonic_and_drops",
    "ct_eq_and_select_no_secret_branch",
    "max_stream_bytes_cap_enforced",
    "nostd_frame_parse_never_panics_property_sweep",
    "nostd_stack_secret_ct_eq_property_sweep",
]


def test_no_false_accreditation_claims():
    """Gate 4.1: zero unearned badges/counts/ratings in README."""
    for frag in FORBIDDEN_BADGE_FRAGMENTS:
        assert frag not in README, f"false accreditation fragment: {frag!r}"
    assert HONESTY_SENTENCE in README
    assert "Pre-Evaluation" in README
    # Design-target rows must carry their qualifier.
    assert "design target, NOT lab-certified" in README


def test_kani_attribution_matches_harness():
    """Gate 4.2: docs cite exactly what kani_harness.rs contains."""
    proofs = re.findall(r"#\[kani::proof\]\s*\n\s*fn\s+(\w+)", KANI_SRC)
    assert sorted(proofs) == sorted(KANI_PROOFS), proofs
    doubles_block = KANI_SRC.split("mod property_doubles")[1]
    doubles = re.findall(r"fn\s+(\w+)\s*\(\s*\)", doubles_block)
    # Filter to actual #[test] fns (exclude helper lcg_next).
    doubles = [d for d in doubles if d != "lcg_next"]
    assert sorted(doubles) == sorted(PROPERTY_DOUBLES), doubles
    # Zeroize-on-drop is a cargo-test unit test, NOT a Kani proof.
    assert "test_stack_secret_zeroize_on_drop" not in proofs
    for name in KANI_PROOFS:
        assert name in README, f"proof missing from README: {name}"
        assert name in FORMAL_README, f"proof missing from formal README: {name}"
    for name in PROPERTY_DOUBLES:
        assert name in FORMAL_README, f"double missing from formal README: {name}"
    # Execution-requirement honesty in both docs.
    assert "cargo kani" in README and "cargo kani" in FORMAL_README
    # The old false "PROVEN" Kani table must be gone.
    assert "ct_eq_no_secret_branch       ==> PROVEN" not in README
    assert "test_stack_secret_zeroize     ==> PROVEN" not in README


def _norm(text: str) -> str:
    # Generated docs hard-wrap prose: audit on whitespace-normalized text.
    return re.sub(r"\s+", " ", text)


def test_physical_boundary_disclosures_present():
    """Gate 4.3: memory + traffic-analysis limits stated, not footnoted."""
    assert MEMORY_DISCLOSURE in README
    assert TRAFFIC_DISCLOSURE in README
    assert _norm(MEMORY_DISCLOSURE) in _norm(SYSVOL)
    assert _norm(TRAFFIC_DISCLOSURE) in _norm(SYSVOL)


def test_native_dataplane_cipher_purity():
    """Gate 5.1: zero ChaCha20 dependencies in the native data-plane.

    CNSA 2.0 admits AES-256-GCM only: Cargo.toml must not depend on any
    chacha/poly1305 crate, and no Rust source may name those primitives.
    """
    import re
    import tomllib
    crate_dir = ROOT / "rust_data_plane"
    manifest = tomllib.loads((crate_dir / "Cargo.toml").read_text(encoding="utf-8"))
    deps = {d.lower() for d in manifest.get("dependencies", {})}
    assert not {d for d in deps if "chacha" in d or "poly1305" in d}, deps
    token_re = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
    hits = []
    for dirpath, _, files in os.walk(crate_dir / "src"):
        for fn in files:
            if not fn.endswith(".rs"):
                continue
            tokens = {t.lower() for t in token_re.findall(
                open(os.path.join(dirpath, fn), encoding="utf-8").read())}
            bad = {t for t in tokens
                   if "chacha" in t or "poly1305" in t or t == "rfc8439"}
            if bad:
                hits.append((fn, sorted(bad)))
    assert not hits, f"non-CNSA cipher symbols in native data-plane: {hits}"
    assert "aes-gcm" in deps, deps
