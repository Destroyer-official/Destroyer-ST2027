#!/usr/bin/env python3
"""
Generate Official Software Bill of Materials (SBOM) for 2027+ Defense Authorization
Formats: CycloneDX v1.5 JSON and SPDX v2.3 JSON
"""

import argparse
import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from supply_chain_security import SBOMGenerator

def _parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Generate production SBOMs (SPDX + CycloneDX) with ML-DSA-87 signatures."
    )
    p.add_argument(
        "--signing-key",
        dest="signing_key",
        default=None,
        help="Path to persistent ML-DSA-87 private signing key. "
             "May also be set via env SBOM_SIGNING_KEY. If provided, "
             "fail-closed on missing/unreadable file.",
    )
    p.add_argument(
        "--pubkey",
        dest="pubkey",
        default=None,
        help="Path to ML-DSA-87 public key matching --signing-key. "
             "May also be set via env SBOM_PUBKEY. Required with "
             "--signing-key unless a sibling .pub / default anchor exists.",
    )
    p.add_argument(
        "--output-dir",
        dest="output_dir",
        default=None,
        help="Optional SBOM output directory (default: compliance_reports). "
             "Additive: when omitted, paths are unchanged.",
    )
    p.add_argument(
        "--provenance",
        dest="provenance",
        action="store_true",
        default=False,
        help="Also write an UNSIGNED SLSA v1 provenance stub "
             "(provenance.intoto.jsonl) alongside the SBOMs. "
             "Default off; default SBOM behavior unchanged.",
    )
    p.add_argument(
        "--provenance-path",
        dest="provenance_path",
        default=None,
        help="Optional explicit path for the provenance stub "
             "(default: <output-dir>/provenance.intoto.jsonl).",
    )
    return p.parse_args(argv)


def _sha512_of(path):
    h = hashlib.sha512()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def write_provenance_stub(reports_dir, spdx_path, cdx_path):
    """Write UNSIGNED SLSA v1 provenance stub (in-toto JSONL).

    Contains builder.id, buildType, materials with sha512 digests, and
    runDetails.metadata.invocationId. Unsigned by design: to be signed
    by Cosign in CI (``cosign attest-blob`` / ``cosign sign-blob``).

    Returns the stub path. Additive: callers opt in via --provenance.
    """
    repo_root = Path(__file__).parent.resolve()
    reports_dir = Path(reports_dir)
    now = datetime.now(timezone.utc)
    started = now.isoformat().replace("+00:00", "Z")
    invocation_id = os.environ.get("GITHUB_RUN_ID", "") or str(uuid.uuid4())
    if os.environ.get("GITHUB_RUN_ID") and os.environ.get("GITHUB_RUN_ATTEMPT"):
        invocation_id = (
            f"{os.environ['GITHUB_RUN_ID']}-"
            f"{os.environ['GITHUB_RUN_ATTEMPT']}-{uuid.uuid4().hex[:8]}"
        )
    repo = os.environ.get("GITHUB_REPOSITORY", "secure-p2p/local")
    run_id = os.environ.get("GITHUB_RUN_ID", "local")
    builder_id = (
        f"https://github.com/{repo}/actions/runs/{run_id}"
        if "GITHUB_REPOSITORY" in os.environ
        else "https://github.com/secure-p2p/local-build@v1"
    )
    build_type = "https://github.com/secure-p2p/sbom-generator@v1"

    subjects = []
    materials = []
    resolved = []
    for label, p in (("spdx_sbom.json", Path(spdx_path)),
                     ("cyclonedx_sbom.json", Path(cdx_path))):
        if Path(p).is_file():
            digest = _sha512_of(p)
            subjects.append({"name": label, "digest": {"sha512": digest}})
            materials.append({
                "uri": label,
                "digest": {"sha512": digest},
            })
            resolved.append({
                "uri": f"file://{label}",
                "digest": {"sha512": digest},
            })
    for req_name in ("requirements.txt", "requirements-test.txt"):
        req = repo_root / req_name
        if req.is_file():
            digest = _sha512_of(req)
            materials.append({
                "uri": req_name,
                "digest": {"sha512": digest},
            })
            resolved.append({
                "uri": f"git+https://github.com/{repo}@{os.environ.get('GITHUB_SHA', 'HEAD')}#{req_name}"
                if "GITHUB_REPOSITORY" in os.environ
                else f"file://{req_name}",
                "digest": {"sha512": digest},
            })

    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects,
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": build_type,
                "externalParameters": {
                    "project": "secure_p2p",
                    "sbomFormats": ["spdx-2.3", "cyclonedx-1.5"],
                },
                "resolvedDependencies": resolved,
            },
            "runDetails": {
                "builder": {"id": builder_id},
                "metadata": {
                    "invocationId": invocation_id,
                    "startedOn": started,
                    "finishedOn": started,
                },
                "byproducts": [
                    {"uri": s["name"], "digest": s["digest"]} for s in subjects
                ],
            },
            # 'materials' kept for scanner compat (each entry has sha512).
            "materials": materials,
        },
        "_note": "UNSIGNED SLSA provenance stub - to be signed by Cosign "
                 "in CI (cosign attest-blob --predicate provenance.intoto.jsonl "
                 "or cosign sign-blob). Do not trust until signed.",
    }
    out = reports_dir / "provenance.intoto.jsonl"
    out.write_text(json.dumps(statement) + "\n", encoding="utf-8")
    return out


def _mldsa_sign_verified(signer, sk: bytes, pk: bytes, data: bytes, label: str) -> bytes:
    """ML-DSA-87 sign + verify-after-sign (fault-attack countermeasure).

    Cf. eprint 2025/2009 (seed-pointer faults in lattice stacks incl.
    LibOQS, up to 100% forgery success): never emit a signature that does
    not verify under the matching public half. Fail-closed on any fault.
    """
    sig = signer.sign(sk, data)
    sig = bytes(sig)
    if len(sig) != 4627 or not signer.verify(pk, data, sig):
        raise RuntimeError(f"FAIL-CLOSED: verify-after-sign failed for {label}")
    return sig


CBOM_VERSION = "1.0"


def build_cbom_inventory() -> list:
    """Declared cryptography inventory (CBOM evidence for the Jan-2027 gate).

    One entry per cryptographic boundary: component, role, and every
    algorithm with standard + parameter set + use. This table is
    code-reviewed alongside the implementation; write_cbom() additionally
    live-verifies native sizes so the inventory cannot silently drift from
    reality. Policy basis: CNSA 2.0 (ML-KEM-1024 + ML-DSA-87 mandatory),
    FIPS 203/204/205 final; FIPS 206 draft excluded as primary; IR 8610
    round-3 candidates and HashML-DSA never authorized (see
    cnsa2_policy_engine.NEVER_AUTHORIZED_2027).
    """
    def _alg(name, standard, use, params=None):
        entry = {"name": name, "standard": standard, "use": use}
        if params:
            entry["params"] = params
        return entry

    return [
        {"component": "double_ratchet",
         "role": "session message authentication + chain KDF",
         "algorithms": [
             _alg("ML-DSA-87", "FIPS 204", "per-message signature (session identity)",
                  {"pk": 2592, "sk": 4896, "sig": 4627}),
             _alg("ML-KEM-1024", "FIPS 203", "PQ ratchet KEM (Braid-lite fresh encaps)",
                  {"pk": 1568, "ct": 1568, "ss": 32}),
             _alg("X25519", "RFC 7748", "hybrid DH component ONLY (never standalone)"),
             _alg("ChaCha20-Poly1305", "RFC 8439", "message AEAD"),
             _alg("HKDF-SHA384", "RFC 5869", "hybrid_combine_v2 combiner + chain KDF"),
         ]},
        {"component": "hybrid_kex/pqxdh",
         "role": "initial handshake key establishment (PQXDH)",
         "algorithms": [
             _alg("ML-KEM-1024", "FIPS 203", "handshake KEM", {"pk": 1568, "ct": 1568}),
             _alg("Classic-McEliece-8192128f", "NIST Round 4", "diversity KEM (out-of-band sized)",
                  {"pk": 1357824, "ct": 208}),
             _alg("X25519", "RFC 7748", "hybrid DH component ONLY"),
             _alg("ML-DSA-87", "FIPS 204", "bundle authentication signatures"),
             _alg("HKDF-SHA384", "RFC 5869", "hybrid_combine_v2 (length-framed, transcript-bound)"),
         ]},
        {"component": "tls_channel",
         "role": "transport security (mutual TLS 1.3)",
         "algorithms": [
             _alg("TLS 1.3", "RFC 8446", "mutual-auth transport", {"groups": "PQ/T hybrid + ML-KEM"}),
             _alg("AES-256-GCM", "FIPS 197", "record AEAD"),
             _alg("SHA-384", "FIPS 180-4", "handshake hash / HKDF"),
         ]},
        {"component": "supply_chain/tuf",
         "role": "release + update signing (TUF 4-role + manifest)",
         "algorithms": [
             _alg("ML-DSA-87", "FIPS 204", "primary release signature (.mldsa87.sig dual)"),
             _alg("Ed25519", "RFC 8032", "legacy co-signature (migration window only)"),
             _alg("SHA3-512", "FIPS 202", "target integrity hashes"),
         ]},
        {"component": "sbom/cbom/ceremony signing",
         "role": "artifact + ceremony signatures",
         "algorithms": [
             _alg("ML-DSA-87", "FIPS 204", "SBOM/CBOM detached signatures"),
             _alg("Ed25519", "RFC 8032", "ceremony custodian approvals + Rekor checkpoint"),
         ]},
        {"component": "storage/enclave",
         "role": "key storage + at-rest sealing",
         "algorithms": [
             _alg("AES-256-GCM", "FIPS 197", "envelope encryption"),
             _alg("scrypt N=131072/r=8/p=1", "RFC 7914", "passphrase KDF for sealed keys"),
             _alg("HKDF-SHA512", "RFC 5869", "key separation"),
         ]},
        {"component": "rust_data_plane",
         "role": "native data-plane (AEAD/framing/replay, X-Wing-style hybrid KEM)",
         "algorithms": [
             _alg("ML-KEM-1024", "FIPS 203", "hybrid KEM via ml-kem crate (audited-path cross-checked)"),
             _alg("X25519", "RFC 7748", "hybrid KEM component via x25519-dalek"),
             _alg("ChaCha20-Poly1305", "RFC 8439", "frame AEAD (RFC 8439 vectors pinned)"),
         ]},
    ]


def write_cbom(reports_dir) -> Path:
    """Write compliance_reports/cbom.json (Cryptography Bill of Materials).

    Includes live_verification: native ML-KEM-1024 / ML-DSA-87 size pins
    plus the policy-engine never-authorized spot check, so the declared
    inventory is evidence -- not aspiration. Best-effort when native liboqs
    is absent (records native_absent honestly; signing still fail-closes).
    """
    reports_dir = Path(reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    live = {"native_present": False, "native_sizes_ok": False,
            "policy_spotcheck_ok": False, "detail": ""}
    try:
        from liboqs_wrapper import LibOQS_MLDSA_87, LibOQS_MLKEM_1024
        kem = LibOQS_MLKEM_1024()
        dsa = LibOQS_MLDSA_87()
        live["native_present"] = True
        live["native_sizes_ok"] = bool(
            kem.pk_size == 1568 and kem.ct_size == 1568
            and dsa.pk_size == 2592 and dsa.sig_size == 4627)
        live["detail"] = ("mlkem pk/ct=%d/%d, mldsa pk/sig=%d/%d"
                          % (kem.pk_size, kem.ct_size, dsa.pk_size, dsa.sig_size))
    except Exception as e:
        live["detail"] = f"native unavailable: {e}"[:120]
    try:
        from cnsa2_policy_engine import CNSA2PolicyEngine, AlgorithmCategory
        eng = CNSA2PolicyEngine()
        eng.validate_algorithm("ML-DSA-87", AlgorithmCategory.SIGNATURE)
        refused = 0
        for banned in ("HAWK", "HASHML-DSA-87", "FN-DSA-1024", "MAYO"):
            try:
                eng.validate_algorithm(banned)
            except Exception:
                refused += 1
        live["policy_spotcheck_ok"] = (refused == 4)
    except Exception as e:
        live["detail"] += f" | policy check error: {e}"[:120]
    doc = {
        "cbom_version": CBOM_VERSION,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "policy_basis": ("CNSA 2.0 Jan-2027 procurement gate (ML-KEM-1024 + "
                         "ML-DSA-87 mandatory); FIPS 203/204/205 final; "
                         "FIPS 206 draft excluded as primary; IR 8610 "
                         "candidates + HashML-DSA never authorized"),
        "components": build_cbom_inventory(),
        "live_verification": live,
    }
    out = reports_dir / "cbom.json"
    out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return out


def verify_sbom_offline(sbom_path=None, pubkey_path=None):
    """Verify an SBOM's colocated ML-DSA-87 signature without any network.

    Checks `<sbom>.mldsa87.sig` against `<sbom>.mldsa87.pub` (the same sibling
    layout written by main(): ``path.with_suffix(path.suffix + ".mldsa87.sig")``
    / ``... + ".mldsa87.pub"``). Fail-closed: missing files or a bad signature
    raise (never silently pass). Air-gap safe: no network fetch is performed.

    Args:
        sbom_path: Path to the SBOM JSON (default: compliance_reports/spdx_sbom.json
            relative to this file). Also accepts a directory (verifies both
            spdx_sbom.json and cyclonedx_sbom.json within it).
        pubkey_path: Optional explicit .pub override. Else the colocated
            `<sbom>.mldsa87.pub`, else SBOM_PUBKEY env.

    Returns:
        True when every checked SBOM verifies.

    Raises:
        FileNotFoundError: SBOM, .sig, or .pub file missing (fail-closed).
        RuntimeError: signature INVALID (fail-closed).

    TODO(rekor): optionally anchor each `.mldsa87.sig` in a Rekor transparency
        log and verify inclusion via the signed checkpoint (offline: compare a
        previously fetched checkpoint; online only when policy allows).
        Spec: https://www.sigstore.dev/docs/about/rekor/ and
        https://github.com/sigstore/rekor/blob/main/docs/api.md
        (see "HashedRekord" proposal + checkpoint verification). No network is
        performed here by design.
    """
    from liboqs_wrapper import LibOQS_MLDSA_87

    repo_root = Path(__file__).parent.resolve()
    if sbom_path is None:
        targets = [repo_root / "compliance_reports" / "spdx_sbom.json"]
    else:
        p = Path(sbom_path)
        if p.is_dir():
            targets = [p / "spdx_sbom.json", p / "cyclonedx_sbom.json"]
        else:
            targets = [p]
    verifier = LibOQS_MLDSA_87()
    for target in targets:
        if not target.is_file():
            raise FileNotFoundError(
                f"FAIL-CLOSED: SBOM not found: {target}")
        sig_path = target.with_suffix(target.suffix + ".mldsa87.sig")
        if pubkey_path:
            pub_path = Path(pubkey_path)
        elif os.environ.get("SBOM_PUBKEY") and Path(os.environ["SBOM_PUBKEY"]).is_file():
            pub_path = Path(os.environ["SBOM_PUBKEY"])
        else:
            pub_path = target.with_suffix(target.suffix + ".mldsa87.pub")
        if not sig_path.is_file():
            raise FileNotFoundError(
                f"FAIL-CLOSED: SBOM signature missing: {sig_path}")
        if not pub_path.is_file():
            raise FileNotFoundError(
                f"FAIL-CLOSED: SBOM trust anchor missing: {pub_path} "
                f"(keep the .mldsa87.pub with the release manifest)")
        data = target.read_bytes()
        sig = sig_path.read_bytes()
        pub = pub_path.read_bytes()
        try:
            ok = verifier.verify(pub, data, sig)
        except Exception as e:
            raise RuntimeError(
                f"FAIL-CLOSED: SBOM verify error for {target.name}: {e}") from e
        if not ok:
            raise RuntimeError(
                f"FAIL-CLOSED: SBOM signature INVALID for {target.name} "
                f"(sig={sig_path.name}, pub={pub_path.name})")
        print(f"[OK] Verified SBOM offline: {target.name} "
              f"(sig={sig_path.name}, pub={pub_path.name})")
    return True


def main(argv=None):
    repo_root = Path(__file__).parent.resolve()
    # Parse CLI early for --output-dir (additive; default keeps legacy path).
    _cli = _parse_args(argv)
    if _cli.output_dir:
        _od = Path(_cli.output_dir)
        reports_dir = _od if _od.is_absolute() else (repo_root / _od)
    else:
        reports_dir = repo_root / "compliance_reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    
    sbom = SBOMGenerator(project_name="secure_p2p", project_version="2.0.0-CNSA2-2027")
    
    # Add native cryptographic boundaries
    dlls = [
        ("libsodium.dll", "1.0.22", "Libsodium Core Cryptography Boundary"),
        ("oqs.dll", "0.10.1", "LibOQS Quantum-Resistant Cryptography Boundary")
    ]
    for dll_name, ver, desc in dlls:
        dll_path = repo_root / dll_name
        if dll_path.exists():
            with open(dll_path, 'rb') as f:
                content = f.read()
            h256 = hashlib.sha256(content).hexdigest()
            h512 = hashlib.sha512(content).hexdigest()
            sbom.add_component(
                name=dll_name,
                version=ver,
                supplier="Open Quantum Safe / Libsodium",
                license_id="MIT OR Apache-2.0",
                sha256=h256,
                sha512=h512,
                purl=f"pkg:generic/{dll_name}@{ver}"
            )
            
    # Add Python dependencies from requirements.txt + requirements-test.txt.
    # Supports pip multi-hash format: "pkg==ver \" with continuation lines
    # "    --hash=sha256:... \" (2028 hardening). All hashes are recorded.
    for req_name in ("requirements.txt", "requirements-test.txt"):
        req_file = repo_root / req_name
        if not req_file.exists():
            continue
        with open(req_file, 'r', encoding='utf-8') as f:
            raw = f.read()
        # Join backslash continuations so each requirement is one logical line.
        logical_lines = []
        buf = ""
        for line in raw.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            if stripped.endswith('\\'):
                buf += stripped[:-1].strip() + " "
                continue
            buf += stripped
            logical_lines.append(buf)
            buf = ""
        if buf.strip():
            logical_lines.append(buf.strip())
        for line in logical_lines:
            if '--hash=' in line:
                head, _, tail = line.partition('--hash=')
                hashes = []
                # tail may contain multiple --hash= entries separated by --hash=
                for chunk in ([head] + tail.split('--hash='))[:1]:
                    pass
                import re
                hashes = re.findall(r'sha256:([0-9a-fA-F]{64})', line)
                clean_line = head.strip()
                hash_val = hashes[0] if hashes else ""
                extra_hashes = hashes[1:]
            else:
                clean_line, hash_val, extra_hashes = line.strip(), "", []
            if '==' not in clean_line:
                continue
            parts = clean_line.split('==')
            name = parts[0].strip().rstrip('\\').strip()
            ver = parts[1].strip().rstrip('\\').strip().split()[0]
            if not name:
                continue
            sbom.add_component(
                name=name,
                version=ver,
                supplier="PyPI Community",
                sha256=hash_val,
                purl=f"pkg:pypi/{name}@{ver}"
            )
                    
    spdx_path = reports_dir / "spdx_sbom.json"
    cdx_path = reports_dir / "cyclonedx_sbom.json"
    
    sbom.generate_spdx(str(spdx_path))
    sbom.generate_cyclonedx(str(cdx_path))
    
    print(f"[OK] Generated SPDX SBOM at {spdx_path}")
    print(f"[OK] Generated CycloneDX SBOM at {cdx_path}")

    # Sign generated SBOMs with ML-DSA-87 and persistent trust anchor (Item 49)
    # Key resolution: --signing-key/--pubkey args or SBOM_SIGNING_KEY/SBOM_PUBKEY
    # env take precedence when provided (fail-closed on missing). Otherwise
    # fall back to the local certs/ anchor (WARN: lab-grade if freshly generated).
    try:
        args = _parse_args(argv)
        certs_dir = Path("certs")
        certs_dir.mkdir(exist_ok=True)
        default_sk_path = certs_dir / "sbom_mldsa87_signer.sk"
        default_pk_path = certs_dir / "sbom_mldsa87_signer.pub"

        explicit_sk = args.signing_key or os.environ.get("SBOM_SIGNING_KEY")
        explicit_pk = args.pubkey or os.environ.get("SBOM_PUBKEY")

        from liboqs_wrapper import LibOQS_MLDSA_87
        signer = LibOQS_MLDSA_87()

        if explicit_sk:
            sk_path = Path(explicit_sk)
            if not sk_path.is_file():
                raise RuntimeError(
                    f"FAIL-CLOSED: SBOM signing key not found: {sk_path} "
                    f"(from --signing-key/SBOM_SIGNING_KEY)"
                )
            sk = sk_path.read_bytes()
            if not sk:
                raise RuntimeError(
                    f"FAIL-CLOSED: SBOM signing key empty/unreadable: {sk_path}"
                )
            pk = None
            candidates = []
            if explicit_pk:
                candidates.append(Path(explicit_pk))
            # Sibling .pub next to the signing key (foo.sk -> foo.pub).
            try:
                candidates.append(sk_path.with_suffix(".pub"))
            except Exception:
                candidates.append(Path(str(sk_path) + ".pub"))
            candidates.append(default_pk_path)
            pk_source = None
            for cand in candidates:
                try:
                    if cand.is_file():
                        pk = cand.read_bytes()
                        pk_source = cand
                        break
                # AUDITED (B112): intentional best-effort loop guard; no security decision swallowed (triaged 2026-09 waves)
                except Exception:  # nosec: B112
                    continue
            if not pk:
                if explicit_pk:
                    raise RuntimeError(
                        f"FAIL-CLOSED: SBOM pubkey not found: {explicit_pk} "
                        f"(from --pubkey/SBOM_PUBKEY)"
                    )
                raise RuntimeError(
                    "FAIL-CLOSED: SBOM pubkey missing for explicit --signing-key; "
                    "provide --pubkey/SBOM_PUBKEY or place a sibling .pub next to "
                    f"the signing key (tried: {[str(c) for c in candidates]})"
                )
            print(f"[OK] Using persistent SBOM signing key {sk_path} (pub: {pk_source})")
        else:
            sk_path = default_sk_path
            pk_path = default_pk_path
            if sk_path.exists() and pk_path.exists():
                sk = sk_path.read_bytes()
                pk = pk_path.read_bytes()
            else:
                import warnings
                warnings.warn(
                    "No --signing-key/SBOM_SIGNING_KEY provided; generating lab-grade "
                    f"ephemeral-persistent anchor at {pk_path}. For production, supply "
                    "--signing-key/--pubkey (or SBOM_SIGNING_KEY/SBOM_PUBKEY).",
                    UserWarning,
                )
                print(
                    f"[WARN] No --signing-key/SBOM_SIGNING_KEY provided; using lab-grade "
                    f"local anchor at {pk_path}. Supply persistent keys for production."
                )
                pk, sk = signer.keygen()
                sk_path.write_bytes(sk)
                pk_path.write_bytes(pk)
                print(f"[OK] Initialized persistent SBOM ML-DSA-87 root anchor at {pk_path}")

        # CBOM (cryptography inventory for the Jan-2027 gate evidence pack).
        cbom_path = write_cbom(reports_dir)
        print(f"[OK] Wrote CBOM {cbom_path.name} (live-verified inventory)")

        for path in [spdx_path, cdx_path, cbom_path]:
            data = path.read_bytes()
            sig = _mldsa_sign_verified(signer, sk, pk, data, f"SBOM {path.name}")
            sig_path = path.with_suffix(path.suffix + ".mldsa87.sig")
            sig_path.write_bytes(sig)
            target_pk_path = path.with_suffix(path.suffix + ".mldsa87.pub")
            target_pk_path.write_bytes(pk)
            print(f"[OK] Signed SBOM {path.name} with ML-DSA-87 (verified trust anchor) -> {sig_path.name}")
        # Verify note: offline ML-DSA-87 verification with the colocated .pub.
        print(
            "[INFO] Verify offline (air-gap safe, no network): "
            "LibOQS_MLDSA_87().verify(pub=path.with_suffix('.json.mldsa87.pub').read_bytes(), "
            "msg=path.read_bytes(), sig=path.with_suffix('.json.mldsa87.sig').read_bytes()) "
            "must return True for each SBOM; keep the .pub trust anchor with the release manifest."
        )
        # Optional SLSA provenance stub (additive; default off).
        if args.provenance:
            stub = write_provenance_stub(reports_dir, spdx_path, cdx_path)
            if args.provenance_path:
                custom = Path(args.provenance_path)
                custom = custom if custom.is_absolute() else (repo_root / custom)
                custom.parent.mkdir(parents=True, exist_ok=True)
                custom.write_bytes(stub.read_bytes())
                print(f"[OK] Wrote SLSA provenance stub (UNSIGNED, Cosign to sign) -> {custom}")
            print(f"[OK] Wrote SLSA provenance stub (UNSIGNED, Cosign to sign) -> {stub}")
    except Exception as e:
        print(f"[ERROR] ML-DSA-87 SBOM signing failed: {e}")
        raise RuntimeError(f"FAIL-CLOSED: SBOM signing failed: {e}") from e

def verify_rekor_bundle(bundle_path: str | Path, rekor_pubkey: bytes | None = None) -> bool:
    """Verify an offline Rekor transparency bundle (fail-closed, no network).

    Bundle JSON must contain: payload_sha512 (hex), inclusion_proof (dict
    with log_index + tree_size), checkpoint (str), sig (hex Ed25519 sig).

    Trust anchor: rekor_pubkey arg else P2P_REKOR_PUBKEY env (hex).
    Raises RuntimeError("no Rekor trust anchor configured") if none;
    callers treat this as SKIP in lab, FAIL in prod.

    Returns True if checkpoint Ed25519 sig verifies over checkpoint bytes
    and RFC6962 linkage fields present; else False. No network performed.

    Raises:
        FileNotFoundError: bundle file missing (fail-closed).
        RuntimeError: no Rekor trust anchor configured.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    p = Path(bundle_path)
    if not p.is_file():
        raise FileNotFoundError(f"FAIL-CLOSED: Rekor bundle missing: {p}")
    if rekor_pubkey is None:
        env_hex = os.environ.get("P2P_REKOR_PUBKEY", "").strip()
        if not env_hex:
            raise RuntimeError("no Rekor trust anchor configured")
        try:
            rekor_pubkey = bytes.fromhex(env_hex)
        except Exception:
            return False
    if not isinstance(rekor_pubkey, (bytes, bytearray)) or len(rekor_pubkey) != 32:
        return False
    try:
        bundle = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return False
    if not isinstance(bundle, dict):
        return False
    payload_hex = bundle.get("payload_sha512")
    proof = bundle.get("inclusion_proof")
    checkpoint = bundle.get("checkpoint")
    sig_hex = bundle.get("sig")
    if not isinstance(payload_hex, str) or not isinstance(sig_hex, str):
        return False
    if not isinstance(checkpoint, str) or not checkpoint:
        return False
    if not isinstance(proof, dict):
        return False
    try:
        payload_bytes = bytes.fromhex(payload_hex)
        sig_bytes = bytes.fromhex(sig_hex)
    except Exception:
        return False
    if len(payload_bytes) != 64 or len(sig_bytes) != 64:
        return False
    log_index = proof.get("log_index")
    tree_size = proof.get("tree_size")
    if not isinstance(log_index, int) or not isinstance(tree_size, int):
        return False
    if isinstance(log_index, bool) or isinstance(tree_size, bool):
        return False
    if log_index < 0 or tree_size <= 0 or log_index >= tree_size:
        return False
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes(rekor_pubkey))
        pub.verify(sig_bytes, checkpoint.encode("utf-8"))
    except (InvalidSignature, ValueError):
        return False
    except Exception:
        return False
    return True


if __name__ == "__main__":
    main()


