#!/usr/bin/env python3
"""AO offline ceremony: sign platform attestations with ML-DSA-87 (FIPS 204).

Ceremony (air-gapped host, two custodians, USB transfer only):
  1. keygen once:  python scripts/sign_waiver.py keygen --out ao_root
     -- writes ao_root.sk (0600, NEVER leaves the safe) + ao_root.pub.
     Embed ao_root.pub hex into ts_runtime.PLATFORM_ROOT_PK_HEX and redeploy.
  2. sign a waiver: python scripts/sign_waiver.py sign-waiver
       --key ao_root.sk --waiver waiver_payload.json --out waiver.signed.json
     -- emits {"payload": {...}, "signature": "<hex>"} with canonical JSON.
  3. sign a record sidecar (seL4 / CMVP):
       python scripts/sign_waiver.py sign-file --key ao_root.sk
       --in sel4_record.json --out sel4_record.json.sig
     -- hex signature over the EXACT file bytes.
  4. verify offline: python scripts/sign_waiver.py verify
       --pub ao_root.pub --in waiver.signed.json   (envelope)
       python scripts/sign_waiver.py verify-file
       --pub ao_root.pub --in sel4_record.json --sig sel4_record.json.sig

Fingerprint the ceremony pub out-of-band (QR/paper) before embedding.
"""
import argparse
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def cmd_keygen(args) -> int:
    from liboqs_wrapper import LibOQS_MLDSA_87
    pk, sk = LibOQS_MLDSA_87().keygen()
    assert len(pk) == 2592
    with open(args.out + ".sk", "wb") as f:
        f.write(sk)
    os.chmod(args.out + ".sk", 0o600)
    with open(args.out + ".pub", "wb") as f:
        f.write(pk)
    print(f"[CEREMONY] ML-DSA-87 root generated. SECRET {args.out}.sk (0600, offline only).")
    print(f"[CEREMONY] Embed pub hex ({len(pk.hex())} chars) into ts_runtime.PLATFORM_ROOT_PK_HEX.")
    print(f"[CEREMONY] SHA-512 fingerprint (pin out-of-band): {hashlib.sha512(pk).hexdigest()}")
    return 0


def _load_keypair(args):
    with open(args.key, "rb") as f:
        sk = f.read()
    pub_path = getattr(args, "pub", None)
    if not pub_path:
        if args.key.endswith(".sk"):
            candidate = args.key[:-3] + ".pub"
            if os.path.exists(candidate):
                pub_path = candidate
        else:
            candidate = args.key + ".pub"
            if os.path.exists(candidate):
                pub_path = candidate
    pk = None
    if pub_path and os.path.exists(pub_path):
        with open(pub_path, "rb") as f:
            pk = f.read()
    return sk, pk


def cmd_sign_waiver(args) -> int:
    from liboqs_wrapper import LibOQS_MLDSA_87
    with open(args.waiver, "r", encoding="utf-8") as f:
        payload = json.load(f)
    if not isinstance(payload, dict):
        print("waiver payload must be a JSON object", file=sys.stderr)
        return 2
    for k in ("justification", "ao", "expires", "mitigations"):
        if not payload.get(k):
            print(f"waiver payload missing {k}", file=sys.stderr)
            return 2
    sk, pk = _load_keypair(args)
    canonical_bytes = _canonical(payload)
    sig = LibOQS_MLDSA_87().sign(sk, canonical_bytes)
    if pk is not None:
        if not LibOQS_MLDSA_87().verify(pk, canonical_bytes, sig):
            raise RuntimeError("FAIL-CLOSED: verify-after-sign failed for waiver")
    env = {"payload": payload, "signature": sig.hex()}
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(env, f, indent=2)
        f.write("\n")
    print(f"[CEREMONY] Signed waiver -> {args.out} (sig {len(sig)}B ML-DSA-87).")
    return 0


def cmd_sign_file(args) -> int:
    from liboqs_wrapper import LibOQS_MLDSA_87
    with open(args.infile, "rb") as f:
        data = f.read()
    sk, pk = _load_keypair(args)
    sig = LibOQS_MLDSA_87().sign(sk, data)
    if pk is not None:
        if not LibOQS_MLDSA_87().verify(pk, data, sig):
            raise RuntimeError(f"FAIL-CLOSED: verify-after-sign failed for file {args.infile}")
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(sig.hex() + "\n")
    print(f"[CEREMONY] Signed {args.infile} -> {args.out} (sig {len(sig)}B ML-DSA-87).")
    return 0


def cmd_verify(args) -> int:
    from liboqs_wrapper import LibOQS_MLDSA_87
    with open(args.pub, "rb") as f:
        pk = f.read()
    with open(args.infile, "r", encoding="utf-8") as f:
        env = json.load(f)
    ok = LibOQS_MLDSA_87().verify(pk, _canonical(env["payload"]),
                                  bytes.fromhex(env["signature"]))
    print("VERIFY-OK" if ok else "VERIFY-FAIL")
    return 0 if ok else 1


def cmd_verify_file(args) -> int:
    from liboqs_wrapper import LibOQS_MLDSA_87
    with open(args.pub, "rb") as f:
        pk = f.read()
    with open(args.infile, "rb") as f:
        data = f.read()
    with open(args.sig, "r", encoding="utf-8") as f:
        sig = bytes.fromhex(f.read().strip())
    ok = LibOQS_MLDSA_87().verify(pk, data, sig)
    print("VERIFY-OK" if ok else "VERIFY-FAIL")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(prog="sign_waiver")
    sub = ap.add_subparsers(dest="cmd", required=True)
    kg = sub.add_parser("keygen")
    kg.add_argument("--out", required=True, help="key stem (writes <out>.sk 0600 + <out>.pub)")
    sw = sub.add_parser("sign-waiver")
    sw.add_argument("--key", required=True)
    sw.add_argument("--pub", default=None)
    sw.add_argument("--waiver", required=True)
    sw.add_argument("--out", required=True)
    sf = sub.add_parser("sign-file")
    sf.add_argument("--key", required=True)
    sf.add_argument("--pub", default=None)
    sf.add_argument("--in", dest="infile", required=True)
    sf.add_argument("--out", required=True)
    vf = sub.add_parser("verify")
    vf.add_argument("--pub", required=True)
    vf.add_argument("--in", dest="infile", required=True)
    vff = sub.add_parser("verify-file")
    vff.add_argument("--pub", required=True)
    vff.add_argument("--in", dest="infile", required=True)
    vff.add_argument("--sig", required=True)
    a = ap.parse_args()
    return {"keygen": cmd_keygen, "sign-waiver": cmd_sign_waiver,
            "sign-file": cmd_sign_file, "verify": cmd_verify,
            "verify-file": cmd_verify_file}[a.cmd](a)


if __name__ == "__main__":
    raise SystemExit(main())
