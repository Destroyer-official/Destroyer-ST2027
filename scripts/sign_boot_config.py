#!/usr/bin/env python3
"""Sign boot config with ML-DSA-87 (CNSA 2.0 offline ceremony output).

Usage:
  python scripts/sign_boot_config.py --config config_production.json --pub-out certs/config_trust_root.pub
  -- generates <config>.mldsa87.sig + <config>.mldsa87.pub (or reuses --signing-key)
  -- prints sha512 fingerprint to pin out-of-band (QR/paper)

Ceremony: run on offline HSM host, transfer .sig+.pub via USB, verify with
utils.config_manager.ConfigManager.verify_config_signature().
"""
import argparse
import base64
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--signing-key", default=None, help="Existing ML-DSA-87 secret key file (raw bytes). If omitted, fresh key is generated (ceremony only).")
    ap.add_argument("--pub-out", default=None)
    ap.add_argument("--dsse", action="store_true", help="Also emit DSSE envelope (.dsse) with PAE binding")
    args = ap.parse_args()

    with open(args.config, "rb") as f:
        data = f.read()

    from liboqs_wrapper import LibOQS_MLDSA_87
    signer = LibOQS_MLDSA_87()
    if args.signing_key and os.path.exists(args.signing_key):
        with open(args.signing_key, "rb") as f:
            sk = f.read()
        # pub must be supplied alongside: <key>.pub
        pub_path = args.signing_key + ".pub"
        if not os.path.exists(pub_path):
            print(f"Missing pubkey sidecar: {pub_path}", file=sys.stderr)
            return 2
        with open(pub_path, "rb") as f:
            pk = f.read()
    else:
        pk, sk = signer.keygen()
        key_path = args.config + ".mldsa87.sk"
        with open(key_path, "wb") as f:
            f.write(sk)
        os.chmod(key_path, 0o600)
        print(f"[CEREMONY] Fresh ML-DSA-87 key generated. SECRET written to {key_path} (0600, offline only).")

    sig = signer.sign(sk, data)
    with open(args.config + ".mldsa87.sig", "wb") as f:
        f.write(sig)
    pub_out = args.pub_out or (args.config + ".mldsa87.pub")
    with open(pub_out, "wb") as f:
        f.write(pk)

    fp = hashlib.sha512(pk).hexdigest()
    print(f"[OK] Signed {args.config} -> {args.config}.mldsa87.sig ({len(sig)}B)")
    print(f"[OK] Pubkey -> {pub_out} ({len(pk)}B)")
    print(f"PIN OUT-OF-BAND fingerprint sha512(pub)={fp}")

    if args.dsse:
        ptype = b"application/vnd.p2p.boot-config+json"
        pae = b"DSSEv1 " + str(len(ptype)).encode() + b" " + ptype + b" " + str(len(data)).encode() + b" " + data
        dsig = signer.sign(sk, pae)
        env = {
            "payloadType": ptype.decode(),
            "payload": base64.b64encode(data).decode(),
            "signatures": [{"keyid": fp[:16], "sig": base64.b64encode(dsig).decode(), "alg": "ML-DSA-87"}],
        }
        with open(args.config + ".dsse", "w", encoding="utf-8") as f:
            json.dump(env, f, indent=2)
        print(f"[OK] DSSE envelope -> {args.config}.dsse")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
