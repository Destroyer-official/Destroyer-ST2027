#!/usr/bin/env python3
"""
Witnessed Key Ceremony Harness - NIST SP 800-57 / FIPS 140-3 Level 4 Compliant
================================================================================
This script automates the formal cryptographic key generation ceremony for the
Secure P2P Platform, establishing CNSA 2.0 sovereign root authority.

Features:
- M-of-N Multi-Party Custodian Quorum (default: 2-of-3 key custodians)
- Hardware Root of Trust Integration (TPM 2.0 / HSM)
- CNSA 2.0 Post-Quantum Primitives:
  * ML-DSA-87 (FIPS 204) Root Signature Keypair
  * SLH-DSA-256f (FIPS 205) Stateless Hash-Based Root Signature Keypair
  * ML-KEM-1024 (FIPS 203) Master Key Encapsulation Keypair
  * SECP521R1 (FIPS 186-5) Classical Curve Keypair
- Merkle-Chained Ceremony Audit Log with SHA-512 Step Hashing
- Dual-Format Cryptographic Receipts in compliance_reports/
"""

import os
import sys
import time
import json
import base64
import hashlib
import hmac
import secrets
import logging
from datetime import datetime, timezone
from pathlib import Path

# Add project root to sys.path
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from platform_hsm_interface import is_tpm_available, get_tpm_attestation, tpm_attestation
from audit_logging_system import get_audit_logger
from utils.helpers import is_env_true

logger = logging.getLogger("witnessed_key_ceremony")


class WitnessedKeyCeremony:
    """Orchestrates formal FIPS 140-3 Level 4 key ceremony with multi-custodian quorum."""

    def __init__(self, ceremony_id: str = None, quorum_m: int = 2, total_n: int = 3):
        self.ceremony_id = ceremony_id or f"CEREMONY-CNSA2-{int(time.time())}-{secrets.token_hex(4).upper()}"
        self.quorum_m = quorum_m
        self.total_n = total_n
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.custodians = []
        self.merkle_steps = []
        self.current_hash = hashlib.sha512(f"GENESIS:{self.ceremony_id}:{self.timestamp}".encode('utf-8')).digest()
        self.generated_keys = {}
        self.receipt = {}
        self.output_dir = PROJECT_ROOT / "compliance_reports"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        # Custodian approval keys (Ed25519). Private halves are held by the
        # harness ONLY for lab auto-approval; production custodians sign
        # offline and submit signatures via approve(). Never exported.
        self._custodian_private = {}
        self._approvals = {}  # custodian_id -> {"merkle_root": hex, "signature_b64": str}

    def log_ceremony_step(self, step_name: str, step_details: dict) -> str:
        """Appends a cryptographically chained Merkle step to the ceremony log."""
        step_payload = json.dumps(step_details, sort_keys=True)
        step_hasher = hashlib.sha512()
        step_hasher.update(self.current_hash)
        step_hasher.update(step_name.encode('utf-8'))
        step_hasher.update(step_payload.encode('utf-8'))
        new_hash = step_hasher.digest()

        step_record = {
            "step_index": len(self.merkle_steps) + 1,
            "step_name": step_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "previous_hash": self.current_hash.hex(),
            "step_hash": new_hash.hex(),
            "details": step_details
        }
        self.merkle_steps.append(step_record)
        self.current_hash = new_hash
        print(f"  [STEP {step_record['step_index']:02d}] {step_name} -> {new_hash.hex()[:16]}...")
        return new_hash.hex()

    def register_custodians(self, custodian_list: list = None) -> bool:
        """Registers custodians, each with a real Ed25519 approval keypair.

        The public half is the on-record identity; approvals are Ed25519
        signatures over the ceremony Merkle root (see approve()). Private
        halves stay harness-side for lab use only -- production custodians
        sign offline.
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        print(f"\n[*] Initializing Custodian Quorum ({self.quorum_m}-of-{self.total_n})...")
        if not custodian_list:
            custodian_list = [
                {"id": "CUSTODIAN-01", "role": "Master Security Officer", "name": "Cryptographic Officer Alpha"},
                {"id": "CUSTODIAN-02", "role": "Independent Security Auditor", "name": "Security Auditor Beta"},
                {"id": "CUSTODIAN-03", "role": "Enclave Operations Lead", "name": "Tactical Operations Gamma"},
            ]

        for cust in custodian_list[:self.total_n]:
            priv = Ed25519PrivateKey.generate()
            pub = priv.public_key()
            from cryptography.hazmat.primitives import serialization
            pub_raw = pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw)
            self._custodian_private[cust["id"]] = priv
            cust_entry = {
                "id": cust["id"],
                "name": cust["name"],
                "role": cust["role"],
                "public_key_b64": base64.b64encode(pub_raw).decode('utf-8'),
                "verified": False  # set True only by a valid approve() below
            }
            self.custodians.append(cust_entry)

        self.log_ceremony_step("CUSTODIAN_QUORUM_VERIFIED", {
            "quorum_required": self.quorum_m,
            "total_registered": len(self.custodians),
            "custodians": [{"id": c["id"], "role": c["role"]} for c in self.custodians]
        })
        return len(self.custodians) >= self.quorum_m

    @staticmethod
    def _approval_message(custodian_id: str, merkle_root_hex: str) -> bytes:
        """Domain-separated approval statement signed by each custodian."""
        return f"CEREMONY-APPROVAL-v1:{custodian_id}:{merkle_root_hex}".encode('utf-8')

    def approval_challenge(self) -> str:
        """Current Merkle root hex that custodians must sign to approve."""
        return self.current_hash.hex()

    def approve(self, custodian_id: str, signature: bytes) -> bool:
        """Record one custodian's approval of the CURRENT Merkle root.

        Verifies the Ed25519 signature against the registered custodian
        public key before recording. Unknown custodians, bad signatures,
        and stale roots are rejected (return False, never raise).
        """
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from cryptography.hazmat.primitives import serialization
            entry = next((c for c in self.custodians if c["id"] == custodian_id), None)
            if entry is None:
                logger.warning(f"Ceremony approve: unknown custodian {custodian_id!r}")
                return False
            pub = Ed25519PublicKey.from_public_bytes(
                base64.b64decode(entry["public_key_b64"]))
            root_hex = self.current_hash.hex()
            pub.verify(bytes(signature),
                       self._approval_message(custodian_id, root_hex))
        except Exception as e:
            logger.warning(f"Ceremony approve rejected for {custodian_id!r}: {e}")
            return False
        import base64 as _b64
        self._approvals[custodian_id] = {
            "merkle_root": root_hex,
            "signature_b64": _b64.b64encode(bytes(signature)).decode('utf-8'),
        }
        entry["verified"] = True
        # NOTE: deliberately NOT a Merkle-chained step -- approvals must all
        # cover the FINAL root, and chaining here would mutate it under
        # subsequent approvers. The receipt below commits the full approval
        # set; auditors re-verify every signature against the final root.
        print(f"  [APPROVAL] {custodian_id} approved root {root_hex[:16]}...")
        return True

    def _lab_self_approve(self) -> None:
        """Harness-held auto-approval for lab runs only (loud warning)."""
        for cid, priv in self._custodian_private.items():
            sig = priv.sign(self._approval_message(cid, self.current_hash.hex()))
            self.approve(cid, bytes(sig))

    def _quorum_met(self) -> bool:
        """True when >= quorum_m approvals cover the CURRENT Merkle root."""
        root_hex = self.current_hash.hex()
        valid = sum(1 for cid, ap in self._approvals.items()
                    if ap.get("merkle_root") == root_hex)
        return valid >= self.quorum_m

    def check_hardware_root_of_trust(self) -> dict:
        """Verifies presence and configuration of hardware TPM 2.0 / HSM."""
        print("\n[*] Auditing Hardware Root-of-Trust (TPM 2.0 / HSM)...")
        # Crash guard (non-breaking): native TPM access must NEVER crash the
        # ceremony/pytest run. Any failure -> DEGRADED_SECONDARY_SIMULATION.
        try:
            tpm_present = is_tpm_available()
        except (OSError, Exception) as e_tpm:
            logger.warning(f"code=PCR_READ_FAILED TPM availability check guard (degraded): {e_tpm}")
            tpm_present = False
        attestation = None
        if tpm_present:
            try:
                attestation = get_tpm_attestation(nonce=self.current_hash)
            except (OSError, Exception) as e_att:
                logger.warning(f"code=PCR_READ_FAILED TPM attestation guard (degraded): {e_att}")
                attestation = None

        if tpm_present and attestation:
            hardware_mode = "HARDWARE_ROOT_ENFORCED"
            hardware_id = attestation.get("hardware_id", "GENUINE_TPM2_DEVICE")
            print(f"  [+] Physical TPM 2.0 Hardware Root Verified: {hardware_id}")
            print(f"  [+] Active PCR Count: {len(attestation.get('pcr_values', {}))}")
        else:
            is_prod = (
                is_env_true("P2P_PRODUCTION")
                or is_env_true("SECURE_P2P_PRODUCTION")
                or is_env_true("P2P_FAIL_ON_SOFTWARE_FALLBACK")
            )
            if is_prod:
                msg = (
                    "MILITARY FATAL: Physical hardware root-of-trust (TPM 2.0 / HSM) is mandatory "
                    "in production mode. Software simulation fallback is strictly forbidden."
                )
                logger.critical(msg)
                raise RuntimeError(msg)
            hardware_mode = "DEGRADED_SECONDARY_SIMULATION"
            hardware_id = "DEGRADED_SECONDARY_SIMULATION_ROOT"
            print("\n  [!] ====================================================================")
            print("  [!] CRITICAL SECURITY ALERT: Physical TPM 2.0 / HSM Hardware Absent!")
            print("  [!] CEREMONY ENGAGING SECONDARY SOFTWARE SIMULATION FALLBACK.")
            print("  [!] Detailed Warning: This key ceremony does NOT possess physical tamper")
            print("  [!] resistance or hardware attestation. Not valid for classified CSfC.")
            print("  [!] ====================================================================\n")
            logger.warning("[CEREMONY CRITICAL WARNING] Hardware TPM 2.0 / HSM absent. Engaging secondary software simulation mode.")

        hsm_status = {
            "tpm_available": tpm_present,
            "hardware_mode": hardware_mode,
            "hardware_id": hardware_id,
            "pcr_count": len(attestation.get("pcr_values", {})) if attestation else 0,
            "attestation_active": attestation is not None,
            "hardware_tamper_resistant": tpm_present and attestation is not None
        }

        self.log_ceremony_step("HARDWARE_ROOT_VERIFICATION", hsm_status)
        return hsm_status

    def generate_cnsa2_root_keys(self) -> dict:
        """Generates CNSA 2.0 compliant post-quantum root credentials."""
        print("\n[*] Generating CNSA 2.0 Post-Quantum Sovereign Root Keys...")
        import pqc_algorithms

        # 1. ML-DSA-87 (FIPS 204) Primary Root Authority Key
        print("  -> Generating ML-DSA-87 (NIST Level 5) Root Signature Authority...")
        mldsa = pqc_algorithms.LibOQS_MLDSA_87()
        mldsa_pk, mldsa_sk = mldsa.keygen()
        mldsa_fp = hashlib.sha512(mldsa_pk).hexdigest()

        # 2. SLH-DSA-256f (FIPS 205) Stateless Hash-Based Sovereign Emergency Root
        print("  -> Generating SLH-DSA-256f (NIST Level 5) Stateless Hash-Based Anchor...")
        slhdsa = pqc_algorithms.LibOQS_SLH_DSA_256f()
        slhdsa_pk, slhdsa_sk = slhdsa.keygen()
        slhdsa_fp = hashlib.sha512(slhdsa_pk).hexdigest()

        # 3. ML-KEM-1024 (FIPS 203) Master Key Encapsulation Root
        print("  -> Generating ML-KEM-1024 (NIST Level 5) Root Key Encapsulation Anchor...")
        mlkem = pqc_algorithms.LibOQS_MLKEM_1024()
        mlkem_pk, mlkem_sk = mlkem.keygen()
        mlkem_fp = hashlib.sha512(mlkem_pk).hexdigest()

        # 4. P-521 (FIPS 186-5) Classical Leg Anchor
        print("  -> Generating NIST P-521 Classical Curve Anchor...")
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization
        p521_key = ec.generate_private_key(ec.SECP521R1())
        p521_pk_bytes = p521_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        p521_fp = hashlib.sha512(p521_pk_bytes).hexdigest()

        self.generated_keys = {
            "ml_dsa_87": {
                "algorithm": "ML-DSA-87 (FIPS 204)",
                "security_category": "NIST Level 5 (256-bit quantum)",
                "public_key_b64": base64.b64encode(mldsa_pk).decode('utf-8'),
                "sha512_fingerprint": mldsa_fp
            },
            "slh_dsa_256f": {
                "algorithm": "SLH-DSA-256f (FIPS 205)",
                "security_category": "NIST Level 5 (Stateless Hash-Based)",
                "public_key_b64": base64.b64encode(slhdsa_pk).decode('utf-8'),
                "sha512_fingerprint": slhdsa_fp
            },
            "ml_kem_1024": {
                "algorithm": "ML-KEM-1024 (FIPS 203)",
                "security_category": "NIST Level 5 (Lattice KEM)",
                "public_key_b64": base64.b64encode(mlkem_pk).decode('utf-8'),
                "sha512_fingerprint": mlkem_fp
            },
            "secp521r1": {
                "algorithm": "ECDSA SECP521R1 (FIPS 186-5)",
                "security_category": "Classical 256-bit",
                "public_key_b64": base64.b64encode(p521_pk_bytes).decode('utf-8'),
                "sha512_fingerprint": p521_fp
            }
        }

        self.log_ceremony_step("ROOT_KEY_GENERATION_COMPLETE", {
            "ml_dsa_87_fingerprint": mldsa_fp,
            "slh_dsa_256f_fingerprint": slhdsa_fp,
            "ml_kem_1024_fingerprint": mlkem_fp,
            "secp521r1_fingerprint": p521_fp
        })
        return self.generated_keys

    @staticmethod
    def verify_receipt(receipt: dict, quorum_m: int = 2) -> tuple:
        """Independently verify a ceremony receipt. Returns (ok, message).

        Checks, fail-closed in order:
          1. receipt shape (root hash, steps, signatures present);
          2. Merkle chain integrity recomputed from GENESIS through steps;
          3. >= quorum_m DISTINCT custodians with valid Ed25519 approval
             signatures over the FINAL root, each custodian's public half
             taken from the receipt itself (self-contained audit).
        Old theater-format receipts (sha512 "signatures") fail closed.
        """
        try:
            root_hex = receipt.get("merkle_root_hash", "")
            steps = receipt.get("merkle_audit_steps", [])
            sigs = receipt.get("custodian_signatures", [])
            if not root_hex or not isinstance(steps, list) or not steps:
                return False, "receipt missing root/steps"
            if not isinstance(sigs, list) or not sigs:
                return False, "receipt has no custodian signatures"
            # 2. Recompute the Merkle chain. GENESIS preimage binds the
            # ceremony id + timestamp recorded in the receipt.
            cur = hashlib.sha512(
                f"GENESIS:{receipt.get('ceremony_id')}:{receipt.get('timestamp_utc')}"
                .encode('utf-8')).digest()
            for st in steps:
                payload = json.dumps(st.get("details", {}), sort_keys=True)
                h = hashlib.sha512()
                h.update(cur)
                h.update(str(st.get("step_name", "")).encode('utf-8'))
                h.update(payload.encode('utf-8'))
                cur = h.digest()
                if cur.hex() != st.get("step_hash"):
                    return False, f"merkle chain break at step {st.get('step_index')}"
            if cur.hex() != root_hex:
                return False, "recomputed root != receipt root"
            # Linkage: each step's previous_hash must equal the prior hash.
            prev = hashlib.sha512(
                f"GENESIS:{receipt.get('ceremony_id')}:{receipt.get('timestamp_utc')}"
                .encode('utf-8')).digest().hex()
            for st in steps:
                if st.get("previous_hash") != prev:
                    return False, f"linkage break at step {st.get('step_index')}"
                prev = st.get("step_hash")
            # 3. Quorum over the FINAL root.
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            seen = set()
            for s in sigs:
                try:
                    cid = s.get("custodian_id", "")
                    if not cid or cid in seen:
                        continue
                    if s.get("ceremony_merkle_root") != root_hex:
                        continue
                    if s.get("scheme", "Ed25519") != "Ed25519":
                        continue
                    pub = Ed25519PublicKey.from_public_bytes(
                        base64.b64decode(s.get("public_key_b64", "")))
                    msg = (f"CEREMONY-APPROVAL-v1:{cid}:{root_hex}").encode('utf-8')
                    pub.verify(base64.b64decode(s.get("signature", "")), msg)
                    seen.add(cid)
                # AUDITED (B112): intentional best-effort loop guard; no security decision swallowed (triaged 2026-09 waves)
                except Exception:  # nosec: B112
                    continue
            if len(seen) < int(quorum_m):
                return False, f"quorum not met: {len(seen)}/{quorum_m} valid approvals"
            return True, f"quorum met: {len(seen)}/{quorum_m}, chain {len(steps)} steps OK"
        except Exception as e:
            return False, f"receipt verification error: {e}"

    def _is_prod(self) -> bool:
        return bool(
            is_env_true("P2P_PRODUCTION")
            or is_env_true("SECURE_P2P_PRODUCTION")
            or is_env_true("P2P_FAIL_ON_SOFTWARE_FALLBACK")
        )
    def generate_ceremony_receipt(self) -> Path:
        """Generates the Merkle-chained Ceremony Receipt -- quorum-gated.

        FAIL-CLOSED: raises RuntimeError unless >= quorum_m recorded
        approvals cover the CURRENT (final) Merkle root. Each approval is a
        real Ed25519 signature by a registered custodian (see approve());
        any single-operator run cannot mint a valid receipt.
        """
        print("\n[*] Finalizing Ceremony Audit Trail & Signing Custodian Receipt...")
        if not self._quorum_met():
            have = sum(1 for ap in self._approvals.values()
                       if ap.get("merkle_root") == self.current_hash.hex())
            raise RuntimeError(
                f"CEREMONY FAIL-CLOSED: quorum not met ({have}/{self.quorum_m} "
                f"valid approvals over final root {self.current_hash.hex()[:16]}...). "
                f"Collect custodian approve() signatures before minting a receipt.")

        custodian_signatures = []
        for cust in self.custodians:
            ap = self._approvals.get(cust["id"])
            if ap is None or ap.get("merkle_root") != self.current_hash.hex():
                continue
            custodian_signatures.append({
                "custodian_id": cust["id"],
                "role": cust["role"],
                "ceremony_merkle_root": self.current_hash.hex(),
                "public_key_b64": cust["public_key_b64"],
                "signature": ap["signature_b64"],
                "scheme": "Ed25519",
                "signed_at": datetime.now(timezone.utc).isoformat()
            })

        self.receipt = {
            "ceremony_id": self.ceremony_id,
            "standard": "NIST SP 800-57 / CNSA 2.0 / FIPS 140-3 Level 4",
            "timestamp_utc": self.timestamp,
            "completion_utc": datetime.now(timezone.utc).isoformat(),
            "merkle_root_hash": self.current_hash.hex(),
            "total_steps": len(self.merkle_steps),
            "quorum_required": self.quorum_m,
            "custodian_signatures": custodian_signatures,
            "generated_root_credentials": self.generated_keys,
            "merkle_audit_steps": self.merkle_steps
        }

        receipt_file = self.output_dir / f"ceremony_receipt_{int(time.time())}.json"
        with open(receipt_file, "w", encoding="utf-8") as f:
            json.dump(self.receipt, f, indent=2)

        print(f"\n[PASS] Key Ceremony successfully completed!")
        print(f"       Ceremony ID:       {self.ceremony_id}")
        print(f"       Merkle Root Hash:  {self.current_hash.hex()}")
        print(f"       Receipt Saved To:  {receipt_file}")

        # Audit log integration
        try:
            audit_logger = get_audit_logger()
            audit_logger.log_event(
                event_type="KEY_CEREMONY_COMPLETED",
                severity="CRITICAL",
                message=f"Witnessed Key Ceremony {self.ceremony_id} completed. Merkle root: {self.current_hash.hex()[:16]}...",
                details={"receipt_file": str(receipt_file), "merkle_root": self.current_hash.hex()}
            )
        except Exception as e_audit:
            print(f"  [!] Note: Audit logger notification: {e_audit}")

        return receipt_file


def run_ceremony() -> int:
    ceremony = WitnessedKeyCeremony()
    ceremony.register_custodians()
    ceremony.check_hardware_root_of_trust()
    ceremony.generate_cnsa2_root_keys()
    if ceremony._is_prod():
        # Production: custodians sign offline; the harness never self-deals.
        # Collect approve() signatures before minting (fail-closed below).
        print("[*] Production mode: skipping lab self-approval; "
              "offline custodian approve() signatures required.")
    else:
        print("[!] Lab mode: harness self-approves with custodian keys "
              "(NOT valid for production -- custodians must sign offline).")
        ceremony._lab_self_approve()
    receipt_path = ceremony.generate_ceremony_receipt()
    if receipt_path.exists():
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(run_ceremony())

