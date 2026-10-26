#!/usr/bin/env python3
# Destroyer-ST2027 Military Production Hardening Release (2026-10-26)
# NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204
"""WORM audit exports must use a keyed chain, not recomputable SHA3-512."""

import json

import audit_logging_system as audit

KEY = b"\x11" * 32


def _make_logger(tmp_path):
    return audit.AuditLogger(db_path=str(tmp_path / "audit.db"))


def test_worm_export_is_keyed_and_verifies(tmp_path):
    logger = _make_logger(tmp_path)
    try:
        logger.log_event(audit.AuditEventType.SECURITY_VIOLATION, "one")
        logger.log_event(audit.AuditEventType.SECURITY_VIOLATION, "two")
        out = logger.export_worm_log(str(tmp_path / "worm.jsonl"), hmac_key=KEY)
    finally:
        logger.close()

    ok, count, _ = audit.AuditLogger.verify_worm_log(out, hmac_key=KEY)
    assert ok is True  # nosec: B101
    assert count == 2  # nosec: B101

    ok, _, _ = audit.AuditLogger.verify_worm_log(out, hmac_key=b"\x22" * 32)
    assert ok is False  # nosec: B101

    with open(out, "r", encoding="utf-8") as f:
        first = json.loads(f.readline())
    assert first["chain_hash"].startswith(audit._WORM_CHAIN_PREFIX)  # nosec: B101


def test_worm_tamper_and_legacy_unkeyed_rejected(tmp_path, monkeypatch):
    logger = _make_logger(tmp_path)
    try:
        logger.log_event(audit.AuditEventType.SECURITY_VIOLATION, "tamper-me")
        out = logger.export_worm_log(str(tmp_path / "worm.jsonl"), hmac_key=KEY)
    finally:
        logger.close()

    with open(out, "r", encoding="utf-8") as f:
        record = json.loads(f.readline())
    record["message"] = "rewritten"
    with open(out, "w", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
    ok, _, _ = audit.AuditLogger.verify_worm_log(out, hmac_key=KEY)
    assert ok is False  # nosec: B101

    monkeypatch.delenv("P2P_ALLOW_LEGACY_WORM_CHAIN", raising=False)
    legacy_record = {
        "index": 0,
        "message": "legacy",
        "previous_chain_hash": audit._WORM_GENESIS,
    }
    serialized = json.dumps(legacy_record, sort_keys=True)
    legacy_record["chain_hash"] = audit.hashlib.sha3_512(
        serialized.encode("utf-8")
    ).hexdigest()
    legacy_path = tmp_path / "legacy.jsonl"
    legacy_path.write_text(json.dumps(legacy_record) + "\n", encoding="utf-8")
    ok, _, msg = audit.AuditLogger.verify_worm_log(str(legacy_path), hmac_key=KEY)
    assert ok is False  # nosec: B101
    assert "legacy" in msg.lower()  # nosec: B101


def test_db_chain_legacy_downgrade_is_gated(monkeypatch):
    monkeypatch.delenv("P2P_ALLOW_LEGACY_AUDIT_CHAIN", raising=False)
    payload = "legacy-row"
    legacy = audit.hashlib.sha512(payload.encode("utf-8")).hexdigest()
    assert audit._verify_chain_value(payload, legacy) is False  # nosec: B101
    monkeypatch.setenv("P2P_ALLOW_LEGACY_AUDIT_CHAIN", "1")
    assert audit._verify_chain_value(payload, legacy) is True  # nosec: B101
