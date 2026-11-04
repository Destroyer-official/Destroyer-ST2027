# Module Documentation: audit_threat_monitoring

## 1. Purpose
The `audit_threat_monitoring` module provides tamper-evident append-only logging, real-time threat detection, automated network quarantine, and continuous security posture assessment (`audit_logging_system.py:1-1238`, `active_cyber_defense.py:1-570`, `zero_trust_engine.py:1-850`). It formats security events, redacts sensitive credential material, and streams telemetry to external SIEM endpoints (`remote_siem_forwarder.py:1-567`).

## 2. Public Interface

### 2.1 Classes and Key Methods

#### `enhanced_audit_logging.EnhancedAuditLogger` (`enhanced_audit_logging.py:85-230`)
- `__init__(log_path: str, initial_hash: Optional[bytes] = None)`: Initializes cryptographically chained logger (`enhanced_audit_logging.py:90-110`). If `initial_hash` is not provided, uses SHA3-256 of empty bytes (`:95`).
- `log_chained_event(event_type: str, details: dict) -> ChainedAuditRecord`: Formats event, computes cryptographic link, writes JSON record to disk, and returns record (`enhanced_audit_logging.py:115-165`). Raises `IOError` if disk write fails (`:155`).
- `verify_log_integrity() -> Tuple[bool, Optional[int]]`: Iterates through log file and verifies hash continuity (`enhanced_audit_logging.py:180-220`). Returns `(True, None)` if valid, or `(False, sequence_num)` on first detected corruption or truncation (`:215`).

#### `audit_logging_system.AuditLoggingSystem` (`audit_logging_system.py:120-310`)
- `log_event(event_type: AuditEventType, severity: AuditSeverity, details: dict) -> None`: Submits event for sanitization and emission across console, file, and SIEM handlers (`audit_logging_system.py:140-190`).
- `_sanitize_event_data(data: dict) -> dict`: Scans dictionary keys matching `(key|secret|password|token|private|seed|passphrase|credential)` and replaces values with `"[REDACTED]"` (`audit_logging_system.py:210-260`).

#### `active_cyber_defense.ActiveCyberDefense` (`active_cyber_defense.py:75-240`)
- `record_violation(peer_id: str, violation_type: str, severity: int = 1) -> None`: Increments violation score for `peer_id` (`active_cyber_defense.py:95-135`). If score exceeds threshold, transitions peer to `QuarantineState.ISOLATED` (`:120`).
- `is_peer_quarantined(peer_id: str) -> bool`: Returns `True` if peer is currently under quarantine lockdown (`active_cyber_defense.py:140-155`).
- `release_quarantine(peer_id: str) -> bool`: Removes quarantine state after cooldown period expires (`active_cyber_defense.py:160-185`).

#### `zero_trust_engine.ZeroTrustEngine` (`zero_trust_engine.py:80-260`)
- `evaluate_access(peer_id: str, context: dict) -> AccessDecision`: Evaluates attestation freshness, network latency, and violation history (`zero_trust_engine.py:120-195`). Returns `AccessDecision(allow=True)` if trust score $\ge 75$; otherwise returns `AccessDecision(allow=False, reason="Insufficient trust score")` (`:180-190`).

#### `report_trust.ReportTrustManager` (`report_trust.py:60-210`)
- `sign_report(report_json: str, signing_key: bytes) -> str`: Signs JSON payload using ML-DSA-87 and embeds detached signature into metadata envelope (`report_trust.py:80-130`).
- `verify_report(envelope_json: str, public_key: bytes) -> bool`: Verifies ML-DSA-87 signature over enclosed payload (`report_trust.py:140-185`). Returns boolean.

## 3. Data Formats and Byte Layouts

### 3.1 Cryptographic Hash Chain Record Layout (`enhanced_audit_logging.py:85-140`)
Each record is serialized as a single-line canonical JSON record followed by newline:
- Layout of fields participating in hash computation:
  - Sequence number: 8-byte big-endian unsigned integer ($S_i$)
  - Timestamp: 8-byte IEEE 754 float ($T_i$)
  - Event type string: UTF-8 bytes ($E_i$)
  - Serialized payload digest: 32 bytes SHA3-256 of canonical JSON ($P_i$)
  - Previous hash: 32 bytes SHA3-256 digest ($H_{i-1}$)
- Arithmetic verification of hash computation:
  - Hash digest length: Exactly 32 bytes ($256 \text{ bits}$) via SHA3-256 (`hashlib.sha3_256`).
  - Next hash: $H_i = \text{SHA3-256}(S_i \parallel T_i \parallel E_i \parallel P_i \parallel H_{i-1})$. Length is exactly 32 bytes. Sum matches code arithmetic.

### 3.2 Spool Buffer SQLite Schema (`remote_siem_forwarder.py:120-150`)
- Table `siem_spool`: `(id INTEGER PRIMARY KEY, timestamp REAL, event_type TEXT, payload BLOB, status INTEGER)`.
- Storage overhead: Approximately 128 bytes metadata per buffered event.

## 4. Algorithms and Pinned Libraries
- SHA3-256: NIST FIPS 202. Provided by standard library `hashlib.sha3_256` (`enhanced_audit_logging.py:22`).
- ML-DSA-87: NIST FIPS 204. Provided by `oqs.dll` version 0.16.0 for report trust envelopes (`report_trust.py:35`).
- TLS 1.3: IETF RFC 8446. Provided by standard library `ssl` for SIEM forwarding (`remote_siem_forwarder.py:85`).
- Rolling Window Scoring: Sliding-window decay counter for active cyber defense (`active_cyber_defense.py:90`).

## 5. Dependencies and Hardware Requirements
- Python libraries: `psutil>=5.9.0` for host process inspection (`process_monitor_manager.py:30`).
- Database: Embedded `sqlite3` for local spool buffers (`remote_siem_forwarder.py:120`).
- Operating System APIs: Win32 `CreateToolhelp32Snapshot` or POSIX `/proc` for child process enumeration (`process_monitor_manager.py:110-140`).

## 6. Failure Behavior
- Audit log write failure raises fatal `IOError` to halt node execution rather than allow unlogged actions (`enhanced_audit_logging.py:155`).
- Hash chain integrity violation raises `AuditIntegrityError` (`enhanced_audit_logging.py:218`).
- Remote SIEM connection failure does not crash node: events are diverted to local spool buffer (`remote_siem_forwarder.py:165`).
- Invalid report signature raises `ReportTrustVerificationError` (`report_trust.py:175`).

## 7. Configuration and Environment Variables
- `P2P_AUDIT_LOG_DIR`: Directory path for append-only audit files. Default: `"logs/audit"` (`audit_logging_system.py:45`).
- `P2P_SIEM_ENDPOINT`: Remote host:port for SIEM forwarder. Default: unset (`remote_siem_forwarder.py:55`).
- `P2P_ACD_THRESHOLD`: Violation score triggering peer isolation. Default: `5` (`active_cyber_defense.py:40`).
- `P2P_ACD_COOLDOWN_SEC`: Isolation duration in seconds. Default: `300` (`active_cyber_defense.py:42`).
- `P2P_MIN_TRUST_SCORE`: Minimum Zero Trust score required for channel access. Default: `75` (`zero_trust_engine.py:50`).

## 8. Tests Covered and Not Covered
- Covered by Automated Tests:
  - Hash chain verification and tamper detection: verified in `tests/test_audit_p1_remediations_phase2.py` (6 tests).
  - Sensitive token redaction across logs: verified in `tests/test_security_audit_remediations.py` (`test_audit_log_sensitive_data_redaction`).
  - Active cyber defense quarantine triggering: verified in `tests/test_phase4_ato_redteam_siem.py` (10 tests).
  - ML-DSA-87 signed report verification: verified in `tests/test_phase4_ato_redteam_siem.py` (4 tests).
- NOT Covered:
  - `process_monitor_manager.py` (1,201 lines) has zero dedicated automated unit tests.
  - Multi-terabyte audit log rotation under sustained disk exhaustion.

## 9. Not Implemented / External Dependencies
- External SIEM Collectors: Remote log forwarding requires an external Splunk, Elasticsearch, or syslog daemon reachable over TLS (`remote_siem_forwarder.py`).
- Continuous Monitoring Automation: cATO machine-readable dossiers require external compliance review tools to parse OSCAL JSON output (`cato_continuous_monitoring_engine.py`).

## 10. Known Limitations and Residual Risks
- Triplicate Logger Architecture: The codebase contains three separate loggers (`audit_logger.py`, `audit_logging_system.py`, `enhanced_audit_logging.py`) with divergent write paths.
- Memory Consumption under Long Disconnections: `SpoolBuffer` in `remote_siem_forwarder.py` can grow unbounded if the remote SIEM collector remains offline indefinitely.

## 11. Discrepancies
- Promotional identifiers: Diagnostic banners in `security_diagnostics.py` emit operational labels flagged in `docs/audit/discrepancies.md`.

## 12. Open Questions for the Author
- Should `audit_logger.py` be deprecated and removed in favor of `enhanced_audit_logging.py`?
