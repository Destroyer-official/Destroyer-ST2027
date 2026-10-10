from __future__ import annotations

import datetime
import json
import sqlite3
import threading
import hashlib
import os
import base64
import secrets
from pathlib import Path
from enum import Enum
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any, List, Callable, Tuple
from collections import deque
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def _get_audit_encryption_key() -> bytes:
    """Derive 256-bit AES-GCM audit encryption key with PBKDF2-210k or sealed DPAPI (Finding 3)."""
    passphrase = os.environ.get("P2P_AUDIT_PASSPHRASE") or os.environ.get("P2P_STORAGE_PASSPHRASE")
    if passphrase:
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        salt = b"SecureP2P::AuditDbSalt::v1::StrictEntropy"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=210000
        )
        return kdf.derive(passphrase.encode('utf-8'))

    # If no passphrase, use sealed DPAPI key
    key_dir = os.environ.get("P2P_BASE_DIR") or os.path.dirname(os.path.abspath(__file__))
    sealed_key_path = os.path.join(key_dir, ".secure_audit_kek.sealed")
    
    raw_key = None
    if os.path.exists(sealed_key_path):
        try:
            from air_gapped_operation import win_dpapi_unprotect
            with open(sealed_key_path, 'rb') as f:
                raw_key = win_dpapi_unprotect(f.read())
        except Exception:
            raw_key = None

    if not raw_key or len(raw_key) < 32:
        new_secret = secrets.token_bytes(32)
        try:
            from air_gapped_operation import win_dpapi_protect
            enc = win_dpapi_protect(new_secret)
            with open(sealed_key_path, 'wb') as f:
                f.write(enc)
            os.chmod(sealed_key_path, 0o600)
            raw_key = new_secret
        except Exception as e:
            raise SecurityError(
                "P2P_AUDIT_PASSPHRASE or P2P_STORAGE_PASSPHRASE environment variable is required to encrypt audit database. "
                "Predictable username/hostname fallbacks are prohibited under NIST Level 5+ / zero-trust policy."
            ) from e

    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    hkdf = HKDF(
        algorithm=hashes.SHA3_512(),
        length=32,
        salt=b"SecureP2P::AuditDbSalt::v1::HKDF",
        info=b"SecureP2P::AuditEncryptionKey::v1"
    )
    return hkdf.derive(raw_key)

def _encrypt_db_field(val: Any) -> str:
    if val is None:
        return ""
    plaintext = json.dumps(val).encode('utf-8')
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = _get_audit_encryption_key()
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=b"SecureP2P::AuditField::v1")
    return "ENC:" + base64.b64encode(nonce + ct).decode('ascii')

def _decrypt_db_field(val_str: Optional[str]) -> Any:
    if not val_str:
        return {}
    if val_str.startswith("ENC:"):
        try:
            raw = base64.b64decode(val_str[4:])
            nonce = raw[:12]
            ct = raw[12:]
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            key = _get_audit_encryption_key()
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ct, associated_data=b"SecureP2P::AuditField::v1")
            return json.loads(plaintext.decode('utf-8'))
        except Exception:
            return {}
    try:
        return json.loads(val_str)
    except Exception:
        return val_str

def enforce_audit_db_permissions(db_path: str) -> None:
    """Enforce restrictive permissions (0600 on POSIX, restricted ACL on Windows) (Finding 7)."""
    try:
        db_file = Path(db_path)
        db_dir = db_file.parent
        db_dir.mkdir(parents=True, exist_ok=True)
        if os.name == 'nt':
            # AUDITED (B404): subprocess use verified list-form argv, zero shell=True repo-wide
            import subprocess  # nosec: B404
            username = os.environ.get('USERNAME')
            if username:
                subprocess.run(['icacls', str(db_dir), '/inheritance:r', '/grant:r', f'{username}:(OI)(CI)F'], capture_output=True, check=False)  # nosec: B603 B607
                if db_file.exists():
                    subprocess.run(['icacls', str(db_file), '/inheritance:r', '/grant:r', f'{username}:F'], capture_output=True, check=False)  # nosec: B603 B607
        else:
            os.chmod(db_dir, 0o700)
            if db_file.exists():
                os.chmod(db_file, 0o600)
    except Exception as e:
        logger.debug(f"Could not enforce database permissions: {e}")

class AuditEventType(Enum):
    """Enumeration of audit event types for comprehensive security logging."""
    SYSTEM_STARTUP = "SYSTEM_STARTUP"
    SYSTEM_SHUTDOWN = "SYSTEM_SHUTDOWN"
    CONNECTION_ESTABLISHED = "CONNECTION_ESTABLISHED"
    CONNECTION_FAILURE = "CONNECTION_FAILURE"
    CONNECTION_CLOSED = "CONNECTION_CLOSED"
    AUTHENTICATION_SUCCESS = "AUTHENTICATION_SUCCESS"
    AUTHENTICATION_FAILURE = "AUTHENTICATION_FAILURE"
    SECURITY_VIOLATION = "SECURITY_VIOLATION"
    MESSAGE_SENT = "MESSAGE_SENT"
    MESSAGE_RECEIVED = "MESSAGE_RECEIVED"
    KEY_EXCHANGE = "KEY_EXCHANGE"
    KEY_ROTATION = "KEY_ROTATION"
    USER_LOGIN = "USER_LOGIN"
    USER_LOGOUT = "USER_LOGOUT"
    DATA_EXPORT = "DATA_EXPORT"
    DATA_IMPORT = "DATA_IMPORT"
    FILE_OPERATION = "FILE_OPERATION"
    CONFIGURATION_CHANGE = "CONFIGURATION_CHANGE"
    THREAT_DETECTED = "THREAT_DETECTED"
    THREAT_MITIGATED = "THREAT_MITIGATED"
    AUDIT_LOG_ACCESSED = "AUDIT_LOG_ACCESSED"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    ANOMALY_DETECTED = "ANOMALY_DETECTED"
    DATABASE_ERROR = "DATABASE_ERROR"
    DATABASE_BACKUP = "DATABASE_BACKUP"
    DATABASE_RESTORE = "DATABASE_RESTORE"
    DATABASE_MIGRATION = "DATABASE_MIGRATION"

class AuditSeverity(Enum):
    """Severity levels for audit events."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    EMERGENCY = "EMERGENCY"

@dataclass
class AuditEvent:
    """Represents a security audit event with comprehensive metadata."""
    event_id: str
    timestamp: datetime.datetime
    event_type: AuditEventType
    severity: AuditSeverity
    message: str
    user_id: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    user_agent: Optional[str] = None
    session_id: Optional[str] = None
    details: Dict[str, Any] = None
    threat_indicators: List[str] = None
    compliance_tags: List[str] = None
    hash_integrity: Optional[str] = None
    previous_hash: Optional[str] = None

    def __post_init__(self):
        """Generate integrity hash after initialization with Merkle chaining."""
        if self.details is None:
            self.details = {}
        if self.threat_indicators is None:
            self.threat_indicators = []
        if self.compliance_tags is None:
            self.compliance_tags = []

        # Calculate Merkle-chained integrity hash (NIST Level 5: SHA-512)
        if not self.hash_integrity:
            prev = self.previous_hash or ("0" * 128)
            et_str = getattr(self.event_type, 'value', str(self.event_type))
            sev_str = getattr(self.severity, 'value', str(self.severity))
            event_data = f"{prev}{self.event_id}{self.timestamp.isoformat()}{et_str}{sev_str}{self.message}"
            self.hash_integrity = hashlib.sha512(event_data.encode('utf-8')).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for serialization."""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        data['event_type'] = getattr(self.event_type, 'value', str(self.event_type))
        data['severity'] = getattr(self.severity, 'value', str(self.severity))
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AuditEvent':
        """Create AuditEvent from dictionary."""
        data['timestamp'] = datetime.datetime.fromisoformat(data['timestamp'])
        data['event_type'] = AuditEventType(data['event_type']) if isinstance(data['event_type'], str) and data['event_type'] in AuditEventType._value2member_map_ else data['event_type']
        data['severity'] = AuditSeverity(data['severity']) if isinstance(data['severity'], str) and data['severity'] in AuditSeverity._value2member_map_ else data['severity']
        return cls(**data)

SENSITIVE_AUDIT_KEYS = {
    'key', 'secret', 'passphrase', 'token', 'content', 'plaintext', 
    'password', 'private_key', 'shared_secret', 'pin', 'seed', 'privkey',
    'mnemonic', 'nonce', 'dek', 'kek', 'key_material', 'credential',
    'auth_token', 'master_key', 'root_key', 'chain_key', 'session_key'
}

SAFE_AUDIT_METADATA_KEYS = {
    'key_id', 'kid', 'key_algorithm', 'key_type', 'key_len', 'key_length', 'key_size',
    'peer_id_hash', 'operation', 'algorithm', 'session_id', 'event_id', 'user_id',
    'public_id', 'node_id', 'device_id', 'fingerprint', 'key_fingerprint'
}

def redact_sensitive_audit_data(data: Any) -> Any:
    """Recursively redact sensitive cryptographic keys and plaintext content (Item 42 / Finding 6.4)."""
    if isinstance(data, dict):
        redacted = {}
        for k, v in data.items():
            k_lower = str(k).lower()
            if k_lower in SAFE_AUDIT_METADATA_KEYS and not (isinstance(v, (bytes, bytearray)) and len(v) >= 16 and 'key' in k_lower and k_lower != 'key_id'):
                redacted[k] = redact_sensitive_audit_data(v)
            elif any(s in k_lower for s in SENSITIVE_AUDIT_KEYS):
                if isinstance(v, (bytes, bytearray)):
                    redacted[k] = f"[REDACTED_BYTES_{len(v)}]"
                elif isinstance(v, str):
                    redacted[k] = f"[REDACTED_STRING_{len(v)}]"
                else:
                    redacted[k] = "[REDACTED]"
            else:
                redacted[k] = redact_sensitive_audit_data(v)
        return redacted
    elif isinstance(data, list):
        return [redact_sensitive_audit_data(item) for item in data]
    return data

def log_event(event_type: AuditEventType, message: str, severity: AuditSeverity = AuditSeverity.LOW, details: dict = None):
    """Logs an audit event with a timestamp, type, message, severity, and optional details."""
    timestamp = datetime.datetime.now()
    event_id = f"{int(timestamp.timestamp() * 1000)}_{hashlib.sha384(message.encode()).hexdigest()[:8]}"

    sanitized_details = redact_sensitive_audit_data(details or {})

    event = AuditEvent(
        event_id=event_id,
        timestamp=timestamp,
        event_type=event_type,
        severity=severity,
        message=message,
        details=sanitized_details
    )

    # Log to console
    et_str = getattr(event_type, 'value', str(event_type))
    sev_str = getattr(severity, 'value', str(severity))
    log_entry = f"[{timestamp.strftime('%Y-%m-%d %H:%M:%S')}] [{et_str}] [{sev_str}] {message}"
    if sanitized_details:
        log_entry += f" Details: {sanitized_details}"
    print(f"AUDIT LOG: {log_entry}")

    # Store in database if available
    if hasattr(_audit_system, 'db_connection') and _audit_system.db_connection:
        _audit_system.store_event(event)

    # Trigger event handlers
    if hasattr(_audit_system, 'event_handlers'):
        for handler in _audit_system.event_handlers:
            try:
                handler(event)
            except Exception as e:
                logger.error(f"Error in event handler: {e}")

    return event

def log_security_violation(violation_type: str, description: str, source_ip: Optional[str] = None,
                          user_id: Optional[str] = None, evidence: Dict[str, Any] = None):
    """Log a security violation with enhanced details."""
    details = {
        'violation_type': violation_type,
        'evidence': evidence or {},
        'mitigation_applied': False
    }

    event = log_event(
        event_type=AuditEventType.SECURITY_VIOLATION,
        message=f"Security Violation: {violation_type} - {description}",
        severity=AuditSeverity.HIGH,
        details=details
    )

    if source_ip:
        event.source_ip = source_ip
    if user_id:
        event.user_id = user_id

    # Trigger security response
    if hasattr(_audit_system, 'security_response_handler'):
        _audit_system.security_response_handler(event)

    return event

class AuditLogger:
    """State-of-the-art audit logger with database persistence and real-time monitoring."""

    def __init__(self, db_path: Optional[str] = None):
        """Initialize audit logger with optional database backend."""
        self.db_path = db_path
        self.db_connection = None
        self.db_lock = threading.Lock()
        self.event_handlers: List[Callable[[AuditEvent], None]] = []
        self.event_buffer = deque(maxlen=1000)  # Buffer for high-frequency events
        self.buffer_lock = threading.Lock()
        self.flush_thread = None
        self.running = False
        self.security_response_handler = None
        self._last_event_hash = "0" * 128
        self.stats = {
            'total_events': 0,
            'events_by_type': {},
            'events_by_severity': {},
            'last_flush': datetime.datetime.now()
        }

        if db_path:
            self._initialize_database()
            self._start_flush_thread()

    def _initialize_database(self):
        """Initialize SQLite database for audit log persistence with restrictive filesystem permissions (Finding 7)."""
        try:
            enforce_audit_db_permissions(self.db_path)
            self.db_connection = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = self.db_connection.cursor()

            # Enforce Write-Ahead Logging (WAL) and synchronous commit for crash-resilience and tamper-resistance
            cursor.execute('PRAGMA journal_mode=WAL;')
            cursor.execute('PRAGMA synchronous=NORMAL;')

            # Create audit events table with comprehensive schema including Merkle chained previous_hash
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    message TEXT NOT NULL,
                    user_id TEXT,
                    source_ip TEXT,
                    destination_ip TEXT,
                    user_agent TEXT,
                    session_id TEXT,
                    details TEXT,
                    threat_indicators TEXT,
                    compliance_tags TEXT,
                    hash_integrity TEXT NOT NULL,
                    previous_hash TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Ensure schema migration for existing databases
            try:
                cursor.execute('ALTER TABLE audit_events ADD COLUMN previous_hash TEXT')
            except sqlite3.OperationalError:
                pass

            # Create indexes for efficient querying
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_events(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_type ON audit_events(event_type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_severity ON audit_events(severity)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_id ON audit_events(user_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_source_ip ON audit_events(source_ip)')

            # Enforce Write-Once-Read-Many (WORM) policy via database-level triggers
            cursor.execute('''
                CREATE TRIGGER IF NOT EXISTS prevent_audit_update BEFORE UPDATE ON audit_events
                BEGIN
                    SELECT RAISE(ABORT, 'WORM Policy Violation: Audit events are immutable and cannot be updated');
                END;
            ''')
            cursor.execute('''
                CREATE TRIGGER IF NOT EXISTS prevent_audit_delete BEFORE DELETE ON audit_events
                BEGIN
                    SELECT RAISE(ABORT, 'WORM Policy Violation: Audit events are immutable and cannot be deleted');
                END;
            ''')

            self.db_connection.commit()

            # Resume Merkle chain state from latest committed record
            cursor.execute('SELECT hash_integrity FROM audit_events ORDER BY rowid DESC LIMIT 1')
            row = cursor.fetchone()
            if row and row[0]:
                self._last_event_hash = row[0]

            logger.info(f"Audit database initialized at {self.db_path} (WAL + WORM triggers + Merkle chaining active)")

        except Exception as e:
            logger.error(f"Failed to initialize audit database: {e}")
            self.db_connection = None

    def _start_flush_thread(self):
        """Start background thread to flush events to database."""
        self.running = True
        self.flush_thread = threading.Thread(target=self._flush_events_loop, daemon=True)
        self.flush_thread.start()

    def _flush_events_loop(self):
        """Background loop to periodically flush buffered events to database."""
        while self.running:
            try:
                threading.Event().wait(5)  # Flush every 5 seconds
                self.flush_buffer()
            except Exception as e:
                logger.error(f"Error in flush loop: {e}")

    def flush_buffer(self):
        """Flush buffered events to database."""
        if not self.db_connection:
            return

        with self.buffer_lock:
            if not self.event_buffer:
                return

            events_to_flush = list(self.event_buffer)
            self.event_buffer.clear()

        with self.db_lock:
            try:
                cursor = self.db_connection.cursor()
                for event in events_to_flush:
                    et_val = getattr(event.event_type, 'value', str(event.event_type))
                    sev_val = getattr(event.severity, 'value', str(event.severity))
                    cursor.execute('''
                        INSERT INTO audit_events (
                            event_id, timestamp, event_type, severity, message,
                            user_id, source_ip, destination_ip, user_agent, session_id,
                            details, threat_indicators, compliance_tags, hash_integrity,
                            previous_hash
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        event.event_id, event.timestamp.isoformat(), et_val,
                        sev_val, event.message, event.user_id, event.source_ip,
                        event.destination_ip, event.user_agent, event.session_id,
                        _encrypt_db_field(event.details), _encrypt_db_field(event.threat_indicators),
                        json.dumps(event.compliance_tags), event.hash_integrity,
                        event.previous_hash
                    ))

                self.db_connection.commit()
                enforce_audit_db_permissions(self.db_path)
                self.stats['last_flush'] = datetime.datetime.now()
                logger.debug(f"Flushed {len(events_to_flush)} events to database")

            except Exception as e:
                logger.error(f"Failed to flush events to database: {e}")

    def store_event(self, event: AuditEvent):
        """Store an audit event in the buffer for eventual persistence with Merkle chaining."""
        with self.buffer_lock:
            # Cryptographic Merkle chaining
            event.previous_hash = self._last_event_hash
            prev = event.previous_hash or ("0" * 128)
            event_type = getattr(event.event_type, 'value', str(event.event_type))
            severity = getattr(event.severity, 'value', str(event.severity))
            event_data = f"{prev}{event.event_id}{event.timestamp.isoformat()}{event_type}{severity}{event.message}"
            event.hash_integrity = hashlib.sha512(event_data.encode('utf-8')).hexdigest()
            self._last_event_hash = event.hash_integrity

            self.event_buffer.append(event)

            # Update statistics
            self.stats['total_events'] += 1

            if event_type not in self.stats['events_by_type']:
                self.stats['events_by_type'][event_type] = 0
            self.stats['events_by_type'][event_type] += 1

            if severity not in self.stats['events_by_severity']:
                self.stats['events_by_severity'][severity] = 0
            self.stats['events_by_severity'][severity] += 1

        # Real-time out-of-band streaming to SIEM
        self._stream_to_siem(event)

    def _stream_to_siem(self, event: AuditEvent):
        """Stream audit event to external SIEM syslog receiver and/or immutable WORM storage."""
        # 2028 hardening: SIEM/WORM sink gets redacted view only. DB keeps
        # field-level encrypted round-trip (pinned by
        # test_finding_7_audit_db_restricted_and_encrypted); external sinks
        # must never receive raw secrets even when operator-gated.
        try:
            redacted_payload = redact_sensitive_audit_data(event.to_dict())
        except Exception:
            redacted_payload = {"event_id": getattr(event, "event_id", "unknown"), "redaction": "failed-closed"}
        # Cryptographic HMAC forward chaining (DoD RMF AU-9 / AU-10 tamper evidence)
        try:
            from remote_siem_forwarder import emit_siem_event
            emit_siem_event(
                event_type=str(event.event_type.value if hasattr(event.event_type, 'value') else event.event_type),
                severity=str(event.severity.value if hasattr(event.severity, 'value') else event.severity),
                payload=redacted_payload,
                source_id="AUDIT_SYSTEM",
            )
        except Exception as e_siem:
            logger.debug(f"SIEM HMAC chaining non-fatal notice: {e_siem}")

        # Check WORM append storage
        worm_path = os.environ.get('P2P_WORM_STORAGE_PATH')
        if worm_path:
            try:
                line = json.dumps(redacted_payload) + "\n"
                with open(worm_path, "a", encoding="utf-8") as f_worm:
                    f_worm.write(line)
                    f_worm.flush()
                    os.fsync(f_worm.fileno())
            except Exception as e_worm:
                logger.debug(f"WORM storage append non-fatal notice: {e_worm}")

        # In Air-Gapped mode, network streaming to external SIEM/syslog is strictly forbidden
        if os.environ.get("P2P_AIR_GAPPED_MODE") == "1":
            return

        siem_endpoint = os.environ.get('SIEM_ENDPOINT') or os.environ.get('P2P_SIEM_ENDPOINT')
        if not siem_endpoint:
            return
        try:
            # Format as JSON payload for SIEM ingest
            payload = (json.dumps(redacted_payload) + "\n").encode('utf-8')
            if siem_endpoint.startswith('udp://'):
                import socket
                parts = siem_endpoint[6:].split(':')
                host, port = parts[0], int(parts[1]) if len(parts) > 1 else 514
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2.0)
                sock.sendto(payload, (host, port))
                sock.close()
            elif siem_endpoint.startswith('tcp://'):
                import socket
                parts = siem_endpoint[6:].split(':')
                host, port = parts[0], int(parts[1]) if len(parts) > 1 else 514
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.0)
                sock.connect((host, port))
                sock.sendall(payload)
                sock.close()
            elif siem_endpoint.startswith('tls://') or siem_endpoint.startswith('ssl://'):
                import socket
                import ssl
                prefix_len = 6 if siem_endpoint.startswith('tls://') else 6
                parts = siem_endpoint[prefix_len:].split(':')
                host, port = parts[0], int(parts[1]) if len(parts) > 1 else 6514
                raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                raw_sock.settimeout(3.0)
                ca_cert_file = os.environ.get('P2P_SIEM_CA_CERT', None)
                if ca_cert_file and os.path.exists(ca_cert_file):
                    ssl_ctx = ssl.create_default_context(cafile=ca_cert_file)
                else:
                    ssl_ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
                ssl_ctx.check_hostname = True
                ssl_ctx.verify_mode = ssl.CERT_REQUIRED
                if hasattr(ssl, 'TLSVersion'):
                    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
                with ssl_ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                    tls_sock.connect((host, port))
                    tls_sock.sendall(payload)
        except Exception as e:
            logger.debug(f"SIEM stream non-fatal notice: {e}")

    def verify_chain_integrity(self) -> Tuple[bool, Optional[str]]:
        """
        Verify the mathematical integrity of the cryptographic Merkle chain.
        Returns:
            (True, None) if the chain is unbroken and valid.
            (False, description) if any tampering, insertion, or deletion is detected.
        """
        if not self.db_connection:
            return False, "Database not connected"

        with self.db_lock:
            cursor = self.db_connection.cursor()
            cursor.execute('''
                SELECT event_id, timestamp, event_type, severity, message, hash_integrity, previous_hash
                FROM audit_events ORDER BY rowid ASC
            ''')
            rows = cursor.fetchall()
            if not rows:
                return True, None

            expected_prev = "0" * 128
            for idx, (event_id, timestamp, event_type, severity, message, hash_integrity, previous_hash) in enumerate(rows):
                if previous_hash != expected_prev:
                    return False, f"Broken chain link at row {idx} (event {event_id}): expected previous {expected_prev[:16]}, got {str(previous_hash)[:16]}"
                
                event_data = f"{previous_hash}{event_id}{timestamp}{event_type}{severity}{message}"
                computed_hash = hashlib.sha512(event_data.encode('utf-8')).hexdigest()
                if computed_hash != hash_integrity:
                    return False, f"Hash integrity failure at row {idx} (event {event_id}): recomputed {computed_hash[:16]} != stored {hash_integrity[:16]}"
                
                expected_prev = hash_integrity

            return True, None

    def log_event(self, event_type: Any, message_or_details: Any = None,
                  severity: Any = AuditSeverity.LOW, details: dict = None,
                  *, message: Any = None, **kwargs) -> AuditEvent:
        """Log an audit event."""
        if event_type is None:
            raise ValueError("event_type cannot be None")
        if message is not None:
            msg_str = str(message)
            if message_or_details is not None and isinstance(message_or_details, dict) and details is None:
                details = message_or_details
        elif isinstance(message_or_details, dict) and details is None:
            details = message_or_details
            msg_str = str(getattr(event_type, 'value', event_type))
        else:
            msg_str = str(message_or_details) if message_or_details is not None else str(getattr(event_type, 'value', event_type))
        if msg_str is None:
            raise ValueError("message cannot be None")

        if isinstance(severity, str):
            sev_upper = severity.upper()
            if sev_upper in AuditSeverity._value2member_map_:
                severity = AuditSeverity(sev_upper)

        timestamp = datetime.datetime.now()
        event_id = f"{int(timestamp.timestamp() * 1000)}_{hashlib.sha384(msg_str.encode()).hexdigest()[:8]}"
        # NOTE (verified, do not "fix"): details are intentionally NOT
        # denylist-redacted here. This path feeds field-level encryption
        # at rest (see test_finding_7_audit_db_restricted_and_encrypted:
        # raw SQLite must not contain plaintext, query_events decrypts).
        # Redacting here would destroy the encrypt/decrypt round-trip the
        # test pins. Untrusted free-form callers are redacted on the
        # global log_event path above; SIEM/WORM sinks are operator-
        # controlled, env-gated channels.
        event = AuditEvent(
            event_id=event_id,
            timestamp=timestamp,
            event_type=event_type,
            severity=severity,
            message=msg_str,
            details=details or {}
        )
        self.store_event(event)
        return event

    def log_security_event(self, event_type: Any, details: dict = None,
                           severity: AuditSeverity = AuditSeverity.HIGH) -> AuditEvent:
        """Log a security event."""
        return self.log_event(event_type=event_type, message_or_details=details, severity=severity)

    async def async_log_event(self, event_type: AuditEventType, message: str,
                             severity: AuditSeverity = AuditSeverity.LOW, details: dict = None) -> AuditEvent:
        """Async version of log_event for compatibility."""
        return self.log_event(event_type, message, severity, details)

    def add_event_handler(self, handler: Callable[[AuditEvent], None]):
        """Add a handler to be called for each audit event."""
        self.event_handlers.append(handler)
        logger.info(f"Added event handler: {handler.__name__ if hasattr(handler, '__name__') else handler}")

    def set_security_response_handler(self, handler: Callable[[AuditEvent], None]):
        """Set handler for security violations."""
        self.security_response_handler = handler

    def query_events(self, start_time: Optional[datetime.datetime] = None,
                    end_time: Optional[datetime.datetime] = None,
                    event_type: Optional[AuditEventType] = None,
                    severity: Optional[AuditSeverity] = None,
                    user_id: Optional[str] = None,
                    limit: int = 100) -> List[AuditEvent]:
        """Query audit events from database with filters."""
        if not self.db_connection:
            return []

        # B608: query is fixed SQL with ? placeholders only; no string-formatted
        # user input is ever interpolated (all filters appended as parameterized
        # clauses). nosec marks the audited false positive.
        query = "SELECT * FROM audit_events WHERE 1=1"  # nosec B608 - parameterized, no string formatting
        params = []

        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time.isoformat())

        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time.isoformat())

        if event_type:
            query += " AND event_type = ?"
            params.append(getattr(event_type, 'value', str(event_type)))

        if severity:
            query += " AND severity = ?"
            params.append(getattr(severity, 'value', str(severity)))

        if user_id:
            query += " AND user_id = ?"
            params.append(user_id)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self.db_lock:
            cursor = self.db_connection.cursor()
            cursor.execute(query, params)  # nosec B608 - fixed query + ? params, see above
            rows = cursor.fetchall()

        events = []
        for row in rows:
            event_data = {
                'event_id': row[0],
                'timestamp': row[1],
                'event_type': row[2],
                'severity': row[3],
                'message': row[4],
                'user_id': row[5],
                'source_ip': row[6],
                'destination_ip': row[7],
                'user_agent': row[8],
                'session_id': row[9],
                'details': _decrypt_db_field(row[10]),
                'threat_indicators': _decrypt_db_field(row[11]),
                'compliance_tags': json.loads(row[12]) if row[12] else [],
                'hash_integrity': row[13]
            }
            events.append(AuditEvent.from_dict(event_data))

        return events

    def get_statistics(self) -> Dict[str, Any]:
        """Get audit logging statistics."""
        return self.stats.copy()

    def export_worm_log(self, export_path: Optional[str] = None) -> str:
        """
        Export audit records to an immutable, cryptographically hash-chained WORM log file.
        Each record is chained to the previous record using SHA3-512 to ensure tamper evidence.
        """
        self.flush_buffer()
        if not self.db_connection:
            raise RuntimeError("Database connection not initialized")

        if not export_path:
            base_dir = os.path.dirname(self.db_path) if self.db_path else "."
            export_path = os.path.join(base_dir, f"{os.path.basename(self.db_path)}.worm.jsonl")

        with self.db_lock:
            cursor = self.db_connection.cursor()
            cursor.execute('''
                SELECT event_id, timestamp, event_type, severity, message,
                       user_id, source_ip, destination_ip, user_agent, session_id,
                       details, threat_indicators, compliance_tags, hash_integrity, created_at
                FROM audit_events
                ORDER BY timestamp ASC, created_at ASC
            ''')
            rows = cursor.fetchall()

        previous_hash = "GENESIS_WORM_BLOCK_0000000000000000000000000000000000000000000000000000000000000000"
        with open(export_path, 'w', encoding='utf-8') as f:
            for idx, row in enumerate(rows):
                record = {
                    "index": idx,
                    "event_id": row[0],
                    "timestamp": row[1],
                    "event_type": row[2],
                    "severity": row[3],
                    "message": row[4],
                    "user_id": row[5],
                    "source_ip": row[6],
                    "destination_ip": row[7],
                    "user_agent": row[8],
                    "session_id": row[9],
                    "details": json.loads(row[10]) if row[10] else {},
                    "threat_indicators": json.loads(row[11]) if row[11] else {},
                    "compliance_tags": json.loads(row[12]) if row[12] else [],
                    "event_hash": row[13],
                    "created_at": str(row[14]),
                    "previous_chain_hash": previous_hash
                }
                serialized = json.dumps(record, sort_keys=True)
                chain_hash = hashlib.sha3_512(serialized.encode('utf-8')).hexdigest()
                record["chain_hash"] = chain_hash
                previous_hash = chain_hash
                f.write(json.dumps(record) + "\n")

        logger.info(f"WORM audit log exported successfully: {len(rows)} records written to {export_path}")
        return export_path

    @staticmethod
    def verify_worm_log(export_path: str) -> Tuple[bool, int, str]:
        """
        Verify the cryptographic SHA3-512 hash chain of a WORM audit export file.
        Returns: (is_valid, record_count, status_message)
        """
        if not os.path.exists(export_path):
            return False, 0, f"File not found: {export_path}"

        previous_hash = "GENESIS_WORM_BLOCK_0000000000000000000000000000000000000000000000000000000000000000"
        count = 0
        with open(export_path, 'r', encoding='utf-8') as f:
            for line_no, line in enumerate(f, 1):
                if not line.strip():
                    continue
                record = json.loads(line.strip())
                stored_chain_hash = record.get("chain_hash")
                if record.get("previous_chain_hash") != previous_hash:
                    return False, count, f"Hash chain break at line {line_no}: previous hash mismatch"

                # Recompute chain hash
                verify_record = record.copy()
                del verify_record["chain_hash"]
                serialized = json.dumps(verify_record, sort_keys=True)
                expected_chain_hash = hashlib.sha3_512(serialized.encode('utf-8')).hexdigest()

                if stored_chain_hash != expected_chain_hash:
                    return False, count, f"Hash tampering at line {line_no}: computed hash does not match stored hash"

                previous_hash = stored_chain_hash
                count += 1

        return True, count, f"Verified intact cryptographic hash chain of {count} records"

    def close(self):
        """Close the audit logger and clean up resources."""
        self.running = False
        self.flush_buffer()  # Final flush

        if self.flush_thread:
            self.flush_thread.join(timeout=2)

        if self.db_connection:
            self.db_connection.close()

        logger.info("Audit logger closed")

# Global audit system instance
_audit_system = AuditLogger()

def initialize_audit_system(db_path: str) -> AuditLogger:
    """Initialize the global audit system with database backend."""
    global _audit_system
    print(f"AUDIT LOG: Initializing audit system with DB path: {db_path}")
    _audit_system = AuditLogger(db_path)
    return _audit_system

def get_audit_logger() -> AuditLogger:
    """Get the global audit logger instance."""
    return _audit_system

# Convenience function for async compatibility
async def async_log_security_violation(*args, **kwargs):
    """Async wrapper for log_security_violation."""
    return log_security_violation(*args, **kwargs)

if __name__ == "__main__":
    # Initialize with database
    audit_system = initialize_audit_system("audit_log.db")

    # Test logging
    log_event(AuditEventType.SYSTEM_STARTUP, "Audit logging system initialized.", AuditSeverity.INFO)
    log_event(AuditEventType.SECURITY_VIOLATION, "Unauthorized access attempt detected.",
             AuditSeverity.HIGH, {"ip": "192.168.1.1", "user": "attacker"})

    # Test security violation logging
    log_security_violation(
        violation_type="brute_force",
        description="Multiple failed login attempts",
        source_ip="192.168.1.100",
        user_id="user123",
        evidence={"attempts": 5, "time_window": "60s"}
    )

    # Flush and close
    audit_system.flush_buffer()
    audit_system.close()

