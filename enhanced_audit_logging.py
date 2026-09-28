"""
Enhanced Audit Logging System with Hash Chain and Cryptographic Signatures

SECURITY FEATURES:
- SHA3-512 hash chain for tamper-evident audit entries
- ML-DSA-87 signatures for log export verification
- Comprehensive logging of all cryptographic operations
- NIST FIPS 203/204/205 compliant cryptographic primitives

Requirements Implemented:
- 10.1: Hash-chain audit log with SHA3-512
- 10.2: Log all cryptographic operations
- 10.3: Log export with ML-DSA-87 signatures
- 10.4: Tamper-evident entries

Property 14: Audit Log Hash Chain
- For any sequence of audit entries, the hash chain must be verifiable
- Tampering with any entry invalidates the chain from that point forward
"""

import datetime
import json
import sqlite3
import threading
import hashlib
import os
import base64
import secrets
from enum import Enum
from dataclasses import dataclass, asdict, field
from typing import Optional, Dict, Any, List, Callable, Tuple
from collections import deque
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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


class CryptoOperationType(Enum):
    """Types of cryptographic operations to log."""
    KEY_GENERATION = "KEY_GENERATION"
    KEY_ROTATION = "KEY_ROTATION"
    KEY_DESTRUCTION = "KEY_DESTRUCTION"
    KEY_EXPORT = "KEY_EXPORT"
    KEY_IMPORT = "KEY_IMPORT"
    ENCRYPTION = "ENCRYPTION"
    DECRYPTION = "DECRYPTION"
    SIGNING = "SIGNING"
    SIGNATURE_VERIFICATION = "SIGNATURE_VERIFICATION"
    KEY_ENCAPSULATION = "KEY_ENCAPSULATION"
    KEY_DECAPSULATION = "KEY_DECAPSULATION"
    HASH_COMPUTATION = "HASH_COMPUTATION"
    KEY_DERIVATION = "KEY_DERIVATION"
    RANDOM_GENERATION = "RANDOM_GENERATION"


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
    CRYPTO_OPERATION = "CRYPTO_OPERATION"
    HASH_CHAIN_VERIFIED = "HASH_CHAIN_VERIFIED"
    HASH_CHAIN_TAMPERED = "HASH_CHAIN_TAMPERED"
    LOG_EXPORT = "LOG_EXPORT"


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
class HashChainEntry:
    """
    A single entry in the hash chain audit log.
    
    Each entry contains (per Requirements 9.1):
    - sequence_number: Monotonically increasing sequence number
    - timestamp: ISO 8601 timestamp
    - event_type: Type of audit event
    - severity: Event severity level
    - peer_id_hash: SHA3-256 hash of peer identifier (if applicable)
    - operation: Operation name
    - result: Operation result (SUCCESS/FAILURE)
    - message: Human-readable message
    - details: Additional structured details
    - previous_hash: SHA3-512 hash of the previous entry (genesis uses SHA3-512("GENESIS"))
    - entry_hash: SHA3-512 hash of this entry (computed from previous_hash + entry_data)
    """
    sequence_number: int
    timestamp: str
    event_type: str
    severity: str
    message: str
    details: Dict[str, Any]
    previous_hash: str
    entry_hash: str = ""
    peer_id_hash: Optional[str] = None  # SHA3-256 of peer_id per Requirements 9.1
    operation: Optional[str] = None  # Operation name per Requirements 9.1
    result: str = "SUCCESS"  # SUCCESS or FAILURE per Requirements 9.1
    
    def compute_hash(self) -> str:
        """
        Compute SHA3-512 hash of this entry.
        
        Per Requirements 9.3: event_hash = SHA3-512(previous_hash + entry_data)
        """
        # Concatenate previous_hash with entry data
        entry_data = (
            f"{self.sequence_number}|"
            f"{self.timestamp}|"
            f"{self.event_type}|"
            f"{self.severity}|"
            f"{self.peer_id_hash or ''}|"
            f"{self.operation or ''}|"
            f"{self.result}|"
            f"{self.message}|"
            f"{json.dumps(self.details, sort_keys=True)}"
        )
        # SHA3-512(previous_hash + entry_data)
        hash_input = self.previous_hash + entry_data
        return hashlib.sha3_512(hash_input.encode('utf-8')).hexdigest()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'sequence_number': self.sequence_number,
            'timestamp': self.timestamp,
            'event_type': self.event_type,
            'severity': self.severity,
            'peer_id_hash': self.peer_id_hash,
            'operation': self.operation,
            'result': self.result,
            'message': self.message,
            'details': self.details,
            'previous_hash': self.previous_hash,
            'entry_hash': self.entry_hash
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'HashChainEntry':
        """Create from dictionary."""
        return cls(
            sequence_number=data['sequence_number'],
            timestamp=data['timestamp'],
            event_type=data['event_type'],
            severity=data['severity'],
            message=data['message'],
            details=data.get('details', {}),
            previous_hash=data['previous_hash'],
            entry_hash=data.get('entry_hash', ''),
            peer_id_hash=data.get('peer_id_hash'),
            operation=data.get('operation'),
            result=data.get('result', 'SUCCESS')
        )




class HashChainAuditLogger:
    """
    Tamper-evident audit logger using SHA3-512 hash chain.
    
    Security Properties:
    - Each entry's hash depends on all previous entries
    - Tampering with any entry invalidates the chain from that point
    - Genesis entry uses SHA3-512("GENESIS") as initial hash
    - Sequence numbers prevent entry deletion/insertion
    
    Requirements:
    - 9.1: Log timestamp(ISO8601), event_type, severity, peer_id_hash, operation, result
    - 9.2: Log all key generation, rotation, destruction events
    - 9.3: Compute entry hash as SHA3-512(previous_hash + entry_data)
    - 9.4: Use previous_hash=SHA3-512("GENESIS") for first entry
    - 9.5: Export logs in JSON with ML-DSA-87 signature
    """
    
    # SHA3-512("GENESIS") as per Requirements 9.4
    GENESIS_HASH = hashlib.sha3_512(b"GENESIS").hexdigest()
    
    def __init__(self, db_path: Optional[str] = None):
        """Initialize hash chain audit logger."""
        self.db_path = db_path
        self.db_connection = None
        self.db_lock = threading.Lock()
        self._sequence_number = 0
        self._last_hash = self.GENESIS_HASH
        self._entries: List[HashChainEntry] = []
        self._signing_keys: Optional[Tuple[dict, dict]] = None
        self._signature_impl = None
        
        # Initialize ML-DSA-87 for signing
        self._init_signature_system()
        
        if db_path:
            self._initialize_database()
            self._load_chain_state()
    
    def _init_signature_system(self):
        """Initialize ML-DSA-87 signature system for log export."""
        try:
            from liboqs_wrapper import HybridSignature
            self._signature_impl = HybridSignature(mode='fast')  # ML-DSA-87
            self._signing_keys = self._signature_impl.keygen()
            logger.info("ML-DSA-87 signature system initialized for audit log signing")
        except ImportError as e:
            logger.warning(f"ML-DSA-87 not available, using fallback: {e}")
            self._signature_impl = None
            self._signing_keys = None
    
    def _initialize_database(self):
        """Initialize SQLite database for hash chain persistence."""
        try:
            self.db_connection = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = self.db_connection.cursor()
            
            # Enforce Write-Ahead Logging (WAL) and synchronous commit for crash-resilience and tamper-resistance
            cursor.execute('PRAGMA journal_mode=WAL;')
            cursor.execute('PRAGMA synchronous=NORMAL;')
            
            # Create hash chain entries table with all required fields per Requirements 9.1
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS hash_chain_entries (
                    sequence_number INTEGER PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    peer_id_hash TEXT,
                    operation TEXT,
                    result TEXT NOT NULL DEFAULT 'SUCCESS',
                    message TEXT NOT NULL,
                    details TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_hc_timestamp ON hash_chain_entries(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_hc_event_type ON hash_chain_entries(event_type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_hc_severity ON hash_chain_entries(severity)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_hc_peer_id ON hash_chain_entries(peer_id_hash)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_hc_operation ON hash_chain_entries(operation)')
            
            # Create signing keys table for ML-DSA-87 export signatures
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS signing_keys (
                    key_id TEXT PRIMARY KEY,
                    public_key_mldsa BLOB,
                    public_key_slhdsa BLOB,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            self.db_connection.commit()
            logger.info(f"Hash chain database initialized at {self.db_path}")
            
        except Exception as e:
            logger.error(f"Failed to initialize hash chain database: {e}")
            self.db_connection = None
    
    def _load_chain_state(self):
        """Load the last entry from database to continue the chain."""
        if not self.db_connection:
            return
        
        with self.db_lock:
            cursor = self.db_connection.cursor()
            cursor.execute('''
                SELECT sequence_number, entry_hash 
                FROM hash_chain_entries 
                ORDER BY sequence_number DESC 
                LIMIT 1
            ''')
            row = cursor.fetchone()
            
            if row:
                self._sequence_number = row[0]
                self._last_hash = row[1]
                logger.info(f"Loaded chain state: seq={self._sequence_number}, last_hash={self._last_hash[:16]}...")
            else:
                logger.info("Starting new hash chain from genesis")
    
    def add_entry(
        self,
        event_type: AuditEventType,
        message: str,
        severity: AuditSeverity = AuditSeverity.INFO,
        details: Optional[Dict[str, Any]] = None,
        peer_id_hash: Optional[str] = None,
        operation: Optional[str] = None,
        result: str = "SUCCESS"
    ) -> HashChainEntry:
        """
        Add a new entry to the hash chain.
        
        Per Requirements 9.1, each entry includes:
        - timestamp (ISO8601)
        - event_type
        - severity
        - peer_id_hash (SHA3-256 of peer_id)
        - operation
        - result (SUCCESS/FAILURE)
        
        Args:
            event_type: Type of audit event
            message: Human-readable message
            severity: Event severity level
            details: Additional structured details
            peer_id_hash: SHA3-256 hash of peer identifier
            operation: Operation name
            result: Operation result (SUCCESS/FAILURE)
        
        Returns:
            The created HashChainEntry with computed hash
        """
        with self.db_lock:
            self._sequence_number += 1
            timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')
            
            entry = HashChainEntry(
                sequence_number=self._sequence_number,
                timestamp=timestamp,
                event_type=event_type.value,
                severity=severity.value,
                message=message,
                details=redact_sensitive_audit_data(details or {}),
                previous_hash=self._last_hash,
                peer_id_hash=peer_id_hash,
                operation=operation,
                result=result
            )
            
            # Compute and set the entry hash per Requirements 9.3
            # event_hash = SHA3-512(previous_hash + entry_data)
            entry.entry_hash = entry.compute_hash()
            self._last_hash = entry.entry_hash
            
            # Store in memory
            self._entries.append(entry)
            
            # Persist to database
            if self.db_connection:
                self._persist_entry(entry)
            
            return entry
    
    def _persist_entry(self, entry: HashChainEntry):
        """Persist entry to database with all required fields per Requirements 9.1."""
        try:
            cursor = self.db_connection.cursor()
            cursor.execute('''
                INSERT INTO hash_chain_entries 
                (sequence_number, timestamp, event_type, severity, peer_id_hash, operation, result, message, details, previous_hash, entry_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                entry.sequence_number,
                entry.timestamp,
                entry.event_type,
                entry.severity,
                entry.peer_id_hash,
                entry.operation,
                entry.result,
                entry.message,
                json.dumps(entry.details),
                entry.previous_hash,
                entry.entry_hash
            ))
            self.db_connection.commit()
        except Exception as e:
            logger.error(f"Failed to persist hash chain entry: {e}")
    
    def verify_chain(self, start_seq: int = 1, end_seq: Optional[int] = None) -> Tuple[bool, Optional[int]]:
        """
        Verify the integrity of the hash chain.
        
        Property 14: Audit Log Hash Chain
        - For any sequence of audit entries, the hash chain must be verifiable
        - Tampering with any entry invalidates the chain from that point forward
        
        Args:
            start_seq: Starting sequence number (default: 1)
            end_seq: Ending sequence number (default: latest)
        
        Returns:
            Tuple of (is_valid, first_invalid_seq)
            - (True, None) if chain is valid
            - (False, seq_num) if chain is invalid starting at seq_num
        """
        entries = self._get_entries_range(start_seq, end_seq)
        
        if not entries:
            return True, None
        
        # Verify first entry links to genesis or previous entry
        expected_prev_hash = self.GENESIS_HASH if start_seq == 1 else self._get_entry_hash(start_seq - 1)
        
        for entry in entries:
            # Verify previous hash link
            if entry.previous_hash != expected_prev_hash:
                logger.error(f"Hash chain broken at seq {entry.sequence_number}: previous_hash mismatch")
                return False, entry.sequence_number
            
            # Verify entry hash
            computed_hash = entry.compute_hash()
            if entry.entry_hash != computed_hash:
                logger.error(f"Hash chain broken at seq {entry.sequence_number}: entry_hash mismatch")
                return False, entry.sequence_number
            
            expected_prev_hash = entry.entry_hash
        
        return True, None
    
    def _get_entries_range(self, start_seq: int, end_seq: Optional[int]) -> List[HashChainEntry]:
        """Get entries in a sequence range."""
        if self.db_connection:
            with self.db_lock:
                cursor = self.db_connection.cursor()
                if end_seq:
                    cursor.execute('''
                        SELECT * FROM hash_chain_entries 
                        WHERE sequence_number >= ? AND sequence_number <= ?
                        ORDER BY sequence_number
                    ''', (start_seq, end_seq))
                else:
                    cursor.execute('''
                        SELECT * FROM hash_chain_entries 
                        WHERE sequence_number >= ?
                        ORDER BY sequence_number
                    ''', (start_seq,))
                
                rows = cursor.fetchall()
                return [self._row_to_entry(row) for row in rows]
        else:
            if end_seq:
                return [e for e in self._entries if start_seq <= e.sequence_number <= end_seq]
            return [e for e in self._entries if e.sequence_number >= start_seq]
    
    def _get_entry_hash(self, seq: int) -> str:
        """Get the hash of a specific entry."""
        if self.db_connection:
            with self.db_lock:
                cursor = self.db_connection.cursor()
                cursor.execute('SELECT entry_hash FROM hash_chain_entries WHERE sequence_number = ?', (seq,))
                row = cursor.fetchone()
                return row[0] if row else self.GENESIS_HASH
        else:
            for entry in self._entries:
                if entry.sequence_number == seq:
                    return entry.entry_hash
            return self.GENESIS_HASH
    
    def _row_to_entry(self, row) -> HashChainEntry:
        """Convert database row to HashChainEntry with all required fields."""
        # Row order: sequence_number, timestamp, event_type, severity, peer_id_hash, 
        #            operation, result, message, details, previous_hash, entry_hash
        return HashChainEntry(
            sequence_number=row[0],
            timestamp=row[1],
            event_type=row[2],
            severity=row[3],
            peer_id_hash=row[4],
            operation=row[5],
            result=row[6],
            message=row[7],
            details=json.loads(row[8]) if row[8] else {},
            previous_hash=row[9],
            entry_hash=row[10]
        )

    
    def export_logs(
        self,
        start_seq: Optional[int] = None,
        end_seq: Optional[int] = None,
        include_signature: bool = True
    ) -> Dict[str, Any]:
        """
        Export audit logs in JSON format with ML-DSA-87 signature.
        
        Requirements:
        - 10.3: Export in JSON format, sign with ML-DSA-87
        
        Args:
            start_seq: Starting sequence number (default: 1)
            end_seq: Ending sequence number (default: latest)
            include_signature: Whether to include ML-DSA-87 signature
        
        Returns:
            Dict containing:
            - entries: List of audit entries
            - metadata: Export metadata
            - signature: ML-DSA-87 signature (if include_signature=True)
            - public_key: Public key for verification
        """
        start = start_seq or 1
        entries = self._get_entries_range(start, end_seq)
        
        # Verify chain integrity before export
        is_valid, invalid_seq = self.verify_chain(start, end_seq)
        
        export_data = {
            'version': '1.0',
            'export_timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z'),
            'chain_valid': is_valid,
            'invalid_from_seq': invalid_seq,
            'entry_count': len(entries),
            'first_seq': entries[0].sequence_number if entries else None,
            'last_seq': entries[-1].sequence_number if entries else None,
            'genesis_hash': self.GENESIS_HASH,
            'entries': [e.to_dict() for e in entries]
        }
        
        result = {
            'metadata': {
                'version': export_data['version'],
                'export_timestamp': export_data['export_timestamp'],
                'chain_valid': export_data['chain_valid'],
                'entry_count': export_data['entry_count'],
                'hash_algorithm': 'SHA3-512',
                'signature_algorithm': 'ML-DSA-87' if self._signature_impl else 'none'
            },
            'entries': export_data['entries']
        }
        
        if include_signature and self._signature_impl and self._signing_keys:
            # Sign the export data
            data_to_sign = json.dumps(export_data, sort_keys=True).encode('utf-8')
            public_keys, secret_keys = self._signing_keys
            
            signature = self._signature_impl.sign(secret_keys, data_to_sign)
            
            # Encode signature for JSON
            result['signature'] = {
                'mldsa': base64.b64encode(signature.get('mldsa', b'')).decode('utf-8') if signature.get('mldsa') else None,
                'slhdsa': base64.b64encode(signature.get('slhdsa', b'')).decode('utf-8') if signature.get('slhdsa') else None
            }
            
            # Include public key for verification
            result['public_key'] = {
                'mldsa': base64.b64encode(public_keys.get('mldsa', b'')).decode('utf-8') if public_keys.get('mldsa') else None,
                'slhdsa': base64.b64encode(public_keys.get('slhdsa', b'')).decode('utf-8') if public_keys.get('slhdsa') else None
            }
        
        # Log the export event
        self.add_entry(
            AuditEventType.LOG_EXPORT,
            f"Exported {len(entries)} audit entries",
            AuditSeverity.INFO,
            {
                'start_seq': start,
                'end_seq': end_seq,
                'entry_count': len(entries),
                'signed': include_signature and self._signature_impl is not None
            }
        )
        
        return result
    
    def verify_export_signature(self, export_data: Dict[str, Any]) -> bool:
        """
        Verify the ML-DSA-87 signature on exported logs.
        
        Args:
            export_data: The exported log data with signature
        
        Returns:
            True if signature is valid, False otherwise
        """
        if not self._signature_impl:
            logger.warning("Signature verification not available - ML-DSA-87 not initialized")
            return False
        
        if 'signature' not in export_data or 'public_key' not in export_data:
            logger.error("Export data missing signature or public key")
            return False
        
        try:
            # Reconstruct the signed data
            entries_data = {
                'version': export_data['metadata']['version'],
                'export_timestamp': export_data['metadata']['export_timestamp'],
                'chain_valid': export_data['metadata']['chain_valid'],
                'invalid_from_seq': None,
                'entry_count': export_data['metadata']['entry_count'],
                'first_seq': export_data['entries'][0]['sequence_number'] if export_data['entries'] else None,
                'last_seq': export_data['entries'][-1]['sequence_number'] if export_data['entries'] else None,
                'genesis_hash': self.GENESIS_HASH,
                'entries': export_data['entries']
            }
            
            data_to_verify = json.dumps(entries_data, sort_keys=True).encode('utf-8')
            
            # Decode signature and public key
            signature = {}
            public_keys = {}
            
            if export_data['signature'].get('mldsa'):
                signature['mldsa'] = base64.b64decode(export_data['signature']['mldsa'])
            if export_data['signature'].get('slhdsa'):
                signature['slhdsa'] = base64.b64decode(export_data['signature']['slhdsa'])
            
            if export_data['public_key'].get('mldsa'):
                public_keys['mldsa'] = base64.b64decode(export_data['public_key']['mldsa'])
            if export_data['public_key'].get('slhdsa'):
                public_keys['slhdsa'] = base64.b64decode(export_data['public_key']['slhdsa'])
            
            return self._signature_impl.verify(public_keys, data_to_verify, signature)
            
        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            return False
    
    def log_crypto_operation(
        self,
        operation: CryptoOperationType,
        algorithm: str,
        key_id: Optional[str] = None,
        success: bool = True,
        details: Optional[Dict[str, Any]] = None
    ) -> HashChainEntry:
        """
        Log a cryptographic operation.
        
        Requirements:
        - 10.2: Log all cryptographic operations (key generation, rotation, 
                destruction, encryption, decryption, signing)
        
        Args:
            operation: Type of cryptographic operation
            algorithm: Algorithm used (e.g., "ML-KEM-1024", "ML-DSA-87")
            key_id: Identifier for the key involved (if applicable)
            success: Whether the operation succeeded
            details: Additional operation details
        
        Returns:
            The created HashChainEntry
        """
        severity = AuditSeverity.INFO if success else AuditSeverity.HIGH
        
        op_details = {
            'operation': operation.value,
            'algorithm': algorithm,
            'key_id': key_id,
            'success': success,
            **(details or {})
        }
        
        message = f"Crypto operation: {operation.value} using {algorithm}"
        if key_id:
            message += f" (key: {key_id[:16]}...)" if len(key_id) > 16 else f" (key: {key_id})"
        if not success:
            message += " [FAILED]"
        
        return self.add_entry(
            AuditEventType.CRYPTO_OPERATION,
            message,
            severity,
            op_details
        )
    
    def get_entry_count(self) -> int:
        """Get the total number of entries in the chain."""
        return self._sequence_number
    
    def get_last_hash(self) -> str:
        """Get the hash of the last entry."""
        return self._last_hash
    
    def close(self):
        """Close the audit logger and clean up resources."""
        if self.db_connection:
            self.db_connection.close()
            logger.info("Hash chain audit logger closed")


# Global instance
_hash_chain_logger: Optional[HashChainAuditLogger] = None


def get_hash_chain_logger() -> HashChainAuditLogger:
    """Get the global hash chain audit logger instance."""
    global _hash_chain_logger
    if _hash_chain_logger is None:
        _hash_chain_logger = HashChainAuditLogger()
    return _hash_chain_logger


def initialize_hash_chain_logger(db_path: str) -> HashChainAuditLogger:
    """Initialize the global hash chain audit logger with database backend."""
    global _hash_chain_logger
    _hash_chain_logger = HashChainAuditLogger(db_path)
    return _hash_chain_logger


# Convenience functions for logging crypto operations
def log_key_generation(algorithm: str, key_id: str, success: bool = True, details: Dict = None):
    """Log a key generation operation."""
    return get_hash_chain_logger().log_crypto_operation(
        CryptoOperationType.KEY_GENERATION, algorithm, key_id, success, details
    )


def log_key_rotation(algorithm: str, old_key_id: str, new_key_id: str, success: bool = True):
    """Log a key rotation operation."""
    return get_hash_chain_logger().log_crypto_operation(
        CryptoOperationType.KEY_ROTATION, algorithm, new_key_id, success,
        {'old_key_id': old_key_id, 'new_key_id': new_key_id}
    )


def log_key_destruction(algorithm: str, key_id: str, wipe_method: str = "DoD-5220.22-M"):
    """Log a key destruction operation."""
    return get_hash_chain_logger().log_crypto_operation(
        CryptoOperationType.KEY_DESTRUCTION, algorithm, key_id, True,
        {'wipe_method': wipe_method}
    )


def log_encryption(algorithm: str, key_id: str, data_size: int, success: bool = True):
    """Log an encryption operation."""
    return get_hash_chain_logger().log_crypto_operation(
        CryptoOperationType.ENCRYPTION, algorithm, key_id, success,
        {'data_size_bytes': data_size}
    )


def log_decryption(algorithm: str, key_id: str, data_size: int, success: bool = True):
    """Log a decryption operation."""
    return get_hash_chain_logger().log_crypto_operation(
        CryptoOperationType.DECRYPTION, algorithm, key_id, success,
        {'data_size_bytes': data_size}
    )


def log_signing(algorithm: str, key_id: str, message_hash: str, success: bool = True):
    """Log a signing operation."""
    return get_hash_chain_logger().log_crypto_operation(
        CryptoOperationType.SIGNING, algorithm, key_id, success,
        {'message_hash': message_hash}
    )


def log_signature_verification(algorithm: str, key_id: str, valid: bool):
    """Log a signature verification operation."""
    return get_hash_chain_logger().log_crypto_operation(
        CryptoOperationType.SIGNATURE_VERIFICATION, algorithm, key_id, True,
        {'signature_valid': valid}
    )


if __name__ == "__main__":
    # Test the enhanced audit logging system
    print("=" * 80)
    print("Testing Enhanced Audit Logging with Hash Chain")
    print("=" * 80)
    
    # Initialize with database
    logger_instance = initialize_hash_chain_logger("test_hash_chain_audit.db")
    
    # Add some test entries
    print("\n1. Adding test entries...")
    logger_instance.add_entry(
        AuditEventType.SYSTEM_STARTUP,
        "System started",
        AuditSeverity.INFO
    )
    
    log_key_generation("ML-KEM-1024", "key_001", True, {'purpose': 'session_key'})
    log_encryption("AES-256-GCM", "key_001", 1024, True)
    log_signing("ML-DSA-87", "signing_key_001", "abc123...", True)
    
    logger_instance.add_entry(
        AuditEventType.SECURITY_VIOLATION,
        "Unauthorized access attempt",
        AuditSeverity.HIGH,
        {'source_ip': '192.168.1.100', 'attempts': 5}
    )
    
    print(f"   Added {logger_instance.get_entry_count()} entries")
    print(f"   Last hash: {logger_instance.get_last_hash()[:32]}...")
    
    # Verify chain integrity
    print("\n2. Verifying hash chain integrity...")
    is_valid, invalid_seq = logger_instance.verify_chain()
    print(f"   Chain valid: {is_valid}")
    if not is_valid:
        print(f"   Invalid from sequence: {invalid_seq}")
    
    # Export with signature
    print("\n3. Exporting logs with ML-DSA-87 signature...")
    export = logger_instance.export_logs(include_signature=True)
    print(f"   Exported {export['metadata']['entry_count']} entries")
    print(f"   Signature algorithm: {export['metadata']['signature_algorithm']}")
    if 'signature' in export:
        print(f"   Signature present: Yes")
        print(f"   ML-DSA signature length: {len(export['signature'].get('mldsa', '')) if export['signature'].get('mldsa') else 0} chars")
    
    # Verify export signature
    print("\n4. Verifying export signature...")
    if 'signature' in export:
        sig_valid = logger_instance.verify_export_signature(export)
        print(f"   Signature valid: {sig_valid}")
    
    # Clean up
    logger_instance.close()
    
    # Clean up test database
    import os
    if os.path.exists("test_hash_chain_audit.db"):
        os.remove("test_hash_chain_audit.db")
    
    print("\n" + "=" * 80)
    print("Enhanced Audit Logging Test Complete")
    print("=" * 80)



# ============================================================================
# Cryptographic Operation Audit Integration
# ============================================================================

class CryptoAuditIntegration:
    """
    Integration layer for auditing cryptographic operations.
    
    This class provides decorators and wrappers to automatically log
    cryptographic operations to the hash chain audit log.
    
    Requirements:
    - 10.2: Log all cryptographic operations (key generation, rotation,
            destruction, encryption, decryption, signing)
    """
    
    def __init__(self, logger: Optional[HashChainAuditLogger] = None):
        """Initialize with optional custom logger."""
        self._logger = logger or get_hash_chain_logger()
    
    def audit_keygen(self, algorithm: str):
        """
        Decorator to audit key generation operations.
        
        Usage:
            @audit.audit_keygen("ML-KEM-1024")
            def keygen(self):
                ...
        """
        def decorator(func):
            def wrapper(*args, **kwargs):
                key_id = secrets.token_hex(16)
                try:
                    result = func(*args, **kwargs)
                    self._logger.log_crypto_operation(
                        CryptoOperationType.KEY_GENERATION,
                        algorithm,
                        key_id,
                        success=True,
                        details={'function': func.__name__}
                    )
                    return result
                except Exception as e:
                    self._logger.log_crypto_operation(
                        CryptoOperationType.KEY_GENERATION,
                        algorithm,
                        key_id,
                        success=False,
                        details={'function': func.__name__, 'error': str(e)}
                    )
                    raise
            return wrapper
        return decorator
    
    def audit_encrypt(self, algorithm: str):
        """Decorator to audit encryption operations."""
        def decorator(func):
            def wrapper(*args, **kwargs):
                key_id = kwargs.get('key_id', 'unknown')
                try:
                    result = func(*args, **kwargs)
                    # Estimate data size from args
                    data_size = len(args[1]) if len(args) > 1 and isinstance(args[1], (bytes, str)) else 0
                    self._logger.log_crypto_operation(
                        CryptoOperationType.ENCRYPTION,
                        algorithm,
                        key_id,
                        success=True,
                        details={'data_size': data_size}
                    )
                    return result
                except Exception as e:
                    self._logger.log_crypto_operation(
                        CryptoOperationType.ENCRYPTION,
                        algorithm,
                        key_id,
                        success=False,
                        details={'error': str(e)}
                    )
                    raise
            return wrapper
        return decorator
    
    def audit_decrypt(self, algorithm: str):
        """Decorator to audit decryption operations."""
        def decorator(func):
            def wrapper(*args, **kwargs):
                key_id = kwargs.get('key_id', 'unknown')
                try:
                    result = func(*args, **kwargs)
                    self._logger.log_crypto_operation(
                        CryptoOperationType.DECRYPTION,
                        algorithm,
                        key_id,
                        success=True
                    )
                    return result
                except Exception as e:
                    self._logger.log_crypto_operation(
                        CryptoOperationType.DECRYPTION,
                        algorithm,
                        key_id,
                        success=False,
                        details={'error': str(e)}
                    )
                    raise
            return wrapper
        return decorator
    
    def audit_sign(self, algorithm: str):
        """Decorator to audit signing operations."""
        def decorator(func):
            def wrapper(*args, **kwargs):
                key_id = kwargs.get('key_id', 'unknown')
                try:
                    result = func(*args, **kwargs)
                    # Compute message hash for audit
                    message = args[1] if len(args) > 1 else kwargs.get('message', b'')
                    if isinstance(message, bytes):
                        msg_hash = hashlib.sha3_256(message).hexdigest()[:16]
                    else:
                        msg_hash = 'unknown'
                    self._logger.log_crypto_operation(
                        CryptoOperationType.SIGNING,
                        algorithm,
                        key_id,
                        success=True,
                        details={'message_hash': msg_hash}
                    )
                    return result
                except Exception as e:
                    self._logger.log_crypto_operation(
                        CryptoOperationType.SIGNING,
                        algorithm,
                        key_id,
                        success=False,
                        details={'error': str(e)}
                    )
                    raise
            return wrapper
        return decorator
    
    def audit_verify(self, algorithm: str):
        """Decorator to audit signature verification operations."""
        def decorator(func):
            def wrapper(*args, **kwargs):
                key_id = kwargs.get('key_id', 'unknown')
                try:
                    result = func(*args, **kwargs)
                    self._logger.log_crypto_operation(
                        CryptoOperationType.SIGNATURE_VERIFICATION,
                        algorithm,
                        key_id,
                        success=True,
                        details={'signature_valid': bool(result)}
                    )
                    return result
                except Exception as e:
                    self._logger.log_crypto_operation(
                        CryptoOperationType.SIGNATURE_VERIFICATION,
                        algorithm,
                        key_id,
                        success=False,
                        details={'error': str(e)}
                    )
                    raise
            return wrapper
        return decorator
    
    def log_key_rotation(self, algorithm: str, old_key_id: str, new_key_id: str):
        """Log a key rotation event."""
        return self._logger.log_crypto_operation(
            CryptoOperationType.KEY_ROTATION,
            algorithm,
            new_key_id,
            success=True,
            details={'old_key_id': old_key_id, 'new_key_id': new_key_id}
        )
    
    def log_key_destruction(self, algorithm: str, key_id: str, wipe_method: str = "DoD-5220.22-M"):
        """Log a key destruction event."""
        return self._logger.log_crypto_operation(
            CryptoOperationType.KEY_DESTRUCTION,
            algorithm,
            key_id,
            success=True,
            details={'wipe_method': wipe_method, 'secure_wipe': True}
        )
    
    def log_encapsulation(self, algorithm: str, key_id: str, success: bool = True):
        """Log a key encapsulation event."""
        return self._logger.log_crypto_operation(
            CryptoOperationType.KEY_ENCAPSULATION,
            algorithm,
            key_id,
            success=success
        )
    
    def log_decapsulation(self, algorithm: str, key_id: str, success: bool = True):
        """Log a key decapsulation event."""
        return self._logger.log_crypto_operation(
            CryptoOperationType.KEY_DECAPSULATION,
            algorithm,
            key_id,
            success=success
        )


# Global audit integration instance
_crypto_audit = CryptoAuditIntegration()


def get_crypto_audit() -> CryptoAuditIntegration:
    """Get the global crypto audit integration instance."""
    return _crypto_audit


# Export all public symbols
__all__ = [
    'HashChainAuditLogger',
    'HashChainEntry',
    'AuditEventType',
    'AuditSeverity',
    'CryptoOperationType',
    'CryptoAuditIntegration',
    'initialize_hash_chain_logger',
    'get_hash_chain_logger',
    'get_crypto_audit',
    'log_key_generation',
    'log_key_rotation',
    'log_key_destruction',
    'log_encryption',
    'log_decryption',
    'log_signing',
    'log_signature_verification',
]
