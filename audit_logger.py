# Destroyer-ST2027 Military Production Hardening Release (2026-10-26)
# NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204
"""
Audit Logger re-export module for backward compatibility.
Exposes AuditLogger and related classes from audit_logging_system.
"""

from audit_logging_system import (
    AuditLogger,
    AuditEvent,
    AuditEventType,
    AuditSeverity,
    log_event,
    get_audit_system,
)

__all__ = [
    "AuditLogger",
    "AuditEvent",
    "AuditEventType",
    "AuditSeverity",
    "log_event",
    "get_audit_system",
]
