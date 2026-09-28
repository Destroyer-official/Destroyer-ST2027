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
