"""Tamper-evident audit API used by generic defense components."""

from redsentinel.defenses.engine.security.audit import (
    configure_signing,
    read_audit_log,
    read_audit_log_json,
    verify_audit_integrity,
    write_audit_log,
)

__all__ = [
    "configure_signing",
    "read_audit_log",
    "read_audit_log_json",
    "verify_audit_integrity",
    "write_audit_log",
]
