"""Stable policy API over the legacy rule implementation.

The large rule table remains a single source of truth during migration. New
research code imports this module; legacy callers keep working through their
existing path until the compatibility window closes.
"""

from redsentinel.defenses.engine.security.policy.engine import (
    DEFAULT_POLICY_RULES,
    PolicyDecision,
    PolicyDecisionValue,
    check_policy,
    evaluate_policy,
    get_policy_summary,
    load_policy_rules,
    reset_policy_rules,
    write_policy_audit,
)

__all__ = [
    "DEFAULT_POLICY_RULES",
    "PolicyDecision",
    "PolicyDecisionValue",
    "check_policy",
    "evaluate_policy",
    "get_policy_summary",
    "load_policy_rules",
    "reset_policy_rules",
    "write_policy_audit",
]
