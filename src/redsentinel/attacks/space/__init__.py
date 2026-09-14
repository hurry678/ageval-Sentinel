"""Canonical attack space and deterministic synthetic target."""

from redsentinel.attacks.engine.threat_taxonomy import (
    DEFAULT_TARGET_RESISTANCE,
    ESCALATION_LADDERS,
    THREAT_CATEGORIES,
    THREAT_CATEGORY_ALIASES,
    AttackStrategy,
    SyntheticTarget,
    TargetResponse,
    canonical_threat_category,
    is_known_threat_category,
    ladder_for,
)

__all__ = [
    "DEFAULT_TARGET_RESISTANCE",
    "ESCALATION_LADDERS",
    "THREAT_CATEGORIES",
    "THREAT_CATEGORY_ALIASES",
    "AttackStrategy",
    "SyntheticTarget",
    "TargetResponse",
    "canonical_threat_category",
    "is_known_threat_category",
    "ladder_for",
]
