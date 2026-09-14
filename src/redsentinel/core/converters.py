"""Explicit compatibility converters for legacy research contracts."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Protocol

from pydantic import BaseModel

from redsentinel.core.models import AgentProfile, AttackCandidate, DefenseCandidate, EvidenceRef


class LegacyAttackSpec(Protocol):
    attack_id: str
    risk_type: str
    strategy: str
    intensity: str
    target: str
    goal: str
    success_criteria: Sequence[str]
    label: str
    metadata: Mapping[str, Any]


class LegacyOptimizationAction(Protocol):
    type: str
    name: str
    mode: str | None
    parameters: Mapping[str, Any]


class LegacyOptimizationDirective(Protocol):
    directive_id: str
    agent_name: str
    target_node_id: str
    recommended_actions: Sequence[LegacyOptimizationAction]
    evidence_refs: Sequence[str]
    risk_type: str
    rationale: str


def agent_profile_from_legacy(source: Mapping[str, Any] | BaseModel) -> AgentProfile:
    """Validate an agent-profile-v1 payload and add canonical identity metadata."""

    payload = source.model_dump(mode="json") if isinstance(source, BaseModel) else dict(source)
    return AgentProfile.model_validate(payload)


def attack_candidate_from_legacy(source: LegacyAttackSpec) -> AttackCandidate:
    """Map a legacy AttackSpec field by field into the canonical contract."""

    metadata = dict(source.metadata)
    metadata.setdefault("legacy_label", source.label)
    return AttackCandidate(
        candidate_id=source.attack_id,
        source="legacy_attack_spec",
        risk_type=source.risk_type,
        strategy=source.strategy,
        intensity=source.intensity,
        target=source.target,
        goal=source.goal,
        success_criteria=list(source.success_criteria),
        metadata=metadata,
    )


def defense_candidate_from_legacy(source: LegacyOptimizationDirective) -> DefenseCandidate:
    """Map one legacy optimization directive into a defense candidate."""

    actions = [
        {
            "type": action.type,
            "name": action.name,
            "mode": action.mode,
            "parameters": dict(action.parameters),
        }
        for action in source.recommended_actions
    ]
    evidence = [EvidenceRef(ref=ref, kind="report") for ref in source.evidence_refs]
    return DefenseCandidate(
        candidate_id=source.directive_id,
        agent_name=source.agent_name,
        target_node_ids=[source.target_node_id],
        actions=actions,
        evidence_refs=evidence,
        metadata={
            "legacy_risk_type": source.risk_type,
            "legacy_rationale": source.rationale,
        },
    )


__all__ = [
    "LegacyAttackSpec",
    "LegacyOptimizationAction",
    "LegacyOptimizationDirective",
    "agent_profile_from_legacy",
    "attack_candidate_from_legacy",
    "defense_candidate_from_legacy",
]
