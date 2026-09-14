from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Literal


GoalGuardDecisionValue = Literal["allow", "block"]
GoalGuardRiskLevel = Literal["normal", "high"]


@dataclass(frozen=True)
class GoalGuardInput:
    goal_id: str
    original_goal: str
    current_goal: str
    metadata: dict[str, Any] = field(default_factory=dict)
    evidence: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class GoalGuardDecision:
    allowed: bool
    decision: GoalGuardDecisionValue
    risk_level: GoalGuardRiskLevel
    reason: str
    attribution: list[dict[str, Any]]
    audit_payload: dict[str, str]


def evaluate_goal_guard(goal_input: GoalGuardInput) -> GoalGuardDecision:
    attribution = [dict(item) for item in goal_input.evidence if _is_goal_drift_evidence(item)]

    if attribution:
        reason = str(attribution[0].get("summary") or "Goal drift evidence found.")
        return GoalGuardDecision(
            allowed=False,
            decision="block",
            risk_level="high",
            reason=reason,
            attribution=attribution,
            audit_payload=_build_audit_payload(goal_input, "blocked_goal_drift", "high", reason),
        )

    reason = "No goal drift evidence found."
    return GoalGuardDecision(
        allowed=True,
        decision="allow",
        risk_level="normal",
        reason=reason,
        attribution=[],
        audit_payload=_build_audit_payload(goal_input, "allowed", "normal", reason),
    )


def _is_goal_drift_evidence(evidence: dict[str, Any]) -> bool:
    if not isinstance(evidence, dict):
        return False

    if evidence.get("kind") == "goal_perturbation":
        return True

    if evidence.get("evidence_type") in {
        "metadata_injection",
        "state_delta_injection",
        "prompt_perturbation",
    }:
        return True

    if evidence.get("label") == "perturbed" or evidence.get("decision") == "drifted":
        return True

    serialized = json.dumps(evidence, ensure_ascii=False, sort_keys=True).lower()
    return "goal_perturbation" in serialized or "goal drift" in serialized


def _build_audit_payload(
    goal_input: GoalGuardInput,
    result: str,
    risk_level: GoalGuardRiskLevel,
    reason: str,
) -> dict[str, str]:
    return {
        "user_id": "goal_guard",
        "role": "system",
        "operation": "goal_guard_decision",
        "input_content": f"goal_id={goal_input.goal_id}; current_goal={goal_input.current_goal[:120]}",
        "result": f"{result}: {reason}",
        "risk_level": risk_level,
    }


__all__ = [
    "GoalGuardDecision",
    "GoalGuardInput",
    "evaluate_goal_guard",
]
