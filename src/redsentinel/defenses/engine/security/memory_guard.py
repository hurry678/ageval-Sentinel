from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Literal


MemoryGuardDecisionValue = Literal["allow", "block"]
MemoryGuardRiskLevel = Literal["normal", "high"]


@dataclass(frozen=True)
class MemoryGuardInput:
    namespace: str
    memory_key: str
    content: str
    metadata: dict[str, Any] = field(default_factory=dict)
    evidence: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class MemoryGuardDecision:
    allowed: bool
    decision: MemoryGuardDecisionValue
    risk_level: MemoryGuardRiskLevel
    reason: str
    attribution: list[dict[str, Any]]
    audit_payload: dict[str, str]


def evaluate_memory_guard(memory_input: MemoryGuardInput) -> MemoryGuardDecision:
    attribution = [dict(item) for item in memory_input.evidence if _is_poisoning_evidence(item)]

    if attribution:
        reason = str(attribution[0].get("summary") or "Memory poisoning evidence found.")
        return MemoryGuardDecision(
            allowed=False,
            decision="block",
            risk_level="high",
            reason=reason,
            attribution=attribution,
            audit_payload=_build_audit_payload(memory_input, "blocked_memory_poisoning", "high", reason),
        )

    reason = "No memory poisoning evidence found."
    return MemoryGuardDecision(
        allowed=True,
        decision="allow",
        risk_level="normal",
        reason=reason,
        attribution=[],
        audit_payload=_build_audit_payload(memory_input, "allowed", "normal", reason),
    )


def _is_poisoning_evidence(evidence: dict[str, Any]) -> bool:
    if not isinstance(evidence, dict):
        return False

    if evidence.get("kind") == "memory_poisoning":
        return True

    if evidence.get("evidence_type") in {
        "metadata_injection",
        "memory_operation",
        "state_delta_injection",
    }:
        return True

    if evidence.get("label") == "poisoned" or evidence.get("decision") == "poisoned":
        return True

    return "poison" in json.dumps(evidence, ensure_ascii=False, sort_keys=True).lower()


def _build_audit_payload(
    memory_input: MemoryGuardInput,
    result: str,
    risk_level: MemoryGuardRiskLevel,
    reason: str,
) -> dict[str, str]:
    return {
        "user_id": "memory_guard",
        "role": "system",
        "operation": "memory_guard_decision",
        "input_content": f"namespace={memory_input.namespace}; memory_key={memory_input.memory_key}",
        "result": f"{result}: {reason}",
        "risk_level": risk_level,
    }


__all__ = [
    "MemoryGuardDecision",
    "MemoryGuardInput",
    "evaluate_memory_guard",
]
