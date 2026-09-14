from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Literal


ToolGuardDecisionValue = Literal["allow", "block"]
ToolGuardRiskLevel = Literal["normal", "high"]


@dataclass(frozen=True)
class ToolGuardInput:
    tool_name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    response: Any = None
    metadata: dict[str, Any] = field(default_factory=dict)
    evidence: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class ToolGuardDecision:
    allowed: bool
    decision: ToolGuardDecisionValue
    risk_level: ToolGuardRiskLevel
    reason: str
    attribution: list[dict[str, Any]]
    audit_payload: dict[str, str]


def evaluate_tool_guard(tool_input: ToolGuardInput) -> ToolGuardDecision:
    attribution = [dict(item) for item in tool_input.evidence if _is_tool_tampering_evidence(item)]

    if not attribution and _response_has_tamper_signal(tool_input.response):
        attribution.append(
            {
                "evidence_type": "tool_response",
                "field_path": "tool_call.response",
                "summary": "Tool response contains tampering evidence.",
            }
        )

    if attribution:
        reason = str(attribution[0].get("summary") or "Tool tampering evidence found.")
        return ToolGuardDecision(
            allowed=False,
            decision="block",
            risk_level="high",
            reason=reason,
            attribution=attribution,
            audit_payload=_build_audit_payload(tool_input, "blocked_tool_tampering", "high", reason),
        )

    reason = "No tool tampering evidence found."
    return ToolGuardDecision(
        allowed=True,
        decision="allow",
        risk_level="normal",
        reason=reason,
        attribution=[],
        audit_payload=_build_audit_payload(tool_input, "allowed", "normal", reason),
    )


def _is_tool_tampering_evidence(evidence: dict[str, Any]) -> bool:
    if not isinstance(evidence, dict):
        return False

    if evidence.get("kind") == "tool_tampering":
        return True

    if evidence.get("evidence_type") in {
        "tool_response",
        "state_delta_injection",
        "metadata_injection",
    }:
        return True

    if evidence.get("label") == "tampered" or evidence.get("decision") == "high":
        return True

    serialized = json.dumps(evidence, ensure_ascii=False, sort_keys=True).lower()
    return "tool_tampering" in serialized or "tampered" in serialized


def _response_has_tamper_signal(response: Any) -> bool:
    if isinstance(response, dict) and response.get("tampered") is True:
        return True

    if isinstance(response, (dict, list)):
        text = json.dumps(response, ensure_ascii=False, sort_keys=True).lower()
    else:
        text = str(response).lower()

    return "tool_tampering" in text or "tampered" in text


def _build_audit_payload(
    tool_input: ToolGuardInput,
    result: str,
    risk_level: ToolGuardRiskLevel,
    reason: str,
) -> dict[str, str]:
    return {
        "user_id": "tool_guard",
        "role": "system",
        "operation": "tool_guard_decision",
        "input_content": f"tool_name={tool_input.tool_name}; arguments={str(tool_input.arguments)[:120]}",
        "result": f"{result}: {reason}",
        "risk_level": risk_level,
    }


__all__ = [
    "ToolGuardDecision",
    "ToolGuardInput",
    "evaluate_tool_guard",
]
