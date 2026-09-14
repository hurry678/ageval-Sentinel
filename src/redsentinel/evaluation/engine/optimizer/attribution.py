from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from redsentinel.core.agent_security import AgentProfile, AgentProfileNode
from redsentinel.evaluation.engine.runner import ClosedLoopEvaluationRecord


NodeAttributionDirection = Literal["attack", "defense"]


class NodeAttribution(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pair_id: str = Field(min_length=1)
    risk_type: str = Field(min_length=1)
    metric: str = Field(min_length=1)
    node_id: str = Field(min_length=1)
    node_type: str = Field(min_length=1)
    detector_decision: str = Field(min_length=1)
    guard_decision: str = Field(min_length=1)
    evidence_refs: list[str] = Field(min_length=1)
    summaries: list[str] = Field(default_factory=list)


def build_node_attributions(
    records: list[ClosedLoopEvaluationRecord],
    profile: AgentProfile,
) -> list[NodeAttribution]:
    return [
        _node_attribution(record, _node_for_risk(profile.nodes, record.risk_type))
        for record in sorted(records, key=lambda item: item.pair_id)
    ]


def _node_attribution(record: ClosedLoopEvaluationRecord, node: AgentProfileNode) -> NodeAttribution:
    evidence_refs = [
        _evidence_ref(record, index)
        for index, _ in enumerate(record.detector_output.attribution)
    ]
    summaries = [item.summary for item in record.detector_output.attribution]
    return NodeAttribution(
        pair_id=record.pair_id,
        risk_type=record.risk_type,
        metric=record.metric,
        node_id=node.id,
        node_type=node.type,
        detector_decision=record.detector_output.decision,
        guard_decision=record.controlled_defense_decision.decision,
        evidence_refs=evidence_refs,
        summaries=summaries,
    )


def _node_for_risk(nodes: list[AgentProfileNode], risk_type: str) -> AgentProfileNode:
    matching = [
        node
        for node in nodes
        if risk_type in node.risk_surfaces
    ]
    if matching:
        return sorted(matching, key=lambda item: item.id)[0]

    fallback_type = _fallback_node_type(risk_type)
    matching = [node for node in nodes if node.type == fallback_type]
    if matching:
        return sorted(matching, key=lambda item: item.id)[0]

    return sorted(nodes, key=lambda item: item.id)[0]


def _fallback_node_type(risk_type: str) -> str:
    return {
        "goal_perturbation": "input_node",
        "memory_poisoning": "memory_node",
        "tool_tampering": "tool_node",
    }.get(risk_type, "input_node")


def _evidence_ref(record: ClosedLoopEvaluationRecord, index: int) -> str:
    return f"detector:{record.metric}:{record.pair_id}:attribution:{index}"


__all__ = [
    "NodeAttribution",
    "build_node_attributions",
]
