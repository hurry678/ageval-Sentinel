from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from redsentinel.core.agent_security import AgentProfile, AgentProfileNode, OptimizationDirective


GuardName = Literal[
    "input_firewall",
    "rag_chunk_scanner",
    "tool_guard",
    "memory_guard",
    "goal_guard",
    "output_filter",
]


class GuardMount(BaseModel):
    model_config = ConfigDict(extra="forbid")

    node_id: str = Field(min_length=1)
    node_type: str = Field(min_length=1)
    target: str = Field(min_length=1)
    guard_name: GuardName
    risk_surfaces: list[str] = Field(default_factory=list)
    directive_ids: list[str] = Field(default_factory=list)
    parameters: dict[str, Any] = Field(default_factory=dict)


class DefensePlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["defense-plan-v0.1"] = "defense-plan-v0.1"
    agent_name: str = Field(min_length=1)
    business_domain: str = Field(min_length=1)
    mounts: list[GuardMount] = Field(default_factory=list)


def build_defense_plan(
    profile: AgentProfile,
    *,
    directives: list[OptimizationDirective] | None = None,
) -> DefensePlan:
    directives_by_node = _directives_by_node(directives or [])
    mounts = [
        _guard_mount(node, directives_by_node.get(node.id, []))
        for node in profile.nodes
        if _guard_name_for_node(node) is not None
    ]
    return DefensePlan(
        agent_name=profile.agent_name,
        business_domain=profile.business_domain,
        mounts=mounts,
    )


def _guard_mount(node: AgentProfileNode, directives: list[OptimizationDirective]) -> GuardMount:
    guard_name = _guard_name_for_node(node)
    if guard_name is None:
        raise ValueError(f"Unsupported node type for guard mount: {node.type}")
    return GuardMount(
        node_id=node.id,
        node_type=node.type,
        target=node.target,
        guard_name=guard_name,
        risk_surfaces=list(node.risk_surfaces),
        directive_ids=[directive.directive_id for directive in sorted(directives, key=lambda item: item.directive_id)],
        parameters=_parameters(node, directives),
    )


def _guard_name_for_node(node: AgentProfileNode) -> GuardName | None:
    if node.type == "input_node":
        if "goal_perturbation" in node.risk_surfaces and "prompt_injection" not in node.risk_surfaces:
            return "goal_guard"
        return "input_firewall"
    return {
        "rag_retriever": "rag_chunk_scanner",
        "tool_node": "tool_guard",
        "memory_node": "memory_guard",
        "output_node": "output_filter",
    }.get(node.type)


def _parameters(node: AgentProfileNode, directives: list[OptimizationDirective]) -> dict[str, Any]:
    evidence_refs: list[str] = []
    for directive in directives:
        evidence_refs.extend(directive.evidence_refs)
    return {
        "risk_surfaces": list(node.risk_surfaces),
        "directive_priorities": {
            directive.directive_id: directive.priority
            for directive in sorted(directives, key=lambda item: item.directive_id)
        },
        "evidence_refs": sorted(set(evidence_refs)),
    }


def _directives_by_node(
    directives: list[OptimizationDirective],
) -> dict[str, list[OptimizationDirective]]:
    grouped: dict[str, list[OptimizationDirective]] = {}
    for directive in directives:
        grouped.setdefault(directive.target_node_id, []).append(directive)
    return grouped


__all__ = [
    "DefensePlan",
    "GuardMount",
    "build_defense_plan",
]
