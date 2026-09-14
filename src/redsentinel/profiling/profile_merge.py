from __future__ import annotations

from redsentinel.core import AgentProfile, AgentProfileNode, AgentProfileTool
from redsentinel.profiling.code_profiler import CandidateProfileDiff
from redsentinel.profiling.profile_patch import CandidateProfilePatch


def merge_patch_into_profile(profile: AgentProfile, patch: CandidateProfilePatch) -> tuple[AgentProfile, CandidateProfileDiff]:
    existing_node_ids = {node.id for node in profile.nodes}
    existing_targets = {node.target for node in profile.nodes}
    existing_tool_names = {tool.name for tool in profile.tools}

    added_nodes: list[AgentProfileNode] = []
    added_tools: list[AgentProfileTool] = []
    evidence_refs: list[dict[str, object]] = []

    for node in patch.nodes:
        evidence_refs.extend([item.model_dump(mode="json") for item in node.evidence])
        if node.id in existing_node_ids or node.target in existing_targets:
            continue
        added_nodes.append(
            AgentProfileNode(
                id=node.id,
                type=node.type,  # validated by CandidateNode
                target=node.target,
                risk_surfaces=node.risk_surfaces,
            )
        )

    for tool in patch.tools:
        evidence_refs.extend([item.model_dump(mode="json") for item in tool.evidence])
        if tool.name in existing_tool_names:
            continue
        added_tools.append(
            AgentProfileTool(
                name=tool.name,
                risk_level=tool.risk_level,
                allowed_roles=tool.permissions,
                side_effect=tool.side_effect,
            )
        )

    rag_enabled = profile.rag_enabled or bool(patch.rag and patch.rag.enabled)
    if patch.rag is not None:
        evidence_refs.extend([item.model_dump(mode="json") for item in patch.rag.evidence])
    if patch.memory is not None:
        evidence_refs.extend([item.model_dump(mode="json") for item in patch.memory.evidence])

    merged = profile.model_copy(
        update={
            "nodes": [*profile.nodes, *added_nodes],
            "tools": [*profile.tools, *added_tools],
            "rag_enabled": rag_enabled,
        }
    )
    diff = CandidateProfileDiff(
        added_nodes=[node.id for node in added_nodes],
        added_tools=[tool.name for tool in added_tools],
        changed_rag_enabled=rag_enabled != profile.rag_enabled,
        evidence_refs=evidence_refs,
    )
    return merged, diff
