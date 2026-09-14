from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict

from redsentinel.profiling import CodeProfileCandidate, analyze_source_profile
from redsentinel.profiling.builder import RISK_SURFACES_BY_NODE_TYPE
from redsentinel.attacks.engine.ingestion.deep import DeepIngestionPlan, TrajectoryArtifacts, build_deep_ingestion_plan, execute_docker_trace
from redsentinel.attacks.engine.ingestion.manifest_builder import ManifestBuildResult, build_manifest_from_materials
from redsentinel.attacks.engine.ingestion.materials import AgentMaterials, load_agent_materials
from redsentinel.attacks.engine.ingestion.static_analysis import StaticAnalysisResult, analyze_source_static
from redsentinel.core.agent_security import AgentProfile, AgentProfileNode, AgentProfileTool


class AgentPerceptionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manifest_result: ManifestBuildResult
    deep_plan: DeepIngestionPlan
    standard_profile: AgentProfile
    code_candidate: CodeProfileCandidate | None = None
    static_analysis_result: StaticAnalysisResult | None = None
    trace_artifacts: TrajectoryArtifacts | None = None
    profile_source: str


def build_agent_perception_from_materials(
    materials: AgentMaterials,
    *,
    base_dir: str | Path | None = None,
    enable_llm: bool = False,
    llm_client: object | None = None,
    execute_docker: bool = False,
) -> AgentPerceptionResult:
    root = Path(base_dir).resolve() if base_dir is not None else Path.cwd()
    manifest_result = build_manifest_from_materials(materials, base_dir=root)
    deep_plan = build_deep_ingestion_plan(materials, base_dir=root)
    profile = _profile_from_manifest(manifest_result)
    candidate = None
    static_analysis_result = None
    trace_artifacts = None

    if materials.integration.type == "source" and deep_plan.source_roots:
        source_root = Path(deep_plan.source_roots[0])
        candidate = analyze_source_profile(
            source_root,
            profile,
            materials=materials.model_dump(mode="json"),
            enable_llm=enable_llm,
            llm_client=llm_client,
        )

    if materials.integration.type == "source" and deep_plan.source_roots and not deep_plan.skip_static_analysis:
        source_root = Path(deep_plan.source_roots[0])
        static_analysis_result = analyze_source_static(source_root)

    if execute_docker and deep_plan.docker_trace_plan:
        trace_artifacts = execute_docker_trace(deep_plan.docker_trace_plan, output_dir=root / "traces")

    return AgentPerceptionResult(
        manifest_result=manifest_result,
        deep_plan=deep_plan,
        standard_profile=candidate.candidate_profile if candidate else profile,
        code_candidate=candidate,
        static_analysis_result=static_analysis_result,
        trace_artifacts=trace_artifacts,
        profile_source="code_profile" if candidate else "manifest_draft",
    )


def build_agent_perception_from_path(
    path: str | Path,
    *,
    enable_llm: bool = False,
    llm_client: object | None = None,
    execute_docker: bool = False,
) -> AgentPerceptionResult:
    material_path = Path(path)
    base_dir = material_path.parent if material_path.is_file() else material_path
    return build_agent_perception_from_materials(
        load_agent_materials(material_path),
        base_dir=base_dir,
        enable_llm=enable_llm,
        llm_client=llm_client,
        execute_docker=execute_docker,
    )


def _profile_from_manifest(manifest_result: ManifestBuildResult) -> AgentProfile:
    manifest = manifest_result.manifest
    return AgentProfile(
        agent_name=manifest.agent.name,
        framework=manifest.agent.framework,
        root_path=manifest.agent.root_path,
        entrypoint=manifest.agent.entrypoint,
        business_domain=manifest.business.domain,
        nodes=[
            AgentProfileNode(
                id=node.id,
                type=node.type,
                target=node.target,
                risk_surfaces=list(RISK_SURFACES_BY_NODE_TYPE[node.type]),
                defenses=node.defenses,
            )
            for node in manifest.nodes
        ],
        tools=[
            AgentProfileTool(
                name=tool.name,
                risk_level=tool.risk_level,
                allowed_roles=tool.allowed_roles,
                side_effect=tool.side_effect,
            )
            for tool in manifest.tools
        ],
        attack_entries=manifest.evaluation.attack_entries,
        sensitive_data=manifest.business.sensitive_data,
        rag_enabled=manifest.rag.enabled,
    )
