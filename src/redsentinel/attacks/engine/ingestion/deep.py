from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from redsentinel.attacks.engine.ingestion.materials import AgentMaterials, inspect_materials

TraceArtifact = Literal["trajectory", "stdout", "stderr", "audit"]


class TrajectoryArtifacts(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trajectory_path: str | None = None
    stdout_path: str | None = None
    stderr_path: str | None = None
    audit_path: str | None = None
    container_id: str | None = None
    exit_code: int | None = None
    duration_ms: float = 0.0
    error: str | None = None


class DockerTracePlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_name: str = Field(min_length=1)
    docker_image: str = Field(min_length=1)
    adapter_entrypoint: str = Field(min_length=1)
    node_targets: list[str] = Field(default_factory=list)
    expected_artifacts: list[TraceArtifact] = Field(default_factory=lambda: ["trajectory", "stdout", "stderr"])
    read_only_mounts: list[str] = Field(default_factory=list)
    network_policy: Literal["disabled", "internal_only"] = "disabled"
    notes: list[str] = Field(default_factory=list)


class DeepIngestionPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_name: str = Field(min_length=1)
    source_roots: list[str] = Field(default_factory=list)
    docker_trace_plan: DockerTracePlan | None = None
    material_missing: list[str] = Field(default_factory=list)
    analysis_targets: list[str] = Field(default_factory=list)
    skip_static_analysis: bool = False


def build_deep_ingestion_plan(materials: AgentMaterials, *, base_dir: str | Path | None = None) -> DeepIngestionPlan:
    root = Path(base_dir).resolve() if base_dir is not None else Path.cwd()
    inspection = inspect_materials(materials, base_dir=root)
    source_roots: list[str] = []
    source_path = materials.integration.source_path or materials.agent.root_path
    if source_path:
        candidate = Path(source_path)
        source_roots.append(str(candidate if candidate.is_absolute() else (root / candidate).resolve()))

    docker_plan = None
    if materials.integration.type == "docker" and materials.integration.docker_image:
        docker_plan = DockerTracePlan(
            agent_name=materials.agent.name,
            docker_image=materials.integration.docker_image,
            adapter_entrypoint=materials.integration.adapter_entrypoint or materials.agent.entrypoint or "redsentinel_adapter:invoke",
            node_targets=[node.target for node in materials.nodes],
            read_only_mounts=source_roots,
            notes=[
                "B-side plan only; C-side sandbox owns actual Docker execution.",
                "Run with network disabled unless an explicit internal-only policy is approved.",
            ],
        )

    analysis_targets = []
    if materials.integration.type == "source" and source_roots:
        analysis_targets.extend(source_roots)
    for node in materials.nodes:
        if node.target:
            analysis_targets.append(node.target)

    return DeepIngestionPlan(
        agent_name=materials.agent.name,
        source_roots=source_roots,
        docker_trace_plan=docker_plan,
        material_missing=inspection.missing,
        analysis_targets=analysis_targets,
    )


def execute_docker_trace(plan: DockerTracePlan, *, output_dir: str | Path | None = None) -> TrajectoryArtifacts:
    try:
        from redsentinel.runtime.engine.sandbox.docker.executor import execute_docker_trace as sandbox_execute

        return sandbox_execute(plan, output_dir=output_dir)
    except (ImportError, ModuleNotFoundError):
        return TrajectoryArtifacts(error="Docker sandbox executor not available")
