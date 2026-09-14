from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from redsentinel.core.agent_security import (
    AgentEvaluationContract,
    AgentNodeContract,
    AgentRagContract,
    AgentToolContract,
)

IntegrationType = Literal["source", "api", "docker"]

MATERIAL_FILENAMES = (
    "redsentinel.materials.yaml",
    "redsentinel.materials.yml",
    "materials.yaml",
    "materials.yml",
)


class AgentMaterialMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    domain: str | None = None
    framework: Literal["python_function", "langgraph"] | None = None
    root_path: str | None = None
    entrypoint: str | None = None


class IntegrationMaterial(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: IntegrationType
    source_path: str | None = None
    openapi_path: str | None = None
    docker_image: str | None = None
    adapter_entrypoint: str | None = None


class BusinessMaterial(BaseModel):
    model_config = ConfigDict(extra="forbid")

    roles: list[str] = Field(default_factory=list)
    sensitive_data: list[str] = Field(default_factory=list)


class AgentMaterials(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["agent-materials-v1"] = "agent-materials-v1"
    agent: AgentMaterialMetadata
    integration: IntegrationMaterial
    nodes: list[AgentNodeContract] = Field(default_factory=list)
    tools: list[AgentToolContract] = Field(default_factory=list)
    business: BusinessMaterial = Field(default_factory=BusinessMaterial)
    rag: AgentRagContract = Field(default_factory=AgentRagContract)
    evaluation: AgentEvaluationContract = Field(default_factory=AgentEvaluationContract)


class MaterialInspection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    integration_type: IntegrationType
    completeness_score: float
    present: list[str] = Field(default_factory=list)
    missing: list[str] = Field(default_factory=list)
    resource_paths: dict[str, str] = Field(default_factory=dict)


def load_agent_materials(path: str | Path) -> AgentMaterials:
    material_path = _resolve_material_file(Path(path))
    payload = yaml.safe_load(material_path.read_text(encoding="utf-8"))
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        raise ValueError("Agent materials must be a YAML mapping.")
    return AgentMaterials.model_validate(payload)


def inspect_materials(materials: AgentMaterials, *, base_dir: str | Path | None = None) -> MaterialInspection:
    root = Path(base_dir).resolve() if base_dir is not None else Path.cwd()
    present: list[str] = []
    missing: list[str] = []
    resource_paths: dict[str, str] = {}

    _mark(bool(materials.agent.name), "agent.name", present, missing)
    _mark(bool(materials.agent.domain), "agent.domain", present, missing)
    _mark(bool(materials.nodes), "nodes", present, missing)
    _mark(bool(materials.tools) or bool(materials.integration.openapi_path), "tools_or_openapi", present, missing)
    _mark(bool(materials.evaluation.attack_entries), "evaluation.attack_entries", present, missing)

    if materials.integration.type == "source":
        _mark(bool(materials.integration.source_path or materials.agent.root_path), "source_path", present, missing)
        _record_path("source_path", materials.integration.source_path or materials.agent.root_path, root, resource_paths)
    elif materials.integration.type == "api":
        _mark(bool(materials.integration.openapi_path), "openapi_path", present, missing)
        _record_path("openapi_path", materials.integration.openapi_path, root, resource_paths)
    else:
        _mark(bool(materials.integration.docker_image), "docker_image", present, missing)
        if materials.integration.docker_image:
            resource_paths["docker_image"] = materials.integration.docker_image

    total = len(present) + len(missing)
    score = round(len(present) / total, 4) if total else 0.0
    return MaterialInspection(
        integration_type=materials.integration.type,
        completeness_score=score,
        present=present,
        missing=missing,
        resource_paths=resource_paths,
    )


def _resolve_material_file(path: Path) -> Path:
    if path.is_file():
        return path
    for name in MATERIAL_FILENAMES:
        candidate = path / name
        if candidate.exists():
            return candidate
    raise FileNotFoundError(f"Agent materials file not found under {path}")


def _record_path(label: str, value: str | None, root: Path, output: dict[str, str]) -> None:
    if value:
        candidate = Path(value)
        output[label] = str(candidate if candidate.is_absolute() else (root / candidate).resolve())


def _mark(condition: bool, label: str, present: list[str], missing: list[str]) -> None:
    if condition:
        present.append(label)
    else:
        missing.append(label)
