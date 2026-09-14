from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from redsentinel.attacks.engine.ingestion.materials import AgentMaterials, MaterialInspection, inspect_materials
from redsentinel.core.agent_security import (
    AgentBusinessContract,
    AgentManifest,
    AgentMetadataContract,
    AgentNodeContract,
    AgentToolContract,
)

_SIDE_EFFECT_METHODS = {"post", "put", "patch", "delete"}


class ManifestBuildResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manifest: AgentManifest
    inspection: MaterialInspection
    valid: bool
    completeness_score: float
    missing_fields: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    inferred_tools: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def build_manifest_from_materials(
    materials: AgentMaterials,
    *,
    base_dir: str | Path | None = None,
) -> ManifestBuildResult:
    root = Path(base_dir).resolve() if base_dir is not None else Path.cwd()
    inspection = inspect_materials(materials, base_dir=root)
    entrypoint = _entrypoint(materials)
    root_path = materials.agent.root_path or materials.integration.source_path or "."
    tools, inferred_tools = _tools(materials, root)
    nodes = materials.nodes or _default_nodes(materials.integration.type, entrypoint)
    attack_entries = list(materials.evaluation.attack_entries)
    if materials.rag.enabled and "rag_text" not in attack_entries:
        attack_entries.append("rag_text")

    manifest = AgentManifest(
        agent=AgentMetadataContract(
            name=materials.agent.name,
            framework=materials.agent.framework or "python_function",
            root_path=root_path,
            entrypoint=entrypoint,
        ),
        nodes=nodes,
        tools=tools,
        business=AgentBusinessContract(
            domain=materials.agent.domain or "unknown",
            roles=materials.business.roles,
            sensitive_data=materials.business.sensitive_data,
        ),
        rag=materials.rag,
        evaluation=materials.evaluation.model_copy(update={"attack_entries": attack_entries}),
    )

    warnings = _notes(materials, inspection, bool(inferred_tools))
    return ManifestBuildResult(
        manifest=manifest,
        inspection=inspection,
        valid=not inspection.missing,
        completeness_score=inspection.completeness_score,
        missing_fields=inspection.missing,
        warnings=warnings,
        inferred_tools=[item.name for item in inferred_tools],
        notes=warnings,
    )


def _entrypoint(materials: AgentMaterials) -> str:
    return materials.agent.entrypoint or materials.integration.adapter_entrypoint or "redsentinel_adapter:invoke"


def _tools(materials: AgentMaterials, root: Path) -> tuple[list[AgentToolContract], list[AgentToolContract]]:
    if materials.tools:
        return list(materials.tools), []
    if materials.integration.type != "api" or not materials.integration.openapi_path:
        return [], []

    openapi_path = _resolve_path(materials.integration.openapi_path, root)
    inferred = _tools_from_openapi(openapi_path)
    return inferred, inferred


def _tools_from_openapi(path: Path) -> list[AgentToolContract]:
    payload = _load_structured_file(path)
    paths = payload.get("paths", {}) if isinstance(payload, dict) else {}
    tools: list[AgentToolContract] = []
    if not isinstance(paths, dict):
        return tools

    for route, operations in paths.items():
        if not isinstance(operations, dict):
            continue
        for method, operation in operations.items():
            method_lower = str(method).lower()
            if method_lower not in {"get", "post", "put", "patch", "delete"}:
                continue
            operation_payload = operation if isinstance(operation, dict) else {}
            name = operation_payload.get("operationId") or f"{method_lower}_{route}"
            tools.append(
                AgentToolContract(
                    name=_safe_name(str(name)),
                    risk_level=_risk_level(method_lower),
                    side_effect=method_lower in _SIDE_EFFECT_METHODS,
                )
            )
    return tools


def _default_nodes(integration_type: str, entrypoint: str) -> list[AgentNodeContract]:
    middle_type = "tool_node" if integration_type in {"api", "docker"} else "llm_node"
    middle_id = "api_executor" if integration_type == "api" else "docker_executor" if integration_type == "docker" else "llm"
    return [
        AgentNodeContract(id="input", type="input_node", target=entrypoint),
        AgentNodeContract(id=middle_id, type=middle_type, target=entrypoint),
        AgentNodeContract(id="output", type="output_node", target=entrypoint),
    ]


def _notes(materials: AgentMaterials, inspection: MaterialInspection, inferred_tools: bool) -> list[str]:
    notes: list[str] = []
    if inspection.missing:
        notes.append("Missing material fields: " + ", ".join(inspection.missing))
    if not materials.nodes:
        notes.append("No node paths were provided; default nodes were generated for draft manifest coverage.")
    if inferred_tools:
        notes.append("API tools were inferred from the OpenAPI paths section.")
    if materials.integration.type == "docker":
        notes.append("Docker runtime trajectory collection is reserved for M5; M1 records the image as material only.")
    return notes


def _load_structured_file(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        payload = json.loads(text)
    else:
        payload = yaml.safe_load(text)
    return payload if isinstance(payload, dict) else {}


def _resolve_path(value: str, root: Path) -> Path:
    candidate = Path(value)
    return candidate if candidate.is_absolute() else (root / candidate).resolve()


def _safe_name(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_")
    return normalized or "api_operation"


def _risk_level(method: str) -> str:
    if method == "delete":
        return "critical"
    if method in _SIDE_EFFECT_METHODS:
        return "high"
    return "low"
