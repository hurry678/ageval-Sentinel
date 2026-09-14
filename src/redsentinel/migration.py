"""Explicit migration helpers for legacy configs and JSON artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal, Mapping

import yaml
from pydantic import BaseModel, ConfigDict, Field

from redsentinel.core import ExperimentManifest
from redsentinel.research.provenance import RunEvidence, persist_run_evidence


LegacyConfigKind = Literal["agent_manifest", "scenario", "product_cli"]


class LegacyArtifact(BaseModel):
    """A lossless envelope around one recognized legacy JSON artifact."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["legacy-artifact-envelope-v1"] = "legacy-artifact-envelope-v1"
    artifact_kind: str = Field(min_length=1)
    legacy_schema_version: str | None = None
    source_path: str = Field(min_length=1)
    payload: dict[str, Any]


def legacy_config_to_manifest(path: str | Path, *, seed: int | None = None) -> ExperimentManifest:
    """Convert a supported legacy YAML/JSON config into an experiment manifest."""

    source = Path(path)
    payload = _read_mapping(source)
    kind = _legacy_config_kind(payload)
    if kind == "agent_manifest":
        return _agent_manifest_to_experiment(source, payload, seed=seed)
    if kind == "scenario":
        return _scenario_to_experiment(source, payload, seed=seed)
    return _product_cli_to_experiment(source, payload, seed=seed)


def read_legacy_artifact(path: str | Path) -> LegacyArtifact:
    """Read a legacy JSON artifact without discarding unknown fields."""

    source = Path(path)
    payload = _read_mapping(source)
    return LegacyArtifact(
        artifact_kind=_artifact_kind(payload),
        legacy_schema_version=_optional_text(payload.get("schema_version")),
        source_path=str(source),
        payload=payload,
    )


def migrate_legacy_artifact(
    path: str | Path,
    output_dir: str | Path,
    *,
    seed: int = 42,
    repo_root: str | Path | None = None,
) -> RunEvidence:
    """Wrap a legacy artifact in the canonical evidence/provenance bundle."""

    artifact = read_legacy_artifact(path)
    source = Path(path)
    manifest = ExperimentManifest(
        experiment_id=f"legacy-{artifact.artifact_kind}-{source.stem}",
        research_question="Compatibility migration of a pre-research RedSentinel artifact.",
        agent_profile_ref="legacy:unknown",
        dataset_refs=["redsentinel-trajectory-fixtures"],
        attack_strategy={"name": "legacy_preserved"},
        defense_strategy={"name": "legacy_preserved"},
        metric_names=["legacy_payload"],
        seeds=[seed],
        repetitions=1,
        budget={},
        execution_mode="offline_fixture",
        metadata={
            "migration": {
                "source_path": str(source),
                "artifact_kind": artifact.artifact_kind,
                "legacy_schema_version": artifact.legacy_schema_version,
            }
        },
    )
    return persist_run_evidence(
        manifest,
        experiment_dir=Path(output_dir),
        raw_result=artifact,
        repo_root=Path(repo_root) if repo_root is not None else _repo_root(),
    )


def _agent_manifest_to_experiment(
    source: Path,
    payload: Mapping[str, Any],
    *,
    seed: int | None,
) -> ExperimentManifest:
    agent = _mapping(payload.get("agent"))
    evaluation = _mapping(payload.get("evaluation"))
    defenses = sorted(
        {
            str(defense)
            for node in payload.get("nodes", [])
            if isinstance(node, Mapping)
            for defense in node.get("defenses", [])
        }
    )
    return _manifest(
        source,
        kind="agent_manifest",
        experiment_id=f"legacy-agent-{agent.get('name', source.stem)}",
        agent_profile_ref=f"legacy-agent-manifest:{source}",
        seed=42 if seed is None else seed,
        attack_strategy={"entries": list(evaluation.get("attack_entries", []))},
        defense_strategy={"mounted_defenses": defenses},
        metadata={"framework": agent.get("framework"), "legacy_schema_version": payload.get("schema_version")},
    )


def _scenario_to_experiment(
    source: Path,
    payload: Mapping[str, Any],
    *,
    seed: int | None,
) -> ExperimentManifest:
    reproducibility = _mapping(payload.get("reproducibility"))
    agent = _mapping(payload.get("agent"))
    injection = _mapping(payload.get("injection"))
    selected_seed = int(reproducibility.get("seed", 42)) if seed is None else seed
    return _manifest(
        source,
        kind="scenario",
        experiment_id=str(payload.get("experiment_id") or source.stem),
        agent_profile_ref=f"legacy-scenario-agent:{agent.get('framework', 'unknown')}",
        seed=selected_seed,
        attack_strategy={"injection": dict(injection)},
        defense_strategy={"name": "legacy_scenario"},
        metadata={"framework": agent.get("framework"), "legacy_schema_version": payload.get("schema_version")},
    )


def _product_cli_to_experiment(
    source: Path,
    payload: Mapping[str, Any],
    *,
    seed: int | None,
) -> ExperimentManifest:
    targets = [
        {
            "id": target.get("id"),
            "type": target.get("type"),
            "mode": target.get("mode"),
        }
        for target in payload.get("target_agents", [])
        if isinstance(target, Mapping)
    ]
    # Agent credentials are intentionally not copied into research metadata.
    return _manifest(
        source,
        kind="product_cli",
        experiment_id=f"legacy-product-cli-{source.stem}",
        agent_profile_ref=f"legacy-targets:{','.join(str(item['id']) for item in targets)}",
        seed=42 if seed is None else seed,
        attack_strategy={"name": "legacy_attack_agent"},
        defense_strategy={"name": "legacy_defense_agent"},
        metadata={"targets": targets, "storage_root": payload.get("storage_root")},
    )


def _manifest(
    source: Path,
    *,
    kind: LegacyConfigKind,
    experiment_id: str,
    agent_profile_ref: str,
    seed: int,
    attack_strategy: dict[str, Any],
    defense_strategy: dict[str, Any],
    metadata: dict[str, Any],
) -> ExperimentManifest:
    return ExperimentManifest(
        experiment_id=experiment_id,
        research_question=f"Migrated legacy {kind} configuration.",
        agent_profile_ref=agent_profile_ref,
        dataset_refs=["redsentinel-attack-cases", "redsentinel-benign-cases"],
        attack_strategy=attack_strategy,
        defense_strategy=defense_strategy,
        metric_names=["asr", "fpr", "coverage"],
        seeds=[seed],
        repetitions=1,
        budget={},
        execution_mode="offline_fixture",
        metadata={
            "legacy_config": {
                "kind": kind,
                "source_path": str(source),
            },
            **metadata,
        },
    )


def _legacy_config_kind(payload: Mapping[str, Any]) -> LegacyConfigKind:
    if payload.get("schema_version") == "agent-manifest-v1" and "agent" in payload:
        return "agent_manifest"
    if "experiment_id" in payload and "reproducibility" in payload and "agent" in payload:
        return "scenario"
    if "target_agents" in payload and "attack_agent" in payload:
        return "product_cli"
    raise ValueError("unsupported legacy configuration shape")


def _artifact_kind(payload: Mapping[str, Any]) -> str:
    if "attack_plans" in payload and "damage_attribution" in payload:
        return "comp1-report"
    if "asr_initial" in payload and "rounds" in payload:
        return "comp4-convergence"
    if "agent_name" in payload and "nodes" in payload:
        return "agent-profile-v1"
    if "records" in payload and "metadata" in payload:
        return "closed-loop-report"
    schema = _optional_text(payload.get("schema_version"))
    if schema:
        return schema
    return "legacy-json"


def _read_mapping(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError(f"legacy input does not exist: {path}")
    if path.suffix.lower() == ".json":
        payload = json.loads(path.read_text(encoding="utf-8"))
    else:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"legacy input must contain an object: {path}")
    return payload


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _optional_text(value: Any) -> str | None:
    return str(value) if value is not None else None


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


__all__ = [
    "LegacyArtifact",
    "legacy_config_to_manifest",
    "migrate_legacy_artifact",
    "read_legacy_artifact",
]
