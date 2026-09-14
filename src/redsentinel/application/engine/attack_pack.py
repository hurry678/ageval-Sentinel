from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator


ATTACK_PACK_REGISTRY: dict[str, str] = {
    "ecommerce-attack-pack-v0.1": "ecommerce-security-v0.1",
    "openmanus-attack-pack-v0.2": "openmanus-security-v0.1",
}


def register_attack_pack(schema_version: str, benchmark: str) -> None:
    """Register an attack-pack version so packs declaring it validate and load."""
    ATTACK_PACK_REGISTRY[schema_version] = benchmark


def _validate_registered_pack(schema_version: str, benchmark: str) -> None:
    expected = ATTACK_PACK_REGISTRY.get(schema_version)
    if expected is None:
        raise ValueError(f"Unregistered attack-pack schema_version: {schema_version!r}.")
    if expected != benchmark:
        raise ValueError(
            f"attack-pack {schema_version!r} must declare benchmark {expected!r}."
        )


class AttackStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: str = Field(default="buyer_001", min_length=1)
    role: str = Field(default="buyer", min_length=1)
    message: str = Field(min_length=1)


class EcommerceAttackScenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str = Field(min_length=1)
    attack_spec_id: str = Field(min_length=1)
    category: str = Field(min_length=1)
    business_flow: str = Field(min_length=1)
    severity: Literal["low", "medium", "high", "critical"]
    expected_decision: Literal["allow", "block"]
    business_impact: str = Field(min_length=1)
    success_criteria: list[str] = Field(min_length=1)
    clean_steps: list[AttackStep] = Field(min_length=1)
    controlled_steps: list[AttackStep] = Field(min_length=1)
    expected_tools: list[str] = Field(default_factory=list)
    baseline_success_markers: list[str] = Field(default_factory=list)
    guarded_block_rules: list[str] = Field(default_factory=list)
    source_reference: str | None = None
    mock_services: list[str] = Field(default_factory=list)
    requires_real_runtime: bool = False


class EcommerceAttackPack(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(default="ecommerce-attack-pack-v0.1", min_length=1)
    benchmark: str = Field(default="ecommerce-security-v0.1", min_length=1)
    scenarios: list[EcommerceAttackScenario] = Field(min_length=1)

    @model_validator(mode="after")
    def require_registered_pack(self) -> "EcommerceAttackPack":
        _validate_registered_pack(self.schema_version, self.benchmark)
        return self


class OpenManusAttackPack(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(default="openmanus-attack-pack-v0.2", min_length=1)
    benchmark: str = Field(default="openmanus-security-v0.1", min_length=1)
    scenarios: list[EcommerceAttackScenario] = Field(min_length=1)

    @model_validator(mode="after")
    def require_registered_pack(self) -> "OpenManusAttackPack":
        _validate_registered_pack(self.schema_version, self.benchmark)
        return self


def default_attack_pack_path() -> Path:
    return (
        _resource_root()
        / "configs"
        / "scenarios"
        / "ecommerce"
        / "attack-pack-v0.1.yaml"
    )


def _resource_root() -> Path:
    configured = os.environ.get("RED_SENTINEL_RESOURCE_ROOT")
    root = (
        Path(configured).expanduser().resolve()
        if configured
        else Path(__file__).resolve().parents[4]
    )
    if (root / "configs").is_dir():
        return root
    resources = root / "Resources"
    return resources if (resources / "configs").is_dir() else root


def default_openmanus_attack_pack_path() -> Path:
    return (
        _resource_root()
        / "configs"
        / "scenarios"
        / "openmanus"
        / "attack-pack-v0.2.yaml"
    )


def load_ecommerce_attack_pack(path: str | Path | None = None) -> EcommerceAttackPack:
    target = Path(path) if path else default_attack_pack_path()
    data = yaml.safe_load(target.read_text(encoding="utf-8"))
    return EcommerceAttackPack.model_validate(data)


def load_openmanus_attack_pack(path: str | Path | None = None) -> OpenManusAttackPack:
    target = Path(path) if path else default_openmanus_attack_pack_path()
    data = yaml.safe_load(target.read_text(encoding="utf-8"))
    return OpenManusAttackPack.model_validate(data)


ATTACK_INTENSITY_MULTIPLIER = {"light": 1, "medium": 2, "heavy": 3}


def _intensity_variant(scenario: EcommerceAttackScenario, n: int) -> EcommerceAttackScenario:
    controlled_steps = [step.model_copy() for step in scenario.controlled_steps]
    last = controlled_steps[-1]
    controlled_steps[-1] = last.model_copy(
        update={
            "message": f"{last.message}\n[intensity-variant-{n}] rephrase and retry the same objective.",
        }
    )
    return scenario.model_copy(
        update={
            "scenario_id": f"{scenario.scenario_id}-i{n}",
            "controlled_steps": controlled_steps,
        }
    )


def expand_scenarios_by_intensity(
    scenarios: list[EcommerceAttackScenario],
    intensity: str | None,
) -> list[EcommerceAttackScenario]:
    multiplier = ATTACK_INTENSITY_MULTIPLIER.get(intensity or "light", 1)
    if multiplier <= 1:
        return list(scenarios)
    expanded: list[EcommerceAttackScenario] = []
    for scenario in scenarios:
        expanded.append(scenario)
        for n in range(2, multiplier + 1):
            expanded.append(_intensity_variant(scenario, n))
    return expanded
