from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field


class PilotPreset(BaseModel):
    model_config = ConfigDict(extra="forbid")

    preset_id: str = Field(min_length=1)
    display_name: str = Field(min_length=1)
    agent_role: Literal["customer_service", "shopping_guide", "merchant_operations"]
    description: str = Field(min_length=1)
    scenario_ids: list[str] = Field(min_length=1)
    demo_data_boundary: dict[str, bool] = Field(default_factory=dict)


class PilotPresetManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["pilot-presets-v0.1"] = "pilot-presets-v0.1"
    benchmark: Literal["ecommerce-security-v0.1"] = "ecommerce-security-v0.1"
    presets: list[PilotPreset] = Field(min_length=1)


def default_preset_manifest_path() -> Path:
    return (
        Path(__file__).resolve().parents[4]
        / "configs"
        / "scenarios"
        / "ecommerce"
        / "pilot-presets-v0.1.yaml"
    )


def load_pilot_presets(path: str | Path | None = None) -> PilotPresetManifest:
    target = Path(path) if path else default_preset_manifest_path()
    data = yaml.safe_load(target.read_text(encoding="utf-8"))
    return PilotPresetManifest.model_validate(data)


def get_pilot_preset(preset_id: str, path: str | Path | None = None) -> PilotPreset:
    manifest = load_pilot_presets(path)
    for preset in manifest.presets:
        if preset.preset_id == preset_id:
            return preset
    raise ValueError(f"Pilot preset not found: {preset_id}")
