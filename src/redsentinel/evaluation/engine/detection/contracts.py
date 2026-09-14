from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

DetectorMetric = Literal["MIS", "GDM", "TRS"]
OracleStatus = Literal["normal", "abnormal", "review"]
DetectorDecision = Literal[
    "clean",
    "poisoned",
    "aligned",
    "drifted",
    "low",
    "medium",
    "high",
    "ambiguous",
]


class DetectorInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    metric: DetectorMetric
    scenario_pair_id: str = Field(min_length=1)
    clean_trajectory_path: str | None = None
    controlled_trajectory_path: str = Field(min_length=1)
    attack_spec_id: str = Field(min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)


class DetectorAttribution(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_type: str = Field(min_length=1)
    step_index: int | None = Field(default=None, ge=0)
    field_path: str = Field(min_length=1)
    summary: str = Field(min_length=1)


class DetectorOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    metric: DetectorMetric
    score: float = Field(ge=0.0, le=1.0)
    decision: DetectorDecision
    attribution: list[DetectorAttribution] = Field(min_length=1)
    failure_notes: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class OracleFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: Literal["monitor", "detector", "llm_judge"] = "monitor"
    risk_type: str = Field(min_length=1)
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str = Field(min_length=1)
    evidence: list[str] = Field(default_factory=list)
    recommended_action: str = Field(min_length=1)


class OracleVerdict(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["anomaly-oracle-verdict-v0.1"] = "anomaly-oracle-verdict-v0.1"
    status: OracleStatus
    confidence: float = Field(ge=0.0, le=1.0)
    findings: list[OracleFinding] = Field(default_factory=list)
    rationale: str = Field(min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AcceptanceFixtureRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fixture_id: str = Field(min_length=1)
    metric: DetectorMetric
    scenario_pair_id: str = Field(min_length=1)
    attack_spec_id: str = Field(min_length=1)
    risk_type: Literal["memory_poisoning", "tool_tampering", "goal_perturbation"]
    controlled_label: str = Field(min_length=1)
    scenario_manifest_path: str = Field(min_length=1)
    clean_scenario_path: str = Field(min_length=1)
    controlled_scenario_path: str = Field(min_length=1)
    controlled_trajectory_path: str = Field(min_length=1)
    expected_decision: DetectorDecision
    expected_evidence: list[str] = Field(min_length=1)


class AcceptanceFixtureManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["detector-acceptance-v0.1"] = "detector-acceptance-v0.1"
    records: list[AcceptanceFixtureRecord] = Field(min_length=1)


def load_acceptance_fixture_manifest(path: str | Path) -> AcceptanceFixtureManifest:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return AcceptanceFixtureManifest.model_validate(data)


__all__ = [
    "AcceptanceFixtureManifest",
    "AcceptanceFixtureRecord",
    "DetectorAttribution",
    "DetectorDecision",
    "DetectorInput",
    "DetectorMetric",
    "DetectorOutput",
    "OracleFinding",
    "OracleStatus",
    "OracleVerdict",
    "load_acceptance_fixture_manifest",
]
