"""Load and validate the frozen P1 real-Agent pilot split."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from redsentinel.datasets.loader import DatasetIntegrityError


class _SplitModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class P1SplitAssignment(_SplitModel):
    pair_id: str = Field(min_length=1)
    payload_lineage: str = Field(pattern=r"^[a-z0-9_]+:[a-z0-9_]+$")
    category: str = Field(min_length=1)
    business_flow: str = Field(min_length=1)
    split: Literal["development", "holdout"]


class P1ExperimentSplit(_SplitModel):
    schema_version: Literal["experiment-split-v1"]
    split_id: str = Field(min_length=1)
    version: Literal["v1.0", "v2.0"]
    source_benchmark: str = Field(min_length=1)
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    protocol: str = Field(min_length=1)
    group_keys: list[Literal["pair_id", "payload_lineage"]]
    assignments: list[P1SplitAssignment] = Field(min_length=2)
    limitations: list[str] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_partition(self) -> P1ExperimentSplit:
        if self.group_keys != ["pair_id", "payload_lineage"]:
            raise ValueError("P1 split must group by pair_id and payload_lineage")
        pair_ids = [item.pair_id for item in self.assignments]
        if len(pair_ids) != len(set(pair_ids)):
            raise ValueError("P1 split pair_id values must be unique")
        splits = {item.split for item in self.assignments}
        if splits != {"development", "holdout"}:
            raise ValueError("P1 split requires non-empty development and holdout assignments")
        development = {item.payload_lineage for item in self.assignments if item.split == "development"}
        holdout = {item.payload_lineage for item in self.assignments if item.split == "holdout"}
        if development & holdout:
            raise ValueError("payload lineage must not cross development and holdout")
        return self


def load_p1_experiment_split(
    split_path: str | Path,
    *,
    repo_root: str | Path,
) -> P1ExperimentSplit:
    """Validate the split file against its pinned benchmark and protocol."""
    root = Path(repo_root).resolve()
    path = Path(split_path).resolve()
    try:
        split = P1ExperimentSplit.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise DatasetIntegrityError(f"invalid P1 experiment split {path}: {exc}") from exc

    benchmark_path = _resolve_inside_root(root, split.source_benchmark)
    protocol_path = _resolve_inside_root(root, split.protocol)
    if not protocol_path.is_file():
        raise DatasetIntegrityError(f"P1 protocol is missing: {split.protocol}")
    if not benchmark_path.is_file():
        raise DatasetIntegrityError(f"P1 source benchmark is missing: {split.source_benchmark}")
    actual_hash = hashlib.sha256(benchmark_path.read_bytes()).hexdigest()
    if actual_hash != split.source_sha256:
        raise DatasetIntegrityError(
            f"P1 source benchmark hash mismatch: expected {split.source_sha256}, got {actual_hash}"
        )

    benchmark = yaml.safe_load(benchmark_path.read_text(encoding="utf-8"))
    scenarios = benchmark.get("scenarios") if isinstance(benchmark, dict) else None
    if not isinstance(scenarios, list):
        raise DatasetIntegrityError("P1 source benchmark must define a scenarios list")
    expected = {
        str(scenario.get("scenario_id")): _scenario_identity(scenario)
        for scenario in scenarios
        if isinstance(scenario, dict)
    }
    actual = {
        item.pair_id: (item.payload_lineage, item.category, item.business_flow)
        for item in split.assignments
    }
    missing = sorted(set(expected) - set(actual))
    unknown = sorted(set(actual) - set(expected))
    mismatched = sorted(pair_id for pair_id in set(expected) & set(actual) if expected[pair_id] != actual[pair_id])
    if missing or unknown or mismatched:
        detail = json.dumps(
            {"missing": missing, "unknown": unknown, "mismatched": mismatched},
            ensure_ascii=False,
            sort_keys=True,
        )
        raise DatasetIntegrityError(f"P1 split does not match source benchmark: {detail}")
    return split


def _scenario_identity(scenario: dict[str, object]) -> tuple[str, str, str]:
    attack_spec_id = str(scenario.get("attack_spec_id") or "")
    parts = attack_spec_id.split(":")
    if len(parts) < 4:
        raise DatasetIntegrityError(f"invalid attack_spec_id in P1 benchmark: {attack_spec_id}")
    lineage = f"{parts[1]}:{parts[2]}"
    return lineage, str(scenario.get("category") or ""), str(scenario.get("business_flow") or "")


def _resolve_inside_root(root: Path, relative_path: str) -> Path:
    path = (root / relative_path).resolve()
    if path != root and root not in path.parents:
        raise DatasetIntegrityError(f"P1 split path escapes repository root: {relative_path}")
    return path


__all__ = ["P1ExperimentSplit", "P1SplitAssignment", "load_p1_experiment_split"]
