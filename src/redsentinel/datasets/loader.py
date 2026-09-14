from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class DatasetIntegrityError(ValueError):
    """Raised when dataset provenance or content integrity cannot be verified."""


class _ManifestModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DatasetFile(_ManifestModel):
    path: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    format: Literal["json", "jsonl", "yaml"]


class SplitPolicy(_ManifestModel):
    names: tuple[Literal["development", "holdout"], Literal["development", "holdout"]] = (
        "development",
        "holdout",
    )
    group_by: list[str] = Field(min_length=1)
    seed: int = 2026
    holdout_fraction: float = Field(default=0.2, gt=0.0, lt=1.0)

    @field_validator("names")
    @classmethod
    def split_names_are_fixed(cls, names: tuple[str, str]) -> tuple[str, str]:
        if names != ("development", "holdout"):
            raise ValueError("dataset splits must be development and holdout")
        return names


class DatasetManifest(_ManifestModel):
    schema_version: Literal["dataset-manifest-v1"]
    dataset_id: str = Field(min_length=1)
    version: str = Field(pattern=r"^v\d+\.\d+$")
    description: str = Field(min_length=1)
    source: list[str] = Field(min_length=1)
    license: str = Field(min_length=1)
    labels: list[str] = Field(default_factory=list)
    generation: Literal["generated", "frozen_authored"]
    generation_seed: int | None = None
    generator: str | None = None
    write_command: str | None = None
    validation_command: str = Field(min_length=1)
    files: list[DatasetFile] = Field(min_length=1)
    split_policy: SplitPolicy

    @model_validator(mode="after")
    def generation_commands_match_policy(self) -> DatasetManifest:
        if self.generation == "generated":
            if self.generation_seed is None:
                raise ValueError("generated datasets require generation_seed")
            if not self.generator or "--dry-run" not in self.generator:
                raise ValueError("generated datasets require a --dry-run generator command")
            if not self.write_command or "--write" not in self.write_command:
                raise ValueError("generated datasets require a --write command")
            seed_argument = f"--seed {self.generation_seed}"
            if seed_argument not in self.generator or seed_argument not in self.write_command:
                raise ValueError(f"generated dataset commands must include {seed_argument}")
        elif self.generation_seed is not None or self.generator is not None or self.write_command is not None:
            raise ValueError("frozen_authored datasets must not declare generation seed or generator commands")
        return self


def load_dataset_manifest(
    manifest_path: str | Path,
    *,
    repo_root: str | Path | None = None,
    expected_version: str | None = None,
) -> DatasetManifest:
    """Load a manifest and verify every declared file before returning it."""
    path = Path(manifest_path).resolve()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        manifest = DatasetManifest.model_validate(payload)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise DatasetIntegrityError(f"invalid dataset manifest {path}: {exc}") from exc

    if expected_version is not None and manifest.version != expected_version:
        raise DatasetIntegrityError(
            f"dataset {manifest.dataset_id} version mismatch: expected {expected_version}, got {manifest.version}"
        )

    root = Path(repo_root).resolve() if repo_root is not None else _find_repo_root(path)
    for entry in manifest.files:
        file_path = _resolve_inside_root(root, entry.path)
        if not file_path.is_file():
            raise DatasetIntegrityError(f"dataset file is missing: {entry.path}")
        actual = hashlib.sha256(file_path.read_bytes()).hexdigest()
        if actual != entry.sha256:
            raise DatasetIntegrityError(
                f"dataset file hash mismatch for {entry.path}: expected {entry.sha256}, got {actual}"
            )
    return manifest


def assign_split(record: dict[str, Any], policy: SplitPolicy) -> Literal["development", "holdout"]:
    """Assign all records sharing a provenance group to the same split."""
    values = [_nested_value(record, field) for field in policy.group_by]
    if any(value in (None, "") for value in values):
        missing = [field for field, value in zip(policy.group_by, values) if value in (None, "")]
        raise DatasetIntegrityError(f"record is missing split group fields: {', '.join(missing)}")
    group = json.dumps(values, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(f"{policy.seed}:{group}".encode()).digest()
    ratio = int.from_bytes(digest[:8], "big") / float(2**64)
    return "holdout" if ratio < policy.holdout_fraction else "development"


def load_jsonl_split(
    manifest_path: str | Path,
    split: Literal["development", "holdout"],
    *,
    repo_root: str | Path | None = None,
    expected_version: str | None = None,
) -> list[dict[str, Any]]:
    """Return verified JSONL records for one deterministic provenance split."""
    path = Path(manifest_path).resolve()
    root = Path(repo_root).resolve() if repo_root is not None else _find_repo_root(path)
    manifest = load_dataset_manifest(path, repo_root=root, expected_version=expected_version)
    records: list[dict[str, Any]] = []
    for entry in manifest.files:
        if entry.format != "jsonl":
            continue
        file_path = _resolve_inside_root(root, entry.path)
        for line_number, line in enumerate(file_path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise DatasetIntegrityError(f"invalid JSONL at {entry.path}:{line_number}: {exc}") from exc
            if not isinstance(record, dict):
                raise DatasetIntegrityError(f"JSONL record must be an object at {entry.path}:{line_number}")
            if assign_split(record, manifest.split_policy) == split:
                records.append(record)
    return records


def _nested_value(record: dict[str, Any], dotted_path: str) -> Any:
    value: Any = record
    for component in dotted_path.split("."):
        if not isinstance(value, dict) or component not in value:
            return None
        value = value[component]
    return value


def _find_repo_root(start: Path) -> Path:
    for candidate in (start.parent, *start.parents):
        if (candidate / "pyproject.toml").is_file():
            return candidate
    raise DatasetIntegrityError(f"cannot locate repository root from {start}")


def _resolve_inside_root(root: Path, relative_path: str) -> Path:
    candidate = (root / relative_path).resolve()
    if candidate != root and root not in candidate.parents:
        raise DatasetIntegrityError(f"dataset path escapes repository root: {relative_path}")
    return candidate


__all__ = [
    "DatasetIntegrityError",
    "DatasetManifest",
    "SplitPolicy",
    "assign_split",
    "load_dataset_manifest",
    "load_jsonl_split",
]
