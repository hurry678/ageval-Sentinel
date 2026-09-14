"""Capture reproducibility metadata and build traceable evidence indexes."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import platform
import subprocess
from pathlib import Path
from typing import Any, Mapping, Sequence

from pydantic import BaseModel, ConfigDict, Field

from redsentinel.core.models import ExperimentManifest, Provenance


_SECRET_MARKERS = ("api_key", "apikey", "password", "secret", "credential", "authorization")
_FIGURE_SUFFIXES = {".html", ".pdf", ".png", ".svg"}


class EvidenceArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    artifact_id: str = Field(min_length=1)
    role: str = Field(min_length=1)
    path: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    manifest_path: str
    raw_result_path: str


class EvidenceIndex(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "evidence-index-v1"
    experiment_id: str = Field(min_length=1)
    artifacts: list[EvidenceArtifact]


class RunEvidence(BaseModel):
    """Paths written for one formal research run."""

    model_config = ConfigDict(extra="forbid")

    manifest_path: str
    raw_result_path: str
    provenance_path: str
    evidence_index_path: str


def capture_provenance(
    manifest: ExperimentManifest,
    *,
    repo_root: str | Path,
    dataset_paths: Mapping[str, str | Path] | None = None,
) -> Provenance:
    """Capture the code, configuration, data, environment, and model context."""
    root = Path(repo_root).resolve()
    config_payload = manifest.model_dump(mode="json", exclude={"provenance"})
    external_model = _external_model_metadata(manifest.metadata.get("external_model"))
    return Provenance(
        git_commit=_git_output(root, "rev-parse", "HEAD") or "unavailable",
        git_dirty=bool(_git_output(root, "status", "--porcelain")),
        python_version=platform.python_version(),
        dependency_versions=_dependency_versions(),
        config_sha256=_hash_json(config_payload),
        dataset_sha256=_dataset_hashes(manifest.dataset_refs, root=root, dataset_paths=dataset_paths or {}),
        execution_mode=manifest.execution_mode,
        external_model=external_model,
    )


def persist_run_evidence(
    manifest: ExperimentManifest,
    *,
    experiment_dir: str | Path,
    raw_result: BaseModel | Mapping[str, Any] | None = None,
    raw_result_path: str | Path | None = None,
    repo_root: str | Path,
    dataset_paths: Mapping[str, str | Path] | None = None,
) -> RunEvidence:
    """Persist one common manifest/provenance/evidence bundle for a formal run."""
    directory = Path(experiment_dir)
    directory.mkdir(parents=True, exist_ok=True)
    manifest_path = directory / "experiment-manifest-v1.json"
    provenance_path = directory / "provenance-v1.json"
    result_path = Path(raw_result_path) if raw_result_path is not None else directory / "raw-result-v1.json"
    provenance = capture_provenance(
        manifest,
        repo_root=repo_root,
        dataset_paths=dataset_paths,
    )
    manifest_with_provenance = manifest.model_copy(update={"provenance": provenance})
    manifest_path.write_text(
        json.dumps(manifest_with_provenance.model_dump(mode="json"), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    provenance_path.write_text(
        json.dumps(provenance.model_dump(mode="json"), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if raw_result is not None:
        payload = raw_result.model_dump(mode="json") if isinstance(raw_result, BaseModel) else dict(raw_result)
        result_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    if not result_path.is_file():
        raise ValueError(f"raw result does not exist: {result_path}")
    index_path = write_evidence_index(
        experiment_id=manifest.experiment_id,
        experiment_dir=directory,
        manifest_path=manifest_path,
        raw_result_path=result_path,
        provenance_path=provenance_path,
    )
    return RunEvidence(
        manifest_path=str(manifest_path),
        raw_result_path=str(result_path),
        provenance_path=str(provenance_path),
        evidence_index_path=str(index_path),
    )


def write_evidence_index(
    *,
    experiment_id: str,
    experiment_dir: str | Path,
    manifest_path: str | Path,
    raw_result_path: str | Path,
    provenance_path: str | Path,
) -> Path:
    """Index primary evidence and any generated figures under the experiment directory."""
    directory = Path(experiment_dir)
    manifest = Path(manifest_path)
    raw_result = Path(raw_result_path)
    provenance = Path(provenance_path)
    primary = [
        ("manifest", manifest),
        ("raw_result", raw_result),
        ("provenance", provenance),
    ]
    primary_paths = {path.resolve() for _, path in primary}
    figures = [
        ("figure", path)
        for path in sorted(directory.rglob("*"))
        if path.is_file() and path.suffix.lower() in _FIGURE_SUFFIXES and path.resolve() not in primary_paths
    ]
    artifacts = [
        EvidenceArtifact(
            artifact_id=f"{role}:{path.relative_to(directory).as_posix()}",
            role=role,
            path=str(path),
            sha256=_hash_path(path),
            manifest_path=str(manifest),
            raw_result_path=str(raw_result),
        )
        for role, path in [*primary, *figures]
    ]
    index = EvidenceIndex(experiment_id=experiment_id, artifacts=artifacts)
    output = directory / "evidence-index-v1.json"
    output.write_text(
        json.dumps(index.model_dump(mode="json"), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return output


def _external_model_metadata(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ValueError("metadata.external_model must be an object")
    _reject_secret_keys(value)
    allowed = {"provider", "model", "temperature", "parameters", "cache_policy"}
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValueError(f"unsupported external model provenance fields: {', '.join(unknown)}")
    required = {"provider", "model", "temperature", "parameters", "cache_policy"}
    missing = sorted(required - set(value))
    if missing:
        raise ValueError(f"missing external model provenance fields: {', '.join(missing)}")
    return {key: value[key] for key in sorted(allowed)}


def _reject_secret_keys(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized = str(key).lower().replace("-", "_")
            token_secret = normalized == "token" or normalized.endswith(
                ("access_token", "auth_token", "bearer_token", "refresh_token", "session_token")
            )
            if any(marker in normalized for marker in _SECRET_MARKERS) or token_secret:
                raise ValueError(f"secret-like field is forbidden in provenance: {key}")
            _reject_secret_keys(item)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for item in value:
            _reject_secret_keys(item)


def _git_output(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip() if completed.returncode == 0 else ""


def _dependency_versions() -> dict[str, str]:
    versions: dict[str, str] = {}
    for distribution in importlib.metadata.distributions():
        name = distribution.metadata.get("Name")
        if name:
            versions[name.lower()] = distribution.version
    return dict(sorted(versions.items()))


def _dataset_hashes(
    references: Sequence[str],
    *,
    root: Path,
    dataset_paths: Mapping[str, str | Path],
) -> dict[str, str]:
    hashes: dict[str, str] = {}
    manifests = _dataset_manifests(root)
    for reference in references:
        configured = dataset_paths.get(reference)
        if configured is not None:
            path = Path(configured)
            path = path if path.is_absolute() else root / path
        else:
            direct = Path(reference)
            direct = direct if direct.is_absolute() else root / direct
            path = direct if direct.exists() else manifests.get(reference)
        if path is None or not path.exists():
            raise ValueError(f"dataset reference cannot be resolved for provenance: {reference}")
        hashes[reference] = _hash_path(path)
    return hashes


def _dataset_manifests(root: Path) -> dict[str, Path]:
    resolved: dict[str, Path] = {}
    for path in sorted((root / "datasets" / "manifests").glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        dataset_id = str(payload.get("dataset_id", ""))
        version = str(payload.get("version", ""))
        if dataset_id:
            resolved[dataset_id] = path
            resolved[f"{dataset_id}@{version}"] = path
    return resolved


def _hash_json(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _hash_path(path: Path) -> str:
    if path.is_file():
        return hashlib.sha256(path.read_bytes()).hexdigest()
    digest = hashlib.sha256()
    for child in sorted(item for item in path.rglob("*") if item.is_file()):
        digest.update(child.relative_to(path).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(child.read_bytes()).digest())
    return digest.hexdigest()


__all__ = [
    "EvidenceArtifact",
    "EvidenceIndex",
    "RunEvidence",
    "capture_provenance",
    "persist_run_evidence",
    "write_evidence_index",
]
