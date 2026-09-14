"""Framework-independent orchestration for one research experiment round."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Literal, Mapping, Sequence

from pydantic import BaseModel, ConfigDict, Field

from redsentinel.core.models import (
    AgentProfile,
    AttackCandidate,
    DefenseCandidate,
    EvaluationResult,
    ExperimentManifest,
    Provenance,
    Trajectory,
)
from redsentinel.core.protocols import Evaluator, RuntimeAdapter
from redsentinel.research.provenance import capture_provenance, write_evidence_index


class _RunModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ExperimentRunRecord(_RunModel):
    """One deterministic seed/repetition execution within an experiment."""

    run_id: str = Field(min_length=1)
    seed: int
    repetition: int = Field(ge=0)
    status: Literal["completed", "failed", "budget_exhausted"]
    trajectories: list[Trajectory] = Field(default_factory=list)
    evaluation: EvaluationResult | None = None
    failure_reason: str | None = None


class ExperimentRun(_RunModel):
    """Structured output persisted by :class:`SingleRoundExperimentRunner`."""

    schema_version: Literal["experiment-run-v1"] = "experiment-run-v1"
    experiment_id: str = Field(min_length=1)
    manifest: ExperimentManifest
    adapter_id: str = Field(min_length=1)
    records: list[ExperimentRunRecord] = Field(default_factory=list)
    aggregate_metrics: dict[str, float] = Field(default_factory=dict)
    failures: list[dict[str, str]] = Field(default_factory=list)
    provenance: Provenance
    artifact_path: str | None = None
    evidence_index_path: str | None = None


class SingleRoundExperimentRunner:
    """Execute fixed attack candidates once per configured seed and repetition.

    The runner intentionally owns no mutation or selection policy. Multi-round
    co-evolution belongs to the evolution engine, while this service provides
    its reproducible single-round execution primitive.
    """

    def __init__(
        self,
        *,
        runtime: RuntimeAdapter,
        evaluator: Evaluator,
        artifact_root: str | Path = "artifacts/experiments",
        repo_root: str | Path = ".",
        dataset_paths: Mapping[str, str | Path] | None = None,
    ) -> None:
        self.runtime = runtime
        self.evaluator = evaluator
        self.artifact_root = Path(artifact_root)
        self.repo_root = Path(repo_root)
        self.dataset_paths = dict(dataset_paths or {})

    def run(
        self,
        manifest: ExperimentManifest,
        profile: AgentProfile,
        attacks: Sequence[AttackCandidate],
        defense: DefenseCandidate | None = None,
    ) -> ExperimentRun:
        """Run one fixed experiment matrix and persist its structured result."""
        max_runs = _integer_budget(manifest, "max_runs")
        max_cases = _integer_budget(manifest, "max_cases")
        records: list[ExperimentRunRecord] = []
        failures: list[dict[str, str]] = []
        cases_used = 0

        for seed in manifest.seeds:
            for repetition in range(manifest.repetitions):
                run_id = f"{manifest.experiment_id}-s{seed}-r{repetition}"
                if max_runs is not None and len(records) >= max_runs:
                    records.append(
                        ExperimentRunRecord(
                            run_id=run_id,
                            seed=seed,
                            repetition=repetition,
                            status="budget_exhausted",
                            failure_reason="max_runs budget exhausted",
                        )
                    )
                    continue

                remaining_attacks = list(attacks)
                if max_cases is not None:
                    remaining = max_cases - cases_used
                    if remaining <= 0:
                        records.append(
                            ExperimentRunRecord(
                                run_id=run_id,
                                seed=seed,
                                repetition=repetition,
                                status="budget_exhausted",
                                failure_reason="max_cases budget exhausted",
                            )
                        )
                        continue
                    remaining_attacks = remaining_attacks[:remaining]

                trajectories: list[Trajectory] = []
                try:
                    for attack in remaining_attacks:
                        trajectories.append(
                            self.runtime.run(
                                profile,
                                attack,
                                defense,
                                experiment_id=manifest.experiment_id,
                                seed=seed,
                            )
                        )
                        cases_used += 1
                    evaluation = self.evaluator.evaluate(profile, trajectories, manifest=manifest)
                except Exception as exc:
                    reason = f"{type(exc).__name__}: {exc}"
                    records.append(
                        ExperimentRunRecord(
                            run_id=run_id,
                            seed=seed,
                            repetition=repetition,
                            status="failed",
                            trajectories=trajectories,
                            failure_reason=reason,
                        )
                    )
                    failures.append({"run_id": run_id, "reason": reason})
                    continue

                records.append(
                    ExperimentRunRecord(
                        run_id=run_id,
                        seed=seed,
                        repetition=repetition,
                        status="completed",
                        trajectories=trajectories,
                        evaluation=evaluation,
                    )
                )

        experiment_dir = self.artifact_root / manifest.experiment_id
        output_path = experiment_dir / "experiment-run-v1.json"
        manifest_path = experiment_dir / "experiment-manifest-v1.json"
        provenance_path = experiment_dir / "provenance-v1.json"
        evidence_index_path = experiment_dir / "evidence-index-v1.json"
        provenance = capture_provenance(
            manifest,
            repo_root=self.repo_root,
            dataset_paths=self.dataset_paths,
        )
        manifest_with_provenance = manifest.model_copy(update={"provenance": provenance})
        result = ExperimentRun(
            experiment_id=manifest.experiment_id,
            manifest=manifest_with_provenance,
            adapter_id=self.runtime.adapter_id,
            records=records,
            aggregate_metrics=_aggregate_metrics(records),
            failures=failures,
            provenance=provenance,
            artifact_path=str(output_path),
            evidence_index_path=str(evidence_index_path),
        )
        experiment_dir.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(
            json.dumps(manifest_with_provenance.model_dump(mode="json"), ensure_ascii=False, indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        provenance_path.write_text(
            json.dumps(provenance.model_dump(mode="json"), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        output_path.write_text(
            json.dumps(result.model_dump(mode="json"), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        write_evidence_index(
            experiment_id=manifest.experiment_id,
            experiment_dir=experiment_dir,
            manifest_path=manifest_path,
            raw_result_path=output_path,
            provenance_path=provenance_path,
        )
        return result


def _integer_budget(manifest: ExperimentManifest, name: str) -> int | None:
    value = manifest.budget.get(name)
    if value is None:
        return None
    if not float(value).is_integer():
        raise ValueError(f"{name} budget must be an integer")
    return int(value)


def _aggregate_metrics(records: Sequence[ExperimentRunRecord]) -> dict[str, float]:
    values: dict[str, list[float]] = defaultdict(list)
    for record in records:
        if record.status != "completed" or record.evaluation is None:
            continue
        for name, value in record.evaluation.metrics.items():
            values[name].append(value)
    return {
        name: sum(metric_values) / len(metric_values)
        for name, metric_values in sorted(values.items())
        if metric_values
    }


__all__ = [
    "ExperimentRun",
    "ExperimentRunRecord",
    "SingleRoundExperimentRunner",
]
