"""Comparable baselines and ablations for co-evolution research."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field

from redsentinel.core.models import (
    AgentProfile,
    AttackCandidate,
    DefenseCandidate,
    EvaluationResult,
    EvolutionState,
    ExperimentManifest,
    Trajectory,
)
from redsentinel.core.protocols import AttackGenerator, DefenseOptimizer, Evaluator, RuntimeAdapter
from redsentinel.research.evolution import CoEvolutionEngine, EvolutionConfig, EvolutionRun
from redsentinel.research.provenance import persist_run_evidence

BaselineName = Literal["fixed", "attack_only", "defense_only", "coevolution"]


class _BaselineModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AblationConfig(_BaselineModel):
    """Signals that may be removed without changing the shared experiment input."""

    profile: bool = True
    trajectory_anomaly: bool = True
    node_attribution: bool = True
    reflection: bool = True
    utility_constraints: bool = True


class BaselineResult(_BaselineModel):
    name: BaselineName
    attack_evolution: bool
    defense_evolution: bool
    run: EvolutionRun
    final_metrics: dict[str, float] = Field(default_factory=dict)
    utility_constrained_metrics: dict[str, float | None] = Field(default_factory=dict)


class BaselineComparison(_BaselineModel):
    """Four experiment arms evaluated under one immutable comparison context."""

    schema_version: Literal["baseline-comparison-v1"] = "baseline-comparison-v1"
    experiment_id: str = Field(min_length=1)
    dataset_refs: list[str]
    budget: dict[str, float]
    seed: int
    metric_names: list[str]
    ablations: AblationConfig
    results: list[BaselineResult]
    artifact_path: str
    provenance_path: str
    evidence_index_path: str


class BaselineMatrixRunner:
    """Run static, one-sided, and two-sided evolution with shared controls."""

    def __init__(
        self,
        *,
        fixed_attack_generator: AttackGenerator,
        evolving_attack_generator: AttackGenerator,
        fixed_defense_optimizer: DefenseOptimizer,
        evolving_defense_optimizer: DefenseOptimizer,
        runtime: RuntimeAdapter,
        evaluator: Evaluator,
        config: EvolutionConfig | None = None,
        artifact_root: str | Path = "artifacts/baselines",
        dataset_paths: Mapping[str, str | Path] | None = None,
    ) -> None:
        self.fixed_attack_generator = fixed_attack_generator
        self.evolving_attack_generator = evolving_attack_generator
        self.fixed_defense_optimizer = fixed_defense_optimizer
        self.evolving_defense_optimizer = evolving_defense_optimizer
        self.runtime = runtime
        self.evaluator = evaluator
        self.config = config or EvolutionConfig()
        self.artifact_root = Path(artifact_root)
        self.dataset_paths = dict(dataset_paths or {})

    def run(
        self,
        manifest: ExperimentManifest,
        profile: AgentProfile,
        *,
        seed: int,
        ablations: AblationConfig | None = None,
    ) -> BaselineComparison:
        """Run all four arms without changing data, budget, seed, or metrics."""
        switches = ablations or AblationConfig()
        effective_profile = _profile_for_ablation(profile, switches)
        arms: list[tuple[BaselineName, bool, bool]] = [
            ("fixed", False, False),
            ("attack_only", True, False),
            ("defense_only", False, True),
            ("coevolution", True, True),
        ]
        results: list[BaselineResult] = []

        for name, attack_evolution, defense_evolution in arms:
            attack_generator = (
                self.evolving_attack_generator if attack_evolution else self.fixed_attack_generator
            )
            defense_optimizer = (
                self.evolving_defense_optimizer if defense_evolution else self.fixed_defense_optimizer
            )
            engine = CoEvolutionEngine(
                attack_generator=_AblatedAttackGenerator(attack_generator, switches),
                defense_optimizer=_AblatedDefenseOptimizer(defense_optimizer, switches),
                runtime=self.runtime,
                evaluator=_AblatedEvaluator(self.evaluator, switches),
                config=_config_for_ablation(self.config, switches),
                artifact_root=self.artifact_root / name,
            )
            evolution_run = engine.run(manifest, effective_profile, seed=seed)
            final_metrics = (
                evolution_run.rounds[-1].regression_evaluation.metrics if evolution_run.rounds else {}
            )
            results.append(
                BaselineResult(
                    name=name,
                    attack_evolution=attack_evolution,
                    defense_evolution=defense_evolution,
                    run=evolution_run,
                    final_metrics={
                        metric: final_metrics[metric]
                        for metric in manifest.metric_names
                        if metric in final_metrics
                    },
                    utility_constrained_metrics=_utility_constrained_metrics(
                        final_metrics,
                        evolution_run,
                    ),
                )
            )

        output_path = self.artifact_root / manifest.experiment_id / f"seed-{seed}" / "comparison.json"
        comparison = BaselineComparison(
            experiment_id=manifest.experiment_id,
            dataset_refs=list(manifest.dataset_refs),
            budget=dict(manifest.budget),
            seed=seed,
            metric_names=list(manifest.metric_names),
            ablations=switches,
            results=results,
            artifact_path=str(output_path),
            provenance_path="pending",
            evidence_index_path="pending",
        )
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(comparison.model_dump(mode="json"), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        evidence = persist_run_evidence(
            manifest,
            experiment_dir=output_path.parent,
            raw_result_path=output_path,
            repo_root=Path(__file__).resolve().parents[3],
            dataset_paths=self.dataset_paths,
        )
        comparison = comparison.model_copy(
            update={
                "provenance_path": evidence.provenance_path,
                "evidence_index_path": evidence.evidence_index_path,
            }
        )
        output_path.write_text(
            json.dumps(comparison.model_dump(mode="json"), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        # Refresh the index after the comparison receives its final evidence paths.
        persist_run_evidence(
            manifest,
            experiment_dir=output_path.parent,
            raw_result_path=output_path,
            repo_root=Path(__file__).resolve().parents[3],
            dataset_paths=self.dataset_paths,
        )
        return comparison


class _AblatedAttackGenerator:
    def __init__(self, delegate: AttackGenerator, switches: AblationConfig) -> None:
        self.delegate = delegate
        self.switches = switches

    def generate(self, profile: AgentProfile, state: EvolutionState, *, seed: int) -> list[AttackCandidate]:
        if not self.switches.reflection:
            state = state.model_copy(update={"evaluation_refs": []})
        return list(self.delegate.generate(profile, state, seed=seed))


class _AblatedDefenseOptimizer:
    def __init__(self, delegate: DefenseOptimizer, switches: AblationConfig) -> None:
        self.delegate = delegate
        self.switches = switches

    def optimize(
        self,
        profile: AgentProfile,
        evaluation: EvaluationResult,
        state: EvolutionState,
        *,
        seed: int,
    ) -> list[DefenseCandidate]:
        if not self.switches.node_attribution:
            evaluation = _without_attribution(evaluation)
        candidates = list(self.delegate.optimize(profile, evaluation, state, seed=seed))
        if self.switches.utility_constraints:
            return candidates
        return [candidate.model_copy(update={"utility_constraints": {}}) for candidate in candidates]


class _AblatedEvaluator:
    def __init__(self, delegate: Evaluator, switches: AblationConfig) -> None:
        self.delegate = delegate
        self.switches = switches

    def evaluate(
        self,
        profile: AgentProfile,
        trajectories: list[Trajectory],
        *,
        manifest: ExperimentManifest,
    ) -> EvaluationResult:
        if not self.switches.trajectory_anomaly:
            trajectories = [_without_anomaly_signals(item) for item in trajectories]
        result = self.delegate.evaluate(profile, trajectories, manifest=manifest)
        return result if self.switches.node_attribution else _without_attribution(result)


def _profile_for_ablation(profile: AgentProfile, switches: AblationConfig) -> AgentProfile:
    if switches.profile:
        return profile
    return profile.model_copy(
        update={
            "nodes": [
                node.model_copy(update={"risk_surfaces": [], "defenses": []})
                for node in profile.nodes
            ],
            "tools": [],
            "attack_entries": [],
            "sensitive_data": [],
            "rag_enabled": False,
        }
    )


def _without_anomaly_signals(trajectory: Trajectory) -> Trajectory:
    metadata = {
        key: value
        for key, value in trajectory.metadata.items()
        if key not in {"anomaly_score", "anomaly_evidence", "trajectory_risk"}
    }
    steps = []
    for step in trajectory.steps:
        if step.monitor_decision is None:
            steps.append(step)
            continue
        decision = {
            key: value
            for key, value in step.monitor_decision.items()
            if key not in {"anomaly_score", "anomaly_evidence", "trajectory_risk"}
        }
        steps.append(step.model_copy(update={"monitor_decision": decision}))
    return trajectory.model_copy(update={"metadata": metadata, "steps": steps})


def _without_attribution(evaluation: EvaluationResult) -> EvaluationResult:
    cases = [
        item.model_copy(update={"blocked_node": None, "bypassed_nodes": []})
        for item in evaluation.cases
    ]
    return evaluation.model_copy(update={"attribution": {}, "cases": cases})


def _config_for_ablation(config: EvolutionConfig, switches: AblationConfig) -> EvolutionConfig:
    if switches.utility_constraints:
        return config
    return config.model_copy(update={"utility_floor": None})


def _utility_constrained_metrics(
    final_metrics: dict[str, float],
    run: EvolutionRun,
) -> dict[str, float | None]:
    """Report security, utility, and cost together without fabricating unavailable values."""
    business_success = final_metrics.get("business_success_rate", final_metrics.get("utility"))
    return {
        "asr": final_metrics.get("asr"),
        "fpr": final_metrics.get("fpr"),
        "business_success_rate": business_success,
        "overhead": final_metrics.get(
            "overhead",
            run.final_state.budget_spent,
        ),
    }


__all__ = [
    "AblationConfig",
    "BaselineComparison",
    "BaselineMatrixRunner",
    "BaselineName",
    "BaselineResult",
]
