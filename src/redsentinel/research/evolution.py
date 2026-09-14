"""Deterministic, protocol-driven attack/defense co-evolution."""

from __future__ import annotations

import hashlib
import json
import random
from pathlib import Path
from typing import Any, Literal, Sequence

from pydantic import BaseModel, ConfigDict, Field

from redsentinel.core.models import (
    AgentProfile,
    AttackCandidate,
    DefenseCandidate,
    EvaluationResult,
    EvolutionStage,
    EvolutionState,
    ExperimentManifest,
    Trajectory,
)
from redsentinel.core.protocols import AttackGenerator, DefenseOptimizer, Evaluator, RuntimeAdapter


class _EvolutionModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EvolutionConfig(_EvolutionModel):
    """Search and stopping policy for one deterministic evolution run."""

    max_rounds: int = Field(default=3, ge=1)
    attack_population_size: int = Field(default=4, ge=1)
    defense_population_size: int = Field(default=3, ge=1)
    attack_elite_count: int = Field(default=1, ge=1)
    defense_elite_count: int = Field(default=1, ge=1)
    exploration_rate: float = Field(default=0.25, ge=0.0, le=1.0)
    max_budget: float | None = Field(default=None, ge=0.0)
    risk_target: float | None = Field(default=None, ge=0.0, le=1.0)
    utility_floor: float | None = Field(default=None, ge=0.0, le=1.0)
    no_improvement_rounds: int | None = Field(default=None, ge=1)
    risk_metric: str = "asr"
    utility_metric: str = "utility"


class LedgerEntry(_EvolutionModel):
    sequence: int = Field(ge=0)
    experiment_id: str = Field(min_length=1)
    round_index: int = Field(ge=0)
    stage: EvolutionStage
    payload: dict[str, Any] = Field(default_factory=dict)
    previous_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    entry_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class EvolutionRound(_EvolutionModel):
    round_index: int = Field(ge=0)
    attack_evaluation: EvaluationResult
    regression_evaluation: EvaluationResult
    selected_attack_ids: list[str]
    selected_defense_ids: list[str]
    budget_spent: float = Field(ge=0.0)


class EvolutionRun(_EvolutionModel):
    schema_version: Literal["evolution-run-v1"] = "evolution-run-v1"
    experiment_id: str = Field(min_length=1)
    seed: int
    final_state: EvolutionState
    rounds: list[EvolutionRound] = Field(default_factory=list)
    ledger_path: str


class AppendOnlyEvolutionLedger:
    """Append-only JSONL ledger with a deterministic forward hash chain."""

    _ZERO_HASH = "0" * 64

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def append(self, state: EvolutionState, payload: dict[str, Any] | None = None) -> LedgerEntry:
        entries = self.read()
        body = {
            "sequence": len(entries),
            "experiment_id": state.experiment_id,
            "round_index": state.round_index,
            "stage": state.stage,
            "payload": payload or {},
            "previous_hash": entries[-1].entry_hash if entries else self._ZERO_HASH,
        }
        digest = hashlib.sha256(
            json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        entry = LedgerEntry(**body, entry_hash=digest)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(entry.model_dump(mode="json"), ensure_ascii=False, sort_keys=True) + "\n")
        return entry

    def read(self) -> list[LedgerEntry]:
        if not self.path.exists():
            return []
        entries = [
            LedgerEntry.model_validate_json(line)
            for line in self.path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        previous_hash = self._ZERO_HASH
        for sequence, entry in enumerate(entries):
            body = entry.model_dump(mode="json", exclude={"entry_hash"})
            expected = hashlib.sha256(
                json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            if entry.sequence != sequence or entry.previous_hash != previous_hash or entry.entry_hash != expected:
                raise ValueError("evolution ledger hash chain is invalid")
            previous_hash = entry.entry_hash
        return entries


class CoEvolutionEngine:
    """Run the minimal attack-generation/evaluation/defense-regression loop."""

    def __init__(
        self,
        *,
        attack_generator: AttackGenerator,
        defense_optimizer: DefenseOptimizer,
        runtime: RuntimeAdapter,
        evaluator: Evaluator,
        config: EvolutionConfig | None = None,
        artifact_root: str | Path = "artifacts/evolution",
    ) -> None:
        self.attack_generator = attack_generator
        self.defense_optimizer = defense_optimizer
        self.runtime = runtime
        self.evaluator = evaluator
        self.config = config or EvolutionConfig()
        self.artifact_root = Path(artifact_root)

    def run(self, manifest: ExperimentManifest, profile: AgentProfile, *, seed: int) -> EvolutionRun:
        ledger = AppendOnlyEvolutionLedger(
            self.artifact_root / manifest.experiment_id / f"seed-{seed}" / "evolution-ledger.jsonl"
        )
        state = EvolutionState(experiment_id=manifest.experiment_id)
        ledger.append(state)
        rounds: list[EvolutionRound] = []
        best_risk: float | None = None
        stale_rounds = 0

        for round_index in range(self.config.max_rounds):
            state = state.model_copy(update={"round_index": round_index})
            state = self._transition(state, "attack_generation", ledger)
            attacks = list(self.attack_generator.generate(profile, state, seed=_stage_seed(seed, round_index, 1)))
            attacks = _bounded_unique(attacks, self.config.attack_population_size)
            if not attacks:
                return self._terminal_run(state, rounds, ledger, seed, "no_attack_candidates", failed=True)
            state = state.model_copy(update={"attack_population": attacks})

            state = self._transition(state, "execution", ledger, {"attack_count": len(attacks)})
            if self._would_exceed_budget(state, attacks, execution_count=len(attacks)):
                return self._terminal_run(state, rounds, ledger, seed, "budget_exhausted")
            attack_trajectories = self._execute(
                profile, attacks, None, manifest.experiment_id, _stage_seed(seed, round_index, 2)
            )
            state = self._spend(state, attacks, execution_count=len(attack_trajectories))

            state = self._transition(state, "evaluation", ledger)
            attack_evaluation = self.evaluator.evaluate(profile, attack_trajectories, manifest=manifest)
            state = state.model_copy(update={"evaluation_refs": [*state.evaluation_refs, attack_evaluation.result_id]})

            state = self._transition(state, "attack_selection", ledger)
            selected_attacks = _select_population(
                attacks,
                count=self.config.attack_elite_count,
                exploration_rate=self.config.exploration_rate,
                seed=_stage_seed(seed, round_index, 3),
            )
            state = state.model_copy(update={"selected_attack_ids": [item.candidate_id for item in selected_attacks]})

            state = self._transition(state, "defense_generation", ledger)
            defenses = list(
                self.defense_optimizer.optimize(
                    profile,
                    attack_evaluation,
                    state,
                    seed=_stage_seed(seed, round_index, 4),
                )
            )
            defenses = _bounded_unique(defenses, self.config.defense_population_size)
            if not defenses:
                return self._terminal_run(state, rounds, ledger, seed, "no_defense_candidates", failed=True)
            state = state.model_copy(update={"defense_population": defenses})
            if self._would_exceed_budget(state, defenses):
                return self._terminal_run(state, rounds, ledger, seed, "budget_exhausted")

            state = self._transition(state, "defense_selection", ledger)
            selected_defenses = _select_population(
                defenses,
                count=self.config.defense_elite_count,
                exploration_rate=self.config.exploration_rate,
                seed=_stage_seed(seed, round_index, 5),
            )
            state = state.model_copy(
                update={"selected_defense_ids": [item.candidate_id for item in selected_defenses]}
            )
            state = self._spend(state, defenses)

            state = self._transition(state, "regression", ledger)
            if self._would_exceed_budget(state, [], execution_count=len(selected_attacks)):
                return self._terminal_run(state, rounds, ledger, seed, "budget_exhausted")
            regression_trajectories = self._execute(
                profile,
                selected_attacks,
                selected_defenses[0],
                manifest.experiment_id,
                _stage_seed(seed, round_index, 6),
            )
            state = self._spend(state, [], execution_count=len(regression_trajectories))
            regression_evaluation = self.evaluator.evaluate(profile, regression_trajectories, manifest=manifest)
            state = state.model_copy(
                update={"evaluation_refs": [*state.evaluation_refs, regression_evaluation.result_id]}
            )
            rounds.append(
                EvolutionRound(
                    round_index=round_index,
                    attack_evaluation=attack_evaluation,
                    regression_evaluation=regression_evaluation,
                    selected_attack_ids=list(state.selected_attack_ids),
                    selected_defense_ids=list(state.selected_defense_ids),
                    budget_spent=state.budget_spent,
                )
            )

            risk = regression_evaluation.metrics.get(self.config.risk_metric)
            if risk is not None:
                if best_risk is None or risk < best_risk:
                    best_risk = risk
                    stale_rounds = 0
                else:
                    stale_rounds += 1
            stop_reason = self._stop_reason(state, regression_evaluation, round_index, stale_rounds)
            if stop_reason:
                return self._terminal_run(state, rounds, ledger, seed, stop_reason)

        return self._terminal_run(state, rounds, ledger, seed, "max_rounds")

    def _execute(
        self,
        profile: AgentProfile,
        attacks: Sequence[AttackCandidate],
        defense: DefenseCandidate | None,
        experiment_id: str,
        seed: int,
    ) -> list[Trajectory]:
        return [
            self.runtime.run(
                profile,
                attack,
                defense,
                experiment_id=experiment_id,
                seed=seed + index,
            )
            for index, attack in enumerate(attacks)
        ]

    def _spend(
        self,
        state: EvolutionState,
        candidates: Sequence[AttackCandidate | DefenseCandidate],
        *,
        execution_count: int = 0,
    ) -> EvolutionState:
        spent = sum(item.estimated_cost for item in candidates) + float(execution_count)
        return state.model_copy(update={"budget_spent": state.budget_spent + spent})

    def _would_exceed_budget(
        self,
        state: EvolutionState,
        candidates: Sequence[AttackCandidate | DefenseCandidate],
        *,
        execution_count: int = 0,
    ) -> bool:
        if self.config.max_budget is None:
            return False
        projected = state.budget_spent + sum(item.estimated_cost for item in candidates) + float(execution_count)
        return projected > self.config.max_budget

    def _stop_reason(
        self,
        state: EvolutionState,
        evaluation: EvaluationResult,
        round_index: int,
        stale_rounds: int,
    ) -> str | None:
        if self.config.max_budget is not None and state.budget_spent >= self.config.max_budget:
            return "budget_exhausted"
        risk = evaluation.metrics.get(self.config.risk_metric)
        if self.config.risk_target is not None and risk is not None and risk <= self.config.risk_target:
            return "risk_target_met"
        utility = evaluation.metrics.get(self.config.utility_metric)
        if self.config.utility_floor is not None and utility is not None and utility < self.config.utility_floor:
            return "utility_floor_violated"
        if self.config.no_improvement_rounds is not None and stale_rounds >= self.config.no_improvement_rounds:
            return "no_improvement"
        if round_index + 1 >= self.config.max_rounds:
            return "max_rounds"
        return None

    def _transition(
        self,
        state: EvolutionState,
        stage: EvolutionStage,
        ledger: AppendOnlyEvolutionLedger,
        payload: dict[str, Any] | None = None,
    ) -> EvolutionState:
        state = state.model_copy(update={"stage": stage})
        ledger.append(state, payload)
        return state

    def _terminal_run(
        self,
        state: EvolutionState,
        rounds: list[EvolutionRound],
        ledger: AppendOnlyEvolutionLedger,
        seed: int,
        reason: str,
        *,
        failed: bool = False,
    ) -> EvolutionRun:
        terminal_stage: Literal["completed", "failed"] = "failed" if failed else "completed"
        state = state.model_copy(update={"stage": terminal_stage, "stop_reason": reason})
        ledger.append(state, {"stop_reason": reason})
        return EvolutionRun(
            experiment_id=state.experiment_id,
            seed=seed,
            final_state=state,
            rounds=rounds,
            ledger_path=str(ledger.path),
        )


def _stage_seed(seed: int, round_index: int, stage: int) -> int:
    return seed * 10_000 + round_index * 100 + stage


def _bounded_unique(population: Sequence[Any], limit: int) -> list[Any]:
    unique: dict[str, Any] = {}
    for candidate in population:
        unique.setdefault(candidate.candidate_id, candidate)
    return list(unique.values())[:limit]


def _select_population(
    population: Sequence[Any],
    *,
    count: int,
    exploration_rate: float,
    seed: int,
) -> list[Any]:
    if not population:
        return []
    count = min(count, len(population))
    ranked = sorted(
        population,
        key=lambda item: (-float(item.metadata.get("fitness", 0.0)), item.candidate_id),
    )
    explore_count = min(count, int(round(count * exploration_rate)))
    elite_count = count - explore_count
    selected = ranked[:elite_count]
    remaining = [item for item in ranked if item not in selected]
    random.Random(seed).shuffle(remaining)
    return [*selected, *remaining[:explore_count]]


__all__ = [
    "AppendOnlyEvolutionLedger",
    "CoEvolutionEngine",
    "EvolutionConfig",
    "EvolutionRound",
    "EvolutionRun",
    "LedgerEntry",
]
