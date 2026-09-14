"""Stable collaboration protocols for RedSentinel research modules."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from redsentinel.core.models import (
    AgentProfile,
    AttackCandidate,
    DefenseCandidate,
    EvaluationResult,
    EvolutionState,
    ExperimentManifest,
    Trajectory,
)


@runtime_checkable
class Profiler(Protocol):
    """Build an evidence-backed Agent profile from declared materials."""

    def profile(self, materials: Sequence[Path], *, manifest: ExperimentManifest) -> AgentProfile: ...


@runtime_checkable
class AttackGenerator(Protocol):
    """Generate attack candidates without executing them."""

    def generate(
        self,
        profile: AgentProfile,
        state: EvolutionState,
        *,
        seed: int,
    ) -> Sequence[AttackCandidate]: ...


@runtime_checkable
class DefenseOptimizer(Protocol):
    """Propose utility-constrained defenses from evaluation evidence."""

    def optimize(
        self,
        profile: AgentProfile,
        evaluation: EvaluationResult,
        state: EvolutionState,
        *,
        seed: int,
    ) -> Sequence[DefenseCandidate]: ...


@runtime_checkable
class Evaluator(Protocol):
    """Evaluate trajectories under one explicit experiment manifest."""

    def evaluate(
        self,
        profile: AgentProfile,
        trajectories: Sequence[Trajectory],
        *,
        manifest: ExperimentManifest,
    ) -> EvaluationResult: ...


@runtime_checkable
class RuntimeAdapter(Protocol):
    """Run one attack/defense pair against an external or local Agent."""

    @property
    def adapter_id(self) -> str: ...

    def run(
        self,
        profile: AgentProfile,
        attack: AttackCandidate,
        defense: DefenseCandidate | None,
        *,
        experiment_id: str,
        seed: int,
    ) -> Trajectory: ...


@runtime_checkable
class Reporter(Protocol):
    """Render derived artifacts while preserving structured source results."""

    def render(
        self,
        evaluation: EvaluationResult,
        *,
        state: EvolutionState | None = None,
        output_dir: Path,
    ) -> Mapping[str, Any]: ...


__all__ = [
    "AttackGenerator",
    "DefenseOptimizer",
    "Evaluator",
    "Profiler",
    "Reporter",
    "RuntimeAdapter",
]
