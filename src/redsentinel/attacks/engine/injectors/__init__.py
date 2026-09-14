"""Controlled risk injection primitives."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Literal

from redsentinel.runtime.engine.events.models import MemoryOpPayload

InjectionKind = Literal["memory_poisoning", "tool_tampering", "goal_perturbation"]
InjectionIntensity = Literal["light", "medium", "heavy"]


@dataclass(frozen=True)
class InjectionEvent:
    injection_id: str
    kind: InjectionKind
    strategy: str
    intensity: InjectionIntensity
    target: str
    label: str
    ground_truth: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "injection_id": self.injection_id,
            "kind": self.kind,
            "strategy": self.strategy,
            "intensity": self.intensity,
            "target": self.target,
            "label": self.label,
            "ground_truth": self.ground_truth,
            "metadata": deepcopy(self.metadata),
        }


@dataclass(frozen=True)
class InjectionResult:
    applied: bool
    events: list[InjectionEvent] = field(default_factory=list)
    memory_ops: list[MemoryOpPayload] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "applied": self.applied,
            "events": [event.to_dict() for event in self.events],
            "memory_ops": [op.model_dump() for op in self.memory_ops],
        }


def injection_id(experiment_id: str, kind: str, strategy: str, intensity: str) -> str:
    return f"{experiment_id}:{kind}:{strategy}:{intensity}"


__all__ = [
    "InjectionEvent",
    "InjectionIntensity",
    "InjectionKind",
    "InjectionResult",
    "injection_id",
]
