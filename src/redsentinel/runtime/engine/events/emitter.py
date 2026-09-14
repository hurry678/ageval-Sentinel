from __future__ import annotations

from copy import deepcopy

from redsentinel.runtime.engine.events.models import StepEvent


class MaxStepsExceeded(Exception):
    """Raised when a backend attempts to emit beyond max_steps."""


class InMemoryStepEmitter:
    """Task 1 default emitter. Task 2 replaces with TelemetryStepEmitter."""

    def __init__(self, max_steps: int = 5) -> None:
        self.max_steps = max_steps
        self._events: list[StepEvent] = []

    def emit(self, event: StepEvent) -> int:
        if len(self._events) >= self.max_steps:
            raise MaxStepsExceeded(f"Cannot emit step {len(self._events)}; max_steps={self.max_steps}")
        stored = deepcopy(event)
        stored.step_index = len(self._events)
        self._events.append(stored)
        return stored.step_index

    def events(self) -> list[StepEvent]:
        return list(self._events)

    def clear(self) -> None:
        self._events.clear()
