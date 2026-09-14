from __future__ import annotations

from copy import deepcopy
from time import perf_counter

from redsentinel.runtime.engine.events.emitter import MaxStepsExceeded
from redsentinel.runtime.engine.events.models import StepEvent


class TelemetryStepEmitter:
    """Side-channel StepEvent collector for telemetry-owned trajectory capture."""

    def __init__(self, max_steps: int = 5) -> None:
        self.max_steps = max_steps
        self._events: list[StepEvent] = []
        self._overhead_ms = 0.0

    @property
    def overhead_ms(self) -> float:
        return self._overhead_ms

    def emit(self, event: StepEvent) -> int:
        started = perf_counter()
        try:
            if len(self._events) >= self.max_steps:
                raise MaxStepsExceeded(
                    f"Cannot emit step {len(self._events)}; max_steps={self.max_steps}"
                )
            stored = deepcopy(event)
            stored.step_index = len(self._events)
            self._events.append(stored)
            return stored.step_index
        finally:
            self._overhead_ms += (perf_counter() - started) * 1000

    def events(self) -> list[StepEvent]:
        return list(self._events)

    def clear(self) -> None:
        started = perf_counter()
        try:
            self._events.clear()
        finally:
            self._overhead_ms += (perf_counter() - started) * 1000
