"""Public telemetry boundary for trajectory emission and recording."""

from typing import Any

from redsentinel.runtime.engine.telemetry import TelemetryStepEmitter
from redsentinel.runtime.engine.telemetry import TrajectoryRecorder as LegacyTrajectoryRecorder


class TrajectoryRecorder(LegacyTrajectoryRecorder):
    """Record schema-ready trajectories at the public runtime boundary."""

    @classmethod
    def from_session(cls, session: Any, started_at: Any = None) -> dict[str, Any]:
        trajectory = super().from_session(session, started_at=started_at)
        return _normalize_optional_numbers(trajectory)


def _normalize_optional_numbers(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: 0.0 if key == "latency_ms" and item is None else _normalize_optional_numbers(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_normalize_optional_numbers(item) for item in value]
    return value

__all__ = ["TelemetryStepEmitter", "TrajectoryRecorder"]
