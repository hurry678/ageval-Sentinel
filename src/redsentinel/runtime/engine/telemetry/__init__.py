"""Out-of-band telemetry — trajectory capture decoupled from execution."""

from redsentinel.runtime.engine.telemetry.emitter import TelemetryStepEmitter
from redsentinel.runtime.engine.telemetry.recorder import TrajectoryRecorder

__all__ = [
    "TelemetryStepEmitter",
    "TrajectoryRecorder",
]
