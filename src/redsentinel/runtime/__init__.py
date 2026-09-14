"""Stable runtime API for sandboxed Agent execution and trajectory capture."""

from redsentinel.runtime.docker import (
    DEFAULT_MAX_OUTPUT_BYTES,
    BoundedCaptureResult,
    DockerTraceExecutor,
    TrajectoryArtifacts,
    execute_docker_trace,
    run_bounded_capture,
)
from redsentinel.runtime.replay import (
    CassetteStore,
    CassetteTurnMismatchError,
    VCRCachedLLMClient,
    should_record_cassette,
)
from redsentinel.runtime.sandbox import (
    SandboxEnvironment,
    SandboxSession,
    ScenarioConfig,
    get_backend,
    run_scenario,
)
from redsentinel.runtime.telemetry import TelemetryStepEmitter, TrajectoryRecorder
from redsentinel.runtime.tools import ToolRegistry

__all__ = [
    "DEFAULT_MAX_OUTPUT_BYTES",
    "BoundedCaptureResult",
    "CassetteStore",
    "CassetteTurnMismatchError",
    "DockerTraceExecutor",
    "SandboxEnvironment",
    "SandboxSession",
    "ScenarioConfig",
    "TelemetryStepEmitter",
    "ToolRegistry",
    "TrajectoryArtifacts",
    "TrajectoryRecorder",
    "VCRCachedLLMClient",
    "execute_docker_trace",
    "get_backend",
    "run_bounded_capture",
    "run_scenario",
    "should_record_cassette",
]
