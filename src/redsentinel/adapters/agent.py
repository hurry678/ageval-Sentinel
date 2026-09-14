"""External Agent adapters exposed without changing their established contracts."""

from redsentinel.adapters.engine.adapter import AgentAdapter as SDKAdapter
from redsentinel.adapters.engine.openmanus import OpenManusAdapter
from redsentinel.adapters.engine.openmanus_real import (
    OpenManusDockerRunner,
    OpenManusDockerRunnerConfig,
    OpenManusRealAdapter,
)
from redsentinel.application.engine.hosted_adapter import HostedAPIAdapter as HTTPAdapter

__all__ = [
    "HTTPAdapter",
    "OpenManusAdapter",
    "OpenManusDockerRunner",
    "OpenManusDockerRunnerConfig",
    "OpenManusRealAdapter",
    "SDKAdapter",
]
