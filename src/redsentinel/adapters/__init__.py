"""Stable adapter boundary for supported Agent and sandbox runtimes."""

from redsentinel.adapters.agent import (
    HTTPAdapter,
    OpenManusAdapter,
    OpenManusDockerRunner,
    OpenManusDockerRunnerConfig,
    OpenManusRealAdapter,
    SDKAdapter,
)
from redsentinel.adapters.registry import (
    RUNNABLE_ADAPTERS,
    SCAFFOLD_ADAPTERS,
    adapter_class,
    create_adapter,
)
from redsentinel.adapters.sandbox import DirectAPIBackend, DockerBackend, LangGraphBackend

__all__ = [
    "HTTPAdapter",
    "OpenManusAdapter",
    "OpenManusDockerRunner",
    "OpenManusDockerRunnerConfig",
    "OpenManusRealAdapter",
    "RUNNABLE_ADAPTERS",
    "SCAFFOLD_ADAPTERS",
    "SDKAdapter",
    "DirectAPIBackend",
    "DockerBackend",
    "LangGraphBackend",
    "adapter_class",
    "create_adapter",
]
