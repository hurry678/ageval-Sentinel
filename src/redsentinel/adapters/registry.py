"""Lazy adapter discovery without importing optional runtimes eagerly."""

from __future__ import annotations

from importlib import import_module
from typing import Any, Final

RUNNABLE_ADAPTERS: Final[tuple[str, ...]] = (
    "direct_api",
    "langgraph",
    "docker",
    "openmanus",
    "http",
    "sdk",
)
SCAFFOLD_ADAPTERS: Final[tuple[str, ...]] = ("autogen",)

_ADAPTER_TARGETS: Final[dict[str, tuple[str, str]]] = {
    "direct_api": ("redsentinel.runtime.engine.sandbox.backends.direct_api", "DirectAPIBackend"),
    "langgraph": ("redsentinel.runtime.engine.sandbox.backends.langgraph", "LangGraphBackend"),
    "docker": ("redsentinel.runtime.engine.sandbox.backends.docker", "DockerBackend"),
    "openmanus": ("redsentinel.adapters.engine.openmanus", "OpenManusAdapter"),
    "http": ("redsentinel.application.engine.hosted_adapter", "HostedAPIAdapter"),
    "sdk": ("redsentinel.adapters.engine.adapter", "AgentAdapter"),
}


def adapter_class(name: str) -> type[Any]:
    """Return a public adapter class while keeping optional dependencies lazy."""
    if name in SCAFFOLD_ADAPTERS:
        raise ValueError(f"{name} is scaffold-only and is not a runnable adapter.")
    try:
        module_name, class_name = _ADAPTER_TARGETS[name]
    except KeyError as exc:
        raise ValueError(f"Unsupported adapter: {name}") from exc
    return getattr(import_module(module_name), class_name)


def create_adapter(name: str, **kwargs: Any) -> Any:
    """Instantiate a runnable adapter by its stable public name."""
    return adapter_class(name)(**kwargs)


__all__ = [
    "RUNNABLE_ADAPTERS",
    "SCAFFOLD_ADAPTERS",
    "adapter_class",
    "create_adapter",
]
