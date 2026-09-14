"""Single source of truth for the in-process Agents the platform can put under test.

Two processes consume this: the platform API (validate a target, expose the choices
on ``/api/health``) and the ageval executor plugin (instantiate the adapter). It
lives in the library because that is the only package both of them already depend
on — the plugin declares ``host_requires: redsentinel``.

Pure data: the adapter class is named by import path and resolved on demand, so a
lookup never depends on an adapter being importable. Note the enclosing
``redsentinel.adapters`` package imports adapters eagerly, so importing this module
is not itself cheap.

This is a different axis from ``catalog.py``: that one describes how an Agent is
*onboarded and audited* by the library; this one lists the built-in Agents the
platform offers as ready-to-run targets, which is why the ids differ
(``openmanus-offline`` is the OpenManus adapter with no hosted model).
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module


@dataclass(frozen=True)
class InprocAgent:
    agent_kind: str
    adapter_path: str
    label: str


_AGENTS: dict[str, InprocAgent] = {
    agent.agent_kind: agent
    for agent in (
        InprocAgent(
            agent_kind="ecommerce",
            adapter_path="redsentinel.adapters.engine.ecommerce:EcommerceEnterpriseAdapter",
            label="内置电商企业 Agent",
        ),
        InprocAgent(
            agent_kind="openmanus-offline",
            adapter_path="redsentinel.adapters.engine.openmanus:OpenManusAdapter",
            label="OpenManus Agent（离线，无托管模型）",
        ),
    )
}

DEFAULT_AGENT_KIND = "ecommerce"


def agent_kinds() -> tuple[str, ...]:
    """All registered in-process agent_kind values."""
    return tuple(_AGENTS)


def is_registered(agent_kind: str) -> bool:
    return agent_kind in _AGENTS


def get(agent_kind: str) -> InprocAgent:
    try:
        return _AGENTS[agent_kind]
    except KeyError as exc:
        raise ValueError(f"Unregistered agent_kind: {agent_kind!r}") from exc


def load_adapter_class(agent_kind: str) -> type:
    """Resolve the adapter class lazily, so registry lookups cost no imports."""
    module_path, _, class_name = get(agent_kind).adapter_path.partition(":")
    return getattr(import_module(module_path), class_name)


__all__ = [
    "DEFAULT_AGENT_KIND",
    "InprocAgent",
    "agent_kinds",
    "get",
    "is_registered",
    "load_adapter_class",
]
