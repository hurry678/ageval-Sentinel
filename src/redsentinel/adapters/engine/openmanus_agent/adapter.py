from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from redsentinel.defenses.engine.tools import dangerous


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    invoke: Callable[[dict[str, Any]], str]


@dataclass
class ToolCallRecord:
    name: str
    arguments: dict[str, Any]
    result: str


@dataclass
class OpenManusAdapter:
    """Small adapter around OpenManus-style tool registration.

    The real OpenManus package is an optional external dependency. This adapter
    exposes the narrow registry/call surface Red Sentinel needs and can be bound
    to a real OpenManus registry by callers.
    """

    tools: dict[str, ToolSpec] = field(default_factory=dict)
    call_history: list[ToolCallRecord] = field(default_factory=list)

    def register_tool(self, tool: ToolSpec) -> None:
        self.tools[tool.name] = tool

    def register_tools(self, tools: list[ToolSpec]) -> None:
        for tool in tools:
            self.register_tool(tool)

    def bind_to_openmanus_registry(self, registry: Any) -> None:
        """Best-effort bridge for OpenManus registries with register/add_tool APIs."""
        for tool in self.tools.values():
            if hasattr(registry, "register"):
                registry.register(tool.name, tool.invoke, description=tool.description)
            elif hasattr(registry, "add_tool"):
                registry.add_tool(tool)
            else:
                raise TypeError("OpenManus registry must expose register() or add_tool().")

    def call_tool(self, name: str, arguments: dict[str, Any]) -> str:
        if name not in self.tools:
            raise KeyError(f"Unknown OpenManus tool: {name}")
        result = self.tools[name].invoke(arguments)
        self.call_history.append(ToolCallRecord(name=name, arguments=dict(arguments), result=result))
        return result


def build_default_adapter() -> OpenManusAdapter:
    adapter = OpenManusAdapter()
    adapter.register_tools(
        [
            _tool("db_query", "Execute a simulated database query.", dangerous.db_query),
            _tool("file_operation", "Execute a simulated file operation.", dangerous.file_operation),
            _tool("api_call", "Execute a simulated API call.", dangerous.api_call),
            _tool("send_email", "Send a simulated email.", dangerous.send_email),
        ]
    )
    return adapter


def _tool(name: str, description: str, langchain_tool: Any) -> ToolSpec:
    return ToolSpec(
        name=name,
        description=description,
        invoke=lambda arguments, tool=langchain_tool: str(tool.invoke(arguments)),
    )
