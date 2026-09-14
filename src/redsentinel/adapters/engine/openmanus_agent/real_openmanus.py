from __future__ import annotations

import json
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

from redsentinel.adapters.engine.openmanus_agent.adapter import OpenManusAdapter, build_default_adapter

if TYPE_CHECKING:
    from redsentinel.defenses.engine.monitor_plugin import OpenManusMonitorHooks


def install_red_sentinel_tools(agent: Any, adapter: OpenManusAdapter | None = None) -> list[str]:
    """Install Red Sentinel tools into a real OpenManus Manus instance.

    OpenManus exposes tools through `agent.available_tools`, which is an
    `app.tool.ToolCollection` instance with `add_tools(*tools)`.
    """
    adapter = adapter or build_default_adapter()
    collection = getattr(agent, "available_tools", None)
    if collection is None or not hasattr(collection, "add_tools"):
        raise TypeError("OpenManus agent must expose available_tools.add_tools(*tools).")

    collection.add_tools(*create_openmanus_tools(adapter))
    return list(adapter.tools)


def create_openmanus_tools(adapter: OpenManusAdapter | None = None) -> list[Any]:
    adapter = adapter or build_default_adapter()
    BaseTool, ToolResult = _load_openmanus_tool_base()
    return [_build_tool_class(BaseTool, ToolResult, tool)() for tool in adapter.tools.values()]


def attach_real_openmanus_monitor(agent: Any, hooks: OpenManusMonitorHooks) -> Any:
    """Patch real OpenManus LLM and tool entry points with monitor hooks.

    Verified upstream entry points:
    - `ToolCallAgent.think()` calls `self.llm.ask_tool(...)`.
    - `ToolCallAgent.act()` delegates each command to `self.execute_tool(command)`.
    """
    llm = getattr(agent, "llm", None)
    if llm is None or not hasattr(llm, "ask_tool"):
        raise TypeError("OpenManus agent must expose llm.ask_tool(...).")
    if not hasattr(agent, "execute_tool"):
        raise TypeError("OpenManus ToolCallAgent must expose execute_tool(command).")

    original_ask_tool = llm.ask_tool
    original_execute_tool = agent.execute_tool

    async def monitored_ask_tool(*args: Any, **kwargs: Any) -> Any:
        messages = _messages_from_call(args, kwargs)
        decision = hooks.before_llm_call(_serialize_messages(messages))
        if decision.decision == "deny":
            return SimpleNamespace(content=f"[MONITOR_DENY] {decision.reason}", tool_calls=[])
        if decision.decision == "ask":
            return SimpleNamespace(content=f"[MONITOR_ASK] {decision.ask_id}: {decision.reason}", tool_calls=[])

        response = await original_ask_tool(*args, **kwargs)
        output_decision = hooks.after_llm_call(str(getattr(response, "content", "") or ""))
        if output_decision.decision == "deny":
            response.content = f"[MONITOR_DENY] {output_decision.reason}"
            response.tool_calls = []
        if output_decision.decision == "ask":
            response.content = f"[MONITOR_ASK] {output_decision.ask_id}: {output_decision.reason}"
            response.tool_calls = []
        return response

    async def monitored_execute_tool(command: Any) -> str:
        tool_name = getattr(getattr(command, "function", None), "name", "")
        arguments = _tool_arguments(command)
        decision = hooks.before_tool_call(tool_name, arguments)
        if decision.decision == "deny":
            return f"[MONITOR_DENY] {decision.reason}"
        if decision.decision == "ask":
            return f"[MONITOR_ASK] {decision.ask_id}: {decision.reason}"

        result = await original_execute_tool(command)
        hooks.after_tool_call(tool_name, arguments, result)
        return result

    llm.ask_tool = monitored_ask_tool
    agent.execute_tool = monitored_execute_tool
    agent._red_sentinel_original_ask_tool = original_ask_tool
    agent._red_sentinel_original_execute_tool = original_execute_tool
    return agent


def _load_openmanus_tool_base() -> tuple[type[Any], type[Any]]:
    try:
        from app.tool.base import BaseTool, ToolResult
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "OpenManus is not importable. Add the external OpenManus checkout to PYTHONPATH before installing tools."
        ) from exc
    return BaseTool, ToolResult


def _build_tool_class(base_tool: type[Any], tool_result: type[Any], tool: Any) -> type[Any]:
    async def execute(self: Any, **kwargs: Any) -> Any:
        return tool_result(output=tool.invoke(dict(kwargs)))

    return type(
        f"RedSentinel{tool.name.title().replace('_', '')}Tool",
        (base_tool,),
        {
            "__annotations__": {
                "name": str,
                "description": str,
                "parameters": dict,
            },
            "name": tool.name,
            "description": tool.description,
            "parameters": {
                "type": "object",
                "properties": {},
                "additionalProperties": True,
            },
            "execute": execute,
        },
    )


def _serialize_messages(messages: Any) -> list[dict[str, Any]]:
    if messages is None:
        return []
    if isinstance(messages, dict):
        messages = [messages]
    elif isinstance(messages, (str, bytes)) or not hasattr(messages, "__iter__"):
        messages = [messages]
    serialized = []
    for message in messages:
        if hasattr(message, "to_dict"):
            serialized.append(message.to_dict())
        elif hasattr(message, "model_dump"):
            serialized.append(message.model_dump())
        elif isinstance(message, dict):
            serialized.append(dict(message))
        else:
            serialized.append({"content": str(message)})
    return serialized


def _tool_arguments(command: Any) -> dict[str, Any]:
    raw = getattr(getattr(command, "function", None), "arguments", None) or "{}"
    if isinstance(raw, dict):
        return dict(raw)
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {"_raw_arguments": str(raw)}
    return parsed if isinstance(parsed, dict) else {"_raw_arguments": parsed}


def _messages_from_call(args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
    if "messages" in kwargs:
        return kwargs["messages"]
    return args[0] if args else None


__all__ = [
    "attach_real_openmanus_monitor",
    "create_openmanus_tools",
    "install_red_sentinel_tools",
]
