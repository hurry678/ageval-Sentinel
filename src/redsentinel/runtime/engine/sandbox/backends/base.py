from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Protocol

from redsentinel.runtime.engine.events.models import (
    LLMInferencePayload,
    StepEvent,
    StepType,
    ToolCallIntent,
    ToolCallPayload,
)
from redsentinel.runtime.engine.sandbox.session import SandboxSession


class AgentBackend(Protocol):
    framework: str

    def run(self, session: SandboxSession) -> list[StepEvent]:
        ...


def utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


def emit_llm_step(session: SandboxSession, messages: list[dict[str, Any]], response: dict[str, Any]) -> int:
    intents = [
        ToolCallIntent(
            call_id=tc["id"],
            name=tc["function"]["name"],
            arguments=session.tools.parse_arguments(tc["function"]["arguments"]),
        )
        for tc in response.get("tool_calls", [])
    ]
    memory_ops = list(getattr(session, "pending_memory_ops", []))
    if hasattr(session, "pending_memory_ops"):
        session.pending_memory_ops.clear()
    pending_injections = list(getattr(session, "pending_step_injections", []))
    if hasattr(session, "pending_step_injections"):
        session.pending_step_injections.clear()
    state_delta = _state_delta_with_injections(
        {"framework": session.config.agent.framework},
        pending_injections,
    )
    event = StepEvent(
        step_type=StepType.LLM_INFERENCE,
        timestamp=utcnow(),
        llm=LLMInferencePayload(
            model=session.config.agent.model,
            input_messages=messages,
            output_content=response.get("content"),
            tool_call_intents=intents,
            turn_index=response["turn_index"],
            latency_ms=response.get("latency_ms"),
        ),
        memory_ops=memory_ops,
        state_delta=state_delta,
    )
    return session.emitter.emit(event)


def emit_tool_step(
    session: SandboxSession,
    call_id: str,
    name: str,
    arguments: dict[str, Any],
    response: Any,
    parent_turn_index: int,
    latency_ms: float = 1.0,
    state_delta: dict[str, Any] | None = None,
) -> int:
    delta = state_delta or {"framework": session.config.agent.framework}
    tool_injection = _consume_tool_injection(session)
    if tool_injection is not None:
        if hasattr(session, "injection_events"):
            session.injection_events.append(tool_injection)
        delta = _state_delta_with_injections(delta, [tool_injection])
    event = StepEvent(
        step_type=StepType.TOOL_CALL,
        timestamp=utcnow(),
        tool_call=ToolCallPayload(
            call_id=call_id,
            name=name,
            arguments=arguments,
            response=response,
            parent_turn_index=parent_turn_index,
            latency_ms=latency_ms,
        ),
        state_delta=delta,
    )
    return session.emitter.emit(event)


def _consume_tool_injection(session: SandboxSession):
    consumer = getattr(session.tools, "consume_last_injection_event", None)
    if callable(consumer):
        return consumer()
    return None


def _state_delta_with_injections(delta: dict[str, Any], injections: list[Any]) -> dict[str, Any]:
    if not injections:
        return delta
    merged = dict(delta)
    existing = merged.get("injection")
    events = [event.to_dict() for event in injections]
    if existing is None:
        merged["injection"] = events
    elif isinstance(existing, list):
        merged["injection"] = [*existing, *events]
    else:
        merged["injection"] = [existing, *events]
    return merged


def append_assistant_tool_message(
    messages: list[dict[str, Any]], tool_calls: list[dict[str, Any]]
) -> None:
    messages.append(
        {
            "role": "assistant",
            "content": None,
            "tool_calls": tool_calls,
        }
    )


def append_tool_result(messages: list[dict[str, Any]], call_id: str, content: str) -> None:
    messages.append({"role": "tool", "tool_call_id": call_id, "content": content})
