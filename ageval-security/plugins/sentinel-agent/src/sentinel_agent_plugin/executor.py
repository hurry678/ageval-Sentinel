"""Sentinel-Guardian enterprise Agent as an ageval executor.

The Agent under test ships its own tools and its own guards, so ageval supplies
no tool catalog: one ``invoke`` is one user turn against the real Agent.

A turn needs the acting identity, not just text, so the prompt is a JSON
envelope::

    {"user_id": "buyer_001", "role": "buyer", "phase": "controlled",
     "message": "查询订单 o9001"}

A bare (non-JSON) prompt is treated as a ``buyer_001`` / ``buyer`` message.

``phase`` selects an isolated Agent session — its own store and its own
trajectory. That is how one scenario replays its clean baseline and its attack
without the two sharing cart/order state.

``defense_mode: baseline`` disarms the guards for that turn, so one scenario can
measure the same attack with and without defenses. Only the OpenManus adapter
honours it; the ecommerce Agent's guards are hardcoded and ignore it.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ageval.plugins.agent_result import AgentResult

DEFAULT_AGENT_KIND = "ecommerce"
DEFAULT_PHASE = "default"
DEFAULT_USER_ID = "buyer_001"
DEFAULT_ROLE = "buyer"
DEFAULT_DEFENSE_MODE = "guarded"


def agent_kinds() -> tuple[str, ...]:
    """The registered in-process Agents, read from the single registry in
    redsentinel. Imported inside the function so this module stays importable
    when redsentinel is absent — see ``build_adapter``."""
    from redsentinel.adapters.inproc import agent_kinds as registered

    return registered()


def build_adapter(agent_kind: str, session_id: str) -> Any:
    """Instantiate the requested Sentinel adapter. Imported lazily: ageval Core
    must stay usable when redsentinel is not installed."""
    from redsentinel.adapters.inproc import load_adapter_class

    return load_adapter_class(agent_kind)(session_id=session_id)


def parse_envelope(prompt: str) -> dict[str, str]:
    try:
        raw = json.loads(prompt)
    except (json.JSONDecodeError, TypeError):
        raw = None
    if not isinstance(raw, Mapping) or "message" not in raw:
        return {
            "user_id": DEFAULT_USER_ID,
            "role": DEFAULT_ROLE,
            "message": prompt,
            "phase": DEFAULT_PHASE,
            "defense_mode": DEFAULT_DEFENSE_MODE,
        }
    return {
        "user_id": str(raw.get("user_id") or DEFAULT_USER_ID),
        "role": str(raw.get("role") or DEFAULT_ROLE),
        "message": str(raw.get("message") or ""),
        "phase": str(raw.get("phase") or DEFAULT_PHASE),
        "defense_mode": str(raw.get("defense_mode") or DEFAULT_DEFENSE_MODE),
    }


def normalize_tool_calls(records: Any) -> tuple[dict[str, Any], ...]:
    """Sentinel ``ToolCallRecord.to_dict()`` → the native tool channel shape.

    ``allowed`` is kept: a denied call is the evidence that a guard fired.
    """
    out: list[dict[str, Any]] = []
    for index, record in enumerate(records or ()):
        if not isinstance(record, Mapping):
            continue
        out.append(
            {
                "id": f"sentinel_{index}",
                "name": str(record.get("tool_name") or record.get("name") or "tool"),
                "arguments": dict(record.get("arguments") or {}),
                "allowed": bool(record.get("allowed", True)),
                "result": str(record.get("result") or ""),
                "risk_level": str(record.get("risk_level") or "normal"),
                "reason": str(record.get("reason") or ""),
            }
        )
    return tuple(out)


def tool_events(calls: Sequence[Mapping[str, Any]]) -> tuple[dict[str, Any], ...]:
    return tuple(
        {
            "kind": "tool",
            "phase": "start",
            "tool_call_id": call["id"],
            "function_name": call["name"],
            "title": call["name"],
            "args": call["arguments"],
            "status": "completed" if call["allowed"] else "denied",
            "source": "sentinel-agent",
        }
        for call in calls
    )


@dataclass
class SentinelAgentExecutor:
    """One Sentinel Agent per phase, alive for the whole Attempt."""

    kind: str = "sentinel-agent"
    model: str = "sentinel/ecommerce-agent"
    agent_kind: str = DEFAULT_AGENT_KIND
    session_prefix: str = "sentinel"
    _adapters: dict[str, Any] = field(default_factory=dict, repr=False)

    def adapter(self, phase: str) -> Any:
        found = self._adapters.get(phase)
        if found is None:
            found = build_adapter(self.agent_kind, f"{self.session_prefix}-{phase}")
            self._adapters[phase] = found
        return found

    def trajectories(self) -> dict[str, Any]:
        return {phase: adapter.export_trajectory() for phase, adapter in self._adapters.items()}

    def invoke(
        self,
        prompt: str,
        *,
        timeout: float = 60.0,
        collect_dir: str | None = None,
        redaction_sentinels: tuple[str, ...] | list[str] | None = None,
        tools: Sequence[Mapping[str, Any]] | None = None,
        messages: Sequence[Mapping[str, Any]] | None = None,
    ) -> AgentResult:
        del timeout, collect_dir, redaction_sentinels, tools, messages
        envelope = parse_envelope(prompt)
        phase = envelope["phase"]
        defense_mode = envelope["defense_mode"]
        context = {"role": envelope["role"], "defense_mode": defense_mode}
        try:
            turn = self.adapter(phase).send_message(
                envelope["user_id"],
                envelope["message"],
                context,
            )
        except Exception as exc:  # noqa: BLE001 — the Agent crashing is a result, not our error
            return AgentResult(
                model=self.model,
                text="",
                structured=None,
                ok=False,
                error=f"{type(exc).__name__}: {exc}",
                metadata={
                    "executor_kind": self.kind,
                    "agent_kind": self.agent_kind,
                    "phase": phase,
                    "defense_mode": defense_mode,
                },
            )
        calls = normalize_tool_calls(turn.tool_calls)
        blocked = bool(turn.blocked)
        risk_level = str(turn.risk_level)
        return AgentResult(
            model=self.model,
            text=str(turn.answer),
            structured={
                "answer": str(turn.answer),
                "blocked": blocked,
                "risk_level": risk_level,
                "user_id": str(turn.user_id),
                "defense_mode": defense_mode,
                "tool_calls": [dict(item) for item in turn.tool_calls or ()],
                "business_events": [dict(item) for item in turn.business_events or ()],
                "audit_events": [dict(item) for item in turn.audit_events or ()],
            },
            ok=True,
            events=tool_events(calls),
            tool_calls=calls,
            extra={
                "phase": phase,
                "blocked": blocked,
                "risk_level": risk_level,
                "defense_mode": defense_mode,
            },
            metadata={
                "executor_kind": self.kind,
                "agent_kind": self.agent_kind,
                "phase": phase,
                "defense_mode": defense_mode,
            },
        )


__all__ = [
    "DEFAULT_AGENT_KIND",
    "SentinelAgentExecutor",
    "agent_kinds",
    "build_adapter",
    "normalize_tool_calls",
    "parse_envelope",
    "tool_events",
]
