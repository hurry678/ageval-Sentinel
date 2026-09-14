from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from redsentinel.defenses.engine.mounting import DefensePlan, GuardMount
from redsentinel.defenses.engine.security.firewall.input_guard import check_malicious_input
from redsentinel.defenses.engine.security.goal_guard import GoalGuardInput, evaluate_goal_guard
from redsentinel.defenses.engine.security.memory_guard import MemoryGuardInput, evaluate_memory_guard
from redsentinel.defenses.engine.security.output.filter import check_output_compliance, mask_sensitive_info
from redsentinel.defenses.engine.security.tool_guard import ToolGuardInput, evaluate_tool_guard


RuntimeDecisionValue = Literal["allow", "block"]
RuntimeRiskLevel = Literal["normal", "low", "medium", "high", "critical"]


class RuntimeNodeInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    node_id: str = Field(min_length=1)
    content: str = ""
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    tool_name: str | None = None
    tool_arguments: dict[str, Any] = Field(default_factory=dict)
    tool_response: Any = None
    memory_namespace: str | None = None
    memory_key: str | None = None
    original_goal: str | None = None
    current_goal: str | None = None
    rag_chunks: list[Any] = Field(default_factory=list)


class RuntimeGuardDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    node_id: str = Field(min_length=1)
    guard_name: str = Field(min_length=1)
    allowed: bool
    decision: RuntimeDecisionValue
    risk_level: RuntimeRiskLevel
    reason: str = Field(min_length=1)
    attribution: list[dict[str, Any]] = Field(default_factory=list)
    sanitized_content: str | None = None
    audit_payload: dict[str, str]


class SecurityEventEmitter:
    def __init__(self, events_path: str | Path, *, max_events: int = 500) -> None:
        self.events_path = Path(events_path)
        self.max_events = max_events

    def emit(
        self,
        *,
        session_id: str,
        agent_id: str,
        call_type: str,
        decision: str,
        reason: str,
        risk_score: float,
        pending: bool = False,
        payload_summary: dict[str, Any] | None = None,
        event_id: str | None = None,
        timestamp: str | None = None,
    ) -> dict[str, Any]:
        normalized_decision = _normalize_event_decision(decision)
        event = {
            "event_id": event_id or f"evt_{uuid4().hex[:12]}",
            "session_id": str(session_id),
            "agent_id": str(agent_id),
            "call_type": str(call_type),
            "decision": normalized_decision,
            "reason": _sanitize_event_text(str(reason)),
            "risk_score": float(risk_score),
            "pending": bool(pending or normalized_decision == "ask"),
            "payload_summary": _sanitize_event_payload(payload_summary or {}),
            "timestamp": timestamp or _utc_now_iso(),
        }

        self.events_path.parent.mkdir(parents=True, exist_ok=True)
        with self.events_path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(event, ensure_ascii=False, sort_keys=True))
            file.write("\n")
        self._trim_events()
        return event

    def _trim_events(self) -> None:
        if self.max_events <= 0 or not self.events_path.exists():
            return
        lines = [line for line in self.events_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if len(lines) <= self.max_events:
            return
        self.events_path.write_text("\n".join(lines[-self.max_events:]) + "\n", encoding="utf-8")


class DefenseRuntime:
    def __init__(
        self,
        plan: DefensePlan,
        *,
        event_emitter: SecurityEventEmitter | None = None,
        session_id: str = "default",
        agent_id: str | None = None,
    ) -> None:
        self.plan = plan
        self._mounts = {mount.node_id: mount for mount in plan.mounts}
        self.event_emitter = event_emitter
        self.session_id = session_id
        self.agent_id = agent_id or plan.agent_name

    def evaluate(self, node_input: RuntimeNodeInput) -> RuntimeGuardDecision:
        mount = self._mounts.get(node_input.node_id)
        if mount is None:
            decision = _decision(
                node_id=node_input.node_id,
                guard_name="unmounted",
                allowed=True,
                reason="allowed_unmounted: no guard mount configured for node.",
            )
        elif mount.guard_name == "input_firewall":
            decision = self._evaluate_input_firewall(mount, node_input)
        elif mount.guard_name == "rag_chunk_scanner":
            decision = self._evaluate_rag_scanner(mount, node_input)
        elif mount.guard_name == "tool_guard":
            decision = self._evaluate_tool_guard(mount, node_input)
        elif mount.guard_name == "memory_guard":
            decision = self._evaluate_memory_guard(mount, node_input)
        elif mount.guard_name == "goal_guard":
            decision = self._evaluate_goal_guard(mount, node_input)
        elif mount.guard_name == "output_filter":
            decision = self._evaluate_output_filter(mount, node_input)
        else:
            raise ValueError(f"Unsupported guard mount: {mount.guard_name}")

        self._emit_event(node_input, decision)
        return decision

    def _emit_event(self, node_input: RuntimeNodeInput, decision: RuntimeGuardDecision) -> None:
        if self.event_emitter is None:
            return
        self.event_emitter.emit(
            session_id=str(node_input.metadata.get("session_id") or self.session_id),
            agent_id=str(node_input.metadata.get("agent_id") or self.agent_id),
            call_type=_event_call_type(node_input, decision),
            decision="allow" if decision.allowed else "deny",
            reason=decision.reason,
            risk_score=_risk_score_from_level(decision.risk_level),
            pending=False,
            payload_summary=_runtime_payload_summary(node_input, decision),
        )

    def _evaluate_input_firewall(
        self,
        mount: GuardMount,
        node_input: RuntimeNodeInput,
    ) -> RuntimeGuardDecision:
        blocked, message = check_malicious_input(node_input.content)
        return _decision(
            node_id=mount.node_id,
            guard_name=mount.guard_name,
            allowed=not blocked,
            reason=message,
            risk_level="high" if blocked else "normal",
            attribution=[_attribution("input_firewall", message)] if blocked else [],
        )

    def _evaluate_rag_scanner(
        self,
        mount: GuardMount,
        node_input: RuntimeNodeInput,
    ) -> RuntimeGuardDecision:
        chunks = node_input.rag_chunks or [node_input.content]
        scan_results = _scan_retrieved_chunks(chunks)
        blocked = any(item.get("should_filter") for item in scan_results)
        reason = "RAG chunks passed scan."
        if blocked:
            reason = "RAG chunk scanner filtered suspicious retrieval content."
        return _decision(
            node_id=mount.node_id,
            guard_name=mount.guard_name,
            allowed=not blocked,
            reason=reason,
            risk_level="high" if blocked else "normal",
            attribution=[dict(item) for item in scan_results if item.get("should_filter")],
        )

    def _evaluate_tool_guard(
        self,
        mount: GuardMount,
        node_input: RuntimeNodeInput,
    ) -> RuntimeGuardDecision:
        decision = evaluate_tool_guard(
            ToolGuardInput(
                tool_name=node_input.tool_name or mount.target,
                arguments=node_input.tool_arguments,
                response=node_input.tool_response,
                metadata=node_input.metadata,
                evidence=node_input.evidence,
            )
        )
        return _from_guard_decision(mount, decision)

    def _evaluate_memory_guard(
        self,
        mount: GuardMount,
        node_input: RuntimeNodeInput,
    ) -> RuntimeGuardDecision:
        decision = evaluate_memory_guard(
            MemoryGuardInput(
                namespace=node_input.memory_namespace or self.plan.agent_name,
                memory_key=node_input.memory_key or mount.node_id,
                content=node_input.content,
                metadata=node_input.metadata,
                evidence=node_input.evidence,
            )
        )
        return _from_guard_decision(mount, decision)

    def _evaluate_goal_guard(
        self,
        mount: GuardMount,
        node_input: RuntimeNodeInput,
    ) -> RuntimeGuardDecision:
        current_goal = node_input.current_goal or node_input.content
        decision = evaluate_goal_guard(
            GoalGuardInput(
                goal_id=mount.node_id,
                original_goal=node_input.original_goal or current_goal,
                current_goal=current_goal,
                metadata=node_input.metadata,
                evidence=node_input.evidence,
            )
        )
        return _from_guard_decision(mount, decision)

    def _evaluate_output_filter(
        self,
        mount: GuardMount,
        node_input: RuntimeNodeInput,
    ) -> RuntimeGuardDecision:
        compliant, message = check_output_compliance(node_input.content)
        sanitized = mask_sensitive_info(node_input.content)
        has_masking = sanitized != node_input.content
        reason = message
        if compliant and has_masking:
            reason = "Output allowed with sensitive content masked."
        return _decision(
            node_id=mount.node_id,
            guard_name=mount.guard_name,
            allowed=compliant,
            reason=reason,
            risk_level="high" if not compliant else "normal",
            attribution=[_attribution("output_masking", "Sensitive output fields were masked.")] if has_masking else [],
            sanitized_content=sanitized,
        )


def _from_guard_decision(mount: GuardMount, guard_decision: Any) -> RuntimeGuardDecision:
    return RuntimeGuardDecision(
        node_id=mount.node_id,
        guard_name=mount.guard_name,
        allowed=guard_decision.allowed,
        decision=guard_decision.decision,
        risk_level=guard_decision.risk_level,
        reason=guard_decision.reason,
        attribution=[dict(item) for item in guard_decision.attribution],
        audit_payload=dict(guard_decision.audit_payload),
    )


def _decision(
    *,
    node_id: str,
    guard_name: str,
    allowed: bool,
    reason: str,
    risk_level: RuntimeRiskLevel = "normal",
    attribution: list[dict[str, Any]] | None = None,
    sanitized_content: str | None = None,
) -> RuntimeGuardDecision:
    return RuntimeGuardDecision(
        node_id=node_id,
        guard_name=guard_name,
        allowed=allowed,
        decision="allow" if allowed else "block",
        risk_level=risk_level,
        reason=reason,
        attribution=attribution or [],
        sanitized_content=sanitized_content,
        audit_payload={
            "user_id": guard_name,
            "role": "system",
            "operation": "guard_mount_decision",
            "input_content": f"node_id={node_id}",
            "result": f"{'allowed' if allowed else 'blocked'}_{guard_name}: {reason}",
            "risk_level": risk_level,
        },
    )


def _attribution(evidence_type: str, summary: str) -> dict[str, Any]:
    return {
        "evidence_type": evidence_type,
        "summary": summary,
    }


def _scan_retrieved_chunks(chunks: list[Any]) -> list[dict[str, Any]]:
    try:
        from redsentinel.defenses.engine.security.ingest.doc_scanner import scan_retrieved_chunks
    except ModuleNotFoundError as exc:
        if exc.name != "langchain_openai":
            raise
        return [_fallback_chunk_scan(chunk, index) for index, chunk in enumerate(chunks)]
    return scan_retrieved_chunks(chunks)


def _fallback_chunk_scan(chunk: Any, index: int) -> dict[str, Any]:
    text = chunk.get("text", "") if isinstance(chunk, dict) else str(chunk)
    blocked, message = check_malicious_input(text)
    return {
        "chunk_index": index,
        "text_preview": text[:200],
        "risk_score": 80 if blocked else 0,
        "category": "input_guard_fallback" if blocked else "clean",
        "should_filter": blocked,
        "reasoning": message,
        "layer": 1,
        "l1_flags": ["input_guard_fallback"] if blocked else [],
    }


_SECRET_KEY_RE = re.compile(r"(secret|token|password)", re.IGNORECASE)
_SECRET_ASSIGNMENT_RE = re.compile(r"\b(secret|token|password)\b\s*[:=]\s*([^\s,;]+)", re.IGNORECASE)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _normalize_event_decision(decision: str) -> str:
    normalized = str(decision).lower()
    if normalized in {"block", "blocked"}:
        return "deny"
    if normalized in {"allow", "deny", "ask"}:
        return normalized
    return "deny"


def _sanitize_event_payload(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if _SECRET_KEY_RE.search(str(key)) else _sanitize_event_payload(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_sanitize_event_payload(item) for item in value]
    if isinstance(value, tuple):
        return [_sanitize_event_payload(item) for item in value]
    if isinstance(value, str):
        return _sanitize_event_text(value)
    return value


def _sanitize_event_text(value: str) -> str:
    return _SECRET_ASSIGNMENT_RE.sub(lambda match: f"{match.group(1)}=[REDACTED]", value)


def _event_call_type(node_input: RuntimeNodeInput, decision: RuntimeGuardDecision) -> str:
    metadata_call_type = node_input.metadata.get("call_type")
    if metadata_call_type:
        return str(metadata_call_type)

    tool_name = (node_input.tool_name or "").lower()
    if "file" in tool_name:
        return "file_access"
    if "code" in tool_name or "exec" in tool_name:
        return "code_exec"
    if decision.guard_name == "input_firewall":
        return "llm_input"
    if decision.guard_name == "output_filter":
        return "llm_output"
    return "tool_call"


def _runtime_payload_summary(node_input: RuntimeNodeInput, decision: RuntimeGuardDecision) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "node_id": decision.node_id,
        "guard_name": decision.guard_name,
    }
    if node_input.tool_name:
        payload["tool_name"] = node_input.tool_name
    if node_input.tool_arguments:
        payload["tool_arguments"] = node_input.tool_arguments
    return payload


def _risk_score_from_level(risk_level: str) -> float:
    return {
        "normal": 0.0,
        "low": 25.0,
        "medium": 50.0,
        "high": 80.0,
        "critical": 100.0,
    }.get(risk_level, 0.0)


__all__ = [
    "DefenseRuntime",
    "RuntimeGuardDecision",
    "RuntimeNodeInput",
    "SecurityEventEmitter",
]
