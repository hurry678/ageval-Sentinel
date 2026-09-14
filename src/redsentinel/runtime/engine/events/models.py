from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


class StepType(str, Enum):
    LLM_INFERENCE = "llm_inference"
    TOOL_CALL = "tool_call"
    MONITOR_DECISION = "monitor_decision"


GOLDEN_STEP_TYPE_SEQUENCE = [
    StepType.LLM_INFERENCE,
    StepType.TOOL_CALL,
    StepType.LLM_INFERENCE,
    StepType.TOOL_CALL,
    StepType.LLM_INFERENCE,
]


class ToolCallIntent(BaseModel):
    call_id: str
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class LLMInferencePayload(BaseModel):
    model: str
    input_messages: list[dict[str, Any]]
    output_content: str | None = None
    tool_call_intents: list[ToolCallIntent] = Field(default_factory=list)
    turn_index: int
    latency_ms: float | None = None


class ToolCallPayload(BaseModel):
    call_id: str
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    response: Any
    parent_turn_index: int
    latency_ms: float | None = None


class MemoryOpPayload(BaseModel):
    op: Literal["read", "write", "delete"]
    namespace: str
    key: str
    layer: Literal["short_term", "long_term", "episodic"]


class MonitorDecisionPayload(BaseModel):
    call_type: Literal["llm_input", "llm_output", "tool_call", "tool_result", "code_execution", "file_access"]
    decision: Literal["allow", "deny", "ask"]
    risk_level: str = "normal"
    reason: str
    audit_object: Literal["tool", "code", "file", "llm", "output"]
    ask_id: str | None = None
    approval_state: Literal["not_required", "pending", "approved", "rejected", "expired"] = "not_required"
    artifact_refs: list[str] = Field(default_factory=list)


class StepEvent(BaseModel):
    step_type: StepType
    timestamp: datetime
    llm: LLMInferencePayload | None = None
    tool_call: ToolCallPayload | None = None
    monitor_decision: MonitorDecisionPayload | None = None
    memory_ops: list[MemoryOpPayload] = Field(default_factory=list)
    state_delta: dict[str, Any] | None = None
    step_index: int | None = None

    @model_validator(mode="after")
    def validate_payload(self) -> StepEvent:
        if self.step_type == StepType.LLM_INFERENCE:
            if self.llm is None or self.tool_call is not None or self.monitor_decision is not None:
                raise ValueError("llm_inference requires llm payload and no tool_call payload")
        if self.step_type == StepType.TOOL_CALL:
            if self.tool_call is None or self.llm is not None or self.monitor_decision is not None:
                raise ValueError("tool_call requires tool_call payload and no llm payload")
        if self.step_type == StepType.MONITOR_DECISION:
            if self.monitor_decision is None or self.llm is not None or self.tool_call is not None:
                raise ValueError("monitor_decision requires monitor_decision payload only")
            if self.monitor_decision.decision == "ask" and not self.monitor_decision.ask_id:
                raise ValueError("ask monitor decisions require ask_id")
        return self
