from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

from redsentinel.runtime.engine.events.models import MemoryOpPayload
from redsentinel.attacks.engine.injectors import InjectionEvent
from redsentinel.attacks.engine.injectors.goal_perturbation import GoalPerturbationInjector
from redsentinel.attacks.engine.injectors.tool_tampering import ToolTamperingProxy
from redsentinel.runtime.engine.memory import InMemoryMemoryStore
from redsentinel.runtime.engine.sandbox.config import ScenarioConfig
from redsentinel.runtime.engine.sandbox.llm.vcr_client import VCRCachedLLMClient
from redsentinel.runtime.engine.sandbox.tools.registry import ToolRegistry
from redsentinel.runtime.engine.telemetry import TelemetryStepEmitter


@dataclass
class SandboxSession:
    config: ScenarioConfig
    session_id: str
    emitter: TelemetryStepEmitter
    tools: Any
    llm: VCRCachedLLMClient
    memory_store: InMemoryMemoryStore
    injection_events: list[InjectionEvent] = field(default_factory=list)
    pending_memory_ops: list[MemoryOpPayload] = field(default_factory=list)
    pending_step_injections: list[InjectionEvent] = field(default_factory=list)

    @property
    def memory_namespace(self) -> str:
        if self.config.memory:
            return self.config.memory.namespace
        return f"session-{self.session_id}"


class SandboxEnvironment:
    """Creates isolated sandbox sessions with no shared mutable state."""

    def create_session(self, config: ScenarioConfig) -> SandboxSession:
        active_config, goal_result = GoalPerturbationInjector().apply_config(config)
        emitter = TelemetryStepEmitter(max_steps=active_config.runner.max_steps)
        tools = ToolRegistry(mode=config.tools.mode)
        tools.register_defaults()
        if (
            active_config.injection.mode == "controlled"
            and active_config.injection.kind == "tool_tampering"
        ):
            tools = ToolTamperingProxy(tools, active_config)
        llm = VCRCachedLLMClient(config=active_config, session_id=str(uuid4()))
        session = SandboxSession(
            config=active_config,
            session_id=str(uuid4()),
            emitter=emitter,
            tools=tools,
            llm=llm,
            memory_store=InMemoryMemoryStore(),
        )
        if goal_result.applied:
            session.injection_events.extend(goal_result.events)
            session.pending_step_injections.extend(goal_result.events)
        return session
