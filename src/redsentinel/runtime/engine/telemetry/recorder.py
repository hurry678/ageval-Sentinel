from __future__ import annotations

import json
from datetime import datetime, timezone
from time import perf_counter
from typing import Any

from redsentinel.runtime.engine.events.models import StepType


class TrajectoryRecorder:
    """Build schema-compatible trajectories from telemetry-collected events."""

    @classmethod
    def from_session(cls, session: Any, started_at: datetime | None = None) -> dict[str, Any]:
        build_started = perf_counter()
        started = started_at or datetime.now(tz=timezone.utc)
        events = session.emitter.events()
        ended = events[-1].timestamp if events else started
        config = session.config
        steps: list[dict[str, Any]] = []
        for event in events:
            step: dict[str, Any] = {
                "step_index": event.step_index,
                "step_type": event.step_type.value,
                "timestamp": event.timestamp.astimezone(timezone.utc).isoformat(),
            }
            if event.memory_ops:
                step["memory_ops"] = [op.model_dump() for op in event.memory_ops]
            if event.state_delta:
                step["state_delta"] = event.state_delta
            if event.step_type == StepType.LLM_INFERENCE and event.llm:
                step["llm"] = event.llm.model_dump(mode="json")
            if event.step_type == StepType.TOOL_CALL and event.tool_call:
                step["tool_call"] = event.tool_call.model_dump(mode="json")
            steps.append(step)

        build_overhead_ms = (perf_counter() - build_started) * 1000
        emit_overhead_ms = float(getattr(session.emitter, "overhead_ms", 0.0))
        injections = [
            event.to_dict()
            for event in getattr(session, "injection_events", [])
        ]
        metadata = {
            "started_at": started.astimezone(timezone.utc).isoformat(),
            "ended_at": ended.astimezone(timezone.utc).isoformat(),
            "telemetry_overhead_ms": emit_overhead_ms + build_overhead_ms,
        }
        if injections:
            metadata["injections"] = injections
        return {
            "schema_version": config.schema_version,
            "session_id": session.session_id,
            "experiment_id": config.experiment_id,
            "seed": config.reproducibility.seed,
            "framework": config.agent.framework,
            "goal": {"text": config.agent.goal},
            "injection_mode": config.injection.mode,
            "steps": steps,
            "metadata": metadata,
        }

    @classmethod
    def to_json(cls, trajectory: dict[str, Any]) -> str:
        return json.dumps(trajectory, ensure_ascii=False, sort_keys=True, indent=2)
