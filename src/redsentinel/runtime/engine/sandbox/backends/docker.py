from __future__ import annotations

import json
from typing import Any

from redsentinel.runtime.engine.events.models import StepEvent, StepType, ToolCallPayload, LLMInferencePayload
from redsentinel.runtime.engine.sandbox.backends.base import utcnow
from redsentinel.runtime.engine.sandbox.docker.capture import DEFAULT_MAX_OUTPUT_BYTES, run_bounded_capture
from redsentinel.runtime.engine.sandbox.session import SandboxSession


class DockerBackend:
    framework = "docker"

    def __init__(self, *, max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES) -> None:
        self.max_output_bytes = max_output_bytes
        self.last_error: str | None = None

    def run(self, session: SandboxSession) -> list[StepEvent]:
        self.last_error = None
        config = session.config
        docker_image = config.agent.framework_config.get("docker_image", "")
        if not docker_image:
            return []

        args = ["docker", "run", "--rm", "--network=none"]

        if config.agent.system_prompt:
            args.extend(["-e", f"SYSTEM_PROMPT={config.agent.system_prompt}"])
        if config.agent.goal:
            args.extend(["-e", f"USER_GOAL={config.agent.goal}"])

        args.append(docker_image)

        result = run_bounded_capture(
            args,
            timeout=getattr(getattr(config, "runner", None), "timeout_seconds", 300),
            max_output_bytes=self.max_output_bytes,
        )
        if result.error:
            self.last_error = result.error
            return []

        events = self._parse_output_to_events(result.stdout_text(), result.stderr_text())
        emitter = getattr(session, "emitter", None)
        emit = getattr(emitter, "emit", None)
        if callable(emit):
            for event in events:
                emit(event)
        return events

    def _parse_output_to_events(self, stdout: str, stderr: str) -> list[StepEvent]:
        events: list[StepEvent] = []
        lines = stdout.strip().split("\n")

        for line in lines:
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
                event = self._create_event_from_payload(payload)
                if event:
                    events.append(event)
            except json.JSONDecodeError:
                continue

        return events

    def _create_event_from_payload(self, payload: dict[str, Any]) -> StepEvent | None:
        event_type = payload.get("type", "").lower()

        if event_type == "llm_inference":
            return StepEvent(
                step_type=StepType.LLM_INFERENCE,
                timestamp=utcnow(),
                llm=LLMInferencePayload(
                    model=payload.get("model", "unknown"),
                    input_messages=payload.get("input_messages", []),
                    output_content=payload.get("output_content", ""),
                    tool_call_intents=[],
                    turn_index=payload.get("turn_index", 0),
                ),
            )

        if event_type == "tool_call":
            return StepEvent(
                step_type=StepType.TOOL_CALL,
                timestamp=utcnow(),
                tool_call=ToolCallPayload(
                    call_id=payload.get("call_id", ""),
                    name=payload.get("tool_name", ""),
                    arguments=payload.get("arguments", {}),
                    response=payload.get("response"),
                    parent_turn_index=payload.get("parent_turn_index", 0),
                ),
            )

        return None
