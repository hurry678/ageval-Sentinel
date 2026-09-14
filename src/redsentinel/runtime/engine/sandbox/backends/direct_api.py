from __future__ import annotations

import json
from typing import Any

from redsentinel.runtime.engine.events.models import StepEvent
from redsentinel.runtime.engine.sandbox.backends.base import (
    append_assistant_tool_message,
    append_tool_result,
    emit_llm_step,
    emit_tool_step,
)
from redsentinel.runtime.engine.sandbox.session import SandboxSession


class DirectAPIBackend:
    framework = "direct_api"

    def run(self, session: SandboxSession) -> list[StepEvent]:
        config = session.config
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": config.agent.system_prompt},
            {"role": "user", "content": config.agent.goal},
        ]
        tools_schema = session.tools.openai_tools_schema()

        while len(session.emitter.events()) < config.runner.max_steps:
            response = session.llm.chat_completion(messages, tools=tools_schema)
            emit_llm_step(session, list(messages), response)

            tool_calls = response.get("tool_calls") or []
            if not tool_calls:
                break

            append_assistant_tool_message(messages, tool_calls)
            for tc in tool_calls:
                if len(session.emitter.events()) >= config.runner.max_steps:
                    break
                args = session.tools.parse_arguments(tc["function"]["arguments"])
                result = session.tools.invoke(tc["function"]["name"], args)
                emit_tool_step(
                    session,
                    call_id=tc["id"],
                    name=tc["function"]["name"],
                    arguments=args,
                    response=result,
                    parent_turn_index=response["turn_index"],
                )
                append_tool_result(messages, tc["id"], json.dumps(result))

            if len(session.emitter.events()) >= config.runner.max_steps:
                break

        return session.emitter.events()
