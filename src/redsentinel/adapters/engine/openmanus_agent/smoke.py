from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any

from redsentinel.adapters.engine.openmanus_agent.real_openmanus import install_red_sentinel_tools


async def run_real_openmanus_smoke(prompt: str = "Run the Red Sentinel OpenManus smoke test.") -> dict[str, Any]:
    """Run a real OpenManus Manus loop with a deterministic fake LLM.

    This requires the external OpenManus checkout to be importable on
    `PYTHONPATH`. The fake LLM avoids live model credentials while still
    exercising OpenManus' real `Manus.run()`, `ToolCallAgent.think()`,
    `ToolCallAgent.act()`, and `execute_tool()` flow.
    """
    try:
        from app.agent.manus import Manus
        from app.schema import Function, ToolCall
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            f"OpenManus is not importable or is missing a runtime dependency: {exc.name}. "
            "Add the external OpenManus checkout to PYTHONPATH and install its runtime dependencies."
        ) from exc

    agent = await Manus.create()
    installed_tools = install_red_sentinel_tools(agent)
    agent.llm = _SmokeLLM(Function=Function, ToolCall=ToolCall)
    agent.max_steps = 1

    result = await agent.run(prompt)
    return {
        "agent": agent.name,
        "mode": "real_openmanus_fake_llm_no_defense_smoke",
        "installed_tools": installed_tools,
        "result": result,
    }


class _SmokeLLM:
    def __init__(self, *, Function: type[Any], ToolCall: type[Any]) -> None:
        self.Function = Function
        self.ToolCall = ToolCall

    async def ask_tool(self, **kwargs: Any) -> Any:
        arguments = {
            "to": "ops@company.com",
            "subject": "OpenManus smoke",
            "body": "Red Sentinel tool bridge smoke test.",
        }
        return SimpleNamespace(
            content="Call the Red Sentinel send_email tool.",
            tool_calls=[
                self.ToolCall(
                    id="red-sentinel-smoke-1",
                    function=self.Function(name="send_email", arguments=json.dumps(arguments)),
                )
            ],
        )


def main() -> None:
    print(json.dumps(asyncio.run(run_real_openmanus_smoke()), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
