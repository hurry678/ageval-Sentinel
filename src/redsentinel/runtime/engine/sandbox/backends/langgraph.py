from __future__ import annotations

import json
from typing import Any, Literal

from typing_extensions import Annotated, TypedDict

from redsentinel.runtime.engine.events.models import StepEvent
from redsentinel.runtime.engine.sandbox.backends.base import emit_llm_step, emit_tool_step
from redsentinel.runtime.engine.sandbox.session import SandboxSession


class GraphState(TypedDict):
    messages: Annotated[list, lambda left, right: left + right]


class LangGraphBackend:
    framework = "langgraph"

    def run(self, session: SandboxSession) -> list[StepEvent]:
        try:
            from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
            from langgraph.graph import END, StateGraph
        except ModuleNotFoundError:
            return self._run_local_replay(session)

        def to_openai_dict(message: Any) -> dict[str, Any]:
            if isinstance(message, SystemMessage):
                return {"role": "system", "content": message.content}
            if isinstance(message, HumanMessage):
                return {"role": "user", "content": message.content}
            if isinstance(message, AIMessage):
                payload: dict[str, Any] = {"role": "assistant", "content": message.content}
                if message.tool_calls:
                    payload["tool_calls"] = [
                        {
                            "id": tc["id"],
                            "type": "function",
                            "function": {
                                "name": tc["name"],
                                "arguments": json.dumps(tc["args"]),
                            },
                        }
                        for tc in message.tool_calls
                    ]
                return payload
            if isinstance(message, ToolMessage):
                return {"role": "tool", "tool_call_id": message.tool_call_id, "content": message.content}
            raise TypeError(f"Unsupported message type: {type(message)}")

        def agent_node(state: GraphState) -> dict[str, list[Any]]:
            prior = [to_openai_dict(m) for m in state["messages"]]
            response = session.llm.chat_completion(prior, tools=session.tools.openai_tools_schema())
            emit_llm_step(session, prior, response)
            ai = AIMessage(
                content=response.get("content") or "",
                tool_calls=[
                    {
                        "id": tc["id"],
                        "name": tc["function"]["name"],
                        "args": session.tools.parse_arguments(tc["function"]["arguments"]),
                    }
                    for tc in response.get("tool_calls", [])
                ]
                if response.get("tool_calls")
                else [],
            )
            return {"messages": [ai]}

        def tools_node(state: GraphState) -> dict[str, list[Any]]:
            last = state["messages"][-1]
            if not isinstance(last, AIMessage) or not last.tool_calls:
                return {"messages": []}
            parent_turn = session.llm.turn_index - 1
            tool_messages: list[ToolMessage] = []
            for tc in last.tool_calls:
                if len(session.emitter.events()) >= session.config.runner.max_steps:
                    break
                result = session.tools.invoke(tc["name"], tc["args"])
                emit_tool_step(
                    session,
                    call_id=tc["id"],
                    name=tc["name"],
                    arguments=tc["args"],
                    response=result,
                    parent_turn_index=parent_turn,
                    state_delta={
                        "framework": session.config.agent.framework,
                        "framework_meta": {"node": "tools"},
                    },
                )
                tool_messages.append(ToolMessage(content=json.dumps(result), tool_call_id=tc["id"]))
            return {"messages": tool_messages}

        def should_continue(state: GraphState) -> Literal["tools", "end"]:
            if len(session.emitter.events()) >= session.config.runner.max_steps:
                return "end"
            last = state["messages"][-1]
            if isinstance(last, AIMessage) and last.tool_calls:
                return "tools"
            return "end"

        graph = StateGraph(GraphState)
        graph.add_node("agent", agent_node)
        graph.add_node("tools", tools_node)
        graph.set_entry_point("agent")
        graph.add_conditional_edges("agent", should_continue, {"tools": "tools", "end": END})
        graph.add_edge("tools", "agent")
        app = graph.compile()

        initial: GraphState = {
            "messages": [
                SystemMessage(content=session.config.agent.system_prompt),
                HumanMessage(content=session.config.agent.goal),
            ]
        }
        app.invoke(initial)
        return session.emitter.events()

    def _run_local_replay(self, session: SandboxSession) -> list[StepEvent]:
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": session.config.agent.system_prompt},
            {"role": "user", "content": session.config.agent.goal},
        ]

        while len(session.emitter.events()) < session.config.runner.max_steps:
            response = session.llm.chat_completion(messages, tools=session.tools.openai_tools_schema())
            emit_llm_step(session, list(messages), response)

            tool_calls = response.get("tool_calls") or []
            if not tool_calls:
                break

            messages.append(
                {
                    "role": "assistant",
                    "content": response.get("content") or "",
                    "tool_calls": tool_calls,
                }
            )
            for tc in tool_calls:
                if len(session.emitter.events()) >= session.config.runner.max_steps:
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
                    state_delta={
                        "framework": session.config.agent.framework,
                        "framework_meta": {"node": "tools"},
                    },
                )
                messages.append({"role": "tool", "tool_call_id": tc["id"], "content": json.dumps(result)})

        return session.emitter.events()
