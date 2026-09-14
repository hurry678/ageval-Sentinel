from __future__ import annotations

import json
import os
import time
from typing import Any

import httpx
from openai import OpenAI

from redsentinel.runtime.engine.sandbox.config import ScenarioConfig, cassette_path
from redsentinel.runtime.engine.sandbox.replay import CassetteStore, CassetteTurnMismatchError, should_record_cassette


class VCRCachedLLMClient:
    """OpenAI client with cassette replay keyed by turn index (X-ARL-Turn semantics)."""

    def __init__(self, config: ScenarioConfig, session_id: str) -> None:
        self.config = config
        self.session_id = session_id
        self.turn_index = 0
        self._current_turn = 0
        self._cassette = CassetteStore(cassette_path(config))

    def _next_turn(self) -> int:
        turn = self.turn_index
        self.turn_index += 1
        self._current_turn = turn
        return turn

    def _request_hook(self, request: httpx.Request) -> None:
        request.headers["X-ARL-Turn"] = str(self._current_turn)

    def _http_client_factory(self) -> httpx.Client:
        return httpx.Client(
            event_hooks={"request": [self._request_hook]},
            timeout=60.0,
        )

    def _parse_completion(self, payload: dict[str, Any], turn: int, latency_ms: float) -> dict[str, Any]:
        message = payload["choices"][0]["message"]
        tool_calls = []
        for tc in message.get("tool_calls") or []:
            tool_calls.append(
                {
                    "id": tc["id"],
                    "type": "function",
                    "function": {
                        "name": tc["function"]["name"],
                        "arguments": tc["function"]["arguments"],
                    },
                }
            )
        return {
            "content": message.get("content"),
            "tool_calls": tool_calls,
            "latency_ms": latency_ms,
            "turn_index": turn,
        }

    def _replay_from_cassette(self, turn: int) -> dict[str, Any]:
        payload = self._cassette.response_json_for_turn(turn)
        return self._parse_completion(payload, turn, latency_ms=0.0)

    def _record_live_call(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        turn: int,
    ) -> dict[str, Any]:
        client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY", ""), http_client=self._http_client_factory())
        started = time.perf_counter()
        kwargs: dict[str, Any] = {
            "model": self.config.agent.model,
            "messages": messages,
        }
        if tools:
            kwargs["tools"] = tools
        response = client.chat.completions.create(**kwargs)
        latency_ms = (time.perf_counter() - started) * 1000
        payload = json.loads(response.model_dump_json())
        return self._parse_completion(payload, turn, latency_ms=latency_ms)

    def chat_completion(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        turn = self._next_turn()
        self._current_turn = turn

        if should_record_cassette():
            if not os.environ.get("OPENAI_API_KEY"):
                raise RuntimeError("VCR_RECORD=1 requires OPENAI_API_KEY for live recording.")
            return self._record_live_call(messages, tools, turn)

        if not self._cassette.exists:
            raise CassetteTurnMismatchError(
                f"Cassette missing at {self._cassette.cassette_path}. "
                "Run with VCR_RECORD=1 and OPENAI_API_KEY to record."
            )
        return self._replay_from_cassette(turn)
