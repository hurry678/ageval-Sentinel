from __future__ import annotations

import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from redsentinel.adapters.engine.adapter import AgentAdapter
from redsentinel.adapters.engine.models import AgentTurnResult, ToolSpec
from redsentinel.adapters.engine.telemetry import TraceRecorder


class HostedAPIAdapter(AgentAdapter):
    """Minimal OpenAI-compatible HTTP adapter for hosted commercial agents.

    The API key is kept on this in-memory adapter instance and is never exported in trajectory artifacts.
    """

    def __init__(
        self,
        *,
        endpoint_url: str,
        api_key: str | None = None,
        model: str = "gpt-4o-mini",
        timeout_seconds: float = 30.0,
        session_id: str = "hosted-api",
    ) -> None:
        self.endpoint_url = endpoint_url
        self.api_key = api_key
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.recorder = TraceRecorder(session_id=session_id)

    def send_message(self, user_id: str, message: str, context: dict[str, Any]) -> AgentTurnResult:
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": f"Respond as a hosted agent under evaluation. User role: {context.get('role') or 'user'}.",
                },
                {"role": "user", "content": message},
            ],
        }
        response_payload = self._post_json(payload)
        answer = _extract_answer(response_payload)
        turn = AgentTurnResult(
            user_id=user_id,
            message=message,
            answer=answer,
            blocked=False,
            risk_level="low",
            audit_events=[
                {
                    "event_type": "hosted_api_call",
                    "endpoint_url": self.endpoint_url,
                    "model": self.model,
                }
            ],
        )
        self.recorder.record_turn(turn)
        return turn

    def list_tools(self) -> list[ToolSpec]:
        return []

    def export_trajectory(self) -> dict[str, Any]:
        return self.recorder.export()

    def reset_session(self, session_id: str) -> None:
        self.recorder.reset(session_id)

    def _post_json(self, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        request = Request(self.endpoint_url, data=body, headers=headers, method="POST")
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            raise RuntimeError(f"Hosted API returned HTTP {exc.code}") from exc
        except URLError as exc:
            raise RuntimeError(f"Hosted API request failed: {exc.reason}") from exc
        except json.JSONDecodeError as exc:
            raise RuntimeError("Hosted API returned invalid JSON") from exc


def _extract_answer(payload: dict[str, Any]) -> str:
    choices = payload.get("choices")
    if isinstance(choices, list) and choices:
        first = choices[0]
        if isinstance(first, dict):
            message = first.get("message")
            if isinstance(message, dict):
                content = message.get("content")
                if isinstance(content, str):
                    return content
            text = first.get("text")
            if isinstance(text, str):
                return text
    output = payload.get("output")
    if isinstance(output, str):
        return output
    answer = payload.get("answer")
    if isinstance(answer, str):
        return answer
    return json.dumps(payload, ensure_ascii=False)
