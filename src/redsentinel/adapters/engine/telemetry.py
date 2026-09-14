from __future__ import annotations

from datetime import datetime
from typing import Any

from redsentinel.adapters.engine.models import AgentTurnResult


class TraceRecorder:
    def __init__(self, session_id: str = "default") -> None:
        self.session_id = session_id
        self.turns: list[dict[str, Any]] = []

    def reset(self, session_id: str) -> None:
        self.session_id = session_id
        self.turns = []

    def record_turn(self, result: AgentTurnResult) -> None:
        payload = result.to_dict()
        payload["turn_index"] = len(self.turns)
        payload["ts"] = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        self.turns.append(payload)

    def export(self) -> dict[str, Any]:
        return {
            "schema_version": "agent-security-trajectory-v0.1",
            "session_id": self.session_id,
            "turns": list(self.turns),
        }
