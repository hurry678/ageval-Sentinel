from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from redsentinel.adapters.engine.models import AgentTurnResult, ToolSpec


class AgentAdapter(ABC):
    @abstractmethod
    def send_message(self, user_id: str, message: str, context: dict[str, Any]) -> AgentTurnResult:
        raise NotImplementedError

    @abstractmethod
    def list_tools(self) -> list[ToolSpec]:
        raise NotImplementedError

    @abstractmethod
    def export_trajectory(self) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def reset_session(self, session_id: str) -> None:
        raise NotImplementedError
