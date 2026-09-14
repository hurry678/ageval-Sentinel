from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class ToolSpec:
    name: str
    risk_level: str
    description: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AgentTurnResult:
    user_id: str
    message: str
    answer: str
    blocked: bool
    risk_level: str
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    business_events: list[dict[str, Any]] = field(default_factory=list)
    audit_events: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
