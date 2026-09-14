from __future__ import annotations

import json
from typing import Any, Callable

from redsentinel.runtime.engine.sandbox.tools import mock as mock_tools

ToolHandler = Callable[..., Any]


class ToolRegistry:
    def __init__(self, mode: str = "mock") -> None:
        self.mode = mode
        self._mock_handlers: dict[str, ToolHandler] = {}
        self._real_handlers: dict[str, ToolHandler] = {}
        self._schemas: dict[str, dict[str, Any]] = {}
        self.call_counts: dict[str, int] = {}

    def register_mock(self, name: str, handler: ToolHandler, schema: dict[str, Any]) -> None:
        self._mock_handlers[name] = handler
        self._schemas[name] = schema

    def register_real(self, name: str, handler: ToolHandler) -> None:
        self._real_handlers[name] = handler

    def register_defaults(self) -> None:
        self.register_mock("get_weather", mock_tools.get_weather, mock_tools.GET_WEATHER_SCHEMA)
        self.register_mock("search_news", mock_tools.search_news, mock_tools.SEARCH_NEWS_SCHEMA)

    def openai_tools_schema(self) -> list[dict[str, Any]]:
        return [
            {
                "type": "function",
                "function": {
                    "name": name,
                    "description": schema.get("description", name),
                    "parameters": schema["parameters"],
                },
            }
            for name, schema in self._schemas.items()
        ]

    def invoke(self, name: str, arguments: dict[str, Any]) -> Any:
        self.call_counts[name] = self.call_counts.get(name, 0) + 1
        if self.mode == "real" and name in self._real_handlers:
            handler = self._real_handlers[name]
        elif name in self._mock_handlers:
            handler = self._mock_handlers[name]
        else:
            raise KeyError(f"Tool not registered: {name}")
        return handler(**arguments)

    def parse_arguments(self, raw: str | dict[str, Any]) -> dict[str, Any]:
        if isinstance(raw, dict):
            return raw
        return json.loads(raw)
