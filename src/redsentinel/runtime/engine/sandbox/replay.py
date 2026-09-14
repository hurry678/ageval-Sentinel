from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import yaml


class CassetteTurnMismatchError(Exception):
    """Raised when no cassette interaction matches the requested turn index."""


class CassetteStore:
    """Load OpenAI-style responses from VCR-compatible YAML cassettes."""

    def __init__(self, cassette_path: Path) -> None:
        self.cassette_path = cassette_path
        self._interactions: list[dict[str, Any]] = []
        if cassette_path.exists():
            data = yaml.safe_load(cassette_path.read_text(encoding="utf-8"))
            self._interactions = data.get("interactions", [])

    @property
    def exists(self) -> bool:
        return self.cassette_path.exists() and bool(self._interactions)

    def response_json_for_turn(self, turn_index: int) -> dict[str, Any]:
        for interaction in self._interactions:
            headers = interaction.get("request", {}).get("headers", {})
            recorded_turn = headers.get("X-ARL-Turn") or headers.get("x-arl-turn")
            if isinstance(recorded_turn, list):
                recorded_turn = recorded_turn[0]
            if str(recorded_turn) == str(turn_index):
                body = interaction["response"]["body"]
                raw = body["string"] if isinstance(body, dict) and "string" in body else body
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8")
                return json.loads(raw)
        raise CassetteTurnMismatchError(
            f"No cassette interaction for turn {turn_index} in {self.cassette_path}"
        )


def should_record_cassette() -> bool:
    return os.environ.get("VCR_RECORD") == "1"
