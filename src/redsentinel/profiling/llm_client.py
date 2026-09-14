from __future__ import annotations

import json
import os
import gzip
import urllib.error
import urllib.request
from typing import Any


class LLMClient:
    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        timeout: int = 60,
    ) -> None:
        self.api_key = api_key or os.getenv("REDSENTINEL_LLM_API_KEY")
        self.base_url = base_url or os.getenv("REDSENTINEL_LLM_BASE_URL")
        self.model = model or os.getenv("REDSENTINEL_LLM_MODEL")
        self.timeout = timeout
        if not self.api_key:
            raise ValueError("Missing REDSENTINEL_LLM_API_KEY")
        if not self.base_url:
            raise ValueError("Missing REDSENTINEL_LLM_BASE_URL")
        if not self.model:
            raise ValueError("Missing REDSENTINEL_LLM_MODEL")

    def complete_json(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        url = self.base_url.rstrip("/") + "/chat/completions"
        request = urllib.request.Request(
            url,
            data=json.dumps(
                {
                    "model": self.model,
                    "messages": messages,
                    "temperature": 0,
                    "response_format": {"type": "json_object"},
                }
            ).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "Accept-Encoding": "gzip",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read()
                if response.headers.get("Content-Encoding") == "gzip" or raw[:2] == b"\x1f\x8b":
                    raw = gzip.decompress(raw)
                payload = json.loads(raw.decode("utf-8"))
        except urllib.error.URLError as exc:
            raise ValueError(f"LLM request failed: {exc}") from exc

        content = payload["choices"][0]["message"]["content"]
        try:
            return json.loads(content)
        except json.JSONDecodeError as exc:
            raise ValueError(f"LLM did not return valid JSON: {exc}") from exc
