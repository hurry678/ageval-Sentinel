"""COMP2 · 三系统共享的 LLM 客户端。

设计目标：
1. **统一接入项目里的 API**：默认从项目防御侧 config 读取 ``LLM_API_BASE /
   LLM_API_KEY / LLM_MODEL``（即 ``.env`` 里的同一套配置）。攻击 / 评测 / 防御
   三个系统都通过本模块取用 LLM，用户后续只需改环境变量即可整体切换。
2. **离线可复现**：当未配置 ``LLM_API_KEY`` 时自动进入 *deterministic fallback*，
   用基于 seed 的确定性合成回复，保证核心 demo 无需 API key 也能离线复现
   （满足 ROADMAP 边界："如使用 LLM 规划，必须有 deterministic fallback"）。

调用方约定：``complete(system, user, seed=...)`` 返回纯文本。是否走真实 API 由
``client.offline`` 决定，调用方无需关心。
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass


def _load_project_llm_config() -> tuple[str, str, str]:
    """读取项目里现成的 LLM 配置（优先复用防御侧 config，回退到环境变量）。"""
    try:
        # 防御系统的 config 是项目里 LLM 配置的事实来源（与 .env 对齐）。
        from redsentinel.defenses.engine.config import (  # type: ignore
            LLM_API_BASE,
            LLM_API_KEY,
            LLM_MODEL,
        )

        return str(LLM_API_BASE), str(LLM_API_KEY), str(LLM_MODEL)
    except Exception:
        return (
            os.getenv("LLM_API_BASE", "https://api-inference.modelscope.cn/v1"),
            os.getenv("LLM_API_KEY", ""),
            os.getenv("LLM_MODEL", "Qwen/Qwen3.5-35B-A3B"),
        )


@dataclass(frozen=True)
class LLMConfig:
    api_base: str
    api_key: str
    model: str

    @classmethod
    def from_project(cls) -> "LLMConfig":
        api_base, api_key, model = _load_project_llm_config()
        return cls(api_base=api_base, api_key=api_key, model=model)

    @property
    def has_credentials(self) -> bool:
        return bool(self.api_key.strip())


class SharedLLMClient:
    """攻击 / 评测 / 防御共用的轻量 LLM 客户端。

    Args:
        config: 不传则从项目配置加载。
        force_offline: 强制离线（测试 / 复现用）。
    """

    def __init__(
        self,
        config: LLMConfig | None = None,
        *,
        force_offline: bool = False,
    ) -> None:
        self.config = config or LLMConfig.from_project()
        self._force_offline = force_offline
        self._client = None  # 懒加载 openai 客户端

    @property
    def offline(self) -> bool:
        return self._force_offline or not self.config.has_credentials

    @property
    def mode(self) -> str:
        return "deterministic-offline" if self.offline else "live-api"

    def complete(
        self,
        system: str,
        user: str,
        *,
        seed: int = 0,
        temperature: float = 0.0,
        max_tokens: int = 512,
    ) -> str:
        """返回一次补全的纯文本。离线时走确定性 fallback。"""
        if self.offline:
            return self._deterministic_response(system, user, seed)
        try:
            return self._live_complete(
                system, user, seed=seed, temperature=temperature, max_tokens=max_tokens
            )
        except Exception as exc:  # 真实 API 失败也要保证 demo 不崩 —— 回退确定性
            fallback = self._deterministic_response(system, user, seed)
            return f"{fallback}\n[llm-fallback: {type(exc).__name__}]"

    # -- live API --------------------------------------------------------
    def _live_complete(
        self,
        system: str,
        user: str,
        *,
        seed: int,
        temperature: float,
        max_tokens: int,
    ) -> str:
        if self._client is None:
            from openai import OpenAI  # 懒加载，离线环境无需安装

            self._client = OpenAI(
                base_url=self.config.api_base,
                api_key=self.config.api_key,
            )
        response = self._client.chat.completions.create(
            model=self.config.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=temperature,
            max_tokens=max_tokens,
            seed=seed,
        )
        return response.choices[0].message.content or ""

    # -- deterministic fallback -----------------------------------------
    @staticmethod
    def _deterministic_response(system: str, user: str, seed: int) -> str:
        """基于内容哈希的确定性合成回复（同输入同输出，离线可复现）。"""
        digest = hashlib.sha256(
            f"{seed}\x00{system}\x00{user}".encode("utf-8")
        ).hexdigest()
        return f"[deterministic:{digest[:16]}]"


__all__ = ["LLMConfig", "SharedLLMClient"]
