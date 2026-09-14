"""sentinel-agent executor factory — plugin.yaml exclusive slot entry.

No box, no credential, no network: the Agent under test is a Python object in
this process. ``options.agent_kind`` picks which Sentinel Agent to put under
test.
"""

from __future__ import annotations

from typing import Any

from ageval.plugins.errors import ExtensionMaterializeError

from sentinel_agent_plugin.executor import (
    DEFAULT_AGENT_KIND,
    SentinelAgentExecutor,
    agent_kinds,
)


def resolve_agent_kind(raw: Any) -> str:
    if raw is None:
        return DEFAULT_AGENT_KIND
    if not isinstance(raw, str):
        raise ExtensionMaterializeError(
            f"sentinel_agent_kind_invalid:{raw!r}",
            kind="extension_materialize_failed",
        )
    value = raw.strip() or DEFAULT_AGENT_KIND
    known = agent_kinds()
    if value not in known:
        raise ExtensionMaterializeError(
            f"sentinel_agent_kind_unknown:{value} (want one of {', '.join(known)})",
            kind="extension_materialize_failed",
        )
    return value


def build_executor(
    *,
    options: dict[str, Any] | None = None,
    profile_id: str | None = None,
    model: str | None = None,
) -> SentinelAgentExecutor:
    opts = dict(options or {})
    agent_kind = resolve_agent_kind(opts.get("agent_kind"))
    return SentinelAgentExecutor(
        model=(model or "").strip() or f"sentinel/{agent_kind}-agent",
        agent_kind=agent_kind,
        session_prefix=f"ageval-{(profile_id or 'sentinel').strip() or 'sentinel'}",
    )


__all__ = ["build_executor", "resolve_agent_kind"]
