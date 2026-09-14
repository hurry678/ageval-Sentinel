from __future__ import annotations

from pathlib import Path

import yaml

from redsentinel.core.agent_security import (
    AgentBusinessContract as BusinessProfile,
    AgentEvaluationContract as EvaluationScope,
    AgentManifest as AgentConfig,
    AgentMetadataContract as AgentMetadata,
    AgentNodeContract as NodeConfig,
    AgentRagContract as RagProfile,
    AgentToolContract as ToolConfig,
)


def load_agent_config(path: str | Path) -> AgentConfig:
    config_path = Path(path)
    payload = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        raise ValueError("Agent config must be a YAML mapping.")
    return AgentConfig.model_validate(payload)


__all__ = [
    "AgentConfig",
    "AgentMetadata",
    "BusinessProfile",
    "EvaluationScope",
    "NodeConfig",
    "RagProfile",
    "ToolConfig",
    "load_agent_config",
]
