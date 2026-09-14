from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field


class ReproducibilityConfig(BaseModel):
    seed: int = 42
    cache_llm_responses: bool = True


class AgentConfig(BaseModel):
    framework: Literal["direct_api", "langgraph", "docker"]
    goal: str
    system_prompt: str
    model: str = "gpt-4o-mini"
    framework_config: dict[str, Any] = Field(default_factory=dict)


class MemoryConfig(BaseModel):
    namespace: str
    layers: list[Literal["short_term", "long_term", "episodic"]] = Field(default_factory=list)


class ToolConfig(BaseModel):
    mode: Literal["mock", "real"] = "mock"


class RunnerConfig(BaseModel):
    max_steps: int = 5
    timeout_seconds: int = 300
    parallel: bool = False


class InjectionConfig(BaseModel):
    mode: Literal["none", "controlled", "observational"] = "none"
    kind: Literal["memory_poisoning", "tool_tampering", "goal_perturbation"] | None = None
    strategy: str | None = None
    intensity: Literal["light", "medium", "heavy"] = "light"
    target: str | None = None
    label: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScenarioConfig(BaseModel):
    experiment_id: str
    schema_version: str = "1.0"
    reproducibility: ReproducibilityConfig = Field(default_factory=ReproducibilityConfig)
    agent: AgentConfig
    memory: MemoryConfig | None = None
    tools: ToolConfig = Field(default_factory=ToolConfig)
    injection: InjectionConfig = Field(default_factory=InjectionConfig)
    runner: RunnerConfig = Field(default_factory=RunnerConfig)

    @classmethod
    def from_yaml(cls, path: str | Path) -> ScenarioConfig:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        return cls.model_validate(data)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[5]


def cassette_path(config: ScenarioConfig) -> Path:
    return (
        repo_root()
        / "tests"
        / "fixtures"
        / "cassettes"
        / config.agent.framework
        / config.experiment_id
        / f"seed_{config.reproducibility.seed}.yaml"
    )
