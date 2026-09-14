from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from redsentinel.core import (
    AgentProfile as AgentProfile,
    AgentProfileNode as AgentProfileNode,
    AgentProfileTool as AgentProfileTool,
)

Framework = Literal["python_function", "langgraph"]
NodeType = Literal["input_node", "rag_retriever", "tool_node", "memory_node", "llm_node", "output_node"]
RiskLevel = Literal["low", "medium", "high", "critical"]
AttackEntry = Literal["prompt", "rag_text"]
EvaluationIntensity = Literal["low", "medium", "high"]
DirectivePriority = Literal["low", "medium", "high", "critical"]
DirectiveSource = Literal["evaluation", "attack", "defense", "manual"]
DirectiveActionType = Literal["add_defense", "tune_defense", "generate_attack", "manual_review"]


class AgentMetadataContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    framework: Framework
    root_path: str = Field(min_length=1)
    entrypoint: str = Field(min_length=1)


class AgentNodeContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    type: NodeType
    target: str = Field(min_length=1)
    defenses: list[str] = Field(default_factory=list)

    @field_validator("defenses")
    @classmethod
    def defenses_must_be_unique(cls, defenses: list[str]) -> list[str]:
        if len(defenses) != len(set(defenses)):
            raise ValueError("node defenses must be unique")
        return defenses


class AgentToolContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    risk_level: RiskLevel
    allowed_roles: list[str] = Field(default_factory=list)
    side_effect: bool = False


class AgentBusinessContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain: str = Field(min_length=1)
    roles: list[str] = Field(default_factory=list)
    sensitive_data: list[str] = Field(default_factory=list)


class AgentRagContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    document_paths: list[str] = Field(default_factory=list)
    retriever_target: Optional[str] = None
    allow_test_injection: bool = False


class AgentEvaluationContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attack_entries: list[AttackEntry] = Field(default_factory=lambda: ["prompt"])
    intensity: EvaluationIntensity = "medium"


class AgentManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["agent-manifest-v1"] = "agent-manifest-v1"
    agent: AgentMetadataContract
    nodes: list[AgentNodeContract] = Field(min_length=1)
    tools: list[AgentToolContract] = Field(default_factory=list)
    business: AgentBusinessContract
    rag: AgentRagContract = Field(default_factory=AgentRagContract)
    evaluation: AgentEvaluationContract = Field(default_factory=AgentEvaluationContract)


class OptimizationAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: DirectiveActionType
    name: str = Field(min_length=1)
    mode: Optional[str] = None
    parameters: dict[str, Any] = Field(default_factory=dict)


class OptimizationDirective(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["optimization-directive-v1"] = "optimization-directive-v1"
    directive_id: str = Field(min_length=1)
    agent_name: str = Field(min_length=1)
    source: DirectiveSource
    target_node_id: str = Field(min_length=1)
    risk_type: str = Field(min_length=1)
    priority: DirectivePriority
    recommended_actions: list[OptimizationAction] = Field(min_length=1)
    rationale: str = Field(min_length=1)
    evidence_refs: list[str] = Field(default_factory=list)
