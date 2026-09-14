from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from redsentinel.profiling.builder import RISK_SURFACES_BY_NODE_TYPE

ALLOWED_NODE_TYPES = set(RISK_SURFACES_BY_NODE_TYPE)
ALLOWED_RISK_SURFACES = {risk for risks in RISK_SURFACES_BY_NODE_TYPE.values() for risk in risks}
ALLOWED_RISK_LEVELS = {"low", "medium", "high", "critical"}


class EvidenceRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file: str = Field(min_length=1)
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    reason: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_line_range(self) -> "EvidenceRef":
        if self.line_end < self.line_start:
            raise ValueError("line_end must be >= line_start")
        return self


class CandidateNode(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    type: str = Field(min_length=1)
    target: str = Field(min_length=1)
    risk_surfaces: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[EvidenceRef] = Field(min_length=1)

    @field_validator("type")
    @classmethod
    def validate_node_type(cls, value: str) -> str:
        if value not in ALLOWED_NODE_TYPES:
            raise ValueError(f"unknown node type: {value}")
        return value

    @field_validator("risk_surfaces")
    @classmethod
    def validate_risk_surfaces(cls, value: list[str]) -> list[str]:
        unknown = [item for item in value if item not in ALLOWED_RISK_SURFACES]
        if unknown:
            raise ValueError(f"unknown risk surfaces: {unknown}")
        return value


class CandidateTool(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    risk_level: str = "medium"
    side_effect: bool = False
    permissions: list[str] = Field(default_factory=list)
    evidence: list[EvidenceRef] = Field(min_length=1)

    @field_validator("risk_level")
    @classmethod
    def validate_risk_level(cls, value: str) -> str:
        if value not in ALLOWED_RISK_LEVELS:
            raise ValueError(f"unknown risk level: {value}")
        return value


class CandidateRag(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool
    retriever_nodes: list[str] = Field(default_factory=list)
    knowledge_sources: list[str] = Field(default_factory=list)
    risk_surfaces: list[str] = Field(default_factory=list)
    evidence: list[EvidenceRef] = Field(default_factory=list)

    @field_validator("risk_surfaces")
    @classmethod
    def validate_risk_surfaces(cls, value: list[str]) -> list[str]:
        unknown = [item for item in value if item not in ALLOWED_RISK_SURFACES]
        if unknown:
            raise ValueError(f"unknown risk surfaces: {unknown}")
        return value

    @model_validator(mode="after")
    def require_evidence_if_enabled(self) -> "CandidateRag":
        if self.enabled and not self.evidence:
            raise ValueError("enabled RAG candidate must include evidence")
        return self


class CandidateMemory(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool
    memory_nodes: list[str] = Field(default_factory=list)
    persistence: Literal["none", "session", "long_term", "unknown"] = "unknown"
    risk_surfaces: list[str] = Field(default_factory=list)
    evidence: list[EvidenceRef] = Field(default_factory=list)

    @field_validator("risk_surfaces")
    @classmethod
    def validate_risk_surfaces(cls, value: list[str]) -> list[str]:
        unknown = [item for item in value if item not in ALLOWED_RISK_SURFACES]
        if unknown:
            raise ValueError(f"unknown risk surfaces: {unknown}")
        return value

    @model_validator(mode="after")
    def require_evidence_if_enabled(self) -> "CandidateMemory":
        if self.enabled and not self.evidence:
            raise ValueError("enabled memory candidate must include evidence")
        return self


class CandidateProfilePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    nodes: list[CandidateNode] = Field(default_factory=list)
    tools: list[CandidateTool] = Field(default_factory=list)
    rag: CandidateRag | None = None
    memory: CandidateMemory | None = None
    warnings: list[str] = Field(default_factory=list)
