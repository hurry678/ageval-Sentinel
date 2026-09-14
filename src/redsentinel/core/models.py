from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Framework = Literal["python_function", "langgraph"]
NodeType = Literal["input_node", "rag_retriever", "tool_node", "memory_node", "llm_node", "output_node"]
RiskLevel = Literal["low", "medium", "high", "critical"]
AttackEntry = Literal["prompt", "rag_text"]
EvolutionStage = Literal[
    "initialized",
    "attack_generation",
    "execution",
    "evaluation",
    "attack_selection",
    "defense_generation",
    "defense_selection",
    "regression",
    "completed",
    "failed",
]
ExecutionMode = Literal["offline_fixture", "simulated_runtime", "real_runtime", "external_model"]
EvidenceKind = Literal["source", "trajectory", "report", "dataset", "config", "runtime", "other"]

_SECRET_KEY_PATTERN = re.compile(
    r"(api[_-]?key|authorization|password|secret|credential|"
    r"(?:access|auth|bearer|refresh|session)[_-]?token|^token$)",
    re.IGNORECASE,
)


class CoreModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EvidenceRef(CoreModel):
    """Reference to evidence without embedding the evidence payload itself."""

    schema_version: Literal["evidence-ref-v1"] = "evidence-ref-v1"
    ref: str = Field(min_length=1)
    kind: EvidenceKind = "other"
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    locator: dict[str, Any] = Field(default_factory=dict)
    description: str | None = None

    @classmethod
    def from_legacy_source(cls, value: Mapping[str, Any] | BaseModel) -> EvidenceRef:
        payload = value.model_dump(mode="json") if isinstance(value, BaseModel) else dict(value)
        return cls(
            ref=str(payload["file"]),
            kind="source",
            locator={"line_start": payload["line_start"], "line_end": payload["line_end"]},
            description=str(payload["reason"]),
        )


class AgentProfileNode(CoreModel):
    id: str = Field(min_length=1)
    type: NodeType
    target: str = Field(min_length=1)
    risk_surfaces: list[str] = Field(default_factory=list)
    defenses: list[str] = Field(default_factory=list)


class AgentProfileTool(CoreModel):
    name: str = Field(min_length=1)
    risk_level: RiskLevel
    allowed_roles: list[str] = Field(default_factory=list)
    side_effect: bool = False


class AgentProfile(CoreModel):
    """Canonical profile; its field set remains compatible with agent-profile-v1."""

    schema_version: Literal["agent-profile-v1"] = "agent-profile-v1"
    profile_id: str | None = Field(default=None, min_length=1)
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    agent_name: str = Field(min_length=1)
    framework: Framework
    root_path: str = Field(min_length=1)
    entrypoint: str = Field(min_length=1)
    business_domain: str = Field(min_length=1)
    nodes: list[AgentProfileNode] = Field(min_length=1)
    tools: list[AgentProfileTool] = Field(default_factory=list)
    attack_entries: list[AttackEntry] = Field(default_factory=list)
    sensitive_data: list[str] = Field(default_factory=list)
    rag_enabled: bool = False

    @model_validator(mode="after")
    def populate_stable_profile_id(self) -> AgentProfile:
        if self.profile_id:
            return self
        identity = self.model_dump(mode="json", exclude={"profile_id", "evidence_refs"})
        encoded = json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
        self.profile_id = f"profile_{hashlib.sha256(encoded.encode('utf-8')).hexdigest()[:16]}"
        return self

    @model_validator(mode="after")
    def node_ids_must_be_unique(self) -> AgentProfile:
        node_ids = [node.id for node in self.nodes]
        if len(node_ids) != len(set(node_ids)):
            raise ValueError("agent profile node ids must be unique")
        return self


class AttackCandidate(CoreModel):
    schema_version: Literal["attack-candidate-v1"] = "attack-candidate-v1"
    candidate_id: str = Field(min_length=1)
    source: str = Field(min_length=1)
    risk_type: str = Field(min_length=1)
    strategy: str = Field(min_length=1)
    intensity: str = Field(min_length=1)
    target: str = Field(min_length=1)
    goal: str = Field(min_length=1)
    success_criteria: list[str] = Field(min_length=1)
    parent_ids: list[str] = Field(default_factory=list)
    mutation_history: list[str] = Field(default_factory=list)
    estimated_cost: float = Field(default=0.0, ge=0.0)
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_attack_spec(cls, value: Mapping[str, Any] | BaseModel) -> AttackCandidate:
        payload = value.model_dump(mode="json") if isinstance(value, BaseModel) else dict(value)
        metadata = dict(payload.get("metadata", {}))
        if payload.get("label"):
            metadata.setdefault("legacy_label", payload["label"])
        return cls(
            candidate_id=str(payload["attack_id"]),
            source="legacy_attack_spec",
            risk_type=str(payload["risk_type"]),
            strategy=str(payload["strategy"]),
            intensity=str(payload["intensity"]),
            target=str(payload["target"]),
            goal=str(payload["goal"]),
            success_criteria=list(payload["success_criteria"]),
            metadata=metadata,
        )


class DefenseCandidate(CoreModel):
    schema_version: Literal["defense-candidate-v1"] = "defense-candidate-v1"
    candidate_id: str = Field(min_length=1)
    agent_name: str = Field(min_length=1)
    target_node_ids: list[str] = Field(min_length=1)
    actions: list[dict[str, Any]] = Field(min_length=1)
    utility_constraints: dict[str, float] = Field(default_factory=dict)
    estimated_cost: float = Field(default=0.0, ge=0.0)
    parent_ids: list[str] = Field(default_factory=list)
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("utility_constraints")
    @classmethod
    def utility_constraints_must_be_rates(cls, values: dict[str, float]) -> dict[str, float]:
        if any(value < 0.0 or value > 1.0 for value in values.values()):
            raise ValueError("utility constraints must be rates in [0, 1]")
        return values


class TrajectoryStep(CoreModel):
    step_index: int = Field(ge=0)
    step_type: Literal["llm_inference", "tool_call", "monitor_decision"]
    timestamp: datetime
    llm: dict[str, Any] | None = None
    tool_call: dict[str, Any] | None = None
    monitor_decision: dict[str, Any] | None = None
    memory_ops: list[dict[str, Any]] = Field(default_factory=list)
    state_delta: dict[str, Any] | None = None

    @model_validator(mode="after")
    def require_matching_payload(self) -> TrajectoryStep:
        payloads = {
            "llm_inference": self.llm,
            "tool_call": self.tool_call,
            "monitor_decision": self.monitor_decision,
        }
        if payloads[self.step_type] is None:
            raise ValueError(f"{self.step_type} requires its matching payload")
        if any(payload is not None for name, payload in payloads.items() if name != self.step_type):
            raise ValueError("trajectory step may contain only its matching payload")
        return self


class Trajectory(CoreModel):
    schema_version: Literal["1.0"] = "1.0"
    session_id: str = Field(min_length=1)
    experiment_id: str = Field(min_length=1)
    seed: int
    framework: Literal["langgraph", "direct_api", "docker"]
    goal: dict[str, Any] | None = None
    injection_mode: Literal["none", "controlled", "observational"] = "none"
    steps: list[TrajectoryStep] = Field(default_factory=list)
    snapshots: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("steps")
    @classmethod
    def step_indexes_must_be_contiguous(cls, steps: list[TrajectoryStep]) -> list[TrajectoryStep]:
        if [step.step_index for step in steps] != list(range(len(steps))):
            raise ValueError("trajectory step indexes must be contiguous and start at zero")
        return steps


class EvaluationCaseResult(CoreModel):
    case_id: str = Field(min_length=1)
    case_type: Literal["attack", "clean"]
    target_node: str = Field(min_length=1)
    expected_decision: Literal["allow", "block"]
    actual_decision: Literal["allow", "block"]
    passed: bool
    blocked_node: str | None = None
    bypassed_nodes: list[str] = Field(default_factory=list)
    trajectory_ref: str | None = None
    failure_kind: Literal["business", "environment", "runtime", "none"] = "none"


class EvaluationResult(CoreModel):
    schema_version: Literal["evaluation-result-v1"] = "evaluation-result-v1"
    result_id: str = Field(min_length=1)
    experiment_id: str = Field(min_length=1)
    agent_profile_ref: str = Field(min_length=1)
    cases: list[EvaluationCaseResult] = Field(default_factory=list)
    metrics: dict[str, float] = Field(default_factory=dict)
    attribution: dict[str, Any] = Field(default_factory=dict)
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    failure_reason: str | None = None

    @field_validator("metrics")
    @classmethod
    def metrics_must_be_finite(cls, metrics: dict[str, float]) -> dict[str, float]:
        if any(value != value or value in {float("inf"), float("-inf")} for value in metrics.values()):
            raise ValueError("evaluation metrics must be finite")
        return metrics


class EvolutionState(CoreModel):
    schema_version: Literal["evolution-state-v1"] = "evolution-state-v1"
    experiment_id: str = Field(min_length=1)
    round_index: int = Field(default=0, ge=0)
    stage: EvolutionStage = "initialized"
    attack_population: list[AttackCandidate] = Field(default_factory=list)
    defense_population: list[DefenseCandidate] = Field(default_factory=list)
    selected_attack_ids: list[str] = Field(default_factory=list)
    selected_defense_ids: list[str] = Field(default_factory=list)
    evaluation_refs: list[str] = Field(default_factory=list)
    budget_spent: float = Field(default=0.0, ge=0.0)
    stop_reason: str | None = None

    @model_validator(mode="after")
    def completed_state_requires_reason(self) -> EvolutionState:
        if self.stage in {"completed", "failed"} and not self.stop_reason:
            raise ValueError("terminal evolution states require stop_reason")
        return self


class Provenance(CoreModel):
    schema_version: Literal["provenance-v1"] = "provenance-v1"
    git_commit: str = Field(min_length=1)
    git_dirty: bool
    python_version: str = Field(min_length=1)
    dependency_versions: dict[str, str] = Field(default_factory=dict)
    config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    dataset_sha256: dict[str, str] = Field(default_factory=dict)
    execution_mode: ExecutionMode
    external_model: dict[str, Any] | None = None
    captured_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("dataset_sha256")
    @classmethod
    def dataset_hashes_must_be_sha256(cls, values: dict[str, str]) -> dict[str, str]:
        if any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in values.values()):
            raise ValueError("dataset hashes must be lowercase SHA-256 values")
        return values

    @model_validator(mode="after")
    def provenance_must_not_contain_secrets(self) -> Provenance:
        if self.external_model and _contains_secret_key(self.external_model):
            raise ValueError("provenance must not contain credentials or secrets")
        return self


class ExperimentManifest(CoreModel):
    schema_version: Literal["experiment-manifest-v1"] = "experiment-manifest-v1"
    experiment_id: str = Field(min_length=1)
    research_question: str = Field(min_length=1)
    agent_profile_ref: str = Field(min_length=1)
    dataset_refs: list[str] = Field(min_length=1)
    attack_strategy: dict[str, Any]
    defense_strategy: dict[str, Any]
    metric_names: list[str] = Field(min_length=1)
    seeds: list[int] = Field(min_length=1)
    repetitions: int = Field(default=1, ge=1)
    budget: dict[str, float] = Field(default_factory=dict)
    execution_mode: ExecutionMode
    provenance: Provenance | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("seeds")
    @classmethod
    def seeds_must_be_unique(cls, seeds: list[int]) -> list[int]:
        if len(seeds) != len(set(seeds)):
            raise ValueError("experiment seeds must be unique")
        return seeds

    @field_validator("budget")
    @classmethod
    def budget_values_must_be_non_negative(cls, budget: dict[str, float]) -> dict[str, float]:
        if any(value < 0 for value in budget.values()):
            raise ValueError("experiment budget values must be non-negative")
        return budget


def _contains_secret_key(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(_SECRET_KEY_PATTERN.search(str(key)) or _contains_secret_key(item) for key, item in value.items())
    if isinstance(value, list):
        return any(_contains_secret_key(item) for item in value)
    return False
