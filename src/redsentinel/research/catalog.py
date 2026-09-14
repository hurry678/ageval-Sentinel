"""Validated, read-only catalog for the RQ1-RQ5 experiment matrix."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator

from redsentinel.core.models import ExecutionMode

ResearchQuestionId = Literal["RQ1", "RQ2", "RQ3", "RQ4", "RQ5"]
BaselineName = Literal["fixed", "attack_only", "defense_only", "coevolution"]
DiagnosticControlName = Literal["random_mutation", "no_evidence_feedback"]
ExperimentTierName = Literal["smoke", "formal"]
AgentKind = Literal["offline_fixture", "open_source_real"]
DatasetSplit = Literal["development", "holdout"]
PilotSlotStatus = Literal["frozen", "pending_w3", "pending_w4"]

DEFAULT_RQ_MATRIX_PATH = Path(__file__).resolve().parents[3] / "configs" / "experiments" / "rq-matrix-v1.yaml"


class RQConfigurationError(ValueError):
    """Raised when an RQ matrix is missing, malformed, or internally inconsistent."""


class _CatalogModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class VariableSpec(_CatalogModel):
    name: str = Field(min_length=1)
    description: str = Field(min_length=1)
    levels: list[str] = Field(default_factory=list)


class ExitCondition(_CatalogModel):
    metric: str = Field(min_length=1)
    operator: Literal["<", "<=", "==", ">=", ">"]
    threshold: float
    minimum_repetitions: int = Field(default=1, ge=1)
    rationale: str = Field(min_length=1)


class CostCap(_CatalogModel):
    max_cases: int = Field(ge=1)
    max_rounds: int = Field(ge=1)
    max_model_calls: int = Field(ge=0)
    max_wall_clock_minutes: int = Field(ge=1)
    max_estimated_usd: float = Field(ge=0.0)


class ExperimentTier(_CatalogModel):
    name: ExperimentTierName
    agent_ids: list[str] = Field(min_length=1)
    dataset_refs: list[str] = Field(min_length=1)
    adaptation_split: DatasetSplit
    evaluation_split: DatasetSplit
    seeds: list[int] = Field(min_length=1)
    repetitions: int = Field(ge=1)
    cost_cap: CostCap
    environment_policy: Literal["required", "skip_with_reason"]

    @model_validator(mode="after")
    def seeds_are_unique(self) -> ExperimentTier:
        if len(self.seeds) != len(set(self.seeds)):
            raise ValueError("experiment tier seeds must be unique")
        return self


class AgentTarget(_CatalogModel):
    agent_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    kind: AgentKind
    profile_ref: str = Field(min_length=1)
    runtime_adapter: str = Field(min_length=1)
    execution_mode: ExecutionMode
    pinned_version: str = Field(min_length=1)
    source_url: HttpUrl | None = None
    environment_requirements: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def real_agent_has_reproducibility_metadata(self) -> AgentTarget:
        if self.kind == "open_source_real":
            if self.source_url is None:
                raise ValueError("open-source real agents require source_url")
            if self.execution_mode != "real_runtime":
                raise ValueError("open-source real agents must use real_runtime")
            if not self.environment_requirements:
                raise ValueError("open-source real agents require explicit environment requirements")
        elif self.execution_mode != "offline_fixture":
            raise ValueError("offline fixtures must use offline_fixture execution mode")
        return self


class PilotAgentSlot(_CatalogModel):
    slot_id: Literal["agent_a", "agent_b"]
    status: PilotSlotStatus
    agent_id: str | None = None
    selection_gate: str = Field(min_length=1)

    @model_validator(mode="after")
    def frozen_slot_has_agent(self) -> PilotAgentSlot:
        if self.status == "frozen" and not self.agent_id:
            raise ValueError("frozen pilot Agent slots require agent_id")
        if self.status != "frozen" and self.agent_id is not None:
            raise ValueError("pending pilot Agent slots cannot claim an agent_id")
        return self


class PilotModelSlot(_CatalogModel):
    slot_id: Literal["model_a", "model_b"]
    status: Literal["frozen", "pending_w4"]
    family_id: str | None = None
    exact_model_id: str | None = None
    selection_gate: str = Field(min_length=1)

    @model_validator(mode="after")
    def frozen_slot_has_model(self) -> PilotModelSlot:
        identifiers = (self.family_id, self.exact_model_id)
        if self.status == "frozen" and not all(identifiers):
            raise ValueError("frozen pilot model slots require family_id and exact_model_id")
        if self.status != "frozen" and any(identifier is not None for identifier in identifiers):
            raise ValueError("pending pilot model slots cannot claim model identifiers")
        return self


class PilotBudget(_CatalogModel):
    max_cells: int = Field(ge=1)
    max_rounds_per_cell: int = Field(ge=1)
    max_model_calls: int = Field(ge=1)
    max_wall_clock_minutes: int = Field(ge=1)
    max_estimated_usd: float = Field(gt=0.0)
    pause_at_budget_fraction: float = Field(gt=0.0, lt=1.0)
    max_environment_failure_rate: float = Field(ge=0.0, le=1.0)
    max_evaluator_unresolved_rate: float = Field(ge=0.0, le=1.0)


class PilotDesign(_CatalogModel):
    pilot_id: str = Field(min_length=1)
    protocol_ref: str = Field(min_length=1)
    split_ref: str = Field(min_length=1)
    agent_slots: list[PilotAgentSlot] = Field(min_length=2, max_length=2)
    model_slots: list[PilotModelSlot] = Field(min_length=2, max_length=2)
    core_arms: list[BaselineName] = Field(min_length=4, max_length=4)
    diagnostic_controls: list[DiagnosticControlName] = Field(min_length=2, max_length=2)
    seeds: list[int] = Field(min_length=3, max_length=3)
    budget: PilotBudget

    @model_validator(mode="after")
    def validate_pilot_axes(self) -> PilotDesign:
        if {slot.slot_id for slot in self.agent_slots} != {"agent_a", "agent_b"}:
            raise ValueError("pilot requires agent_a and agent_b slots")
        if {slot.slot_id for slot in self.model_slots} != {"model_a", "model_b"}:
            raise ValueError("pilot requires model_a and model_b slots")
        if set(self.core_arms) != {"fixed", "attack_only", "defense_only", "coevolution"}:
            raise ValueError("pilot requires all four core arms")
        if set(self.diagnostic_controls) != {"random_mutation", "no_evidence_feedback"}:
            raise ValueError("pilot requires both diagnostic controls")
        if len(self.seeds) != len(set(self.seeds)):
            raise ValueError("pilot seeds must be unique")
        expected_cells = (
            len(self.agent_slots)
            * len(self.model_slots)
            * (len(self.core_arms) + len(self.diagnostic_controls))
            * len(self.seeds)
        )
        if self.budget.max_cells != expected_cells:
            raise ValueError(f"pilot max_cells must equal the declared matrix size ({expected_cells})")
        return self


class ResearchQuestion(_CatalogModel):
    rq_id: ResearchQuestionId
    title: str = Field(min_length=1)
    hypothesis: str = Field(min_length=1)
    independent_variables: list[VariableSpec] = Field(min_length=1)
    dependent_variables: list[VariableSpec] = Field(min_length=1)
    control_variables: list[str] = Field(min_length=1)
    baselines: list[BaselineName] = Field(min_length=1)
    metrics: list[str] = Field(min_length=1)
    exit_conditions: list[ExitCondition] = Field(min_length=1)
    tiers: list[ExperimentTier] = Field(min_length=2, max_length=2)

    @model_validator(mode="after")
    def validate_research_design(self) -> ResearchQuestion:
        if {tier.name for tier in self.tiers} != {"smoke", "formal"}:
            raise ValueError(f"{self.rq_id} must define exactly smoke and formal tiers")
        if len(self.baselines) != len(set(self.baselines)):
            raise ValueError(f"{self.rq_id} baseline names must be unique")
        if len(self.metrics) != len(set(self.metrics)):
            raise ValueError(f"{self.rq_id} metric names must be unique")
        names = [
            variable.name
            for variable in [*self.independent_variables, *self.dependent_variables]
        ]
        if len(names) != len(set(names)):
            raise ValueError(f"{self.rq_id} variable names must be unique")
        return self


class RQExperimentMatrix(_CatalogModel):
    schema_version: Literal["rq-experiment-matrix-v1"]
    matrix_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    agents: list[AgentTarget] = Field(min_length=2)
    p1_pilot: PilotDesign
    research_questions: list[ResearchQuestion] = Field(min_length=5, max_length=5)

    @model_validator(mode="after")
    def validate_complete_matrix(self) -> RQExperimentMatrix:
        agent_ids = [agent.agent_id for agent in self.agents]
        if len(agent_ids) != len(set(agent_ids)):
            raise ValueError("agent ids must be unique")
        kinds = {agent.kind for agent in self.agents}
        if not {"offline_fixture", "open_source_real"} <= kinds:
            raise ValueError("matrix requires an offline fixture and an open-source real agent")

        rq_ids = [question.rq_id for question in self.research_questions]
        if set(rq_ids) != {"RQ1", "RQ2", "RQ3", "RQ4", "RQ5"} or len(rq_ids) != 5:
            raise ValueError("matrix must define RQ1 through RQ5 exactly once")

        known_agents = set(agent_ids)
        real_agents = {agent.agent_id for agent in self.agents if agent.kind == "open_source_real"}
        offline_agents = {agent.agent_id for agent in self.agents if agent.kind == "offline_fixture"}
        frozen_pilot_agents = {
            slot.agent_id for slot in self.p1_pilot.agent_slots if slot.status == "frozen"
        }
        unknown_pilot_agents = frozen_pilot_agents - known_agents
        if unknown_pilot_agents:
            raise ValueError(f"pilot references unknown frozen agents: {sorted(unknown_pilot_agents)}")
        for question in self.research_questions:
            for tier in question.tiers:
                unknown = set(tier.agent_ids) - known_agents
                if unknown:
                    raise ValueError(f"{question.rq_id}/{tier.name} references unknown agents: {sorted(unknown)}")
                if tier.name == "smoke" and not set(tier.agent_ids) & offline_agents:
                    raise ValueError(f"{question.rq_id} smoke tier requires an offline fixture")
                if tier.name == "formal" and not set(tier.agent_ids) & real_agents:
                    raise ValueError(f"{question.rq_id} formal tier requires an open-source real agent")
        return self


def load_rq_experiment_matrix(path: str | Path = DEFAULT_RQ_MATRIX_PATH) -> RQExperimentMatrix:
    """Load and strictly validate the research matrix without executing experiments."""
    config_path = Path(path)
    try:
        payload = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("matrix root must be an object")
        return RQExperimentMatrix.model_validate(payload)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise RQConfigurationError(f"invalid RQ experiment matrix {config_path}: {exc}") from exc


def list_rq_experiment_matrix(
    *,
    rq_id: ResearchQuestionId | None = None,
    path: str | Path = DEFAULT_RQ_MATRIX_PATH,
) -> dict:
    """Return a JSON-compatible matrix or one RQ; this function has no execution side effects."""
    matrix = load_rq_experiment_matrix(path)
    if rq_id is None:
        return matrix.model_dump(mode="json")
    for question in matrix.research_questions:
        if question.rq_id == rq_id:
            return {
                "schema_version": matrix.schema_version,
                "matrix_id": matrix.matrix_id,
                "agents": [agent.model_dump(mode="json") for agent in matrix.agents],
                "research_question": question.model_dump(mode="json"),
            }
    raise RQConfigurationError(f"research question not found: {rq_id}")


def main(argv: list[str] | None = None) -> int:
    """Dedicated read-only catalog command; the unified Task 19 CLI is intentionally separate."""
    parser = argparse.ArgumentParser(description="List the validated RedSentinel RQ experiment matrix.")
    parser.add_argument("command", choices=["list"])
    parser.add_argument("--rq", choices=["RQ1", "RQ2", "RQ3", "RQ4", "RQ5"])
    parser.add_argument("--config", type=Path, default=DEFAULT_RQ_MATRIX_PATH)
    parser.add_argument("--format", choices=["json", "yaml"], default="json")
    args = parser.parse_args(argv)

    payload = list_rq_experiment_matrix(rq_id=args.rq, path=args.config)
    if args.format == "yaml":
        print(yaml.safe_dump(payload, allow_unicode=True, sort_keys=False).rstrip())
    else:
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "AgentTarget",
    "CostCap",
    "DEFAULT_RQ_MATRIX_PATH",
    "PilotAgentSlot",
    "PilotBudget",
    "PilotDesign",
    "PilotModelSlot",
    "ExperimentTier",
    "ExitCondition",
    "RQConfigurationError",
    "RQExperimentMatrix",
    "ResearchQuestion",
    "VariableSpec",
    "list_rq_experiment_matrix",
    "load_rq_experiment_matrix",
    "main",
]
