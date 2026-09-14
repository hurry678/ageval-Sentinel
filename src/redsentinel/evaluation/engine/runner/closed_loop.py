from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from redsentinel.attacks.engine.attack_spec import load_scenario_manifest
from redsentinel.defenses.engine.security.goal_guard import GoalGuardInput, evaluate_goal_guard
from redsentinel.defenses.engine.security.memory_guard import MemoryGuardInput, evaluate_memory_guard
from redsentinel.defenses.engine.security.tool_guard import ToolGuardInput, evaluate_tool_guard
from redsentinel.evaluation.engine.detection import run_gdm_baseline, run_mis_baseline, run_trs_baseline
from redsentinel.evaluation.engine.detection.contracts import (
    DetectorInput,
    DetectorMetric,
    DetectorOutput,
    load_acceptance_fixture_manifest,
)
from redsentinel.evaluation.engine.runner.core import ExperimentRunner

ClosedLoopRiskType = Literal["memory_poisoning", "tool_tampering", "goal_perturbation"]


class ClosedLoopDefenseDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    guard: Literal["memory_guard", "tool_guard", "goal_guard"]
    allowed: bool
    decision: Literal["allow", "block"]
    risk_level: Literal["normal", "high"]
    reason: str = Field(min_length=1)
    attribution: list[dict[str, Any]] = Field(default_factory=list)
    audit_payload: dict[str, str]


class ClosedLoopAuditIntegrity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    valid: bool
    total_entries: int
    tampered_at: list[int]
    first_tampered: int | None
    details: list[str]


class ClosedLoopEvaluationRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pair_id: str = Field(min_length=1)
    risk_type: ClosedLoopRiskType
    metric: DetectorMetric
    clean_run_path: str = Field(min_length=1)
    controlled_run_path: str = Field(min_length=1)
    detector_output: DetectorOutput
    clean_defense_decision: ClosedLoopDefenseDecision
    controlled_defense_decision: ClosedLoopDefenseDecision
    audit_integrity: ClosedLoopAuditIntegrity
    passed: bool
    failure_notes: list[str] = Field(default_factory=list)


class ClosedLoopEvaluationReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["closed-loop-report-v0.1"] = "closed-loop-report-v0.1"
    records: list[ClosedLoopEvaluationRecord] = Field(min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)


def run_closed_loop_evaluation(
    scenario_manifest_path: str | Path,
    detector_acceptance_manifest_path: str | Path,
    *,
    repo_root: str | Path,
    results_root: str | Path,
) -> ClosedLoopEvaluationReport:
    root = Path(repo_root)
    evaluation_root = _evaluation_root(root)
    scenario_manifest_file = _resolve_path(scenario_manifest_path, root, evaluation_root)
    acceptance_manifest_file = _resolve_path(detector_acceptance_manifest_path, root, evaluation_root)
    results_root_path = Path(results_root)
    results_root_path.mkdir(parents=True, exist_ok=True)

    scenario_manifest = load_scenario_manifest(scenario_manifest_file)
    acceptance_manifest = load_acceptance_fixture_manifest(acceptance_manifest_file)
    runner = ExperimentRunner(results_root=results_root_path)

    records: list[ClosedLoopEvaluationRecord] = []
    for pair in scenario_manifest.records:
        metric = _metric_for_risk(pair.risk_type)
        fixture = next(
            (
                item
                for item in acceptance_manifest.records
                if item.scenario_pair_id == pair.pair_id and item.metric == metric
            ),
            None,
        )
        if fixture is None:
            raise ValueError(f"Acceptance fixture not found for pair {pair.pair_id} and metric {metric}.")

        clean_result = runner.run_scenario(_resolve_path(pair.clean_scenario, root, evaluation_root))
        controlled_result = runner.run_scenario(_resolve_path(pair.controlled_scenario, root, evaluation_root))
        controlled_trajectory_path = controlled_result.output_dir / "trajectory.json"

        detector_output = _run_detector(
            DetectorInput(
                metric=metric,
                scenario_pair_id=pair.pair_id,
                controlled_trajectory_path=str(controlled_trajectory_path),
                attack_spec_id=fixture.attack_spec_id,
            ),
            evaluation_root,
        )
        evidence = [item.model_dump(mode="json") for item in detector_output.attribution]

        clean_decision = _run_guard(pair.risk_type, clean_result.trajectory, [])
        controlled_decision = _run_guard(pair.risk_type, controlled_result.trajectory, evidence)
        _attach_defense_decision(clean_result.trajectory, clean_result.output_dir, clean_decision)
        _attach_defense_decision(controlled_result.trajectory, controlled_result.output_dir, controlled_decision)

        audit_log_path = controlled_result.output_dir / "defense-audit.log"
        audit_integrity = _write_defense_audit(audit_log_path, [clean_decision, controlled_decision])

        failure_notes = _failure_notes(
            pair_id=pair.pair_id,
            expected_decision=fixture.expected_decision,
            detector_output=detector_output,
            clean_decision=clean_decision,
            controlled_decision=controlled_decision,
            audit_integrity=audit_integrity,
        )

        records.append(
            ClosedLoopEvaluationRecord(
                pair_id=pair.pair_id,
                risk_type=pair.risk_type,
                metric=metric,
                clean_run_path=str(clean_result.output_dir),
                controlled_run_path=str(controlled_result.output_dir),
                detector_output=detector_output,
                clean_defense_decision=clean_decision,
                controlled_defense_decision=controlled_decision,
                audit_integrity=audit_integrity,
                passed=not failure_notes,
                failure_notes=failure_notes,
            )
        )

    report_path = results_root_path / "closed-loop-report-v0.1.json"
    report = ClosedLoopEvaluationReport(
        records=records,
        metadata={
            "scenario_manifest_path": str(scenario_manifest_file),
            "detector_acceptance_manifest_path": str(acceptance_manifest_file),
            "results_root": str(results_root_path),
            "report_path": str(report_path),
        },
    )
    report_path.write_text(
        json.dumps(report.model_dump(mode="json"), ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return report


def _evaluation_root(root: Path) -> Path:
    return root


def _resolve_path(path: str | Path, root: Path, evaluation_root: Path) -> Path:
    candidate = Path(path)
    if candidate.is_absolute():
        return candidate

    candidates = [root / candidate, evaluation_root / candidate]

    for item in candidates:
        if item.exists():
            return item
    return evaluation_root / candidate


def _metric_for_risk(risk_type: ClosedLoopRiskType) -> DetectorMetric:
    return {
        "memory_poisoning": "MIS",
        "tool_tampering": "TRS",
        "goal_perturbation": "GDM",
    }[risk_type]


def _run_detector(detector_input: DetectorInput, evaluation_root: Path) -> DetectorOutput:
    if detector_input.metric == "MIS":
        return run_mis_baseline(detector_input, root=evaluation_root)
    if detector_input.metric == "TRS":
        return run_trs_baseline(detector_input, root=evaluation_root)
    if detector_input.metric == "GDM":
        return run_gdm_baseline(detector_input, root=evaluation_root)
    raise ValueError(f"Unsupported detector metric: {detector_input.metric}")


def _run_guard(
    risk_type: ClosedLoopRiskType,
    trajectory: dict[str, Any],
    evidence: list[dict[str, Any]],
) -> ClosedLoopDefenseDecision:
    if risk_type == "memory_poisoning":
        decision = evaluate_memory_guard(
            MemoryGuardInput(
                namespace=_memory_namespace(trajectory),
                memory_key=_memory_key(trajectory),
                content=_trajectory_content(trajectory),
                evidence=evidence,
            )
        )
        return _defense_decision("memory_guard", asdict(decision))

    if risk_type == "tool_tampering":
        tool_name, arguments, response = _first_tool_call(trajectory)
        decision = evaluate_tool_guard(
            ToolGuardInput(
                tool_name=tool_name,
                arguments=arguments,
                response=response,
                evidence=evidence,
            )
        )
        return _defense_decision("tool_guard", asdict(decision))

    if risk_type == "goal_perturbation":
        original_goal = _original_goal(trajectory)
        decision = evaluate_goal_guard(
            GoalGuardInput(
                goal_id=str(trajectory.get("experiment_id") or "closed-loop-goal"),
                original_goal=original_goal,
                current_goal=_goal_text(trajectory),
                evidence=evidence,
            )
        )
        return _defense_decision("goal_guard", asdict(decision))

    raise ValueError(f"Unsupported risk type: {risk_type}")


def _defense_decision(guard: Literal["memory_guard", "tool_guard", "goal_guard"], payload: dict[str, Any]) -> ClosedLoopDefenseDecision:
    return ClosedLoopDefenseDecision(
        guard=guard,
        allowed=payload["allowed"],
        decision=payload["decision"],
        risk_level=payload["risk_level"],
        reason=payload["reason"],
        attribution=payload["attribution"],
        audit_payload=payload["audit_payload"],
    )


def _memory_namespace(trajectory: dict[str, Any]) -> str:
    for step in trajectory.get("steps", []):
        for op in step.get("memory_ops", []):
            namespace = op.get("namespace")
            if isinstance(namespace, str) and namespace:
                return namespace
    return str(trajectory.get("experiment_id") or "closed-loop-memory")


def _memory_key(trajectory: dict[str, Any]) -> str:
    for step in trajectory.get("steps", []):
        for op in step.get("memory_ops", []):
            key = op.get("key")
            if isinstance(key, str) and key:
                return key
    return "closed-loop-memory"


def _trajectory_content(trajectory: dict[str, Any]) -> str:
    final = None
    for step in reversed(trajectory.get("steps", [])):
        llm = step.get("llm")
        if isinstance(llm, dict) and llm.get("output_content"):
            final = llm["output_content"]
            break
    return str(final or trajectory.get("experiment_id") or "closed-loop-trajectory")


def _first_tool_call(trajectory: dict[str, Any]) -> tuple[str, dict[str, Any], Any]:
    for step in trajectory.get("steps", []):
        tool_call = step.get("tool_call")
        if isinstance(tool_call, dict):
            return (
                str(tool_call.get("name") or "unknown_tool"),
                dict(tool_call.get("arguments") or {}),
                tool_call.get("response"),
            )
    return "unknown_tool", {}, None


def _goal_text(trajectory: dict[str, Any]) -> str:
    goal = trajectory.get("goal")
    if isinstance(goal, dict) and isinstance(goal.get("text"), str):
        return goal["text"]
    return str(trajectory.get("experiment_id") or "closed-loop-goal")


def _original_goal(trajectory: dict[str, Any]) -> str:
    for injection in trajectory.get("metadata", {}).get("injections", []):
        metadata = injection.get("metadata")
        if isinstance(metadata, dict) and isinstance(metadata.get("original_goal"), str):
            return metadata["original_goal"]
    return _goal_text(trajectory)


def _attach_defense_decision(
    trajectory: dict[str, Any],
    output_dir: Path,
    decision: ClosedLoopDefenseDecision,
) -> None:
    metadata = trajectory.setdefault("metadata", {})
    decisions = metadata.setdefault("defense_decisions", [])
    decisions.append(decision.model_dump(mode="json"))
    (output_dir / "trajectory.json").write_text(
        json.dumps(trajectory, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def _write_defense_audit(
    audit_log_path: Path,
    decisions: list[ClosedLoopDefenseDecision],
) -> ClosedLoopAuditIntegrity:
    from redsentinel.defenses.engine.security import audit

    old_log_file = audit.LOG_FILE
    audit.LOG_FILE = str(audit_log_path)
    try:
        for decision in decisions:
            audit.write_audit_log(**decision.audit_payload)
        return ClosedLoopAuditIntegrity.model_validate(audit.verify_audit_integrity())
    finally:
        audit.LOG_FILE = old_log_file


def _failure_notes(
    *,
    pair_id: str,
    expected_decision: str,
    detector_output: DetectorOutput,
    clean_decision: ClosedLoopDefenseDecision,
    controlled_decision: ClosedLoopDefenseDecision,
    audit_integrity: ClosedLoopAuditIntegrity,
) -> list[str]:
    notes: list[str] = []
    if detector_output.decision != expected_decision:
        notes.append(f"{pair_id}: expected detector decision {expected_decision}, got {detector_output.decision}.")
    if not clean_decision.allowed:
        notes.append(f"{pair_id}: clean defense decision should allow.")
    if controlled_decision.allowed:
        notes.append(f"{pair_id}: controlled defense decision should block.")
    if not audit_integrity.valid:
        notes.append(f"{pair_id}: defense audit integrity failed.")
    return notes


__all__ = [
    "ClosedLoopAuditIntegrity",
    "ClosedLoopDefenseDecision",
    "ClosedLoopEvaluationRecord",
    "ClosedLoopEvaluationReport",
    "run_closed_loop_evaluation",
]
