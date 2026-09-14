from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from redsentinel.core.agent_security import OptimizationDirective
from redsentinel.evaluation.engine.optimizer import OptimizerHubResult
from redsentinel.application.contracts import AgentSecurityReport


FeedbackConsumer = Literal["attack_self_evolution", "defense_self_optimization", "security_dashboard"]


class AttackFeedback(BaseModel):
    model_config = ConfigDict(extra="forbid")

    consumer: Literal["attack_self_evolution"] = "attack_self_evolution"
    report: AgentSecurityReport
    directives: list[OptimizationDirective] = Field(default_factory=list)
    failed_attempt_refs: list[str] = Field(default_factory=list)


class DefenseFeedback(BaseModel):
    model_config = ConfigDict(extra="forbid")

    consumer: Literal["defense_self_optimization"] = "defense_self_optimization"
    report: AgentSecurityReport
    directives: list[OptimizationDirective] = Field(default_factory=list)
    defense_plan_inputs: list[dict[str, Any]] = Field(default_factory=list)


class DashboardFeedback(BaseModel):
    model_config = ConfigDict(extra="forbid")

    consumer: Literal["security_dashboard"] = "security_dashboard"
    overview: dict[str, Any]
    finding_rows: list[dict[str, Any]] = Field(default_factory=list)
    scenario_rows: list[dict[str, Any]] = Field(default_factory=list)
    node_attribution_rows: list[dict[str, Any]] = Field(default_factory=list)


class FeedbackRoute(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["feedback-route-v0.1"] = "feedback-route-v0.1"
    report: AgentSecurityReport
    attack: AttackFeedback
    defense: DefenseFeedback
    dashboard: DashboardFeedback


class FeedbackArtifactPaths(BaseModel):
    model_config = ConfigDict(extra="forbid")

    route_path: str = Field(min_length=1)
    attack_path: str = Field(min_length=1)
    defense_path: str = Field(min_length=1)
    dashboard_path: str = Field(min_length=1)


def route_optimizer_feedback(result: OptimizerHubResult) -> FeedbackRoute:
    report = result.agent_security_report
    attack = AttackFeedback(
        report=report,
        directives=sorted(result.attack_directives, key=lambda item: item.directive_id),
        failed_attempt_refs=_failed_attempt_refs(report),
    )
    defense = DefenseFeedback(
        report=report,
        directives=sorted(result.defense_directives, key=lambda item: item.directive_id),
        defense_plan_inputs=_defense_plan_inputs(result),
    )
    dashboard = DashboardFeedback(
        overview=_overview(report),
        finding_rows=_finding_rows(report),
        scenario_rows=_scenario_rows(report),
        node_attribution_rows=_node_attribution_rows(result),
    )
    return FeedbackRoute(
        report=report,
        attack=attack,
        defense=defense,
        dashboard=dashboard,
    )


def write_feedback_artifacts(route: FeedbackRoute, output_dir: str | Path) -> FeedbackArtifactPaths:
    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)

    route_path = root / "feedback-route-v0.1.json"
    attack_path = root / "attack-feedback-v0.1.json"
    defense_path = root / "defense-feedback-v0.1.json"
    dashboard_path = root / "dashboard-feedback-v0.1.json"

    _write_json(route_path, route.model_dump(mode="json"))
    _write_json(attack_path, route.attack.model_dump(mode="json"))
    _write_json(defense_path, route.defense.model_dump(mode="json"))
    _write_json(dashboard_path, route.dashboard.model_dump(mode="json"))

    return FeedbackArtifactPaths(
        route_path=str(route_path),
        attack_path=str(attack_path),
        defense_path=str(defense_path),
        dashboard_path=str(dashboard_path),
    )


def _overview(report: AgentSecurityReport) -> dict[str, Any]:
    return {
        "agent_id": report.agent_id,
        "tenant_id": report.tenant_id,
        "benchmark": report.benchmark,
        "overall_score": report.overall_score,
        "risk_level": report.risk_level,
        "attack_success_rate": report.attack_success_rate,
        "false_positive_rate": report.false_positive_rate,
    }


def _finding_rows(report: AgentSecurityReport) -> list[dict[str, Any]]:
    return [
        {
            "finding_id": item.finding_id,
            "scenario_id": item.scenario_id,
            "severity": item.severity,
            "title": item.title,
            "business_impact": item.business_impact,
            "recommendation": item.recommendation,
        }
        for item in sorted(report.findings, key=lambda finding: finding.finding_id)
    ]


def _scenario_rows(report: AgentSecurityReport) -> list[dict[str, Any]]:
    return [
        {
            "scenario_id": item.scenario_id,
            "category": item.category,
            "severity": item.severity,
            "expected_decision": item.expected_decision,
            "actual_decision": item.actual_decision,
            "clean_decision": item.clean_decision,
            "passed": item.passed,
            "trajectory_ref": item.trajectory_ref,
        }
        for item in sorted(report.scenario_results, key=lambda scenario: scenario.scenario_id)
    ]


def _node_attribution_rows(result: OptimizerHubResult) -> list[dict[str, Any]]:
    return [
        item.model_dump(mode="json")
        for item in sorted(result.node_attributions, key=lambda attribution: attribution.pair_id)
    ]


def _defense_plan_inputs(result: OptimizerHubResult) -> list[dict[str, Any]]:
    directive_by_node = {
        directive.target_node_id: directive
        for directive in result.defense_directives
    }
    rows: list[dict[str, Any]] = []
    for attribution in sorted(result.node_attributions, key=lambda item: item.pair_id):
        directive = directive_by_node.get(attribution.node_id)
        rows.append(
            {
                "node_id": attribution.node_id,
                "node_type": attribution.node_type,
                "risk_type": attribution.risk_type,
                "directive_id": directive.directive_id if directive else None,
                "priority": directive.priority if directive else None,
                "evidence_refs": list(attribution.evidence_refs),
            }
        )
    return rows


def _failed_attempt_refs(report: AgentSecurityReport) -> list[str]:
    refs = [
        item.trajectory_ref
        for item in report.scenario_results
        if not item.passed
    ]
    return sorted(set(refs))


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )


__all__ = [
    "AttackFeedback",
    "DashboardFeedback",
    "DefenseFeedback",
    "FeedbackArtifactPaths",
    "FeedbackRoute",
    "route_optimizer_feedback",
    "write_feedback_artifacts",
]
