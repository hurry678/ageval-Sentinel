from __future__ import annotations

import json
from pathlib import Path

from redsentinel.application.contracts import (
    AgentSecurityComparisonReport,
    AgentSecurityReport,
    ComparisonArtifacts,
    ComparisonFinding,
    ComparisonScenarioDelta,
    Finding,
)


def build_retest_comparison(
    before: AgentSecurityReport,
    after: AgentSecurityReport,
    comparison_id: str = "comparison_preview",
    artifacts: ComparisonArtifacts | None = None,
) -> AgentSecurityComparisonReport:
    _ensure_same_report_target(before, after)
    artifacts = artifacts or ComparisonArtifacts(
        before_report_path=before.artifacts.report_path,
        after_report_path=after.artifacts.report_path,
        comparison_path="runs/product/comparison.json",
    )
    before_findings = {item.finding_id: item for item in before.findings}
    after_findings = {item.finding_id: item for item in after.findings}
    resolved = [
        _comparison_finding(before_findings[key], "resolved")
        for key in sorted(before_findings.keys() - after_findings.keys())
    ]
    new = [_comparison_finding(after_findings[key], "new") for key in sorted(after_findings.keys() - before_findings.keys())]
    persisted = [
        _comparison_finding(after_findings[key], "persisted")
        for key in sorted(before_findings.keys() & after_findings.keys())
    ]
    scenario_deltas = _scenario_deltas(before, after)
    return AgentSecurityComparisonReport(
        comparison_id=comparison_id,
        tenant_id=before.tenant_id,
        agent_id=before.agent_id,
        benchmark=before.benchmark,
        before_score=before.overall_score,
        after_score=after.overall_score,
        score_delta=after.overall_score - before.overall_score,
        before_risk_level=before.risk_level,
        after_risk_level=after.risk_level,
        risk_level_change=f"{before.risk_level} -> {after.risk_level}",
        resolved_findings=resolved,
        new_findings=new,
        persisted_findings=persisted,
        scenario_deltas=scenario_deltas,
        summary={
            "resolved_count": len(resolved),
            "new_count": len(new),
            "persisted_count": len(persisted),
            "improved_scenarios": sum(1 for item in scenario_deltas if item.status == "improved"),
            "regressed_scenarios": sum(1 for item in scenario_deltas if item.status == "regressed"),
        },
        artifacts=artifacts,
    )


def render_markdown_comparison(report: AgentSecurityComparisonReport) -> str:
    lines = [
        "# Agent Security Retest Comparison",
        "",
        f"- Agent: `{report.agent_id}`",
        f"- Tenant: `{report.tenant_id}`",
        f"- Benchmark: `{report.benchmark}`",
        f"- Score delta: `{report.score_delta:+d}` (`{report.before_score}` -> `{report.after_score}`)",
        f"- Risk level: `{report.risk_level_change}`",
        "",
        "## Finding Delta",
        f"- Resolved: `{len(report.resolved_findings)}`",
        f"- New: `{len(report.new_findings)}`",
        f"- Persisted: `{len(report.persisted_findings)}`",
        "",
        "## Resolved Findings",
    ]
    lines.extend(_finding_lines(report.resolved_findings))
    lines.append("")
    lines.append("## New Findings")
    lines.extend(_finding_lines(report.new_findings))
    lines.append("")
    lines.append("## Persisted Findings")
    lines.extend(_finding_lines(report.persisted_findings))
    lines.append("")
    lines.append("## Scenario Delta")
    for item in report.scenario_deltas:
        lines.append(
            f"- `{item.status}` - `{item.scenario_id}` "
            f"({item.before_decision or 'missing'} -> {item.after_decision or 'missing'})"
        )
    return "\n".join(lines) + "\n"


def write_comparison_artifacts(
    report: AgentSecurityComparisonReport,
    comparison_path: Path,
    markdown_path: Path,
) -> None:
    comparison_path.parent.mkdir(parents=True, exist_ok=True)
    comparison_path.write_text(
        json.dumps(report.model_dump(mode="json"), ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    markdown_path.write_text(render_markdown_comparison(report), encoding="utf-8")


def _comparison_finding(finding: Finding, status: str) -> ComparisonFinding:
    return ComparisonFinding(
        finding_id=finding.finding_id,
        scenario_id=finding.scenario_id,
        severity=finding.severity,
        title=finding.title,
        status=status,
        recommendation=finding.recommendation,
    )


def _finding_lines(findings: list[ComparisonFinding]) -> list[str]:
    if not findings:
        return ["No findings in this bucket."]
    return [
        f"- `{item.severity}` `{item.scenario_id}` - {item.title}; recommendation: {item.recommendation}"
        for item in findings
    ]


def _scenario_deltas(before: AgentSecurityReport, after: AgentSecurityReport) -> list[ComparisonScenarioDelta]:
    before_scenarios = {item.scenario_id: item for item in before.scenario_results}
    after_scenarios = {item.scenario_id: item for item in after.scenario_results}
    deltas: list[ComparisonScenarioDelta] = []
    for scenario_id in sorted(before_scenarios.keys() | after_scenarios.keys()):
        before_item = before_scenarios.get(scenario_id)
        after_item = after_scenarios.get(scenario_id)
        before_passed = before_item.passed if before_item else None
        after_passed = after_item.passed if after_item else None
        deltas.append(
            ComparisonScenarioDelta(
                scenario_id=scenario_id,
                before_passed=before_passed,
                after_passed=after_passed,
                before_decision=before_item.actual_decision if before_item else None,
                after_decision=after_item.actual_decision if after_item else None,
                status=_scenario_status(before_passed, after_passed),
            )
        )
    return deltas


def _scenario_status(before_passed: bool | None, after_passed: bool | None) -> str:
    if before_passed is False and after_passed is True:
        return "improved"
    if before_passed is True and after_passed is False:
        return "regressed"
    if before_passed is True and after_passed is True:
        return "unchanged_pass"
    return "unchanged_fail"


def _ensure_same_report_target(before: AgentSecurityReport, after: AgentSecurityReport) -> None:
    if before.tenant_id != after.tenant_id:
        raise ValueError("Reports must belong to the same tenant.")
    if before.agent_id != after.agent_id:
        raise ValueError("Reports must belong to the same agent.")
    if before.benchmark != after.benchmark:
        raise ValueError("Reports must use the same benchmark.")
