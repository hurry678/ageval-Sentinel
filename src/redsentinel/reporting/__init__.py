"""Structured and presentation report APIs."""

from redsentinel.reporting.artifacts import write_report_artifacts
from redsentinel.reporting.schema import (
    AgentSecurityReport,
    Finding,
    ReportArtifacts,
    ScenarioResult,
)
from redsentinel.reporting.structured import (
    render_markdown_report,
    safe_report_payload,
    write_structured_report,
)

__all__ = [
    "AgentSecurityReport",
    "Finding",
    "ReportArtifacts",
    "ScenarioResult",
    "render_markdown_report",
    "safe_report_payload",
    "write_report_artifacts",
    "write_structured_report",
]
