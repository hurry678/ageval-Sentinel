"""Combined report artifact writer kept separate from structured reporting."""

from __future__ import annotations

from pathlib import Path

from redsentinel.reporting.html import write_html_dashboard
from redsentinel.reporting.schema import AgentSecurityReport
from redsentinel.reporting.structured import write_structured_report


def write_report_artifacts(
    report: AgentSecurityReport,
    report_path: str | Path,
    markdown_path: str | Path,
    dashboard_path: str | Path | None = None,
) -> None:
    """Write structured artifacts and, when requested, an HTML dashboard."""
    write_structured_report(report, json_path=report_path, markdown_path=markdown_path)
    if dashboard_path is not None:
        write_html_dashboard(report, str(dashboard_path))


__all__ = ["write_report_artifacts"]
