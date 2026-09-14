"""Optional HTML/dashboard rendering boundary."""

from redsentinel.reporting.engine.reports import render_html_dashboard
from redsentinel.reporting.schema import AgentSecurityReport


def write_html_dashboard(report: AgentSecurityReport, path: str) -> str:
    """Render and write a dashboard, returning the artifact path."""
    from pathlib import Path

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_html_dashboard(report), encoding="utf-8")
    return str(target)


__all__ = ["render_html_dashboard", "write_html_dashboard"]
