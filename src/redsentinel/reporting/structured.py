"""Structured JSON and Markdown reporting without dashboard dependencies."""

from __future__ import annotations

import json
from pathlib import Path

from redsentinel.reporting.engine.reports import render_markdown_report
from redsentinel.application.engine.storage import sanitize_secret_fields
from redsentinel.reporting.schema import AgentSecurityReport


def safe_report_payload(report: AgentSecurityReport) -> dict:
    """Return a JSON-compatible report payload with secret fields removed."""
    return sanitize_secret_fields(report.model_dump(mode="json"))


def write_structured_report(
    report: AgentSecurityReport,
    *,
    json_path: str | Path,
    markdown_path: str | Path | None = None,
) -> dict[str, str]:
    """Write canonical JSON and optional Markdown artifacts."""
    json_target = Path(json_path)
    json_target.parent.mkdir(parents=True, exist_ok=True)
    payload = safe_report_payload(report)
    json_target.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    artifacts = {"json": str(json_target)}

    if markdown_path is not None:
        markdown_target = Path(markdown_path)
        markdown_target.parent.mkdir(parents=True, exist_ok=True)
        safe_report = AgentSecurityReport.model_validate(payload)
        markdown_target.write_text(render_markdown_report(safe_report), encoding="utf-8")
        artifacts["markdown"] = str(markdown_target)
    return artifacts


__all__ = [
    "render_markdown_report",
    "safe_report_payload",
    "write_structured_report",
]
