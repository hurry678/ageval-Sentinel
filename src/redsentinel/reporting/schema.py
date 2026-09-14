"""Versioned structured report contracts.

Aliases intentionally preserve object identity with legacy Product API reports
during migration, preventing schema drift between research and application
consumers.
"""

from redsentinel.application.contracts import (
    AgentSecurityReport,
    Finding,
    ReportArtifacts,
    ScenarioResult,
)

__all__ = [
    "AgentSecurityReport",
    "Finding",
    "ReportArtifacts",
    "ScenarioResult",
]
