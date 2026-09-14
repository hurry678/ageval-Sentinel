"""Canonical deterministic metric and score API.

The implementation remains shared with the legacy Product API during the
migration period so historical reports and research runs use identical
formulas.
"""

from redsentinel.application.contracts import (
    DeterministicMetrics,
    MetricInputs,
    RiskLevel,
    ScoreBreakdown,
)
from redsentinel.reporting.engine.reports import (
    compute_deterministic_metrics,
    risk_level_from_score,
    score_breakdown_from_metric_inputs,
    score_breakdown_from_metrics,
    score_from_metrics,
    severity_weight,
)

__all__ = [
    "DeterministicMetrics",
    "MetricInputs",
    "RiskLevel",
    "ScoreBreakdown",
    "compute_deterministic_metrics",
    "risk_level_from_score",
    "score_breakdown_from_metric_inputs",
    "score_breakdown_from_metrics",
    "score_from_metrics",
    "severity_weight",
]
