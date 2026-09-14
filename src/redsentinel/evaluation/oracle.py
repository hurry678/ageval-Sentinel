"""Canonical trajectory oracle API."""

from redsentinel.evaluation.engine.detection.oracle import (
    OracleEvidence,
    OracleOutput,
    OracleVerdict,
    evaluate_oracle,
)
from redsentinel.evaluation.engine.detection.trajectory_risk.anomaly_model import (
    AnomalyScore,
    TrajectoryAnomalyDetector,
)

__all__ = [
    "AnomalyScore",
    "OracleEvidence",
    "OracleOutput",
    "OracleVerdict",
    "TrajectoryAnomalyDetector",
    "evaluate_oracle",
]
