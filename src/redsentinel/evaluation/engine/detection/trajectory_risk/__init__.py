"""Trajectory Risk Model — TRS computation and early warning."""

from redsentinel.evaluation.engine.detection.trajectory_risk.baseline import run_trs_baseline
from redsentinel.evaluation.engine.detection.trajectory_risk.anomaly_model import (
    TrajectoryAnomalyDetector,
    extract_trajectory_features,
)

__all__ = ["TrajectoryAnomalyDetector", "extract_trajectory_features", "run_trs_baseline"]
