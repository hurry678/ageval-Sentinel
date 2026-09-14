"""Detection & trajectory modeling — GDM, TRS, MIS."""

from redsentinel.evaluation.engine.detection.goal_drift import run_gdm_baseline
from redsentinel.evaluation.engine.detection.memory_integrity import run_mis_baseline
from redsentinel.evaluation.engine.detection.oracle import OracleEvidence, OracleOutput, evaluate_oracle
from redsentinel.evaluation.engine.detection.trajectory_risk import run_trs_baseline

__all__ = [
    "OracleEvidence",
    "OracleOutput",
    "evaluate_oracle",
    "run_gdm_baseline",
    "run_mis_baseline",
    "run_trs_baseline",
]
