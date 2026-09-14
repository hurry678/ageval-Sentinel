"""Evaluation, oracle, attribution, metric, and paired-analysis APIs."""

from redsentinel.evaluation.attribution import NodeAttribution, build_node_attributions
from redsentinel.evaluation.detectors import (
    DetectorInput,
    DetectorOutput,
    run_gdm_baseline,
    run_mis_baseline,
    run_trs_baseline,
)
from redsentinel.evaluation.metrics import (
    DeterministicMetrics,
    MetricInputs,
    ScoreBreakdown,
    compute_deterministic_metrics,
    risk_level_from_score,
    score_breakdown_from_metric_inputs,
    score_breakdown_from_metrics,
    score_from_metrics,
)
from redsentinel.evaluation.oracle import OracleEvidence, OracleOutput, evaluate_oracle
from redsentinel.evaluation.paired import (
    PairedEvaluationReportSkeleton,
    build_paired_evaluation_report_skeleton,
    run_paired_evaluation_dry_run,
)

__all__ = [
    "DetectorInput",
    "DetectorOutput",
    "DeterministicMetrics",
    "MetricInputs",
    "NodeAttribution",
    "OracleEvidence",
    "OracleOutput",
    "PairedEvaluationReportSkeleton",
    "ScoreBreakdown",
    "build_node_attributions",
    "build_paired_evaluation_report_skeleton",
    "compute_deterministic_metrics",
    "evaluate_oracle",
    "risk_level_from_score",
    "run_gdm_baseline",
    "run_mis_baseline",
    "run_paired_evaluation_dry_run",
    "run_trs_baseline",
    "score_breakdown_from_metric_inputs",
    "score_breakdown_from_metrics",
    "score_from_metrics",
]
