"""Experiment runner — scenario scheduling and result storage."""

from redsentinel.evaluation.engine.runner.closed_loop import (
    ClosedLoopAuditIntegrity,
    ClosedLoopDefenseDecision,
    ClosedLoopEvaluationRecord,
    ClosedLoopEvaluationReport,
    run_closed_loop_evaluation,
)
from redsentinel.evaluation.engine.runner.comp1_demo import Comp1DemoResult, run_comp1_demo
from redsentinel.evaluation.engine.runner.core import ExperimentRunner, RunResult, diff_trajectories
from redsentinel.evaluation.engine.runner.paired_evaluation import (
    GDMAcceptanceEvaluationResult,
    MISAcceptanceEvaluationResult,
    PairedEvaluationDryRunResult,
    PairedEvaluationReportRecord,
    PairedEvaluationReportSkeleton,
    TRSAcceptanceEvaluationResult,
    build_gdm_paired_report_with_status,
    build_mis_paired_report_with_status,
    build_paired_evaluation_report_skeleton,
    build_trs_paired_report_with_status,
    run_paired_evaluation_dry_run,
    run_gdm_acceptance_evaluation,
    run_mis_acceptance_evaluation,
    run_trs_acceptance_evaluation,
)

__all__ = [
    "ClosedLoopAuditIntegrity",
    "ClosedLoopDefenseDecision",
    "ClosedLoopEvaluationRecord",
    "ClosedLoopEvaluationReport",
    "Comp1DemoResult",
    "ExperimentRunner",
    "GDMAcceptanceEvaluationResult",
    "MISAcceptanceEvaluationResult",
    "PairedEvaluationDryRunResult",
    "PairedEvaluationReportRecord",
    "PairedEvaluationReportSkeleton",
    "TRSAcceptanceEvaluationResult",
    "RunResult",
    "build_gdm_paired_report_with_status",
    "build_mis_paired_report_with_status",
    "build_paired_evaluation_report_skeleton",
    "build_trs_paired_report_with_status",
    "diff_trajectories",
    "run_closed_loop_evaluation",
    "run_comp1_demo",
    "run_paired_evaluation_dry_run",
    "run_gdm_acceptance_evaluation",
    "run_mis_acceptance_evaluation",
    "run_trs_acceptance_evaluation",
]
