"""Paired clean/controlled evaluation and acceptance APIs."""

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
    run_gdm_acceptance_evaluation,
    run_mis_acceptance_evaluation,
    run_paired_evaluation_dry_run,
    run_trs_acceptance_evaluation,
)

__all__ = [
    "GDMAcceptanceEvaluationResult",
    "MISAcceptanceEvaluationResult",
    "PairedEvaluationDryRunResult",
    "PairedEvaluationReportRecord",
    "PairedEvaluationReportSkeleton",
    "TRSAcceptanceEvaluationResult",
    "build_gdm_paired_report_with_status",
    "build_mis_paired_report_with_status",
    "build_paired_evaluation_report_skeleton",
    "build_trs_paired_report_with_status",
    "run_gdm_acceptance_evaluation",
    "run_mis_acceptance_evaluation",
    "run_paired_evaluation_dry_run",
    "run_trs_acceptance_evaluation",
]
