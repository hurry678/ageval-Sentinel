from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from redsentinel.attacks.engine.attack_spec import load_scenario_manifest
from redsentinel.evaluation.engine.detection import run_gdm_baseline, run_mis_baseline, run_trs_baseline
from redsentinel.evaluation.engine.detection.contracts import (
    DetectorInput,
    DetectorDecision,
    DetectorMetric,
    DetectorOutput,
    load_acceptance_fixture_manifest,
)

PairedEvaluationStatus = Literal["not_run", "passed", "failed", "needs_review"]
PairedRiskType = Literal["memory_poisoning", "tool_tampering", "goal_perturbation"]


class PairedEvaluationReportRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pair_id: str = Field(min_length=1)
    risk_type: PairedRiskType
    metric: DetectorMetric
    attack_spec_id: str = Field(min_length=1)
    expected_decision: DetectorDecision
    evidence_summary: list[str] = Field(min_length=1)
    failure_notes: list[str] = Field(default_factory=list)
    test_status: PairedEvaluationStatus = "not_run"
    clean_scenario_path: str = Field(min_length=1)
    controlled_scenario_path: str = Field(min_length=1)
    controlled_trajectory_path: str = Field(min_length=1)


class PairedEvaluationReportSkeleton(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["paired-evaluation-report-v0.1"] = "paired-evaluation-report-v0.1"
    records: list[PairedEvaluationReportRecord] = Field(min_length=1)


class PairedEvaluationDryRunResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    generated_report: PairedEvaluationReportSkeleton
    golden_report: PairedEvaluationReportSkeleton | None = None
    matches_golden: bool | None = None


class MISAcceptanceEvaluationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fixture_id: str = Field(min_length=1)
    pair_id: str = Field(min_length=1)
    expected_decision: DetectorDecision
    actual_decision: DetectorDecision
    passed: bool
    detector_output: DetectorOutput


class TRSAcceptanceEvaluationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fixture_id: str = Field(min_length=1)
    pair_id: str = Field(min_length=1)
    expected_decision: DetectorDecision
    actual_decision: DetectorDecision
    passed: bool
    detector_output: DetectorOutput


class GDMAcceptanceEvaluationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fixture_id: str = Field(min_length=1)
    pair_id: str = Field(min_length=1)
    expected_decision: DetectorDecision
    actual_decision: DetectorDecision
    passed: bool
    detector_output: DetectorOutput


def build_paired_evaluation_report_skeleton(
    acceptance_manifest_path: str | Path,
    *,
    repo_root: str | Path,
) -> PairedEvaluationReportSkeleton:
    root = Path(repo_root)
    acceptance_manifest = load_acceptance_fixture_manifest(acceptance_manifest_path)
    records: list[PairedEvaluationReportRecord] = []

    for fixture in acceptance_manifest.records:
        scenario_manifest = load_scenario_manifest(root / fixture.scenario_manifest_path)
        scenario_pair = next(
            (item for item in scenario_manifest.records if item.pair_id == fixture.scenario_pair_id),
            None,
        )
        if scenario_pair is None:
            raise ValueError(f"Scenario pair not found: {fixture.scenario_pair_id}")

        records.append(
            PairedEvaluationReportRecord(
                pair_id=fixture.scenario_pair_id,
                risk_type=fixture.risk_type,
                metric=fixture.metric,
                attack_spec_id=fixture.attack_spec_id,
                expected_decision=fixture.expected_decision,
                evidence_summary=list(fixture.expected_evidence),
                clean_scenario_path=scenario_pair.clean_scenario,
                controlled_scenario_path=scenario_pair.controlled_scenario,
                controlled_trajectory_path=fixture.controlled_trajectory_path,
            )
        )

    return PairedEvaluationReportSkeleton(records=records)


def run_paired_evaluation_dry_run(
    acceptance_manifest_path: str | Path,
    *,
    repo_root: str | Path,
    golden_report_path: str | Path | None = None,
) -> PairedEvaluationDryRunResult:
    generated_report = build_paired_evaluation_report_skeleton(
        acceptance_manifest_path,
        repo_root=repo_root,
    )

    if any(record.test_status != "not_run" for record in generated_report.records):
        raise ValueError("Dry-run reports must keep all records in not_run status")

    if golden_report_path is None:
        return PairedEvaluationDryRunResult(generated_report=generated_report)

    golden_payload = json.loads(Path(golden_report_path).read_text(encoding="utf-8"))
    golden_report = PairedEvaluationReportSkeleton.model_validate(golden_payload)

    if golden_report.model_dump(mode="json") != generated_report.model_dump(mode="json"):
        raise ValueError("Golden paired evaluation report does not match dry-run output")

    return PairedEvaluationDryRunResult(
        generated_report=generated_report,
        golden_report=golden_report,
        matches_golden=True,
    )


def run_mis_acceptance_evaluation(
    acceptance_manifest_path: str | Path,
    *,
    repo_root: str | Path,
) -> MISAcceptanceEvaluationResult:
    manifest = load_acceptance_fixture_manifest(acceptance_manifest_path)
    mis_fixtures = [fixture for fixture in manifest.records if fixture.metric == "MIS"]
    if len(mis_fixtures) != 1:
        raise ValueError("MIS acceptance evaluation requires exactly one MIS fixture.")

    fixture = mis_fixtures[0]
    detector_input = DetectorInput(
        metric="MIS",
        scenario_pair_id=fixture.scenario_pair_id,
        controlled_trajectory_path=fixture.controlled_trajectory_path,
        attack_spec_id=fixture.attack_spec_id,
    )
    detector_output = run_mis_baseline(detector_input, root=repo_root)

    return MISAcceptanceEvaluationResult(
        fixture_id=fixture.fixture_id,
        pair_id=fixture.scenario_pair_id,
        expected_decision=fixture.expected_decision,
        actual_decision=detector_output.decision,
        passed=detector_output.decision == fixture.expected_decision,
        detector_output=detector_output,
    )


def run_trs_acceptance_evaluation(
    acceptance_manifest_path: str | Path,
    *,
    repo_root: str | Path,
) -> TRSAcceptanceEvaluationResult:
    manifest = load_acceptance_fixture_manifest(acceptance_manifest_path)
    trs_fixtures = [fixture for fixture in manifest.records if fixture.metric == "TRS"]
    if len(trs_fixtures) != 1:
        raise ValueError("TRS acceptance evaluation requires exactly one TRS fixture.")

    fixture = trs_fixtures[0]
    detector_input = DetectorInput(
        metric="TRS",
        scenario_pair_id=fixture.scenario_pair_id,
        controlled_trajectory_path=fixture.controlled_trajectory_path,
        attack_spec_id=fixture.attack_spec_id,
    )
    detector_output = run_trs_baseline(detector_input, root=repo_root)

    return TRSAcceptanceEvaluationResult(
        fixture_id=fixture.fixture_id,
        pair_id=fixture.scenario_pair_id,
        expected_decision=fixture.expected_decision,
        actual_decision=detector_output.decision,
        passed=detector_output.decision == fixture.expected_decision,
        detector_output=detector_output,
    )


def run_gdm_acceptance_evaluation(
    acceptance_manifest_path: str | Path,
    *,
    repo_root: str | Path,
) -> GDMAcceptanceEvaluationResult:
    manifest = load_acceptance_fixture_manifest(acceptance_manifest_path)
    gdm_fixtures = [fixture for fixture in manifest.records if fixture.metric == "GDM"]
    if len(gdm_fixtures) != 1:
        raise ValueError("GDM acceptance evaluation requires exactly one GDM fixture.")

    fixture = gdm_fixtures[0]
    detector_input = DetectorInput(
        metric="GDM",
        scenario_pair_id=fixture.scenario_pair_id,
        controlled_trajectory_path=fixture.controlled_trajectory_path,
        attack_spec_id=fixture.attack_spec_id,
    )
    detector_output = run_gdm_baseline(detector_input, root=repo_root)

    return GDMAcceptanceEvaluationResult(
        fixture_id=fixture.fixture_id,
        pair_id=fixture.scenario_pair_id,
        expected_decision=fixture.expected_decision,
        actual_decision=detector_output.decision,
        passed=detector_output.decision == fixture.expected_decision,
        detector_output=detector_output,
    )


def build_mis_paired_report_with_status(
    acceptance_manifest_path: str | Path,
    *,
    repo_root: str | Path,
) -> PairedEvaluationReportSkeleton:
    report = build_paired_evaluation_report_skeleton(
        acceptance_manifest_path,
        repo_root=repo_root,
    )
    result = run_mis_acceptance_evaluation(
        acceptance_manifest_path,
        repo_root=repo_root,
    )

    updated_records: list[PairedEvaluationReportRecord] = []
    updated_mis_record = False
    for record in report.records:
        if record.metric != "MIS":
            updated_records.append(record)
            continue

        failure_notes = list(record.failure_notes)
        if not result.passed:
            failure_notes.append(
                f"Expected MIS decision {result.expected_decision}, got {result.actual_decision}."
            )
            failure_notes.extend(result.detector_output.failure_notes)

        updated_records.append(
            record.model_copy(
                update={
                    "test_status": "passed" if result.passed else "failed",
                    "failure_notes": failure_notes,
                }
            )
        )
        updated_mis_record = True

    if not updated_mis_record:
        raise ValueError("MIS report record not found in paired evaluation skeleton.")

    return PairedEvaluationReportSkeleton(records=updated_records)


def build_trs_paired_report_with_status(
    acceptance_manifest_path: str | Path,
    *,
    repo_root: str | Path,
) -> PairedEvaluationReportSkeleton:
    report = build_paired_evaluation_report_skeleton(
        acceptance_manifest_path,
        repo_root=repo_root,
    )
    result = run_trs_acceptance_evaluation(
        acceptance_manifest_path,
        repo_root=repo_root,
    )

    updated_records: list[PairedEvaluationReportRecord] = []
    updated_trs_record = False
    for record in report.records:
        if record.metric != "TRS":
            updated_records.append(record)
            continue

        failure_notes = list(record.failure_notes)
        if not result.passed:
            failure_notes.append(
                f"Expected TRS decision {result.expected_decision}, got {result.actual_decision}."
            )
            failure_notes.extend(result.detector_output.failure_notes)

        updated_records.append(
            record.model_copy(
                update={
                    "test_status": "passed" if result.passed else "failed",
                    "failure_notes": failure_notes,
                }
            )
        )
        updated_trs_record = True

    if not updated_trs_record:
        raise ValueError("TRS report record not found in paired evaluation skeleton.")

    return PairedEvaluationReportSkeleton(records=updated_records)


def build_gdm_paired_report_with_status(
    acceptance_manifest_path: str | Path,
    *,
    repo_root: str | Path,
) -> PairedEvaluationReportSkeleton:
    report = build_paired_evaluation_report_skeleton(
        acceptance_manifest_path,
        repo_root=repo_root,
    )
    result = run_gdm_acceptance_evaluation(
        acceptance_manifest_path,
        repo_root=repo_root,
    )

    updated_records: list[PairedEvaluationReportRecord] = []
    updated_gdm_record = False
    for record in report.records:
        if record.metric != "GDM":
            updated_records.append(record)
            continue

        failure_notes = list(record.failure_notes)
        if not result.passed:
            failure_notes.append(
                f"Expected GDM decision {result.expected_decision}, got {result.actual_decision}."
            )
            failure_notes.extend(result.detector_output.failure_notes)

        updated_records.append(
            record.model_copy(
                update={
                    "test_status": "passed" if result.passed else "failed",
                    "failure_notes": failure_notes,
                }
            )
        )
        updated_gdm_record = True

    if not updated_gdm_record:
        raise ValueError("GDM report record not found in paired evaluation skeleton.")

    return PairedEvaluationReportSkeleton(records=updated_records)


__all__ = [
    "GDMAcceptanceEvaluationResult",
    "MISAcceptanceEvaluationResult",
    "PairedEvaluationDryRunResult",
    "PairedEvaluationReportRecord",
    "PairedEvaluationReportSkeleton",
    "PairedEvaluationStatus",
    "TRSAcceptanceEvaluationResult",
    "build_gdm_paired_report_with_status",
    "build_mis_paired_report_with_status",
    "build_paired_evaluation_report_skeleton",
    "build_trs_paired_report_with_status",
    "run_paired_evaluation_dry_run",
    "run_gdm_acceptance_evaluation",
    "run_mis_acceptance_evaluation",
    "run_trs_acceptance_evaluation",
]
