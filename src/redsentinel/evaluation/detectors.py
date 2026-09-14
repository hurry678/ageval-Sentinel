"""Detector contracts and deterministic baseline implementations."""

from redsentinel.evaluation.engine.detection import (
    run_gdm_baseline,
    run_mis_baseline,
    run_trs_baseline,
)
from redsentinel.evaluation.engine.detection.contracts import (
    AcceptanceFixtureManifest,
    AcceptanceFixtureRecord,
    DetectorAttribution,
    DetectorDecision,
    DetectorInput,
    DetectorMetric,
    DetectorOutput,
    load_acceptance_fixture_manifest,
)

__all__ = [
    "AcceptanceFixtureManifest",
    "AcceptanceFixtureRecord",
    "DetectorAttribution",
    "DetectorDecision",
    "DetectorInput",
    "DetectorMetric",
    "DetectorOutput",
    "load_acceptance_fixture_manifest",
    "run_gdm_baseline",
    "run_mis_baseline",
    "run_trs_baseline",
]
