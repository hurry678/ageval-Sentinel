"""Versioned dataset manifests and integrity-checked loading."""

from redsentinel.datasets.loader import (
    DatasetIntegrityError,
    DatasetManifest,
    assign_split,
    load_dataset_manifest,
    load_jsonl_split,
)
from redsentinel.datasets.p1_split import (
    P1ExperimentSplit,
    P1SplitAssignment,
    load_p1_experiment_split,
)

__all__ = [
    "DatasetIntegrityError",
    "DatasetManifest",
    "assign_split",
    "load_dataset_manifest",
    "load_jsonl_split",
    "P1ExperimentSplit",
    "P1SplitAssignment",
    "load_p1_experiment_split",
]
