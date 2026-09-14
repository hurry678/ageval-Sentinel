"""Compatibility facade for legacy benchmark evaluators.

New research orchestration should use ``redsentinel.research``. These exports
keep the historical classifier and output-filter benchmarks reachable from one
documented evaluation namespace while their datasets are migrated.
"""

from redsentinel.evaluation.engine.benchmarks.evaluate import (
    NORMAL_QUERIES,
    compare_classifiers,
    evaluate_classifier,
)
from redsentinel.evaluation.engine.benchmarks.output_eval import (
    compute_refusal_matrix,
    evaluate_multiclass,
    evaluate_output_filter,
    evaluate_refusal_quality,
)

__all__ = [
    "NORMAL_QUERIES",
    "compare_classifiers",
    "compute_refusal_matrix",
    "evaluate_classifier",
    "evaluate_multiclass",
    "evaluate_output_filter",
    "evaluate_refusal_quality",
]
