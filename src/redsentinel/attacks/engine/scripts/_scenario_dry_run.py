"""Compatibility exports for the canonical research scenario runner."""

from redsentinel.attacks.datasets import validate_attack_case
from redsentinel.attacks.datasets.runner import (
    ROOT,
    ScenarioConfig,
    load_cases,
    run_scenario_cli,
)


def validate_case(case: dict, path, line_number: int) -> None:
    validate_attack_case(case, path, line_number, repository_root=ROOT)


__all__ = [
    "ROOT",
    "ScenarioConfig",
    "load_cases",
    "run_scenario_cli",
    "validate_case",
]
