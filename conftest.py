from __future__ import annotations

from pathlib import Path

import pytest


_OPTIONAL_ENV_MARKERS = {"docker", "external_model", "research_full"}


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Classify legacy tests without a disruptive bulk directory move."""
    for item in items:
        marker = _layer_marker(Path(str(item.path)))
        item.add_marker(getattr(pytest.mark, marker))

        marker_names = {mark.name for mark in item.iter_markers()}
        if not marker_names.intersection(_OPTIONAL_ENV_MARKERS):
            item.add_marker(pytest.mark.fast)


def _layer_marker(path: Path) -> str:
    parts = path.parts
    if "experiments" in parts or _contains_layer(parts, "research"):
        return "research"
    if _contains_layer(parts, "unit"):
        return "unit"
    if (
        _contains_layer(parts, "contract")
        or _contains_layer(parts, "contracts")
        or _contains_layer(parts, "architecture")
    ):
        return "contract"
    if _contains_layer(parts, "integration"):
        return "integration"
    if _contains_layer(parts, "regression"):
        return "regression"

    # Existing package, SDK, and frontend tests remain in place during the
    # migration and protect established public behavior.
    return "regression"


def _contains_layer(parts: tuple[str, ...], layer: str) -> bool:
    return "tests" in parts and layer in parts[parts.index("tests") + 1 :]
