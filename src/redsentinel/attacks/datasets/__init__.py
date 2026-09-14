"""Attack case loading and payload provenance validation."""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any, Iterable


REQUIRED_CASE_FIELDS = frozenset(
    {
        "id",
        "scenario",
        "category",
        "canonical_category",
        "payload_id",
        "payload_source",
        "attack_goal",
        "expected_violation",
        "success_criteria",
        "script_entry",
    }
)


def load_jsonl_records(path: str | Path) -> list[dict[str, Any]]:
    """Load non-empty JSONL objects while preserving file/line attribution."""
    source_path = Path(path)
    records: list[dict[str, Any]] = []
    with source_path.open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{source_path}:{line_number}: invalid JSONL record: {exc.msg}") from exc
            if not isinstance(record, dict):
                raise ValueError(f"{source_path}:{line_number}: JSONL record must be an object")
            records.append(record)
    return records


def load_attack_cases(path: str | Path, *, repository_root: str | Path | None = None) -> list[dict[str, Any]]:
    """Load canonical attack cases and verify their payload provenance."""
    source_path = Path(path)
    cases = load_jsonl_records(source_path)
    if not cases:
        raise ValueError(f"{source_path}: no JSONL cases found")
    root = Path(repository_root) if repository_root is not None else _repository_root()
    for line_number, case in enumerate(cases, start=1):
        validate_attack_case(case, source_path, line_number, repository_root=root)
    return cases


def validate_attack_case(
    case: dict[str, Any],
    path: str | Path,
    line_number: int,
    *,
    repository_root: str | Path | None = None,
) -> None:
    """Validate one case without changing its research labels."""
    source_path = Path(path)
    missing = REQUIRED_CASE_FIELDS - set(case)
    if missing:
        raise ValueError(f"{source_path}:{line_number}: missing required fields: {sorted(missing)}")
    if not isinstance(case["success_criteria"], list) or not case["success_criteria"]:
        raise ValueError(f"{source_path}:{line_number}: success_criteria must be a non-empty list")
    if not all(str(item).strip() for item in case["success_criteria"]):
        raise ValueError(f"{source_path}:{line_number}: success_criteria contains a blank item")
    if not isinstance(case["script_entry"], str) or not case["script_entry"].strip():
        raise ValueError(f"{source_path}:{line_number}: script_entry must be a non-empty string")

    source = case["payload_source"]
    if not isinstance(source, dict):
        raise ValueError(f"{source_path}:{line_number}: payload_source must be an object")
    for field in ("module", "symbol", "path", "payload_id"):
        if field not in source:
            raise ValueError(f"{source_path}:{line_number}: payload_source missing {field}")
    if case["payload_id"] != source["payload_id"]:
        raise ValueError(f"{source_path}:{line_number}: payload_id does not match payload_source")
    validate_payload_source(source, repository_root=repository_root)


def validate_payload_source(
    source: dict[str, Any],
    *,
    repository_root: str | Path | None = None,
) -> None:
    """Resolve a payload reference to its source module, symbol, and ID."""
    root = Path(repository_root) if repository_root is not None else _repository_root()
    source_path = root / str(source["path"])
    if not source_path.exists():
        raise ValueError(f"payload source path does not exist: {source['path']}")

    module = importlib.import_module(str(source["module"]))
    payloads = getattr(module, str(source["symbol"]))
    payload_ids = {
        str(payload["id"])
        for payload in _payload_records(payloads)
        if payload.get("id") is not None
    }
    if str(source["payload_id"]) not in payload_ids:
        raise ValueError(f"unknown payload_id: {source['payload_id']}")


def _payload_records(value: Any) -> Iterable[dict[str, Any]]:
    if not isinstance(value, (list, tuple)):
        raise ValueError("payload source symbol must be a list or tuple")
    for item in value:
        if not isinstance(item, dict):
            raise ValueError("payload source contains a non-object record")
        yield item


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[4]


from redsentinel.attacks.datasets.runner import (  # noqa: E402
    ROOT,
    ScenarioConfig,
    load_cases,
    run_scenario_cli,
)


__all__ = [
    "REQUIRED_CASE_FIELDS",
    "ROOT",
    "ScenarioConfig",
    "load_attack_cases",
    "load_cases",
    "load_jsonl_records",
    "run_scenario_cli",
    "validate_attack_case",
    "validate_payload_source",
]
