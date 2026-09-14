"""Detection suites: what this platform can throw at an Agent.

A suite is an ageval dataset directory. Everything shown in the UI is read from
the dataset itself — manifest, per-task ``task.yaml`` parameters and the gold
``evaluation/expected.json`` — so adding a suite means dropping in a dataset, not
editing the platform.

Pipeline-node coverage comes from Sentinel's own threat taxonomy, which is what
lets the UI say *which* of the eight Agent attack surfaces a suite leaves untested.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from platform_api.config import suite_roots

SEVERITIES = ("low", "medium", "high", "critical")
# Attack-pack categories that predate the taxonomy table.
CATEGORY_ALIASES = {
    "direct_injection": "prompt_injection",
    "data_exfiltration": "sensitive_leakage",
    "business_logic_abuse": "tool_abuse",
}


def _taxonomy() -> tuple[dict[str, str], dict[str, list[str]]]:
    from redsentinel.attacks.engine.threat_taxonomy import PIPELINE_NODES, RISK_TYPE_NODES

    return dict(PIPELINE_NODES), dict(RISK_TYPE_NODES)


def nodes_for(category: str) -> list[str]:
    _, risk_type_nodes = _taxonomy()
    return risk_type_nodes.get(CATEGORY_ALIASES.get(category, category), [])


def pipeline_nodes() -> dict[str, str]:
    nodes, _ = _taxonomy()
    return nodes


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return {}


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def task_summary(task_dir: Path) -> dict[str, Any] | None:
    manifest = _read_yaml(task_dir / "task.yaml")
    if not manifest:
        return None
    params = manifest.get("parameters") or {}
    gold = _read_json(task_dir / "evaluation" / "expected.json")
    category = str(params.get("risk_category") or gold.get("category") or "unknown")
    severity = str(params.get("severity") or gold.get("severity") or "medium")
    scenario = _read_json(task_dir / "data" / "scenario.json")
    return {
        "task_id": str(manifest.get("task_id") or task_dir.name),
        "scenario_id": str(params.get("scenario_id") or task_dir.name),
        "category": category,
        "severity": severity if severity in SEVERITIES else "medium",
        "business_flow": str(params.get("business_flow") or ""),
        "attack_spec_id": str(params.get("attack_spec_id") or ""),
        "expected_decision": str(params.get("expected_decision") or "block"),
        "business_impact": str(gold.get("business_impact") or ""),
        "success_criteria": list(gold.get("success_criteria") or []),
        "nodes": list(params.get("pipeline_nodes") or gold.get("nodes") or nodes_for(category)),
        "clean_steps": len(scenario.get("clean_steps") or []),
        "controlled_steps": len(scenario.get("controlled_steps") or []),
        # A suite that replays the attack unguarded can report a defense delta.
        "has_baseline_phase": "baseline"
        in {
            str(item.get("id"))
            for item in (manifest.get("artifacts") or {}).get("publishable") or []
        },
    }


def suite_detail(root: Path) -> dict[str, Any]:
    manifest = _read_yaml(root / "ageval.yaml")
    tasks = [
        summary
        for summary in (
            task_summary(child) for child in sorted((root / "tasks").iterdir()) if child.is_dir()
        )
        if summary is not None
    ]
    nodes = pipeline_nodes()
    tested = sorted({node for task in tasks for node in task["nodes"]})
    categories: dict[str, int] = {}
    severities = {level: 0 for level in SEVERITIES}
    for task in tasks:
        categories[task["category"]] = categories.get(task["category"], 0) + 1
        severities[task["severity"]] += 1
    return {
        "suite_id": root.name,
        "dataset_id": str(manifest.get("dataset_id") or root.name),
        "version": str(manifest.get("version") or ""),
        "description": str(manifest.get("description") or ""),
        "root": str(root),
        "task_count": len(tasks),
        "categories": categories,
        "severities": severities,
        "node_coverage": {
            "tested": tested,
            "untested": [node for node in nodes if node not in tested],
            "labels": nodes,
            "ratio": len(tested) / len(nodes) if nodes else 0.0,
        },
        "supports_defense_delta": any(task["has_baseline_phase"] for task in tasks),
        "tasks": tasks,
    }


def list_suites() -> list[dict[str, Any]]:
    """Suite cards without the task list — cheap enough for the overview page."""
    out = []
    for root in suite_roots():
        detail = suite_detail(root)
        detail.pop("tasks")
        out.append(detail)
    return out


def get_suite(suite_id: str) -> dict[str, Any] | None:
    root = next((path for path in suite_roots() if path.name == suite_id), None)
    return suite_detail(root) if root is not None else None


def scenario_payload(suite_id: str, task_id: str) -> dict[str, Any] | None:
    """The raw attack script — the payload an auditor needs to see."""
    root = next((path for path in suite_roots() if path.name == suite_id), None)
    if root is None:
        return None
    task_dir = root / "tasks" / task_id
    summary = task_summary(task_dir)
    if summary is None:
        return None
    scenario = _read_json(task_dir / "data" / "scenario.json")
    return {
        **summary,
        "suite_id": suite_id,
        "clean_script": scenario.get("clean_steps") or [],
        "controlled_script": scenario.get("controlled_steps") or [],
        "gold": _read_json(task_dir / "evaluation" / "expected.json"),
    }


__all__ = [
    "get_suite",
    "list_suites",
    "nodes_for",
    "pipeline_nodes",
    "scenario_payload",
    "suite_detail",
]
