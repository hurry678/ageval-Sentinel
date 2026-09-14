from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any

import yaml

from platform_api.config import CUSTOM_SUITES_ROOT, PLATFORM_ROOT, ensure_state, suite_roots
from platform_api.suites import SEVERITIES, pipeline_nodes, suite_detail

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
DECISIONS = {"block", "allow", "warn", "review"}


def _fail(message: str) -> tuple[dict[str, Any] | None, str]:
    return None, message


def _steps(raw: Any, field: str) -> tuple[list[dict[str, str]] | None, str]:
    if not isinstance(raw, list):
        return None, f"{field} must be a list"
    out: list[dict[str, str]] = []
    for index, item in enumerate(raw):
        if isinstance(item, str):
            message = item.strip()
            role = "user"
            user_id = "user"
        elif isinstance(item, dict):
            message = str(item.get("message") or "").strip()
            role = str(item.get("role") or "user").strip()
            user_id = str(item.get("user_id") or "user").strip()
        else:
            return None, f"{field}[{index}] must be a string or object"
        if not message:
            return None, f"{field}[{index}].message is required"
        out.append({"role": role, "user_id": user_id, "message": message})
    return out, ""


def normalize_custom_suite(payload: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    suite_id = str(payload.get("suite_id") or "").strip()
    task_id = str(payload.get("task_id") or "").strip()
    if not SLUG_RE.match(suite_id):
        return _fail("suite_id must be a lowercase slug")
    if not suite_id.startswith("custom-"):
        return _fail("suite_id must start with custom-")
    if not SLUG_RE.match(task_id):
        return _fail("task_id must be a lowercase slug")

    custom_root = CUSTOM_SUITES_ROOT
    for path in suite_roots():
        if path.name == suite_id and not str(path).startswith(str(custom_root)):
            return _fail(f"suite_id conflicts with built-in suite: {suite_id}")

    severity = str(payload.get("severity") or "medium").strip()
    if severity not in SEVERITIES:
        return _fail(f"severity must be one of {' / '.join(SEVERITIES)}")

    valid_nodes = set(pipeline_nodes())
    nodes = [str(item).strip().upper() for item in payload.get("nodes") or []]
    if not nodes:
        return _fail("nodes is required")
    unknown = [node for node in nodes if node not in valid_nodes]
    if unknown:
        return _fail(f"unknown pipeline nodes: {', '.join(unknown)}")

    category = str(payload.get("category") or "custom_risk").strip() or "custom_risk"
    expected_decision = str(payload.get("expected_decision") or "block").strip()
    if expected_decision not in DECISIONS:
        return _fail(f"expected_decision must be one of {' / '.join(sorted(DECISIONS))}")

    clean, reason = _steps(payload.get("clean_steps") or [], "clean_steps")
    if clean is None:
        return _fail(reason)
    controlled, reason = _steps(payload.get("controlled_steps") or [], "controlled_steps")
    if controlled is None:
        return _fail(reason)
    if not controlled:
        return _fail("controlled_steps must include at least one attack step")

    success_criteria = [str(item).strip() for item in payload.get("success_criteria") or [] if str(item).strip()]
    if not success_criteria:
        return _fail("success_criteria is required")

    title = str(payload.get("title") or task_id).strip()
    description = str(payload.get("description") or "User-defined Sentinel test flow").strip()

    return {
        "suite_id": suite_id,
        "task_id": task_id,
        "title": title,
        "description": description,
        "category": category,
        "severity": severity,
        "nodes": sorted(set(nodes)),
        "business_flow": str(payload.get("business_flow") or title).strip(),
        "expected_decision": expected_decision,
        "clean_steps": clean,
        "controlled_steps": controlled,
        "success_criteria": success_criteria,
        "business_impact": str(payload.get("business_impact") or "User-defined impact").strip(),
    }, ""


def validate_custom_suite(payload: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    return normalize_custom_suite(payload)


def write_custom_suite(payload: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    data, reason = normalize_custom_suite(payload)
    if data is None:
        return None, reason
    ensure_state()
    suite_root = CUSTOM_SUITES_ROOT / data["suite_id"]
    task_root = suite_root / "tasks" / data["task_id"]
    suite_existed = suite_root.exists()
    if suite_root.exists() and not (suite_root / "ageval.yaml").is_file():
        return None, "custom suite path exists but is not a suite"

    try:
        (task_root / "data").mkdir(parents=True, exist_ok=True)
        (task_root / "evaluation").mkdir(parents=True, exist_ok=True)
        (suite_root / "ageval.yaml").write_text(
            yaml.safe_dump(
                {
                    "format": "ageval.dataset/1",
                    "dataset_id": f"custom/{data['suite_id']}",
                    "version": "0.1.0",
                    "description": data["description"],
                    "tasks": {"root": "tasks"},
                },
                allow_unicode=True,
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        (task_root / "task.yaml").write_text(
            yaml.safe_dump(
                {
                    "format": "ageval.task/1",
                    "task_id": data["task_id"],
                    "parameters": {
                        "scenario_id": data["task_id"],
                        "risk_category": data["category"],
                        "severity": data["severity"],
                        "business_flow": data["business_flow"],
                        "expected_decision": data["expected_decision"],
                        "pipeline_nodes": data["nodes"],
                        "models": {"default": "sentinel"},
                        "max_turns": 8,
                    },
                    "agent_profiles": [{"id": "sentinel"}],
                    "artifacts": {
                        "publishable": [
                            {"id": "clean", "path": "artifacts/clean.json"},
                            {"id": "controlled", "path": "artifacts/controlled.json"},
                        ]
                    },
                    "evaluation": {
                        "inputs": [
                            {"artifact": "clean", "target": "artifacts/clean.json"},
                            {"artifact": "controlled", "target": "artifacts/controlled.json"},
                        ]
                    },
                },
                allow_unicode=True,
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        (task_root / "data" / "scenario.json").write_text(
            json.dumps(
                {
                    "scenario_id": data["task_id"],
                    "title": data["title"],
                    "clean_steps": data["clean_steps"],
                    "controlled_steps": data["controlled_steps"],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        (task_root / "scenario.json").write_text(
            json.dumps(
                {
                    "scenario_id": data["task_id"],
                    "title": data["title"],
                    "clean_steps": data["clean_steps"],
                    "controlled_steps": data["controlled_steps"],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        shutil.copyfile(PLATFORM_ROOT / "custom_run.py", task_root / "run.py")
        shutil.copyfile(PLATFORM_ROOT / "custom_evaluator.py", task_root / "evaluator.py")
        (task_root / "evaluation" / "expected.json").write_text(
            json.dumps(
                {
                    "category": data["category"],
                    "severity": data["severity"],
                    "business_impact": data["business_impact"],
                    "success_criteria": data["success_criteria"],
                    "expected_decision": data["expected_decision"],
                    "nodes": data["nodes"],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        detail = suite_detail(suite_root)
    except (OSError, TypeError, ValueError, yaml.YAMLError) as exc:
        if not suite_existed:
            shutil.rmtree(suite_root, ignore_errors=True)
        else:
            shutil.rmtree(task_root, ignore_errors=True)
        return None, f"failed to write custom suite: {type(exc).__name__}: {exc}"
    return detail, ""
