from __future__ import annotations

from pathlib import Path
from typing import Any

from platform_api.reports import build_report, replay
from platform_api.runs import load_run, suite_root
from platform_api.suites import get_suite, pipeline_nodes

STATUS_ORDER = ("ERROR", "FAIL", "running", "PASS", "pending")


def _task_status(tasks: dict[str, dict[str, Any]], task_id: str) -> str:
    statuses = [str(item.get("status") or "pending") for item in tasks.values() if item.get("task_id") == task_id]
    if not statuses:
        return "pending"
    return min(statuses, key=lambda status: STATUS_ORDER.index(status) if status in STATUS_ORDER else 99)


def _has_attempt_artifacts(run_id: str, task_id: str) -> bool:
    try:
        found = replay(run_id, task_id)
    except (OSError, ValueError, TypeError):
        return False
    return found is not None


def build_attack_path(run_id: str) -> dict[str, Any] | None:
    record = load_run(run_id)
    if record is None:
        return None

    nodes = pipeline_nodes()
    suite = get_suite(record.suite_id)
    tasks = suite.get("tasks", []) if suite else []
    report = build_report(run_id)
    case_by_task = {
        str(item.get("task_id")): item
        for item in (report or {}).get("cases", [])
        if isinstance(item, dict)
    }

    task_rows: list[dict[str, Any]] = []
    covered_nodes: set[str] = set()
    node_status: dict[str, str] = {}

    for task in tasks:
        task_id = str(task.get("task_id") or "")
        status = _task_status(record.tasks, task_id)
        case = case_by_task.get(task_id, {})
        task_nodes = [str(node) for node in task.get("nodes") or case.get("nodes") or []]
        covered_nodes.update(task_nodes)
        for node in task_nodes:
            current = node_status.get(node, "pending")
            if STATUS_ORDER.index(status) < STATUS_ORDER.index(current):
                node_status[node] = status
        task_rows.append(
            {
                "task_id": task_id,
                "attempts": [
                    item
                    for item in record.tasks.values()
                    if str(item.get("task_id") or "") == task_id
                ],
                "status": status,
                "category": str(task.get("category") or case.get("category") or "unknown"),
                "severity": str(task.get("severity") or case.get("severity") or "medium"),
                "nodes": task_nodes,
                "expected_decision": str(task.get("expected_decision") or ""),
                "has_replay": _has_attempt_artifacts(run_id, task_id),
                "has_report_case": bool(case),
            }
        )

    graph_nodes = [
        {
            "id": node_id,
            "label": label,
            "covered": node_id in covered_nodes,
            "status": node_status.get(node_id, "pending") if node_id in covered_nodes else "uncovered",
        }
        for node_id, label in nodes.items()
    ]
    ordered = [node["id"] for node in graph_nodes]
    edges = [
        {"source": ordered[index], "target": ordered[index + 1], "count": 1}
        for index in range(len(ordered) - 1)
    ]

    events = [
        {
            "seq": event.get("seq"),
            "kind": event.get("kind"),
            "task_id": event.get("task_id"),
            "attempt": event.get("attempt"),
            "status": event.get("status"),
            "at": event.get("at"),
        }
        for event in record.events
        if event.get("kind") in {"suite", "task", "suite_complete", "done"}
    ]

    root = suite_root(record.suite_id)
    summary_ready = bool(record.suite_run_id and root and (Path(root) / ".ageval" / "suite-runs" / record.suite_run_id / "summary.json").is_file())

    return {
        "run_id": run_id,
        "suite_id": record.suite_id,
        "target_id": record.target_id,
        "target_name": record.target_name,
        "status": record.status,
        "ready": bool(tasks),
        "summary_ready": summary_ready,
        "nodes": graph_nodes,
        "edges": edges,
        "tasks": task_rows,
        "events": events,
        "report_ready": report is not None,
    }
