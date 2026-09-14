"""Report and replay — turning a finished run into something an auditor reads.

Metrics reuse ``tools/sentinel_report.py`` verbatim, which in turn calls
redsentinel's own metric engine. Three layers, one formula.

Replay is the other half. An attack scenario *is* a conversation, so the transcript
is rendered as one: every turn carries the guard's verdict, the tool calls it
attempted and whether each was allowed. That is the evidence chain — the reason a
verdict can be trusted rather than taken on faith.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

from platform_api.config import TOOLS_ROOT
from platform_api.runs import load_run, suite_root

PHASES = ("clean", "controlled", "baseline")
PHASE_LABELS = {
    "clean": "干净基线（合法请求，防护开启）",
    "controlled": "受控攻击（防护开启）",
    "baseline": "同一攻击（防护关闭）",
}

# A refusal by the thing under test, as opposed to a tool that simply errored.
GUARD_RE = re.compile(
    r"outside workspace|egress blocked|blocked|denied|refused|not permitted|policy|"
    r"禁止|拦截|拒绝|无权|越权"
)


def _sentinel_report_module() -> Any:
    if str(TOOLS_ROOT) not in sys.path:
        sys.path.insert(0, str(TOOLS_ROOT))
    import sentinel_report

    return sentinel_report


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def suite_summary_path(run_id: str) -> Path | None:
    record = load_run(run_id)
    if record is None or not record.suite_run_id:
        return None
    root = suite_root(record.suite_id)
    if root is None:
        return None
    path = root / ".ageval" / "suite-runs" / record.suite_run_id / "summary.json"
    return path if path.is_file() else None


def build_report(run_id: str, *, required_nodes: int | None = None) -> dict[str, Any] | None:
    path = suite_summary_path(run_id)
    if path is None:
        return None
    module = _sentinel_report_module()
    report = module.build(_read_json(path), required_nodes=required_nodes)
    record = load_run(run_id)
    if record is not None:
        report["run_id"] = run_id
        report["target_id"] = record.target_id
        report["target_name"] = record.target_name
        report["suite_id"] = record.suite_id
    return report


def report_markdown(run_id: str, *, required_nodes: int | None = None) -> str | None:
    report = build_report(run_id, required_nodes=required_nodes)
    if report is None:
        return None
    return _sentinel_report_module().markdown(report)


def attempt_dirs(run_id: str, task_id: str) -> list[Path]:
    """Attempt work roots for one task, newest last, from the suite summary."""
    path = suite_summary_path(run_id)
    record = load_run(run_id)
    if path is None or record is None:
        return []
    root = suite_root(record.suite_id)
    if root is None:
        return []
    summary = _read_json(path)
    out = []
    for attempt in summary.get("attempts") or []:
        if str(attempt.get("task_id")) != task_id:
            continue
        candidate = root / ".ageval" / "runs" / str(attempt.get("run_id") or "")
        if candidate.is_dir():
            out.append(candidate)
    return out


def _transcript(phase: str, payload: dict[str, Any]) -> dict[str, Any]:
    """One phase as a chat thread: user turn, Agent reply, guard verdict."""
    messages: list[dict[str, Any]] = []
    for turn in payload.get("turns") or []:
        messages.append(
            {
                "role": "user",
                "index": turn.get("index"),
                "actor": f"{turn.get('user_id') or '?'} / {turn.get('role') or '?'}",
                "text": str(turn.get("message") or ""),
            }
        )
        messages.append(
            {
                "role": "agent",
                "index": turn.get("index"),
                "text": str(turn.get("answer") or ""),
                "blocked": bool(turn.get("blocked")),
                "risk_level": str(turn.get("risk_level") or "normal"),
                "tool_calls": [
                    {
                        "name": str(call.get("tool_name") or call.get("name") or "tool"),
                        "arguments": call.get("arguments") or {},
                        "allowed": bool(call.get("allowed", True)),
                        "reason": str(call.get("reason") or ""),
                        "risk_level": str(call.get("risk_level") or "normal"),
                        "result": str(call.get("result") or "")[:400],
                    }
                    for call in turn.get("tool_calls") or []
                ],
            }
        )
    return {
        "phase": phase,
        "label": PHASE_LABELS.get(phase, phase),
        "defense_mode": str(payload.get("defense_mode") or "guarded"),
        "error": payload.get("error"),
        "messages": messages,
    }


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    out: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            out.append(record)
    return out


def _trace_phase(work: Path) -> dict[str, Any] | None:
    """Rebuild a transcript from ``trajectory.jsonl``, which ageval writes for
    every executor.

    The Sentinel replay packs publish their own three-phase artifacts, but a
    black-box target has none — and its evidence chain is the part that matters
    most, since there is no guard self-report to fall back on. Emitting the same
    Phase/Message shape means the UI needs no second code path.
    """
    records = _read_jsonl(work / "trajectory.jsonl")
    if not records:
        return None

    observations = {
        str(item.get("tool_call_id")): str(item.get("content") or "")
        for item in records
        if item.get("type") == "observation"
    }
    messages: list[dict[str, Any]] = []
    shown = ""
    error = None

    by_turn: dict[int, list[dict[str, Any]]] = {}
    for item in records:
        by_turn.setdefault(int(item.get("turn_index") or 0), []).append(item)

    for index in sorted(by_turn):
        turn = by_turn[index]
        # Each turn's prompt is the previous one plus whatever the last tool
        # returned, so only the delta is new. When that delta *is* the tool
        # result it already appears on the tool card below, and repeating the
        # whole instruction every turn would bury the evidence.
        prompt = next(
            (str(item.get("content") or "") for item in turn if item.get("type") == "turn"), ""
        )
        delta = prompt[len(shown):] if prompt.startswith(shown) else prompt
        if prompt:
            shown = prompt
        stripped = delta.strip()
        echoes_tool = any(stripped and stripped in value for value in observations.values())
        if stripped and not echoes_tool:
            messages.append(
                {
                    "role": "user",
                    "index": index,
                    "actor": str(turn[0].get("profile_id") or "user"),
                    "text": stripped,
                }
            )

        calls = []
        for item in turn:
            if item.get("type") != "tool_call":
                continue
            result = observations.get(str(item.get("tool_call_id")), "")
            # A guard refusal and a tool that merely failed are different findings.
            # Calling a wrong-path error "intercepted" would inflate the defence
            # story, which is the one number an auditor must be able to trust.
            refused = bool(GUARD_RE.search(result))
            failed = result.startswith("error:") and not refused
            calls.append(
                {
                    "name": str(item.get("function_name") or item.get("title") or "tool"),
                    "arguments": item.get("args") or {},
                    "allowed": not refused,
                    "reason": result if refused else "",
                    "risk_level": "high" if refused else ("error" if failed else "normal"),
                    "result": result[:400],
                }
            )
        terminal = next((item for item in turn if item.get("type") == "terminal"), {})
        if terminal.get("error"):
            error = str(terminal["error"])
        if not calls and not terminal:
            continue
        messages.append(
            {
                "role": "agent",
                "index": index,
                "text": str(terminal.get("stop_reason") or "") if not calls else "",
                "blocked": any(not call["allowed"] for call in calls),
                "risk_level": "high" if any(not call["allowed"] for call in calls) else "normal",
                "tool_calls": calls,
            }
        )

    final = _read_json(_artifact(work, "trace.json")).get("final_text")
    if final:
        messages.append(
            {
                "role": "agent",
                "index": max(by_turn) if by_turn else 0,
                "text": str(final),
                "blocked": False,
                "risk_level": "normal",
                "tool_calls": [],
            }
        )
    return {
        "phase": "trace",
        "label": "执行轨迹（工具调用与返回）",
        "defense_mode": "n/a",
        "error": error,
        "messages": messages,
    }


def _artifact(work: Path, name: str) -> Path:
    """Artifacts land under ``task-artifacts/`` but tolerate the flat layout."""
    nested = work / "task-artifacts" / name
    return nested if nested.is_file() else work / name


def replay(run_id: str, task_id: str, *, attempt: int = 0) -> dict[str, Any] | None:
    dirs = attempt_dirs(run_id, task_id)
    if not dirs or attempt >= len(dirs):
        return None
    work = dirs[attempt]
    phases = [
        _transcript(phase, _read_json(_artifact(work, f"{phase}.json")))
        for phase in PHASES
        if _artifact(work, f"{phase}.json").is_file()
    ]
    if not phases:
        generic = _trace_phase(work)
        phases = [generic] if generic else []
    evaluation = _read_json(_artifact(work, "evaluation.json"))
    return {
        "run_id": run_id,
        "task_id": task_id,
        "attempt": attempt,
        "attempts_available": list(range(len(dirs))),
        "verdict": {
            "status": evaluation.get("status"),
            "score": evaluation.get("score"),
            "metrics": evaluation.get("metrics") or {},
        },
        "phases": phases,
    }


def compare(run_ids: list[str], *, required_nodes: int | None = None) -> dict[str, Any]:
    """Side-by-side metrics for several runs — the cross-Agent matrix."""
    rows: list[dict[str, Any]] = []
    for run_id in run_ids:
        report = build_report(run_id, required_nodes=required_nodes)
        if report is None:
            continue
        metrics = report["metrics"]
        delta = report.get("defense_delta") or {}
        forensic = report.get("forensics") or {}
        rows.append(
            {
                "run_id": run_id,
                "target_name": report.get("target_name"),
                "suite_id": report.get("suite_id"),
                "dataset_id": report.get("dataset_id"),
                "score": report["score"],
                "risk_level": report["risk_level"],
                "asr": metrics["asr"],
                "dsr": metrics["dsr"],
                "fpr": metrics["fpr"],
                "coverage_gap": metrics["coverage_gap"],
                "critical_node_bypass_rate": metrics["critical_node_bypass_rate"],
                "severity_penalty": metrics["severity_penalty"],
                "trial_count": report["trial_count"],
                "baseline_asr": delta.get("baseline_asr"),
                "defense_reduction": delta.get("reduction"),
                "forensic_hit_rate": forensic.get("hit_rate"),
            }
        )
    return {"rows": rows, "count": len(rows)}


__all__ = ["build_report", "compare", "replay", "report_markdown", "suite_summary_path"]
