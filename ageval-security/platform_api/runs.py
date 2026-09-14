"""Launching and watching an ageval suite run.

The platform never reimplements the runner: it spawns the real ``ageval`` CLI and
reads its stdout. That keeps one execution path for the CLI and the web UI, so a
run started from the browser is byte-for-byte the run an auditor can reproduce in
a terminal — the command is recorded on the run record for exactly that reason.

Progress is a growing list of parsed events. The SSE endpoint walks it with a
cursor instead of bridging threads to the event loop, which keeps the streaming
path boring.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from platform_api.config import AGEVAL_ROOT, RUNS_STATE, ensure_state, suite_roots
from platform_api.targets import get_target, materialize_profiles

# `suite dca2973d  sentinel/openmanus-security@0.1.0  todo=6 total=6  cancel: ...`
SUITE_RE = re.compile(r"^suite\s+(\S+)\s+(\S+)\s+todo=(\d+)\s+total=(\d+)")
# `start  cross-user-order-access` / `start  task  #2`
START_RE = re.compile(r"^start\s+(\S+)(?:\s+#(\d+))?\s*$")
# `  cross-user-order-access  PASS  6.2s` / `  task  #1   FAIL  2.4s`
RESULT_RE = re.compile(r"^\s+(\S+)\s+(?:#(\d+)\s+)?(PASS|FAIL|ERROR)\s+([\d.]+)s")
DONE_RE = re.compile(r"^suite complete\s+exit=(\d+)\s+done=(\d+)/(\d+)")

TERMINAL = ("completed", "failed", "cancelled")


@dataclass
class RunRecord:
    run_id: str
    target_id: str
    target_name: str
    suite_id: str
    dataset_id: str
    n_attempts: int
    max_concurrent: int
    command: list[str]
    status: str = "starting"
    suite_run_id: str = ""
    total: int = 0
    done: int = 0
    exit_code: int | None = None
    created_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    error: str = ""
    events: list[dict[str, Any]] = field(default_factory=list)
    tasks: dict[str, dict[str, Any]] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    def summary(self) -> dict[str, Any]:
        data = self.as_dict()
        data.pop("events")
        data["counts"] = {
            state: sum(1 for item in self.tasks.values() if item["status"] == state)
            for state in ("PASS", "FAIL", "ERROR", "running")
        }
        return data

    def path(self) -> Path:
        return RUNS_STATE / f"{self.run_id}.json"

    def save(self) -> None:
        ensure_state()
        self.path().write_text(
            json.dumps(self.as_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
        )


_LIVE: dict[str, RunRecord] = {}
_LOCK = threading.Lock()


def ageval_bin() -> Path:
    """The CLI from this interpreter's environment — no `uv run` indirection."""
    return Path(sys.executable).parent / "ageval"


def suite_root(suite_id: str) -> Path | None:
    return next((path for path in suite_roots() if path.name == suite_id), None)


def _emit(record: RunRecord, kind: str, **payload: Any) -> None:
    record.events.append({"seq": len(record.events), "at": time.time(), "kind": kind, **payload})


def _consume(record: RunRecord, line: str) -> None:
    """Translate one CLI line into a structured event the UI can render."""
    _emit(record, "log", text=line)

    matched = SUITE_RE.match(line)
    if matched:
        record.suite_run_id = matched.group(1)
        record.total = int(matched.group(4))
        record.status = "running"
        _emit(record, "suite", suite_run_id=record.suite_run_id, total=record.total)
        return

    matched = START_RE.match(line)
    if matched:
        key = _key(matched.group(1), matched.group(2))
        record.tasks[key] = {
            "task_id": matched.group(1),
            "attempt": int(matched.group(2) or 0),
            "status": "running",
            "seconds": None,
        }
        _emit(record, "task", **record.tasks[key])
        return

    matched = RESULT_RE.match(line)
    if matched:
        key = _key(matched.group(1), matched.group(2))
        record.tasks[key] = {
            "task_id": matched.group(1),
            "attempt": int(matched.group(2) or 0),
            "status": matched.group(3),
            "seconds": float(matched.group(4)),
        }
        record.done = sum(1 for item in record.tasks.values() if item["status"] != "running")
        _emit(record, "task", **record.tasks[key])
        return

    matched = DONE_RE.match(line)
    if matched:
        record.exit_code = int(matched.group(1))
        record.done = int(matched.group(2))
        record.total = int(matched.group(3))
        _emit(record, "suite_complete", exit_code=record.exit_code, done=record.done)


def _key(task_id: str, attempt: str | None) -> str:
    return f"{task_id}#{attempt or 0}"


def _pump(record: RunRecord, process: subprocess.Popen[str]) -> None:
    assert process.stdout is not None
    for raw in process.stdout:
        line = raw.rstrip("\n")
        if not line:
            continue
        # The CLI ends with the full result document; keep it out of the log feed.
        if line.startswith("{"):
            _emit(record, "result_document", size=len(line))
            continue
        _consume(record, line)
        record.save()
    process.wait()
    if record.status != "cancelled":
        record.status = "completed" if process.returncode in (0, 1) else "failed"
    if record.exit_code is None:
        record.exit_code = process.returncode
    record.finished_at = time.time()
    _emit(record, "done", status=record.status, exit_code=record.exit_code)
    record.save()


def start_run(
    *, target_id: str, suite_id: str, n_attempts: int = 1, max_concurrent: int = 4
) -> tuple[RunRecord | None, str]:
    target = get_target(target_id)
    if target is None:
        return None, f"未知目标 {target_id}"
    root = suite_root(suite_id)
    if root is None:
        return None, f"未知检测套件 {suite_id}"
    binary = ageval_bin()
    if not binary.exists():
        return None, f"未找到 ageval CLI：{binary}"

    profiles = materialize_profiles(target)
    command = [
        str(binary),
        "run",
        str(root),
        "--profiles",
        profiles,
        "-k",
        str(max(1, n_attempts)),
        "--max-concurrent-tasks",
        str(max(1, max_concurrent)),
    ]
    record = RunRecord(
        run_id=uuid.uuid4().hex[:12],
        target_id=target.id,
        target_name=target.name,
        suite_id=suite_id,
        dataset_id=str(suite_id),
        n_attempts=max(1, n_attempts),
        max_concurrent=max(1, max_concurrent),
        command=command,
    )
    _emit(record, "launch", command=" ".join(command))
    try:
        process = subprocess.Popen(
            command,
            cwd=str(AGEVAL_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except OSError as exc:
        record.status = "failed"
        record.error = f"{type(exc).__name__}: {exc}"
        record.save()
        return record, ""

    with _LOCK:
        _LIVE[record.run_id] = record
    record.save()
    threading.Thread(target=_pump, args=(record, process), daemon=True).start()
    return record, ""


def cancel_run(run_id: str) -> tuple[bool, str]:
    record = _LIVE.get(run_id)
    if record is None or record.status in TERMINAL:
        return False, "该运行已结束或不在本进程中"
    if not record.suite_run_id:
        return False, "套件还未开始，稍后再试"
    subprocess.run(
        [str(ageval_bin()), "cancel", record.suite_run_id],
        cwd=str(AGEVAL_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    record.status = "cancelled"
    _emit(record, "cancelled")
    record.save()
    return True, ""


def load_run(run_id: str) -> RunRecord | None:
    live = _LIVE.get(run_id)
    if live is not None:
        return live
    path = RUNS_STATE / f"{run_id}.json"
    if not path.is_file():
        return None
    try:
        return RunRecord(**json.loads(path.read_text(encoding="utf-8")))
    except (json.JSONDecodeError, TypeError):
        return None


def list_runs() -> list[dict[str, Any]]:
    ensure_state()
    out: list[dict[str, Any]] = []
    for path in RUNS_STATE.glob("*.json"):
        record = load_run(path.stem)
        if record is not None:
            out.append(record.summary())
    return sorted(out, key=lambda item: item["created_at"], reverse=True)


def events_since(run_id: str, cursor: int) -> tuple[list[dict[str, Any]], bool]:
    """New events plus whether the run is over — the SSE loop needs both."""
    record = load_run(run_id)
    if record is None:
        return [], True
    return record.events[cursor:], record.status in TERMINAL


__all__ = [
    "RunRecord",
    "cancel_run",
    "events_since",
    "list_runs",
    "load_run",
    "start_run",
    "suite_root",
]
