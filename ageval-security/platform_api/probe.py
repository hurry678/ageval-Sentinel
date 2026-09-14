"""Is this target actually reachable?

``ageval run --probe`` only locks the config and checks that the credential's env
variable exists (``application/run.py:275-304``) — it never touches the endpoint.
Reporting that as "connected" would be a lie the UI repeats, so an http target
also gets a real handshake: one minimal chat completion against the very endpoint
a run would use.

Both results are returned separately and labelled, because they fail for different
reasons and the fix differs: ``config`` fails on a bad profile, ``endpoint`` fails
on a wrong URL, a dead server or a rejected key.
"""

from __future__ import annotations

import json
import os
import subprocess
import urllib.error
import urllib.request
from typing import Any

from platform_api.config import AGEVAL_ROOT
from platform_api.runs import ageval_bin, suite_root
from platform_api.suites import list_suites
from platform_api.targets import Target, is_loopback, materialize_profiles

HANDSHAKE_TIMEOUT = 15.0


def _probe_config(target: Target, suite_id: str, task_id: str) -> dict[str, Any]:
    """Lock + preflight through the real CLI, so a bad profile fails here."""
    profiles = materialize_profiles(target)
    root = suite_root(suite_id)
    if root is None:
        return {"ok": False, "detail": f"套件 {suite_id} 不存在"}
    completed = subprocess.run(
        [
            str(ageval_bin()), "run", str(root),
            "--task", task_id, "--profiles", profiles, "--probe",
        ],
        cwd=str(AGEVAL_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    output = (completed.stdout + completed.stderr).strip()
    return {
        "ok": completed.returncode == 0,
        "exit_code": completed.returncode,
        "suite_id": suite_id,
        "task_id": task_id,
        "output": output[-2000:],
        "detail": "配置可锁定，运行环境可用" if completed.returncode == 0 else "配置或凭据不可用",
    }


def _probe_endpoint(target: Target) -> dict[str, Any]:
    """One real chat completion — the check ``--probe`` does not perform."""
    key = os.environ.get(target.api_key_env, "") if target.api_key_env else ""
    if not key and not is_loopback(target.base_url):
        return {
            "ok": False,
            "detail": f"环境变量 {target.api_key_env} 未设置，无法握手",
            "credential": "missing",
        }
    url = f"{target.base_url.rstrip('/')}/chat/completions"
    body = json.dumps(
        {
            "model": target.model,
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 1,
            "temperature": 0,
        }
    ).encode()
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    request = urllib.request.Request(url, data=body, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=HANDSHAKE_TIMEOUT) as response:
            payload = json.loads(response.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:400]
        return {"ok": False, "status": exc.code, "detail": f"端点返回 {exc.code}：{detail}"}
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        return {"ok": False, "detail": f"{type(exc).__name__}: {exc}"}
    choice = (payload.get("choices") or [{}])[0]
    return {
        "ok": True,
        "status": 200,
        "model": payload.get("model") or target.model,
        "finish_reason": choice.get("finish_reason"),
        "credential": "present" if key else "loopback-none",
        "detail": "端点握手成功",
    }


def probe(target: Target) -> dict[str, Any]:
    suites = list_suites()
    checks: dict[str, Any] = {}
    if suites:
        suite = next((s for s in suites if s["task_count"]), suites[0])
        detail = suite_root(suite["suite_id"])
        first_task = ""
        if detail is not None:
            tasks = sorted(p.name for p in (detail / "tasks").iterdir() if p.is_dir())
            first_task = tasks[0] if tasks else ""
        if first_task:
            checks["config"] = _probe_config(target, suite["suite_id"], first_task)
    if target.kind == "http":
        checks["endpoint"] = _probe_endpoint(target)
    else:
        checks["endpoint"] = {
            "ok": True,
            "detail": "inproc 目标在本进程内运行，无需网络握手",
            "credential": "none",
        }
    return {
        "target_id": target.id,
        "kind": target.kind,
        "ok": all(item.get("ok") for item in checks.values()),
        "checks": checks,
    }


__all__ = ["probe"]
