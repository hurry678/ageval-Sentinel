"""Shared harness for Sentinel security tasks.

One tool loop, one path guard, one trace shape. Task ``run.py`` only supplies
the workspace layout it wants and publishes the artifacts the evaluator reads.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

FILE_TOOLS: list[dict[str, Any]] = [
    {
        "name": "list_files",
        "description": "List files under a workspace-relative directory.",
        "parameters": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "read_file",
        "description": "Read a workspace-relative text file.",
        "parameters": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "write_file",
        "description": "Write text to a workspace-relative file.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "content": {"type": "string"},
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "done",
        "description": "Signal the task is finished.",
        "parameters": {"type": "object", "properties": {}},
    },
]

HTTP_TOOL: dict[str, Any] = {
    "name": "http_get",
    "description": "Fetch a URL and return the response body.",
    "parameters": {
        "type": "object",
        "properties": {"url": {"type": "string"}},
        "required": ["url"],
    },
}

SEND_TOOL: dict[str, Any] = {
    "name": "send_email",
    "description": "Send an email to a recipient.",
    "parameters": {
        "type": "object",
        "properties": {
            "to": {"type": "string"},
            "subject": {"type": "string"},
            "body": {"type": "string"},
        },
        "required": ["to", "body"],
    },
}


class Trace:
    """Everything the evaluator needs to decide whether the attack landed."""

    def __init__(self) -> None:
        self.tools_used: list[str] = []
        self.reads: list[str] = []
        self.writes: list[str] = []
        self.denied: list[str] = []
        self.urls: list[str] = []
        self.emails: list[dict[str, str]] = []
        self.turns = 0
        self.finished = False
        self.final_text = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "tools_used": self.tools_used,
            "reads": self.reads,
            "writes": self.writes,
            "denied": self.denied,
            "urls": self.urls,
            "emails": self.emails,
            "turns": self.turns,
            "finished": self.finished,
            "final_text": self.final_text[:4000],
        }


def safe_path(root: Path, raw: str) -> Path | None:
    """Confine *raw* to *root*. Returns None for escapes — the guard under test."""
    candidate = Path(raw)
    if candidate.is_absolute() or ".." in candidate.parts:
        return None
    resolved = (root / candidate).resolve()
    base = root.resolve()
    if resolved != base and base not in resolved.parents:
        return None
    return resolved


def run_file_tool(root: Path, name: str, args: dict[str, Any], trace: Trace) -> str:
    """Execute one file tool call, recording its effect on *trace*."""
    if name == "done":
        trace.finished = True
        return "acknowledged"
    if name == "http_get":
        url = str(args.get("url") or "")
        trace.urls.append(url)
        return f"error: network egress blocked for {url}"
    if name == "send_email":
        trace.emails.append(
            {
                "to": str(args.get("to") or ""),
                "subject": str(args.get("subject") or ""),
                "body": str(args.get("body") or "")[:2000],
            }
        )
        return "queued"

    raw_path = str(args.get("path") or "")
    target = safe_path(root, raw_path)
    if target is None:
        trace.denied.append(raw_path)
        return f"error: path outside workspace: {raw_path}"
    if name == "list_files":
        if not target.is_dir():
            return f"error: not a directory: {raw_path}"
        return json.dumps(sorted(p.name for p in target.iterdir()))
    if name == "read_file":
        if not target.is_file():
            return f"error: not a file: {raw_path}"
        trace.reads.append(raw_path)
        return target.read_text(encoding="utf-8")
    if name == "write_file":
        target.parent.mkdir(parents=True, exist_ok=True)
        content = str(args.get("content") or "")
        target.write_text(content, encoding="utf-8")
        trace.writes.append(raw_path)
        return f"wrote {len(content)} bytes"
    return f"error: unknown tool {name}"


async def tool_loop(
    session: Any,
    root: Path,
    prompt: str,
    *,
    tools: list[dict[str, Any]],
    max_turns: int,
    followups: list[str] | None = None,
) -> tuple[Trace, str | None]:
    """Drive *session* until ``done``, no tool calls, or *max_turns*.

    ``followups`` feeds extra user turns after the model stops calling tools —
    that is how multi-turn goal-drift pressure is applied. Returns the trace and
    an error reason (None on success).
    """
    messages: list[dict[str, Any]] = [{"role": "user", "content": prompt}]
    pending = list(followups or [])
    trace = Trace()

    for _ in range(max_turns):
        inv = await session.invoke(prompt, messages=messages, tools=tools)
        trace.turns += 1
        if not inv.get("ok"):
            return trace, str(inv.get("error") or "agent_invoke_failed")
        trace.final_text = str(inv.get("text") or "")
        calls = list(inv.get("tool_calls") or [])

        if not calls:
            if pending:
                messages.append({"role": "assistant", "content": trace.final_text or ""})
                messages.append({"role": "user", "content": pending.pop(0)})
                continue
            break

        messages.append(
            {
                "role": "assistant",
                "content": trace.final_text or None,
                "tool_calls": [
                    {
                        "id": call["id"],
                        "type": "function",
                        "function": {
                            "name": call["name"],
                            "arguments": json.dumps(call.get("arguments") or {}),
                        },
                    }
                    for call in calls
                ],
            }
        )
        for call in calls:
            name = str(call.get("name") or "")
            args = call.get("arguments") if isinstance(call.get("arguments"), dict) else {}
            trace.tools_used.append(name)
            content = run_file_tool(root, name, args, trace)[:4000]
            await session.record_observation(
                str(call.get("id") or ""), content=content, function_name=name
            )
            messages.append(
                {"role": "tool", "tool_call_id": call["id"], "content": content}
            )
        if trace.finished:
            if pending:
                trace.finished = False
                messages.append({"role": "user", "content": pending.pop(0)})
                continue
            break

    return trace, None


def profile_and_turns(ctx: Any, default_turns: int = 8) -> tuple[str, int]:
    models = ctx.params.get("models") if isinstance(ctx.params.get("models"), dict) else {}
    profile_id = str(ctx.params.get("active_profile") or models.get("default") or "solver")
    return profile_id, int(ctx.params.get("max_turns") or default_turns)
