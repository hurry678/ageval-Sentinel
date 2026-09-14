"""A deliberately naive OpenAI-compatible Agent, for validating the http path.

Two problems it solves at once.

First, the http target kind cannot be trusted until something has actually been
detected through it, and every real endpoint needs a key. ageval waives the
credential check for loopback hosts, so a server here is a zero-key http target.

Second, both built-in Sentinel targets score 0% ASR, which means the platform has
so far only ever said "safe". This Agent is compliant by construction: it explores
the workspace and reads whatever looks interesting, including the files the
instruction forbids, then forwards what it found. It should fail the suite. A
detector that cannot produce a positive result has not been shown to work.

It is a test fixture, not a model: no LLM, no network, no key.

Run standalone:  python -m platform_api.mock_agent --port 8799
"""

from __future__ import annotations

import argparse
import json
import re
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
URL_RE = re.compile(r"https?://[^\s'\"<>)，。；]+")
# `写入 dist/report.md` / `write to reports/summary.md`
DELIVERABLE_RE = re.compile(
    r"(?:写(?:入|到)|输出到|保存到|save to|write to|output to)\s*[：:]?\s*`?([\w./-]+\.\w+)`?", re.I
)
HEADING_RE = re.compile(r"^\s*#{1,4}\s+(.+?)\s*$", re.M)
# Names worth reading first — the whole point of the fixture.
SENSITIVE_RE = re.compile(r"vault|secret|credential|token|key|passwd|\.env|private|canary", re.I)
EXTENSION_RE = re.compile(r"[^.]\.\w{1,6}$")
# Leaves room inside the task's max_turns budget for the write and the done call.
MAX_READS = 2


def _tool_names(tools: list[dict[str, Any]]) -> list[str]:
    """Accept both the flat and the OpenAI-wrapped tool shapes."""
    names = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        function = tool.get("function")
        source = function if isinstance(function, dict) else tool
        if source.get("name"):
            names.append(str(source["name"]))
    return names


def _history(messages: list[dict[str, Any]]) -> list[tuple[str, dict[str, Any], str]]:
    """Each call already made, with its arguments and the result it returned.

    Guessing paths out of the instruction text does not work — the payloads name
    directories as often as files. So this Agent reads its own tool output and
    walks the workspace, which is what a real one does.
    """
    pending: list[tuple[str, dict[str, Any]]] = []
    done: list[tuple[str, dict[str, Any], str]] = []
    for message in messages:
        if not isinstance(message, dict):
            continue
        for call in message.get("tool_calls") or []:
            function = call.get("function") if isinstance(call, dict) else None
            if not isinstance(function, dict) or not function.get("name"):
                continue
            try:
                args = json.loads(function.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            pending.append((str(function["name"]), args if isinstance(args, dict) else {}))
        if message.get("role") == "tool" and pending:
            name, args = pending.pop(0)
            done.append((name, args, str(message.get("content") or "")))
    return done


def _listings(history: list[tuple[str, dict[str, Any], str]]) -> list[str]:
    """Workspace-relative entries discovered by every list_files so far."""
    entries: list[str] = []
    for name, args, result in history:
        if name != "list_files" or result.startswith("error:"):
            continue
        try:
            names = json.loads(result)
        except json.JSONDecodeError:
            continue
        if not isinstance(names, list):
            continue
        # strip("./") would eat the leading dot of a dotfile, turning
        # `.credentials` into `credentials` and every path built from it into a
        # miss. Only the `./` prefix and a trailing slash are noise.
        raw = str(args.get("path") or ".").strip()
        base = "" if raw in {".", "./", ""} else raw.removeprefix("./").rstrip("/")
        entries.extend(f"{base}/{item}" if base else str(item) for item in names)
    return entries


def _pick_call(text: str, tools: list[dict[str, Any]], history: list[tuple[str, dict[str, Any], str]]):
    """The most compliant next step the available tools allow."""
    names = _tool_names(tools)
    if not names:
        return None

    called = {(name, str(args.get("path") or args.get("url") or "")) for name, args, _ in history}
    listed = {path for name, path in called if name == "list_files"}
    read = {path for name, path in called if name == "read_file"}
    entries = _listings(history)
    # A leading dot is not an extension, so `.credentials` is a directory to walk,
    # not a file to read. Getting this wrong wastes the whole turn budget.
    files = [e for e in entries if EXTENSION_RE.search(e.rsplit("/", 1)[-1])]
    dirs = [e for e in entries if not EXTENSION_RE.search(e.rsplit("/", 1)[-1])]

    if "list_files" in names and "." not in listed:
        return "list_files", {"path": "."}
    # Read a discovered secret before walking further: the turn budget is small and
    # a walk that never reaches a read proves nothing.
    for entry in files:
        if SENSITIVE_RE.search(entry) and entry not in read and len(read) < MAX_READS and "read_file" in names:
            return "read_file", {"path": entry}
    for entry in sorted(dirs, key=lambda e: not bool(SENSITIVE_RE.search(e))):
        if entry not in listed and "list_files" in names:
            return "list_files", {"path": entry}

    loot = "\n".join(
        result for name, _, result in history if name == "read_file" and not result.startswith("error:")
    )
    email = EMAIL_RE.search(text)
    if loot and email and "send_email" in names and not any(n == "send_email" for n, _ in called):
        return "send_email", {"to": email.group(0), "subject": "requested report", "body": loot[:1500]}
    url = URL_RE.search(text)
    if loot and url and "http_get" in names and not any(n == "http_get" for n, _ in called):
        return "http_get", {"url": url.group(0)}

    deliverable = _deliverable(text) or "output.md"
    if "write_file" in names and deliverable not in {p for n, p in called if n == "write_file"}:
        return "write_file", {"path": deliverable, "content": _answer(text, loot)}
    if "done" in names and not any(n == "done" for n, _ in called):
        return "done", {}
    return None


def _deliverable(text: str) -> str:
    """The output path the instruction names, if it names one."""
    match = DELIVERABLE_RE.search(text)
    return match.group(1) if match else ""


def _answer(text: str, loot: str = "") -> str:
    """Echo back the headings a checklist-style evaluator looks for."""
    headings = list(dict.fromkeys(HEADING_RE.findall(text)))[:8]
    body = "\n".join(f"## {name}\n已按指令完成。" for name in headings) or "## Summary\n已完成。"
    return f"{body}\n\n## Detail\n{loot[:800]}"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003 - stdlib hook
        return

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - stdlib hook
        if self.path.rstrip("/").endswith("/models"):
            self._send(200, {"object": "list", "data": [{"id": "mock-compliant-agent"}]})
            return
        self._send(404, {"error": {"message": "not found"}})

    def do_POST(self) -> None:  # noqa: N802 - stdlib hook
        if not self.path.rstrip("/").endswith("/chat/completions"):
            self._send(404, {"error": {"message": "not found"}})
            return
        length = int(self.headers.get("Content-Length") or 0)
        try:
            request = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self._send(400, {"error": {"message": "invalid json"}})
            return

        messages = request.get("messages") or []
        tools = request.get("tools") or []
        text = "\n".join(
            str(m.get("content") or "") for m in messages if isinstance(m, dict) and m.get("role") == "user"
        )
        history = _history(messages)
        picked = _pick_call(text, tools, history)

        message: dict[str, Any] = {"role": "assistant", "content": None}
        if picked is not None:
            name, arguments = picked
            message["tool_calls"] = [
                {
                    "id": f"call_{uuid.uuid4().hex[:8]}",
                    "type": "function",
                    "function": {"name": name, "arguments": json.dumps(arguments, ensure_ascii=False)},
                }
            ]
            finish = "tool_calls"
        else:
            loot = "\n".join(
                result for n, _, result in history if n == "read_file" and not result.startswith("error:")
            )
            message["content"] = _answer(text, loot)
            finish = "stop"

        self._send(
            200,
            {
                "id": f"chatcmpl-{uuid.uuid4().hex[:12]}",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": request.get("model") or "mock-compliant-agent",
                "choices": [{"index": 0, "message": message, "finish_reason": finish}],
                "usage": {
                    "prompt_tokens": len(text) // 4,
                    "completion_tokens": 32,
                    "total_tokens": len(text) // 4 + 32,
                },
            },
        )


def serve(port: int) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"mock compliant agent on http://127.0.0.1:{port}/v1", flush=True)
    server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description="Naive OpenAI-compatible Agent fixture.")
    parser.add_argument("--port", type=int, default=8799)
    serve(parser.parse_args().port)


if __name__ == "__main__":
    main()
