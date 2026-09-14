from __future__ import annotations

import hashlib
import json
import shlex
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from redsentinel.attacks.engine.ingestion.deep import DockerTracePlan
from redsentinel.runtime.engine.sandbox.docker.capture import (
    DEFAULT_MAX_OUTPUT_BYTES,
    BoundedCaptureResult,
    run_bounded_capture,
)


class TrajectoryArtifacts(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trajectory_path: str | None = None
    stdout_path: str | None = None
    stderr_path: str | None = None
    audit_path: str | None = None
    container_id: str | None = None
    exit_code: int | None = None
    duration_ms: float = 0.0
    error: str | None = None


class DockerTraceExecutor:
    def __init__(
        self,
        plan: DockerTracePlan,
        *,
        output_dir: str | Path | None = None,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    ) -> None:
        self.plan = plan
        self.output_dir = Path(output_dir) if output_dir else Path(tempfile.mkdtemp())
        self.max_output_bytes = max_output_bytes
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def run(self) -> TrajectoryArtifacts:
        start_time = time.time()
        artifacts = TrajectoryArtifacts()
        try:
            result = self._execute_container()
            artifacts = self._collect_artifacts(result)
        except Exception as exc:
            artifacts.error = str(exc)
        artifacts.duration_ms = (time.time() - start_time) * 1000
        return artifacts

    def _execute_container(self) -> BoundedCaptureResult:
        return run_bounded_capture(
            self._build_docker_args(),
            timeout=300,
            max_output_bytes=self.max_output_bytes,
            stdout_path=self.output_dir / "stdout.log",
            stderr_path=self.output_dir / "stderr.log",
        )

    def _build_docker_args(self) -> list[str]:
        args = ["docker", "run", "--rm"]

        if self.plan.network_policy == "disabled":
            args.append("--network=none")
        elif self.plan.network_policy == "internal_only":
            args.append("--network=internal")

        for mount_path in self.plan.read_only_mounts:
            host_path = Path(mount_path).resolve()
            container_path = f"/workspace/{host_path.name}"
            args.extend(["-v", f"{host_path}:{container_path}:ro"])

        args.extend(["-e", f"RED_SENTINEL_AGENT_NAME={self.plan.agent_name}"])
        args.extend(["-e", "RED_SENTINEL_OUTPUT_DIR=/tmp/artifacts"])
        args.extend(
            [
                "-e",
                f"RED_SENTINEL_NODE_TARGETS={json.dumps(self.plan.node_targets, ensure_ascii=False, separators=(',', ':'))}",
            ]
        )

        if self.plan.node_targets:
            args.extend(["-e", f"RED_SENTINEL_NODE_TARGET={self.plan.node_targets[0]}"])

        args.append(self.plan.docker_image)
        if self.plan.adapter_entrypoint:
            args.extend(shlex.split(self.plan.adapter_entrypoint))
        return args

    def _collect_artifacts(self, result: BoundedCaptureResult) -> TrajectoryArtifacts:
        artifacts = TrajectoryArtifacts(exit_code=result.returncode)

        artifacts.stdout_path = str(result.stdout_path)
        artifacts.stderr_path = str(result.stderr_path)
        artifacts.error = result.error

        trajectory_path = self.output_dir / "trajectory.jsonl"
        stdout = result.stdout_text()
        if stdout and not result.stdout_truncated and not result.timed_out:
            self._parse_stdout_to_trajectory(stdout, trajectory_path)
            artifacts.trajectory_path = str(trajectory_path)

        audit_path = self.output_dir / "audit.log"
        self._generate_audit_log(
            audit_path,
            {
                "trajectory": artifacts.trajectory_path,
                "stdout": artifacts.stdout_path,
                "stderr": artifacts.stderr_path,
            },
        )
        artifacts.audit_path = str(audit_path)

        return artifacts

    def _parse_stdout_to_trajectory(self, stdout: str, output_path: Path) -> None:
        lines = stdout.strip().split("\n")
        events: list[dict[str, Any]] = []
        for line in lines:
            if line.strip():
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    events.append({"type": "raw_output", "content": line})

        with output_path.open("w", encoding="utf-8") as f:
            for event in events:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")

    def _generate_audit_log(self, output_path: Path, artifact_paths: dict[str, str | Path | None]) -> None:
        audit_entries = [
            {
                "timestamp": time.time(),
                "event_type": "docker_trace_start",
                "agent_name": self.plan.agent_name,
                "docker_image": self.plan.docker_image,
                "network_policy": self.plan.network_policy,
                "read_only_mounts": self.plan.read_only_mounts,
                "trace_id": str(uuid.uuid4()),
            },
            {
                "timestamp": time.time(),
                "event_type": "docker_trace_complete",
                "artifacts": [
                    {"name": name, "hash": self._file_hash(artifact_paths.get(name))}
                    for name in ["trajectory", "stdout", "stderr"]
                ],
            },
        ]

        with output_path.open("w", encoding="utf-8") as f:
            for entry in audit_entries:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def _file_hash(self, path: str | Path | None) -> str | None:
        if not path or not Path(path).exists():
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()


def execute_docker_trace(plan: DockerTracePlan, *, output_dir: str | Path | None = None) -> TrajectoryArtifacts:
    executor = DockerTraceExecutor(plan, output_dir=output_dir)
    return executor.run()
