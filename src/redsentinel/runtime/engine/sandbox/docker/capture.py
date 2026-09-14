from __future__ import annotations

import subprocess
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Sequence

DEFAULT_MAX_OUTPUT_BYTES = 1024 * 1024
_CHUNK_SIZE = 64 * 1024


@dataclass(frozen=True)
class BoundedCaptureResult:
    args: list[str]
    returncode: int | None
    stdout_path: Path
    stderr_path: Path
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    timed_out: bool = False
    error: str | None = None

    def stdout_text(self) -> str:
        return self.stdout_path.read_bytes().decode("utf-8", errors="replace")

    def stderr_text(self) -> str:
        return self.stderr_path.read_bytes().decode("utf-8", errors="replace")


@dataclass
class _CaptureTarget:
    path: Path
    max_bytes: int
    bytes_written: int = 0
    truncated: bool = False


def run_bounded_capture(
    args: Sequence[str],
    *,
    timeout: float,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    stdout_path: str | Path | None = None,
    stderr_path: str | Path | None = None,
) -> BoundedCaptureResult:
    if max_output_bytes < 1:
        raise ValueError("max_output_bytes must be positive")

    stdout_file, stderr_file = _output_paths(stdout_path, stderr_path)
    stdout_file.parent.mkdir(parents=True, exist_ok=True)
    stderr_file.parent.mkdir(parents=True, exist_ok=True)

    command = list(args)
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as exc:
        stdout_file.write_bytes(b"")
        stderr_file.write_bytes(b"")
        return BoundedCaptureResult(
            args=command,
            returncode=None,
            stdout_path=stdout_file,
            stderr_path=stderr_file,
            error=f"failed to start process: {exc}",
        )

    # Drain to bounded files instead of communicate() so noisy containers cannot exhaust process memory.
    stdout_target = _CaptureTarget(stdout_file, max_output_bytes)
    stderr_target = _CaptureTarget(stderr_file, max_output_bytes)
    threads = [
        threading.Thread(target=_drain_stream, args=(process.stdout, stdout_target), daemon=True),
        threading.Thread(target=_drain_stream, args=(process.stderr, stderr_target), daemon=True),
    ]
    for thread in threads:
        thread.start()

    timed_out = False
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        returncode = process.wait()

    for thread in threads:
        thread.join()

    errors: list[str] = []
    if timed_out:
        errors.append(f"process timed out after {timeout:g} seconds")
    if stdout_target.truncated:
        errors.append(f"stdout exceeded {max_output_bytes} bytes")
    if stderr_target.truncated:
        errors.append(f"stderr exceeded {max_output_bytes} bytes")

    return BoundedCaptureResult(
        args=command,
        returncode=returncode,
        stdout_path=stdout_file,
        stderr_path=stderr_file,
        stdout_truncated=stdout_target.truncated,
        stderr_truncated=stderr_target.truncated,
        timed_out=timed_out,
        error="; ".join(errors) or None,
    )


def _output_paths(stdout_path: str | Path | None, stderr_path: str | Path | None) -> tuple[Path, Path]:
    if stdout_path is not None and stderr_path is not None:
        return Path(stdout_path), Path(stderr_path)
    temp_dir = Path(tempfile.mkdtemp(prefix="red-sentinel-docker-"))
    return (
        Path(stdout_path) if stdout_path is not None else temp_dir / "stdout.log",
        Path(stderr_path) if stderr_path is not None else temp_dir / "stderr.log",
    )


def _drain_stream(stream: IO[bytes] | None, target: _CaptureTarget) -> None:
    if stream is None:
        target.path.write_bytes(b"")
        return

    with stream, target.path.open("wb") as output:
        for chunk in iter(lambda: stream.read(_CHUNK_SIZE), b""):
            remaining = target.max_bytes - target.bytes_written
            if remaining <= 0:
                target.truncated = True
                continue
            output.write(chunk[:remaining])
            target.bytes_written += min(len(chunk), remaining)
            if len(chunk) > remaining:
                target.truncated = True
