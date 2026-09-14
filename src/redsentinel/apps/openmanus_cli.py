"""Run the pinned real OpenManus benchmark."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import Sequence

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_IMAGE = "redsentinel/openmanus-real:local"


def main(argv: Sequence[str] | None = None) -> int:
    """Run a real OpenManus evaluation with explicit runtime checks."""

    args = _parse_openmanus_args(argv)
    if args.require_real:
        _require_real_environment(args.image, require_image=not args.build_image)
    _require_vendor_source()
    if args.build_image:
        _build_image(args.image)
        if args.require_real:
            _require_docker_image(args.image)

    from redsentinel.application.contracts import AgentRegistration, EvaluationRequest
    from redsentinel.application.engine.service import OPENMANUS_BENCHMARK_ID, ProductEvaluationService

    os.environ["RED_SENTINEL_OPENMANUS_IMAGE"] = args.image
    service = ProductEvaluationService(storage_root=args.storage_root)
    registration = service.register_agent(
        AgentRegistration(
            tenant_id=args.tenant,
            username=args.tenant,
            agent_id=args.agent_id,
            name="OpenManus Official Real Runtime",
            domain="general",
            integration_type="source",
            framework="OpenManus",
            adapter_type="openmanus",
            status="ready",
            data_boundary={
                "deployment": "docker_real_runtime",
                "runtime_mode": "openmanus_real",
                "no_real_external_attack": True,
            },
        )
    )
    status = service.run_evaluation(
        EvaluationRequest(
            tenant_id=args.tenant,
            agent_id=registration.agent_id,
            benchmark_id=args.benchmark,
            benchmark_version=args.version,
            mode="openmanus_real",
            defense_enabled=True,
        )
    )
    report = service.get_report(status.report_id or status.evaluation_id, tenant_id=args.tenant)
    summary = report.summary
    print("OPENMANUS_REAL_RUNTIME=true")
    print(f"SIMULATED={str(summary.get('simulated')).lower()}")
    print(f"REPORT_PATH={report.artifacts.report_path}")
    print(f"BENCHMARK={report.benchmark_id or OPENMANUS_BENCHMARK_ID}")
    print(f"BASELINE_ASR={summary.get('baseline_attack_success_rate')}")
    print(f"GUARDED_ASR={report.attack_success_rate}")
    print(f"FPR={report.false_positive_rate}")
    print(f"DSR={report.defense_success_rate}")
    print(f"REAL_TOOL_EXECUTIONS={summary.get('real_tool_execution_count')}")
    print(f"BLOCKED_TOOL_EXECUTIONS={summary.get('blocked_tool_execution_count')}")
    print(f"BASELINE_REFUSALS={summary.get('baseline_refusal_count')}")
    return 0 if report.status == "complete" and summary.get("real_runtime") is True else 1


def _parse_openmanus_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run real OpenManus benchmark under RedSentinel.")
    parser.add_argument("--build-image", action="store_true")
    parser.add_argument("--require-real", action="store_true")
    parser.add_argument("--image", default=DEFAULT_IMAGE)
    parser.add_argument("--storage-root", default="runs/product")
    parser.add_argument("--tenant", default="platform-admin")
    parser.add_argument("--agent-id", default="openmanus_official")
    parser.add_argument("--benchmark", default="openmanus-security-v0.1")
    parser.add_argument("--version", default="v0.2")
    return parser.parse_args(None if argv is None else list(argv))


def _require_real_environment(image: str, *, require_image: bool = True) -> None:
    missing = [name for name in ("OPENAI_API_KEY", "OPENAI_BASE_URL", "OPENAI_MODEL") if not os.environ.get(name)]
    if missing:
        raise RuntimeError(f"Missing required environment variables: {', '.join(missing)}")
    subprocess.run(["docker", "version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if require_image:
        _require_docker_image(image)


def _require_docker_image(image: str) -> None:
    result = subprocess.run(
        ["docker", "image", "inspect", image],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(f"OpenManus Docker image not found or unavailable: {image}. {detail}")


def _require_vendor_source() -> None:
    required = [
        REPO_ROOT / "third_party" / "OpenManus" / "upstream" / "main.py",
        REPO_ROOT / "third_party" / "OpenManus" / "upstream" / "app" / "agent" / "toolcall.py",
        REPO_ROOT / "third_party" / "OpenManus" / "upstream" / "requirements.txt",
    ]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        raise RuntimeError(f"OpenManus vendored source is incomplete: {', '.join(missing)}")


def _build_image(image: str) -> None:
    subprocess.run(
        ["docker", "build", "-f", "infra/openmanus/Dockerfile", "-t", image, "."],
        cwd=REPO_ROOT,
        check=True,
    )


def openmanus_cli_boundary(argv: Sequence[str] | None = None) -> int:
    """Convert expected runtime failures into a stable process exit code."""

    try:
        return main(argv)
    except RuntimeError as exc:
        print(f"ERROR={exc}", file=sys.stderr)
        return 1


__all__ = [
    "DEFAULT_IMAGE",
    "_build_image",
    "_require_docker_image",
    "_require_real_environment",
    "_require_vendor_source",
    "openmanus_cli_boundary",
    "main",
]
