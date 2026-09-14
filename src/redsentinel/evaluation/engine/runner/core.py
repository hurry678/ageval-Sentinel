from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from redsentinel.runtime.engine.sandbox.config import ScenarioConfig
from redsentinel.runtime.engine.sandbox.run import run_scenario as run_sandbox_scenario


@dataclass(frozen=True)
class RunResult:
    experiment_id: str
    seed: int
    run_id: str
    output_dir: Path
    trajectory: dict[str, Any]
    metadata: dict[str, Any]


class ExperimentRunner:
    """Serial experiment runner with structured result storage."""

    def __init__(self, results_root: str | Path = "runs") -> None:
        self.results_root = Path(results_root)

    def run_scenario(self, path: str | Path) -> RunResult:
        scenario_path = Path(path)
        config = ScenarioConfig.from_yaml(scenario_path)
        if config.runner.parallel:
            raise NotImplementedError("Parallel runner execution is not implemented in the MVP.")

        started_at = datetime.now(tz=timezone.utc)
        trajectory = run_sandbox_scenario(str(scenario_path))
        ended_at = datetime.now(tz=timezone.utc)
        run_id = self._run_id()
        output_dir = (
            self.results_root
            / config.experiment_id
            / f"seed_{config.reproducibility.seed}"
            / run_id
        )
        output_dir.mkdir(parents=True, exist_ok=False)

        metadata = {
            "experiment_id": config.experiment_id,
            "seed": config.reproducibility.seed,
            "framework": config.agent.framework,
            "run_id": run_id,
            "scenario_path": str(scenario_path),
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "output_dir": str(output_dir),
        }

        shutil.copyfile(scenario_path, output_dir / "scenario.yaml")
        self._write_json(output_dir / "trajectory.json", trajectory)
        self._write_json(output_dir / "metadata.json", metadata)

        return RunResult(
            experiment_id=config.experiment_id,
            seed=config.reproducibility.seed,
            run_id=run_id,
            output_dir=output_dir,
            trajectory=trajectory,
            metadata=metadata,
        )

    def run_many(self, paths: list[str | Path]) -> list[RunResult]:
        return [self.run_scenario(path) for path in paths]

    def _run_id(self) -> str:
        timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        return f"{timestamp}-{uuid4().hex[:8]}"

    def _write_json(self, path: Path, payload: dict[str, Any]) -> None:
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


def diff_trajectories(baseline: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    baseline_steps = baseline.get("steps", [])
    candidate_steps = candidate.get("steps", [])
    baseline_step_types = [step.get("step_type") for step in baseline_steps]
    candidate_step_types = [step.get("step_type") for step in candidate_steps]
    baseline_tools = _tool_call_sequence(baseline_steps)
    candidate_tools = _tool_call_sequence(candidate_steps)
    baseline_tool_responses = _tool_response_sequence(baseline_steps)
    candidate_tool_responses = _tool_response_sequence(candidate_steps)
    baseline_memory_ops = _memory_op_sequence(baseline_steps)
    candidate_memory_ops = _memory_op_sequence(candidate_steps)
    baseline_first_input = _first_llm_input(baseline_steps)
    candidate_first_input = _first_llm_input(candidate_steps)
    baseline_final = _final_llm_output(baseline_steps)
    candidate_final = _final_llm_output(candidate_steps)
    baseline_labels = _injection_labels(baseline)
    candidate_labels = _injection_labels(candidate)

    return {
        "step_count": {
            "baseline": len(baseline_steps),
            "candidate": len(candidate_steps),
            "changed": len(baseline_steps) != len(candidate_steps),
        },
        "step_type_sequence": {
            "baseline": baseline_step_types,
            "candidate": candidate_step_types,
            "changed": baseline_step_types != candidate_step_types,
        },
        "tool_call_sequence": {
            "baseline": baseline_tools,
            "candidate": candidate_tools,
            "changed": baseline_tools != candidate_tools,
        },
        "tool_response_sequence": {
            "baseline": baseline_tool_responses,
            "candidate": candidate_tool_responses,
            "changed": baseline_tool_responses != candidate_tool_responses,
        },
        "memory_op_sequence": {
            "baseline": baseline_memory_ops,
            "candidate": candidate_memory_ops,
            "changed": baseline_memory_ops != candidate_memory_ops,
        },
        "first_llm_input": {
            "baseline": baseline_first_input,
            "candidate": candidate_first_input,
            "changed": baseline_first_input != candidate_first_input,
        },
        "final_llm_output": {
            "baseline": baseline_final,
            "candidate": candidate_final,
            "changed": baseline_final != candidate_final,
        },
        "injection_labels": {
            "baseline": baseline_labels,
            "candidate": candidate_labels,
            "changed": baseline_labels != candidate_labels,
        },
    }


def _tool_call_sequence(steps: list[dict[str, Any]]) -> list[str]:
    return [
        step["tool_call"]["name"]
        for step in steps
        if step.get("step_type") == "tool_call" and "tool_call" in step
    ]


def _tool_response_sequence(steps: list[dict[str, Any]]) -> list[Any]:
    return [
        step["tool_call"]["response"]
        for step in steps
        if step.get("step_type") == "tool_call" and "tool_call" in step
    ]


def _memory_op_sequence(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        op
        for step in steps
        for op in step.get("memory_ops", [])
    ]


def _first_llm_input(steps: list[dict[str, Any]]) -> list[dict[str, Any]] | None:
    for step in steps:
        llm = step.get("llm")
        if llm:
            return llm.get("input_messages")
    return None


def _final_llm_output(steps: list[dict[str, Any]]) -> str | None:
    for step in reversed(steps):
        llm = step.get("llm")
        if llm and llm.get("output_content") is not None:
            return llm.get("output_content")
    return None


def _injection_labels(trajectory: dict[str, Any]) -> list[str]:
    injections = trajectory.get("metadata", {}).get("injections", [])
    return [item.get("label") for item in injections if item.get("label") is not None]
