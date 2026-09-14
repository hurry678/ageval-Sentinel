"""Offline attack-case validation runner shared by scenario entry points."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from redsentinel.attacks.datasets import load_attack_cases


ROOT = Path(__file__).resolve().parents[4]


@dataclass(frozen=True)
class ScenarioConfig:
    scenario: str
    case_path: Path


def run_scenario_cli(config: ScenarioConfig, argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=f"{config.scenario} attack scenario runner")
    parser.add_argument("--dry-run", action="store_true", help="Validate and preview cases without calling a target model")
    parser.add_argument("--cases", type=Path, default=config.case_path, help="Override the scenario cases JSONL path")
    args = parser.parse_args(argv)

    if not args.dry_run:
        parser.error("live attack execution requires an explicit target runner; use --dry-run for offline validation")

    cases = load_cases(args.cases)
    summary = {
        "scenario": config.scenario,
        "mode": "dry-run",
        "cases_path": str(args.cases),
        "case_count": len(cases),
        "case_ids": [case["id"] for case in cases],
        "payload_ids": [case["payload_id"] for case in cases],
        "metrics": {
            "asr": None,
            "status": "not_evaluated",
            "reason": "dry-run validates case metadata only and does not call a target model",
        },
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def load_cases(path: Path) -> list[dict]:
    return load_attack_cases(path, repository_root=ROOT)


__all__ = ["ROOT", "ScenarioConfig", "load_cases", "run_scenario_cli"]
