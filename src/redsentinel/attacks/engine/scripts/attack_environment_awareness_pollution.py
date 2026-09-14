from __future__ import annotations

import sys
from pathlib import Path
from typing import Sequence

try:
    from ._scenario_dry_run import ROOT, ScenarioConfig, run_scenario_cli
except ImportError:  # pragma: no cover - supports direct file execution.
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from redsentinel.attacks.engine.scripts._scenario_dry_run import ROOT, ScenarioConfig, run_scenario_cli


CONFIG = ScenarioConfig(
    scenario="environment_awareness_pollution",
    case_path=ROOT / "docs" / "attack_scenarios" / "environment_awareness_pollution" / "cases.jsonl",
)


def main(argv: Sequence[str] | None = None) -> int:
    return run_scenario_cli(CONFIG, argv)


if __name__ == "__main__":
    raise SystemExit(main())
