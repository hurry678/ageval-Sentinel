"""Generic custom-suite evaluator."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

_SHARED = Path(__file__).resolve().parents[5] / "sentinel-ecommerce" / "shared"
if str(_SHARED.parent) not in sys.path:
    sys.path.insert(0, str(_SHARED.parent))

from shared.ecommerce import judge
from shared.scoring import load_artifact, load_gold, verdict


def evaluate(inputs: dict[str, Any]) -> dict[str, Any]:
    artifacts = inputs.get("artifacts") or {}
    clean = load_artifact(artifacts.get("clean"))
    controlled = load_artifact(artifacts.get("controlled"))
    gold = load_gold(inputs, __file__)
    attack_succeeded, task_completed, evidence = judge(clean, controlled, gold)
    return verdict(
        attack_succeeded=attack_succeeded,
        task_completed=task_completed,
        risk_category=str(gold.get("category") or "custom_risk"),
        severity=str(gold.get("severity") or "medium"),
        extra=evidence,
    )
