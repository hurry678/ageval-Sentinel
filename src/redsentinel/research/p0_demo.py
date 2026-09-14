"""Build the evidence summary for the deterministic P0 interview demo."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_EXPECTED_RISKS = ("memory_poisoning", "tool_tampering", "goal_perturbation")


def write_p0_demo_summary(
    *,
    output_root: Path,
    seed: int,
    doctor_checks: dict[str, str | bool],
    profile_path: Path,
    evaluation_dir: Path,
    evaluation_evidence_index: Path,
    evolution_dir: Path,
    evolution_evidence_index: Path,
) -> Path:
    """Write one machine-readable index over existing P0 demo artifacts."""
    report_path = evaluation_dir / "report.json"
    audit_refs_path = evaluation_dir / "audit_refs.json"
    evolution_result_path = evolution_dir / "raw-result-v1.json"
    report = _read_json(report_path)
    audits = _read_json(audit_refs_path)
    evolution_result = _read_json(evolution_result_path)

    trajectory_evidence = _trajectory_evidence(
        report=report,
        audits=audits,
        report_path=report_path,
        audit_refs_path=audit_refs_path,
    )
    missing = sorted(set(_EXPECTED_RISKS) - {item["risk_type"] for item in trajectory_evidence})
    if missing:
        raise ValueError(f"P0 demo report is missing expected risk evidence: {', '.join(missing)}")

    evaluation_metrics = report.get("metrics", {})
    evolution_metrics = evolution_result.get("metrics", {})
    payload = {
        "schema_version": "p0-demo-summary-v1",
        "stage": "P0",
        "status": "completed",
        "execution_mode": "offline_fixture",
        "seed": seed,
        "environment": doctor_checks,
        "profile": {
            "path": str(profile_path),
            "source": "examples/agents/simple_agent/redsentinel.yaml",
        },
        "metrics": {
            "paired_cases": {
                "passed": evaluation_metrics.get("passed_pairs"),
                "total": evaluation_metrics.get("total_attack_pairs"),
            },
            "asr_before_defense": evaluation_metrics.get("asr_before_defense"),
            "asr_after_defense": evaluation_metrics.get("asr_after_defense"),
            "false_positive_rate": evaluation_metrics.get("false_positive_rate"),
            "audit_chain_valid": evaluation_metrics.get("audit_chain_valid"),
            "coevolution_asr_initial": evolution_metrics.get("asr_initial"),
            "coevolution_asr_final": evolution_metrics.get("asr_final"),
            "coevolution_rounds": evolution_metrics.get("convergence_rounds"),
            "business_success_rate": {
                "status": "not_evaluated",
                "reason": "The P0 fixture measures benign false positives, not end-to-end business success.",
            },
            "overhead": {
                "status": "not_evaluated",
                "reason": "The P0 fixture does not provide a controlled latency or token-cost baseline.",
            },
        },
        "trajectory_evidence": trajectory_evidence,
        "evidence_indexes": {
            "evaluation": str(evaluation_evidence_index),
            "evolution": str(evolution_evidence_index),
        },
        "artifact_roots": {
            "evaluation": str(evaluation_dir),
            "evolution": str(evolution_dir),
        },
        "claim_boundary": {
            "allowed": [
                "deterministic offline pipeline smoke",
                "three paired trajectory-level risk cases",
                "seven-category co-evolution convergence smoke",
            ],
            "forbidden": [
                "real Agent effectiveness",
                "cross-Agent generalization",
                "paper-level statistical significance",
            ],
        },
    }
    output_path = output_root / "p0-demo-summary-v1.json"
    _write_json(output_path, payload)
    return output_path


def _trajectory_evidence(
    *,
    report: dict[str, Any],
    audits: dict[str, Any],
    report_path: Path,
    audit_refs_path: Path,
) -> list[dict[str, Any]]:
    audit_by_pair = {
        str(item.get("pair_id")): item
        for item in audits.get("references", [])
        if isinstance(item, dict)
    }
    evidence: list[dict[str, Any]] = []
    for index, item in enumerate(report.get("damage_attribution", [])):
        if not isinstance(item, dict) or item.get("risk_type") not in _EXPECTED_RISKS:
            continue
        pair_id = str(item.get("pair_id"))
        audit = audit_by_pair.get(pair_id, {})
        evidence.append(
            {
                "risk_type": item.get("risk_type"),
                "pair_id": pair_id,
                "detector_decision": item.get("detector_decision"),
                "detector_score": item.get("detector_score"),
                "blocked_by_defense": item.get("blocked_by_defense"),
                "passed": item.get("passed"),
                "attribution": item.get("attribution", []),
                "audit_integrity": audit.get("integrity"),
                "evidence_refs": [
                    f"{report_path}#/damage_attribution/{index}",
                    f"{audit_refs_path}#/references/{_audit_index(audits, pair_id)}",
                    str(audit.get("audit_log_path", "")),
                ],
            }
        )
    return sorted(evidence, key=lambda item: _EXPECTED_RISKS.index(str(item["risk_type"])))


def _audit_index(audits: dict[str, Any], pair_id: str) -> int:
    for index, item in enumerate(audits.get("references", [])):
        if isinstance(item, dict) and str(item.get("pair_id")) == pair_id:
            return index
    raise ValueError(f"missing audit reference for pair: {pair_id}")


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError(f"required P0 demo artifact does not exist: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"required P0 demo artifact must contain a JSON object: {path}")
    return payload


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


__all__ = ["write_p0_demo_summary"]
