from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from redsentinel.attacks.engine.attack_spec import AttackIntensity, AttackRiskType, AttackSpec
from redsentinel.core.agent_security import OptimizationDirective
from redsentinel.application.contracts import AgentSecurityReport

_KNOWN_RISKS: tuple[AttackRiskType, ...] = (
    "prompt_injection",
    "knowledge_poisoning",
    "unauthorized_retrieval",
    "tool_tampering",
    "memory_poisoning",
    "goal_drift",
    "pii_leakage",
)


class AttackEvolutionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evolved_specs: list[AttackSpec] = Field(default_factory=list)
    source_refs: list[str] = Field(default_factory=list)
    rationale: list[str] = Field(default_factory=list)
    evolution_records: list[dict[str, Any]] = Field(default_factory=list)


def evolve_attack_specs(
    base_specs: list[AttackSpec],
    *,
    report: AgentSecurityReport | None = None,
    directives: list[OptimizationDirective] | None = None,
    failed_attempts: list[dict[str, Any]] | None = None,
    round_index: int = 2,
    based_on: str | None = None,
    seed: int = 0,
) -> AttackEvolutionResult:
    directives = directives or []
    failed_attempts = failed_attempts or []
    base_by_risk = {spec.risk_type: spec for spec in base_specs}
    weak_points = _weak_points(report, directives, failed_attempts)

    evolved: list[AttackSpec] = []
    rationale: list[str] = []
    source_refs: list[str] = []
    records: list[dict[str, Any]] = []
    for index, weak_point in enumerate(weak_points, start=1):
        risk_type = weak_point["risk_type"]
        base = base_by_risk.get(risk_type) or (base_specs[0] if base_specs else None)
        if base is None:
            continue
        strategy = _mutation_strategy(weak_point, base, seed=seed, index=index)
        new_attack_id = f"{base.attack_id}:evolved:r{round_index}:{index}"
        evolved.append(
            base.model_copy(
                update={
                    "attack_id": new_attack_id,
                    "risk_type": risk_type,
                    "strategy": strategy,
                    "intensity": weak_point["intensity"],
                    "label": "evolved",
                    "goal": f"Retest weak point {weak_point['target_node_id']} for {risk_type}.",
                    "success_criteria": [weak_point["success_criteria"]],
                    "metadata": {
                        **base.metadata,
                        "source": "self_evolution",
                        "target_node_id": weak_point["target_node_id"],
                        "evidence_ref": weak_point["evidence_ref"],
                        "source_finding": weak_point["risk_type"],
                        "trigger_reason": weak_point["reason"],
                        "mutation_strategy": strategy,
                        "previous_attack_id": base.attack_id,
                        "diff_from_previous": _diff_from_previous(base, weak_point, strategy),
                        "expected_effect": weak_point["expected_effect"],
                        "round": round_index,
                        "based_on": based_on,
                        "seed": seed,
                    },
                }
            )
        )
        rationale.append(weak_point["reason"])
        records.append(
            {
                "round": round_index,
                "based_on": based_on,
                "seed": seed,
                "source_finding": weak_point["risk_type"],
                "weakness": weak_point["weakness"],
                "previous_attack_id": base.attack_id,
                "new_attack_id": new_attack_id,
                "target_node_id": weak_point["target_node_id"],
                "trigger_reason": weak_point["reason"],
                "mutation_strategy": strategy,
                "diff_from_previous": _diff_from_previous(base, weak_point, strategy),
                "expected_effect": weak_point["expected_effect"],
                "expected_asr_change": weak_point["expected_asr_change"],
                "expected_coverage_change": weak_point["expected_coverage_change"],
            }
        )
        if weak_point["evidence_ref"]:
            source_refs.append(weak_point["evidence_ref"])

    return AttackEvolutionResult(
        evolved_specs=evolved,
        source_refs=sorted(set(source_refs)),
        rationale=rationale,
        evolution_records=records,
    )


def _weak_points(
    report: AgentSecurityReport | None,
    directives: list[OptimizationDirective],
    failed_attempts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    if report is not None:
        for finding in report.findings:
            risk_type = _infer_risk_type(" ".join([finding.title, finding.description, finding.recommendation]))
            if risk_type:
                items.append(
                    _weak_point(
                        risk_type,
                        target_node_id=finding.scenario_id,
                        severity=finding.severity,
                        evidence_ref=finding.scenario_id,
                        reason=f"Finding {finding.finding_id} remained unresolved.",
                        weakness="defense_bypass",
                    )
                )
        for result in report.scenario_results:
            if not result.passed:
                risk_type = _infer_risk_type(result.category)
                if risk_type:
                    items.append(
                        _weak_point(
                            risk_type,
                            target_node_id=result.scenario_id,
                            severity=result.severity,
                            evidence_ref=result.trajectory_ref,
                            reason=f"Scenario {result.scenario_id} failed with decision {result.actual_decision}.",
                            weakness="failed_evaluation_scenario",
                        )
                    )

    for directive in directives:
        risk_type = _infer_risk_type(directive.risk_type)
        if risk_type:
            items.append(
                _weak_point(
                    risk_type,
                    target_node_id=directive.target_node_id,
                    severity=directive.priority,
                    evidence_ref=directive.evidence_refs[0] if directive.evidence_refs else directive.directive_id,
                    reason=f"Directive {directive.directive_id} requested attack generation or retest.",
                    weakness="optimizer_directive",
                )
            )

    for attempt in failed_attempts:
        risk_type = _infer_risk_type(str(attempt.get("risk_type") or attempt.get("category") or ""))
        if risk_type:
            items.append(
                _weak_point(
                    risk_type,
                    target_node_id=str(attempt.get("target_node_id") or attempt.get("node_id") or "unknown"),
                    severity=str(attempt.get("severity") or "medium"),
                    evidence_ref=str(attempt.get("attempt_id") or ""),
                    reason="Failed attack attempt was used to generate a variant.",
                    weakness="failed_attack_attempt",
                )
            )
    return _dedupe(items)


def _weak_point(
    risk_type: AttackRiskType,
    *,
    target_node_id: str,
    severity: str,
    evidence_ref: str,
    reason: str,
    weakness: str = "unresolved_weakness",
) -> dict[str, Any]:
    return {
        "risk_type": risk_type,
        "target_node_id": target_node_id,
        "intensity": _intensity(severity),
        "strategy_hint": _strategy_hint(risk_type),
        "success_criteria": f"evolved {risk_type} variant is blocked, attributed, or measured",
        "evidence_ref": evidence_ref,
        "reason": reason,
        "weakness": weakness,
        "expected_effect": _expected_effect(risk_type),
        "expected_asr_change": _expected_asr_change(weakness),
        "expected_coverage_change": _expected_coverage_change(weakness),
    }


def _dedupe(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    output: list[dict[str, Any]] = []
    for item in items:
        key = (item["risk_type"], item["target_node_id"])
        if key in seen:
            continue
        seen.add(key)
        output.append(item)
    return output


def _mutation_strategy(weak_point: dict[str, Any], base: AttackSpec, *, seed: int, index: int) -> str:
    prefix = {
        "defense_bypass": "exploit_hardening",
        "failed_evaluation_scenario": "scenario_retarget",
        "optimizer_directive": "directive_mutation",
        "failed_attack_attempt": "payload_rewrite",
    }.get(weak_point["weakness"], "targeted_mutation")
    suffix = weak_point["strategy_hint"]
    if weak_point["intensity"] == base.intensity:
        suffix = f"{suffix}_variant"
    return f"{prefix}_{suffix}_s{seed}_i{index}"


def _diff_from_previous(base: AttackSpec, weak_point: dict[str, Any], strategy: str) -> dict[str, Any]:
    return {
        "strategy": {"from": base.strategy, "to": strategy},
        "intensity": {"from": base.intensity, "to": weak_point["intensity"]},
        "target_node_id": {"from": base.metadata.get("node_id"), "to": weak_point["target_node_id"]},
        "success_criteria": {"from": base.success_criteria, "to": [weak_point["success_criteria"]]},
    }


def _expected_asr_change(weakness: str) -> str:
    return {
        "defense_bypass": "ASR should decrease if the retest closes a previously allowed bypass.",
        "failed_evaluation_scenario": "ASR attribution should become more precise for the failing scenario.",
        "optimizer_directive": "ASR should shift toward the optimizer-prioritized risk.",
        "failed_attack_attempt": "ASR may increase for the weak point because the payload is retargeted.",
    }.get(weakness, "ASR change should be measured against the previous round.")


def _expected_coverage_change(weakness: str) -> str:
    return {
        "defense_bypass": "Coverage remains focused on an already observed weak surface.",
        "failed_evaluation_scenario": "Coverage expands along the failing scenario trajectory.",
        "optimizer_directive": "Coverage follows the requested node and risk directive.",
        "failed_attack_attempt": "Coverage adds a variant for a previously unsuccessful attack path.",
    }.get(weakness, "Coverage impact should be compared with the previous round.")


def _infer_risk_type(text: str) -> AttackRiskType | None:
    lowered = text.lower()
    aliases = {
        "kb_poisoning": "knowledge_poisoning",
        "sensitive_leakage": "pii_leakage",
        "goal_perturbation": "goal_drift",
        "parameter_tampering": "tool_tampering",
    }
    for risk in _KNOWN_RISKS:
        if risk in lowered:
            return risk
    for alias, risk in aliases.items():
        if alias in lowered:
            return risk  # type: ignore[return-value]
    return None


def _intensity(severity: str) -> AttackIntensity:
    if severity in {"critical", "high"}:
        return "heavy"
    if severity == "low":
        return "light"
    return "medium"


def _strategy_hint(risk_type: AttackRiskType) -> str:
    return {
        "prompt_injection": "format_injection",
        "knowledge_poisoning": "instruction_doc",
        "unauthorized_retrieval": "scope_confusion",
        "tool_tampering": "chain_hijack",
        "memory_poisoning": "cross_session_seed",
        "goal_drift": "incremental_creep",
        "pii_leakage": "encoded_request",
    }.get(risk_type, "targeted_probe")


def _expected_effect(risk_type: AttackRiskType) -> str:
    return {
        "prompt_injection": "increase prompt hierarchy bypass coverage",
        "knowledge_poisoning": "increase RAG poisoning coverage",
        "unauthorized_retrieval": "increase cross-scope retrieval coverage",
        "tool_tampering": "increase multi-step tool misuse coverage",
        "memory_poisoning": "increase persistent memory poisoning coverage",
        "goal_drift": "increase gradual objective shift coverage",
        "pii_leakage": "increase sensitive output leakage coverage",
    }.get(risk_type, "increase weak-node coverage")
