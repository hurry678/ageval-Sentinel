from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from redsentinel.core.agent_security import OptimizationDirective
from redsentinel.application.contracts import AgentSecurityReport


SampleDecision = Literal["allow", "block"]
TuningActionType = Literal["add_keyword", "suppress_keyword", "adjust_threshold"]


class FirewallEvaluationSample(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sample_id: str = Field(min_length=1)
    text: str = Field(min_length=1)
    expected_decision: SampleDecision
    actual_decision: SampleDecision
    risk_type: str = Field(min_length=1)


class FirewallTuningAdjustment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: TuningActionType
    value: str = Field(min_length=1)
    reason: str = Field(min_length=1)


class FirewallTuningEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sample_id: str = Field(min_length=1)
    risk_type: str = Field(min_length=1)
    before_decision: SampleDecision
    after_decision: SampleDecision
    matched_keywords: list[str] = Field(default_factory=list)


class FirewallTuningPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["firewall-tuning-plan-v0.1"] = "firewall-tuning-plan-v0.1"
    agent_id: str = Field(min_length=1)
    rollback_id: str = Field(min_length=1)
    add_keywords: list[str] = Field(default_factory=list)
    suppress_keywords: list[str] = Field(default_factory=list)
    risk_threshold_delta: int = 0
    adjustments: list[FirewallTuningAdjustment] = Field(default_factory=list)
    evidence: list[FirewallTuningEvidence] = Field(default_factory=list)


class FirewallTuningRunEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    before_attack_success_rate: float = Field(ge=0.0)
    after_attack_success_rate: float = Field(ge=0.0)
    before_false_positive_rate: float = Field(ge=0.0)
    after_false_positive_rate: float = Field(ge=0.0)
    attack_success_reduced: bool
    false_positive_not_increased: bool
    sample_evidence: list[FirewallTuningEvidence] = Field(default_factory=list)


class TunedFirewall:
    def __init__(self, plan: FirewallTuningPlan) -> None:
        self.plan = plan

    def classify(self, text: str) -> dict:
        normalized = _normalize(text)
        suppress_matches = _matched_keywords(normalized, self.plan.suppress_keywords)
        if suppress_matches:
            return {
                "risk_score": 0,
                "category": "allowlisted_false_positive",
                "reasoning": f"suppressed keywords: {', '.join(suppress_matches)}",
                "should_block": False,
                "layer": "tuned_firewall",
                "matched_keywords": suppress_matches,
            }

        add_matches = _matched_keywords(normalized, self.plan.add_keywords)
        if add_matches:
            return {
                "risk_score": max(85 + self.plan.risk_threshold_delta, 1),
                "category": "self_tuned_firewall",
                "reasoning": f"matched tuned keywords: {', '.join(add_matches)}",
                "should_block": True,
                "layer": "tuned_firewall",
                "matched_keywords": add_matches,
            }

        return {
            "risk_score": 0,
            "category": "normal",
            "reasoning": "no tuned firewall rule matched",
            "should_block": False,
            "layer": "tuned_firewall",
            "matched_keywords": [],
        }


def build_firewall_tuning_plan(
    report: AgentSecurityReport,
    *,
    directives: list[OptimizationDirective] | None = None,
    bypass_samples: list[FirewallEvaluationSample] | None = None,
    false_positive_samples: list[FirewallEvaluationSample] | None = None,
) -> FirewallTuningPlan:
    directives = directives or []
    bypass_samples = _bypass_samples(report, bypass_samples or [])
    false_positive_samples = false_positive_samples or []
    suppress_keywords = _suppress_keywords(false_positive_samples)
    add_keywords = [
        keyword
        for keyword in _candidate_keywords(bypass_samples, directives)
        if keyword not in suppress_keywords
    ]
    add_keywords = sorted(dict.fromkeys(add_keywords))
    suppress_keywords = sorted(dict.fromkeys(suppress_keywords))

    adjustments = [
        FirewallTuningAdjustment(
            action="add_keyword",
            value=keyword,
            reason="Bypass sample was allowed but should be blocked.",
        )
        for keyword in add_keywords
    ]
    adjustments.extend(
        FirewallTuningAdjustment(
            action="suppress_keyword",
            value=keyword,
            reason="False-positive sample should remain allowed.",
        )
        for keyword in suppress_keywords
    )
    if report.false_positive_rate > 0.05:
        adjustments.append(
            FirewallTuningAdjustment(
                action="adjust_threshold",
                value="raise_on_false_positive",
                reason="False-positive rate exceeded 5%; prefer suppressions over broad blocking.",
            )
        )

    plan = FirewallTuningPlan(
        agent_id=report.agent_id,
        rollback_id=f"rollback-{report.agent_id}-{report.benchmark}",
        add_keywords=add_keywords,
        suppress_keywords=suppress_keywords,
        risk_threshold_delta=0,
        adjustments=adjustments,
    )
    return plan.model_copy(update={"evidence": _sample_evidence(plan, bypass_samples)})


def evaluate_firewall_tuning(
    plan: FirewallTuningPlan,
    samples: list[FirewallEvaluationSample],
) -> FirewallTuningRunEvidence:
    tuned = TunedFirewall(plan)
    before_attack_successes = 0
    after_attack_successes = 0
    before_false_positives = 0
    after_false_positives = 0
    attack_total = 0
    benign_total = 0
    evidence: list[FirewallTuningEvidence] = []

    for sample in samples:
        tuned_result = tuned.classify(sample.text)
        after_decision: SampleDecision = "block" if tuned_result["should_block"] else "allow"
        if sample.actual_decision == "block":
            after_decision = "block"
        if sample.expected_decision == "block":
            attack_total += 1
            if sample.actual_decision == "allow":
                before_attack_successes += 1
            if after_decision == "allow":
                after_attack_successes += 1
        else:
            benign_total += 1
            if sample.actual_decision == "block":
                before_false_positives += 1
            if after_decision == "block":
                after_false_positives += 1
        evidence.append(
            FirewallTuningEvidence(
                sample_id=sample.sample_id,
                risk_type=sample.risk_type,
                before_decision=sample.actual_decision,
                after_decision=after_decision,
                matched_keywords=list(tuned_result["matched_keywords"]),
            )
        )

    before_asr = before_attack_successes / attack_total if attack_total else 0.0
    after_asr = after_attack_successes / attack_total if attack_total else 0.0
    before_fpr = before_false_positives / benign_total if benign_total else 0.0
    after_fpr = after_false_positives / benign_total if benign_total else 0.0
    return FirewallTuningRunEvidence(
        before_attack_success_rate=before_asr,
        after_attack_success_rate=after_asr,
        before_false_positive_rate=before_fpr,
        after_false_positive_rate=after_fpr,
        attack_success_reduced=after_asr < before_asr,
        false_positive_not_increased=after_fpr <= before_fpr,
        sample_evidence=evidence,
    )


def _bypass_samples(
    report: AgentSecurityReport,
    samples: list[FirewallEvaluationSample],
) -> list[FirewallEvaluationSample]:
    output = list(samples)
    for result in report.scenario_results:
        if result.expected_decision == "block" and result.actual_decision == "allow":
            output.append(
                FirewallEvaluationSample(
                    sample_id=result.scenario_id,
                    text=" ".join([result.category, result.business_impact]),
                    expected_decision="block",
                    actual_decision="allow",
                    risk_type=result.category,
                )
            )
    return output


def _candidate_keywords(
    samples: list[FirewallEvaluationSample],
    directives: list[OptimizationDirective],
) -> list[str]:
    candidates: list[str] = []
    for sample in samples:
        candidates.extend(_extract_phrases(sample.text))
    for directive in directives:
        if directive.risk_type in {"prompt_injection", "goal_perturbation", "goal_drift"}:
            candidates.extend(_extract_phrases(directive.rationale))
    return candidates


def _suppress_keywords(samples: list[FirewallEvaluationSample]) -> list[str]:
    keywords: list[str] = []
    for sample in samples:
        keywords.extend(_extract_phrases(sample.text))
    return keywords


def _sample_evidence(
    plan: FirewallTuningPlan,
    samples: list[FirewallEvaluationSample],
) -> list[FirewallTuningEvidence]:
    tuned = TunedFirewall(plan)
    evidence: list[FirewallTuningEvidence] = []
    for sample in samples:
        tuned_result = tuned.classify(sample.text)
        evidence.append(
            FirewallTuningEvidence(
                sample_id=sample.sample_id,
                risk_type=sample.risk_type,
                before_decision=sample.actual_decision,
                after_decision="block" if tuned_result["should_block"] else "allow",
                matched_keywords=list(tuned_result["matched_keywords"]),
            )
        )
    return evidence


def _extract_phrases(text: str) -> list[str]:
    normalized = _normalize(text)
    phrases: list[str] = []
    patterns = [
        r"supreme\s+override\s+mode",
        r"ignore\s+safety\s+guardrails",
        r"ignore\s+all\s+(previous|prior)\s+instructions",
        r"disregard\s+all\s+(previous|prior)\s+instructions",
        r"忽略.{0,6}(指令|规则|安全|策略)",
        r"绕过.{0,6}(限制|安全|防火墙|管控)",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, normalized):
            phrase = match.group(0).strip()
            if len(phrase) >= 4:
                phrases.append(phrase)

    if not phrases:
        risk_terms = ["prompt_injection", "goal_perturbation", "jailbreak"]
        phrases.extend(term for term in risk_terms if term in normalized)
    return phrases


def _matched_keywords(text: str, keywords: list[str]) -> list[str]:
    return [
        keyword
        for keyword in keywords
        if keyword and keyword in text
    ]


def _normalize(text: str) -> str:
    return " ".join(text.lower().split())


__all__ = [
    "FirewallEvaluationSample",
    "FirewallTuningAdjustment",
    "FirewallTuningEvidence",
    "FirewallTuningPlan",
    "FirewallTuningRunEvidence",
    "TunedFirewall",
    "build_firewall_tuning_plan",
    "evaluate_firewall_tuning",
]
