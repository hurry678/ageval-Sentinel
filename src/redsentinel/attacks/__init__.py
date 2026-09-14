"""Public attack APIs grouped by research responsibility."""

from redsentinel.attacks.datasets import (
    REQUIRED_CASE_FIELDS,
    ScenarioConfig,
    load_attack_cases,
    load_cases,
    load_jsonl_records,
    run_scenario_cli,
    validate_attack_case,
    validate_payload_source,
)
from redsentinel.attacks.generation import (
    AttackAgent,
    AttackAttempt,
    AttackSpec,
    CampaignResult,
    ProfileDrivenAttackPlan,
    ReflectionEntry,
    build_profile_driven_attack_plan,
    build_profile_driven_attack_plan_from_candidate,
)
from redsentinel.attacks.mutation import AttackEvolutionResult, evolve_attack_specs
from redsentinel.attacks.selection import select_unique
from redsentinel.attacks.space import (
    ESCALATION_LADDERS,
    THREAT_CATEGORIES,
    THREAT_CATEGORY_ALIASES,
    AttackStrategy,
    SyntheticTarget,
    canonical_threat_category,
    ladder_for,
)

__all__ = [
    "ESCALATION_LADDERS",
    "REQUIRED_CASE_FIELDS",
    "THREAT_CATEGORIES",
    "THREAT_CATEGORY_ALIASES",
    "AttackAgent",
    "AttackAttempt",
    "AttackEvolutionResult",
    "AttackSpec",
    "AttackStrategy",
    "CampaignResult",
    "ProfileDrivenAttackPlan",
    "ReflectionEntry",
    "ScenarioConfig",
    "SyntheticTarget",
    "build_profile_driven_attack_plan",
    "build_profile_driven_attack_plan_from_candidate",
    "canonical_threat_category",
    "evolve_attack_specs",
    "ladder_for",
    "load_attack_cases",
    "load_cases",
    "load_jsonl_records",
    "run_scenario_cli",
    "select_unique",
    "validate_attack_case",
    "validate_payload_source",
]
