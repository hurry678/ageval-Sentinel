"""Defense optimization APIs that consume evaluation evidence.

The historical synthetic e-commerce ``DefenseAgent`` remains in
``redsentinel.defenses.engine.defense_agent``. It is intentionally not exported here:
research optimizers must operate on generic reports and directives.
"""

from redsentinel.defenses.engine.security.firewall.tuning import (
    FirewallEvaluationSample,
    FirewallTuningAdjustment,
    FirewallTuningEvidence,
    FirewallTuningPlan,
    FirewallTuningRunEvidence,
    TunedFirewall,
    build_firewall_tuning_plan,
    evaluate_firewall_tuning,
)

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
