"""RedSentinel Agent security co-evolution research framework."""

from redsentinel.core import (
    AgentProfile,
    AttackCandidate,
    DefenseCandidate,
    EvaluationResult,
    EvidenceRef,
    EvolutionState,
    ExperimentManifest,
    Provenance,
    Trajectory,
)
from redsentinel.migration import (
    LegacyArtifact,
    legacy_config_to_manifest,
    migrate_legacy_artifact,
    read_legacy_artifact,
)

__all__ = [
    "AgentProfile",
    "AttackCandidate",
    "DefenseCandidate",
    "EvaluationResult",
    "EvidenceRef",
    "EvolutionState",
    "ExperimentManifest",
    "LegacyArtifact",
    "Provenance",
    "Trajectory",
    "legacy_config_to_manifest",
    "migrate_legacy_artifact",
    "read_legacy_artifact",
]
