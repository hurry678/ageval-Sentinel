"""Application services for reproducible RedSentinel research experiments."""

from redsentinel.research.analysis import (
    AnalysisResult,
    MetricSummary,
    Observation,
    SignificanceResult,
    SourceRef,
    analyze_files,
    render_paper_tables,
    write_analysis_artifacts,
)
from redsentinel.research.baselines import (
    AblationConfig,
    BaselineComparison,
    BaselineMatrixRunner,
    BaselineResult,
)
from redsentinel.research.catalog import (
    AgentTarget,
    CostCap,
    ExperimentTier,
    ExitCondition,
    RQConfigurationError,
    RQExperimentMatrix,
    ResearchQuestion,
    VariableSpec,
    list_rq_experiment_matrix,
    load_rq_experiment_matrix,
)
from redsentinel.research.evolution import (
    AppendOnlyEvolutionLedger,
    CoEvolutionEngine,
    EvolutionConfig,
    EvolutionRound,
    EvolutionRun,
    LedgerEntry,
)
from redsentinel.research.provenance import (
    EvidenceArtifact,
    EvidenceIndex,
    RunEvidence,
    capture_provenance,
    persist_run_evidence,
    write_evidence_index,
)
from redsentinel.research.p1_protocol import (
    P1AggregateMetrics,
    P1CaseOutcome,
    aggregate_p1_outcomes,
)
from redsentinel.research.runner import (
    ExperimentRun,
    ExperimentRunRecord,
    SingleRoundExperimentRunner,
)

__all__ = [
    "AblationConfig",
    "AgentTarget",
    "AnalysisResult",
    "AppendOnlyEvolutionLedger",
    "BaselineComparison",
    "BaselineMatrixRunner",
    "BaselineResult",
    "CoEvolutionEngine",
    "CostCap",
    "EvolutionConfig",
    "EvolutionRound",
    "EvolutionRun",
    "EvidenceArtifact",
    "EvidenceIndex",
    "RunEvidence",
    "ExperimentTier",
    "ExperimentRun",
    "ExperimentRunRecord",
    "ExitCondition",
    "LedgerEntry",
    "MetricSummary",
    "Observation",
    "P1AggregateMetrics",
    "P1CaseOutcome",
    "RQConfigurationError",
    "RQExperimentMatrix",
    "ResearchQuestion",
    "SignificanceResult",
    "SingleRoundExperimentRunner",
    "SourceRef",
    "VariableSpec",
    "analyze_files",
    "aggregate_p1_outcomes",
    "capture_provenance",
    "persist_run_evidence",
    "list_rq_experiment_matrix",
    "load_rq_experiment_matrix",
    "render_paper_tables",
    "write_evidence_index",
    "write_analysis_artifacts",
]
