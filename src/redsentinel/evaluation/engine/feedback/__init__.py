"""M3.5 feedback routing for attack, defense, and dashboard consumers."""

from redsentinel.evaluation.engine.feedback.router import (
    AttackFeedback,
    DashboardFeedback,
    DefenseFeedback,
    FeedbackArtifactPaths,
    FeedbackRoute,
    route_optimizer_feedback,
    write_feedback_artifacts,
)


__all__ = [
    "AttackFeedback",
    "DashboardFeedback",
    "DefenseFeedback",
    "FeedbackArtifactPaths",
    "FeedbackRoute",
    "route_optimizer_feedback",
    "write_feedback_artifacts",
]
