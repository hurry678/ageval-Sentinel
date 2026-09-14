from __future__ import annotations

import importlib
import json
import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Iterable

DEFAULT_RANDOM_SEED = 42
RISK_LEVELS = ("low", "medium", "high", "critical", "unknown")


@dataclass(frozen=True)
class AnomalyScore:
    score: float
    model_type: str
    top_features: list[str] = field(default_factory=list)


class TrajectoryFeatureExtractor:
    """Extract compact, deterministic features from tool-call trajectories."""

    def __init__(self, *, ngram_range: tuple[int, int] = (1, 3)) -> None:
        self.ngram_range = ngram_range
        self._feature_names: list[str] = []
        self._ngram_features: set[str] = set()
        self._tool_features: set[str] = set()

    @property
    def feature_names(self) -> list[str]:
        return list(self._feature_names)

    def fit(self, trajectories: Iterable[dict[str, Any] | list[dict[str, Any]]]) -> "TrajectoryFeatureExtractor":
        ngram_features: set[str] = set()
        tool_features: set[str] = set()
        for trajectory in trajectories:
            events = normalize_trajectory(trajectory)
            tools = [_tool_label(event) for event in events]
            tool_features.update(f"freq:{tool}" for tool in tools)
            ngram_features.update(f"ngram:{ngram}" for ngram in _tool_ngrams(tools, self.ngram_range))

        self._ngram_features = ngram_features
        self._tool_features = tool_features
        self._feature_names = _static_feature_names() + sorted(tool_features) + sorted(ngram_features)
        return self

    def extract_feature_dict(self, trajectory: dict[str, Any] | list[dict[str, Any]]) -> dict[str, float]:
        events = normalize_trajectory(trajectory)
        total = max(len(events), 1)
        tools = [_tool_label(event) for event in events]
        tool_counts = Counter(tools)
        risk_counts = Counter(_risk_level(event) for event in events)
        parameter_entropies = [_parameter_entropy(_arguments(event)) for event in events]
        ngrams = _tool_ngrams(tools, self.ngram_range)
        ngram_counts = Counter(ngrams)
        known_ngrams = {name.removeprefix("ngram:") for name in self._ngram_features}
        unknown_ngram_count = sum(count for ngram, count in ngram_counts.items() if ngram not in known_ngrams)
        total_ngram_count = max(sum(ngram_counts.values()), 1)

        features: dict[str, float] = {
            "event_count": min(len(events) / 20.0, 1.0),
            "unique_tool_ratio": len(tool_counts) / total,
            "max_tool_frequency_ratio": (max(tool_counts.values()) / total) if tool_counts else 0.0,
            "failed_ratio": sum(1 for event in events if _is_failed(event)) / total,
            "denied_ratio": sum(1 for event in events if _is_denied(event)) / total,
            "external_channel_ratio": sum(1 for event in events if _uses_external_channel(event)) / total,
            "sensitive_argument_ratio": sum(1 for event in events if _has_sensitive_marker(event)) / total,
            "parameter_entropy_mean": min((_mean(parameter_entropies) / 6.0), 1.0),
            "parameter_entropy_max": min((max(parameter_entropies) if parameter_entropies else 0.0) / 6.0, 1.0),
            "argument_key_count_mean": min(_mean([len(_arguments(event)) for event in events]) / 10.0, 1.0),
            "unknown_ngram_ratio": unknown_ngram_count / total_ngram_count,
        }
        for level in RISK_LEVELS:
            features[f"risk_level:{level}"] = risk_counts[level] / total
        for feature_name in self._tool_features:
            tool = feature_name.removeprefix("freq:")
            features[feature_name] = tool_counts[tool] / total
        for feature_name in self._ngram_features:
            ngram = feature_name.removeprefix("ngram:")
            features[feature_name] = ngram_counts[ngram] / total_ngram_count
        return features

    def transform_one(self, trajectory: dict[str, Any] | list[dict[str, Any]]) -> list[float]:
        features = self.extract_feature_dict(trajectory)
        return [features.get(name, 0.0) for name in self._feature_names]

    def transform(self, trajectories: Iterable[dict[str, Any] | list[dict[str, Any]]]) -> list[list[float]]:
        return [self.transform_one(trajectory) for trajectory in trajectories]


class TrajectoryAnomalyDetector:
    def __init__(self, *, random_seed: int = DEFAULT_RANDOM_SEED, prefer_sklearn: bool = True) -> None:
        self.random_seed = random_seed
        self.prefer_sklearn = prefer_sklearn
        self.feature_extractor = TrajectoryFeatureExtractor()
        self.model_type = "unfitted"
        self._model: Any | None = None
        self._baseline_mean: list[float] = []
        self._baseline_std: list[float] = []
        self._iforest_mean = 0.0
        self._iforest_std = 1.0

    def fit(
        self,
        normal_trajectories: Iterable[dict[str, Any] | list[dict[str, Any]]],
        attack_trajectories: Iterable[dict[str, Any] | list[dict[str, Any]]] | None = None,
    ) -> "TrajectoryAnomalyDetector":
        normal = list(normal_trajectories)
        attacks = list(attack_trajectories or [])
        if not normal:
            raise ValueError("At least one normal trajectory is required to fit anomaly detector.")

        self.feature_extractor.fit([*normal, *attacks])
        normal_vectors = self.feature_extractor.transform(normal)
        self._fit_statistical_baseline(normal_vectors)

        if self.prefer_sklearn and self._fit_isolation_forest(normal_vectors):
            self.model_type = "isolation_forest"
        else:
            self.model_type = "statistical_fallback"
        return self

    def score(self, trajectory: dict[str, Any] | list[dict[str, Any]]) -> float:
        if self.model_type == "unfitted":
            raise RuntimeError("TrajectoryAnomalyDetector.fit() must be called before score().")

        vector = self.feature_extractor.transform_one(trajectory)
        features = self.feature_extractor.extract_feature_dict(trajectory)
        statistical_score = self._statistical_score(vector, features)
        if self.model_type != "isolation_forest" or self._model is None:
            return statistical_score

        raw_score = float(self._model.score_samples([vector])[0])
        z_score = max(0.0, (self._iforest_mean - raw_score) / self._iforest_std)
        isolation_score = _clamp(18.0 + z_score * 22.0, 0.0, 100.0)
        return _clamp(max(isolation_score, statistical_score), 0.0, 100.0)

    def score_with_metadata(self, trajectory: dict[str, Any] | list[dict[str, Any]]) -> AnomalyScore:
        return AnomalyScore(score=self.score(trajectory), model_type=self.model_type)

    def score_with_evidence(
        self,
        trajectory: dict[str, Any] | list[dict[str, Any]],
        *,
        limit: int = 5,
    ) -> AnomalyScore:
        if self.model_type == "unfitted":
            raise RuntimeError("TrajectoryAnomalyDetector.fit() must be called before score_with_evidence().")

        vector = self.feature_extractor.transform_one(trajectory)
        features = self.feature_extractor.extract_feature_dict(trajectory)
        return AnomalyScore(
            score=self.score(trajectory),
            model_type=self.model_type,
            top_features=self._top_features(vector, features, limit=limit),
        )

    def _fit_isolation_forest(self, normal_vectors: list[list[float]]) -> bool:
        try:
            ensemble = importlib.import_module("sklearn.ensemble")
            isolation_forest = ensemble.IsolationForest(
                n_estimators=64,
                contamination="auto",
                random_state=self.random_seed,
            )
            isolation_forest.fit(normal_vectors)
            raw_scores = [float(score) for score in isolation_forest.score_samples(normal_vectors)]
        except Exception:
            self._model = None
            return False

        self._model = isolation_forest
        self._iforest_mean = _mean(raw_scores)
        self._iforest_std = max(_std(raw_scores, self._iforest_mean), 1e-6)
        return True

    def _fit_statistical_baseline(self, normal_vectors: list[list[float]]) -> None:
        width = len(normal_vectors[0])
        self._baseline_mean = []
        self._baseline_std = []
        for index in range(width):
            values = [vector[index] for vector in normal_vectors]
            mean = _mean(values)
            self._baseline_mean.append(mean)
            self._baseline_std.append(max(_std(values, mean), 0.05))

    def _statistical_score(self, vector: list[float], features: dict[str, float]) -> float:
        z_distance = _mean(
            [
                abs(value - self._baseline_mean[index]) / self._baseline_std[index]
                for index, value in enumerate(vector)
            ]
        )
        signal_score = 0.0
        signal_score += max(0.0, features.get("max_tool_frequency_ratio", 0.0) - 0.55) * 35.0
        signal_score += features.get("failed_ratio", 0.0) * 18.0
        signal_score += features.get("denied_ratio", 0.0) * 35.0
        signal_score += features.get("risk_level:high", 0.0) * 35.0
        signal_score += features.get("risk_level:critical", 0.0) * 50.0
        signal_score += features.get("sensitive_argument_ratio", 0.0) * 18.0
        signal_score += features.get("external_channel_ratio", 0.0) * 12.0
        signal_score += features.get("unknown_ngram_ratio", 0.0) * 25.0
        signal_score += max(0.0, features.get("parameter_entropy_mean", 0.0) - 0.55) * 20.0
        return _clamp(z_distance * 14.0 + signal_score, 0.0, 100.0)

    def _top_features(self, vector: list[float], features: dict[str, float], *, limit: int) -> list[str]:
        if limit <= 0:
            return []

        contributions: list[tuple[float, str]] = []
        for index, value in enumerate(vector):
            if index >= len(self._baseline_mean) or index >= len(self.feature_extractor.feature_names):
                continue
            deviation = abs(value - self._baseline_mean[index]) / self._baseline_std[index]
            if deviation > 0.1:
                contributions.append((deviation, self.feature_extractor.feature_names[index]))

        signal_weights = {
            "denied_ratio": 35.0,
            "risk_level:critical": 50.0,
            "risk_level:high": 35.0,
            "sensitive_argument_ratio": 18.0,
            "external_channel_ratio": 12.0,
            "failed_ratio": 18.0,
            "unknown_ngram_ratio": 25.0,
            "parameter_entropy_mean": 20.0,
            "max_tool_frequency_ratio": 35.0,
        }
        for name, weight in signal_weights.items():
            value = features.get(name, 0.0)
            if value > 0.0:
                contributions.append((value * weight, name))

        top_features: list[str] = []
        seen: set[str] = set()
        for _, name in sorted(contributions, key=lambda item: item[0], reverse=True):
            if name in seen:
                continue
            seen.add(name)
            top_features.append(name)
            if len(top_features) >= limit:
                break
        return top_features


def normalize_trajectory(observation: dict[str, Any] | list[dict[str, Any]]) -> list[dict[str, Any]]:
    if isinstance(observation, list):
        return [dict(item) for item in observation if isinstance(item, dict)]
    if not isinstance(observation, dict):
        return []
    if isinstance(observation.get("events"), list):
        return [dict(item) for item in observation["events"] if isinstance(item, dict)]
    if isinstance(observation.get("steps"), list):
        return _events_from_steps(observation["steps"])
    return [dict(observation)]


def extract_trajectory_features(
    trajectory: dict[str, Any] | list[dict[str, Any]],
    *,
    ngram_range: tuple[int, int] = (1, 3),
) -> dict[str, float]:
    extractor = TrajectoryFeatureExtractor(ngram_range=ngram_range)
    extractor.fit([trajectory])
    return extractor.extract_feature_dict(trajectory)


def _events_from_steps(steps: list[Any]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for step in steps:
        if not isinstance(step, dict):
            continue
        if isinstance(step.get("tool_call"), dict):
            tool_call = step["tool_call"]
            events.append(
                {
                    "call_type": "tool_call",
                    "tool_name": tool_call.get("name"),
                    "arguments": tool_call.get("arguments", {}),
                    "response": tool_call.get("response"),
                    "risk_level": step.get("risk_level"),
                    "status": step.get("status"),
                    "decision": step.get("decision"),
                }
            )
        elif step.get("call_type") or step.get("tool_name"):
            events.append(dict(step))
    return events


def _static_feature_names() -> list[str]:
    return [
        "event_count",
        "unique_tool_ratio",
        "max_tool_frequency_ratio",
        "failed_ratio",
        "denied_ratio",
        "external_channel_ratio",
        "sensitive_argument_ratio",
        "parameter_entropy_mean",
        "parameter_entropy_max",
        "argument_key_count_mean",
        "unknown_ngram_ratio",
        *[f"risk_level:{level}" for level in RISK_LEVELS],
    ]


def _tool_label(event: dict[str, Any]) -> str:
    call_type = str(event.get("call_type") or "event").lower()
    tool_name = str(event.get("tool_name") or event.get("tool") or _arguments(event).get("tool_name") or "unknown")
    return f"{call_type}:{tool_name.lower()}"


def _tool_ngrams(tools: list[str], ngram_range: tuple[int, int]) -> list[str]:
    ngrams: list[str] = []
    start, end = ngram_range
    for size in range(start, end + 1):
        if size <= 0:
            continue
        for index in range(0, max(len(tools) - size + 1, 0)):
            ngrams.append(">".join(tools[index : index + size]))
    return ngrams


def _arguments(event: dict[str, Any]) -> dict[str, Any]:
    for key in ("arguments", "tool_arguments", "payload", "payload_summary"):
        value = event.get(key)
        if isinstance(value, dict):
            return value
    return {}


def _risk_level(event: dict[str, Any]) -> str:
    value = str(event.get("risk_level") or event.get("severity") or "").strip().lower()
    if value in RISK_LEVELS:
        return value
    score = event.get("risk_score")
    if isinstance(score, int | float):
        if score >= 90:
            return "critical"
        if score >= 70:
            return "high"
        if score >= 40:
            return "medium"
        return "low"
    return "unknown"


def _is_failed(event: dict[str, Any]) -> bool:
    status = str(event.get("status") or "").lower()
    return status in {"failed", "error", "blocked", "rejected"}


def _is_denied(event: dict[str, Any]) -> bool:
    decision = str(event.get("decision") or "").lower()
    return decision in {"deny", "block", "blocked"} or event.get("allowed") is False


def _uses_external_channel(event: dict[str, Any]) -> bool:
    args = _arguments(event)
    text = " ".join(str(args.get(key) or event.get(key) or "") for key in ("endpoint", "url", "destination", "to"))
    lowered = text.lower()
    return any(marker in lowered for marker in ("http://", "https://", "@")) and "internal" not in lowered


def _has_sensitive_marker(event: dict[str, Any]) -> bool:
    text = json.dumps(event, ensure_ascii=False, sort_keys=True, default=str).lower()
    return any(marker in text for marker in ("api_key", "token", "secret", "password", "credential", "sk-"))


def _parameter_entropy(arguments: dict[str, Any]) -> float:
    if not arguments:
        return 0.0
    text = json.dumps(arguments, ensure_ascii=False, sort_keys=True, default=str)
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _mean(values: Iterable[float]) -> float:
    items = list(values)
    return sum(items) / len(items) if items else 0.0


def _std(values: Iterable[float], mean: float) -> float:
    items = list(values)
    if not items:
        return 0.0
    return math.sqrt(sum((value - mean) ** 2 for value in items) / len(items))


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


__all__ = [
    "AnomalyScore",
    "DEFAULT_RANDOM_SEED",
    "TrajectoryAnomalyDetector",
    "TrajectoryFeatureExtractor",
    "extract_trajectory_features",
    "normalize_trajectory",
]
