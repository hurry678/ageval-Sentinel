"""Statistical aggregation and traceable paper artifacts for research runs."""

from __future__ import annotations

import hashlib
import itertools
import json
import math
import random
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any, Literal, Sequence

from pydantic import BaseModel, ConfigDict, Field


class _AnalysisModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SourceRef(_AnalysisModel):
    path: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    json_pointer: str


class Observation(_AnalysisModel):
    experiment_id: str
    arm: str
    seed: int
    metric: str
    value: float
    ablation: str = "full"
    round_index: int | None = None
    source: SourceRef


class MetricSummary(_AnalysisModel):
    experiment_id: str
    arm: str
    metric: str
    ablation: str
    count: int
    mean: float
    variance: float | None
    standard_deviation: float | None
    confidence_level: float = 0.95
    confidence_interval: tuple[float, float] | None
    source_refs: list[SourceRef]


class SignificanceResult(_AnalysisModel):
    experiment_id: str
    metric: str
    baseline_arm: str
    treatment_arm: str
    paired_seeds: list[int]
    status: Literal["computed", "not_applicable"]
    test: str
    assumptions: list[str]
    mean_difference: float | None = None
    effect_size_cohens_dz: float | None = None
    p_value_two_sided: float | None = None
    reason: str | None = None
    source_refs: list[SourceRef]


class AnalysisResult(_AnalysisModel):
    schema_version: Literal["research-analysis-v1"] = "research-analysis-v1"
    source_files: list[SourceRef]
    observations: list[Observation]
    summaries: list[MetricSummary]
    significance_tests: list[SignificanceResult]


def analyze_files(paths: Sequence[str | Path]) -> AnalysisResult:
    """Load raw JSON runs and aggregate them without changing their metric values."""
    observations: list[Observation] = []
    source_files: list[SourceRef] = []
    for raw_path in sorted(Path(path) for path in paths):
        payload_bytes = raw_path.read_bytes()
        digest = hashlib.sha256(payload_bytes).hexdigest()
        payload = json.loads(payload_bytes)
        source_files.append(SourceRef(path=str(raw_path), sha256=digest, json_pointer=""))
        observations.extend(_extract_observations(raw_path, digest, payload))
    summaries = _summarize(observations)
    significance = _significance_tests(observations)
    return AnalysisResult(
        source_files=source_files,
        observations=observations,
        summaries=summaries,
        significance_tests=significance,
    )


def write_analysis_artifacts(
    analysis: AnalysisResult,
    output_dir: str | Path,
    *,
    prefer_matplotlib: bool = True,
) -> dict[str, Path]:
    """Write JSON, Markdown and figures whose values point back to raw JSON."""
    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)
    analysis_path = root / "analysis.json"
    table_path = root / "paper-tables.md"
    analysis_path.write_text(
        json.dumps(analysis.model_dump(mode="json"), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    table_path.write_text(render_paper_tables(analysis), encoding="utf-8")
    figures = _write_figures(analysis, root, prefer_matplotlib=prefer_matplotlib)
    return {"analysis": analysis_path, "tables": table_path, **figures}


def render_paper_tables(analysis: AnalysisResult) -> str:
    """Render traceable Markdown tables without recomputing research metrics."""
    lines = [
        "<!-- generated from raw JSON by redsentinel.research.analysis -->",
        "",
        "# Research Analysis Tables",
        "",
        "## Aggregated metrics",
        "",
        "| experiment | arm | ablation | metric | n | mean | variance | std | 95% CI | sources |",
        "|---|---|---|---|---:|---:|---:|---:|---|---|",
    ]
    for item in analysis.summaries:
        interval = (
            f"[{item.confidence_interval[0]:.6g}, {item.confidence_interval[1]:.6g}]"
            if item.confidence_interval
            else "not_applicable"
        )
        lines.append(
            "| {experiment} | {arm} | {ablation} | {metric} | {count} | {mean:.6g} | {variance} | "
            "{std} | {interval} | {sources} |".format(
                experiment=item.experiment_id,
                arm=item.arm,
                ablation=item.ablation,
                metric=item.metric,
                count=item.count,
                mean=item.mean,
                variance=_format_optional(item.variance),
                std=_format_optional(item.standard_deviation),
                interval=interval,
                sources="<br>".join(_source_label(ref) for ref in item.source_refs),
            )
        )
    lines.extend(
        [
            "",
            "## Paired significance tests",
            "",
            "| experiment | metric | comparison | test | paired seeds | status | mean diff | Cohen dz | p (two-sided) | assumptions / reason | sources |",
            "|---|---|---|---|---|---|---:|---:|---:|---|---|",
        ]
    )
    for item in analysis.significance_tests:
        detail = "; ".join(item.assumptions)
        if item.reason:
            detail = f"{detail}; {item.reason}" if detail else item.reason
        lines.append(
            "| {experiment} | {metric} | {baseline} vs {treatment} | {test} | {seeds} | {status} | {difference} | "
            "{effect} | {p_value} | {detail} | {sources} |".format(
                experiment=item.experiment_id,
                metric=item.metric,
                baseline=item.baseline_arm,
                treatment=item.treatment_arm,
                test=item.test,
                seeds=", ".join(str(seed) for seed in item.paired_seeds) or "-",
                status=item.status,
                difference=_format_optional(item.mean_difference),
                effect=_format_optional(item.effect_size_cohens_dz),
                p_value=_format_optional(item.p_value_two_sided),
                detail=detail,
                sources="<br>".join(_source_label(ref) for ref in item.source_refs),
            )
        )
    lines.append("")
    return "\n".join(lines)


def _extract_observations(path: Path, digest: str, payload: dict[str, Any]) -> list[Observation]:
    schema = payload.get("schema_version")
    if schema == "baseline-comparison-v1":
        return _extract_baseline(path, digest, payload)
    if schema == "experiment-run-v1":
        return _extract_experiment(path, digest, payload)
    raise ValueError(f"Unsupported research result schema {schema!r}: {path}")


def _extract_baseline(path: Path, digest: str, payload: dict[str, Any]) -> list[Observation]:
    output: list[Observation] = []
    ablation = _ablation_label(payload.get("ablations", {}))
    seed = int(payload["seed"])
    for result_index, result in enumerate(payload.get("results", [])):
        arm = str(result["name"])
        for metric, value in sorted(result.get("final_metrics", {}).items()):
            pointer = f"/results/{result_index}/final_metrics/{_pointer(metric)}"
            output.append(_observation(path, digest, payload["experiment_id"], arm, seed, metric, value, ablation, pointer))
        for round_index, round_payload in enumerate(result.get("run", {}).get("rounds", [])):
            metrics = round_payload.get("regression_evaluation", {}).get("metrics", {})
            for metric, value in sorted(metrics.items()):
                pointer = f"/results/{result_index}/run/rounds/{round_index}/regression_evaluation/metrics/{_pointer(metric)}"
                output.append(
                    _observation(
                        path,
                        digest,
                        payload["experiment_id"],
                        arm,
                        seed,
                        metric,
                        value,
                        ablation,
                        pointer,
                        round_index=int(round_payload.get("round_index", round_index)),
                    )
                )
    return output


def _extract_experiment(path: Path, digest: str, payload: dict[str, Any]) -> list[Observation]:
    output: list[Observation] = []
    for record_index, record in enumerate(payload.get("records", [])):
        if record.get("status") != "completed":
            continue
        metrics = (record.get("evaluation") or {}).get("metrics", {})
        for metric, value in sorted(metrics.items()):
            pointer = f"/records/{record_index}/evaluation/metrics/{_pointer(metric)}"
            output.append(
                _observation(
                    path,
                    digest,
                    payload["experiment_id"],
                    "experiment",
                    int(record["seed"]),
                    metric,
                    value,
                    "full",
                    pointer,
                )
            )
    return output


def _observation(
    path: Path,
    digest: str,
    experiment_id: str,
    arm: str,
    seed: int,
    metric: str,
    value: Any,
    ablation: str,
    pointer: str,
    round_index: int | None = None,
) -> Observation:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        raise ValueError(f"Metric must be a finite number at {path}#{pointer}")
    return Observation(
        experiment_id=experiment_id,
        arm=arm,
        seed=seed,
        metric=metric,
        value=float(value),
        ablation=ablation,
        round_index=round_index,
        source=SourceRef(path=str(path), sha256=digest, json_pointer=pointer),
    )


def _summarize(observations: Sequence[Observation]) -> list[MetricSummary]:
    groups: dict[tuple[str, str, str, str], list[Observation]] = defaultdict(list)
    for item in observations:
        if item.round_index is None:
            groups[(item.experiment_id, item.arm, item.metric, item.ablation)].append(item)
    output: list[MetricSummary] = []
    for (experiment, arm, metric, ablation), items in sorted(groups.items()):
        values = [item.value for item in items]
        variance = statistics.variance(values) if len(values) >= 2 else None
        deviation = math.sqrt(variance) if variance is not None else None
        interval = _confidence_interval(values)
        output.append(
            MetricSummary(
                experiment_id=experiment,
                arm=arm,
                metric=metric,
                ablation=ablation,
                count=len(values),
                mean=statistics.fmean(values),
                variance=variance,
                standard_deviation=deviation,
                confidence_interval=interval,
                source_refs=_unique_refs(item.source for item in items),
            )
        )
    return output


def _confidence_interval(values: Sequence[float]) -> tuple[float, float] | None:
    if len(values) < 2:
        return None
    mean = statistics.fmean(values)
    standard_error = statistics.stdev(values) / math.sqrt(len(values))
    margin = _t_critical_95(len(values) - 1) * standard_error
    return mean - margin, mean + margin


def _significance_tests(observations: Sequence[Observation]) -> list[SignificanceResult]:
    final = [item for item in observations if item.round_index is None and item.ablation == "full"]
    experiments = sorted({item.experiment_id for item in final})
    output: list[SignificanceResult] = []
    for experiment in experiments:
        metrics = sorted({item.metric for item in final if item.experiment_id == experiment})
        arms = {item.arm for item in final if item.experiment_id == experiment}
        comparisons = [("fixed", "coevolution")] if {"fixed", "coevolution"} <= arms else []
        for metric in metrics:
            for baseline, treatment in comparisons:
                output.append(_paired_test(final, experiment, metric, baseline, treatment))
    return output


def _paired_test(
    observations: Sequence[Observation],
    experiment: str,
    metric: str,
    baseline: str,
    treatment: str,
) -> SignificanceResult:
    by_arm: dict[str, dict[int, Observation]] = {baseline: {}, treatment: {}}
    for item in observations:
        if item.experiment_id == experiment and item.metric == metric and item.arm in by_arm:
            if item.seed in by_arm[item.arm]:
                raise ValueError(f"Duplicate final observation for {experiment}/{item.arm}/{metric}/seed-{item.seed}")
            by_arm[item.arm][item.seed] = item
    seeds = sorted(set(by_arm[baseline]) & set(by_arm[treatment]))
    refs = _unique_refs(by_arm[arm][seed].source for arm in (baseline, treatment) for seed in seeds)
    assumptions = [
        "observations are paired by identical seed",
        "seed pairs are independent of other seed pairs",
        "two-sided sign-flip permutation test assumes exchangeable paired differences under the null",
        "Cohen dz uses the sample standard deviation of paired differences",
    ]
    if len(seeds) < 2:
        return SignificanceResult(
            experiment_id=experiment,
            metric=metric,
            baseline_arm=baseline,
            treatment_arm=treatment,
            paired_seeds=seeds,
            status="not_applicable",
            test="paired_sign_flip_permutation",
            assumptions=assumptions,
            reason="at least two paired seeds are required",
            source_refs=refs,
        )
    differences = [by_arm[treatment][seed].value - by_arm[baseline][seed].value for seed in seeds]
    deviation = statistics.stdev(differences)
    effect = statistics.fmean(differences) / deviation if deviation > 0 else None
    return SignificanceResult(
        experiment_id=experiment,
        metric=metric,
        baseline_arm=baseline,
        treatment_arm=treatment,
        paired_seeds=seeds,
        status="computed",
        test="paired_sign_flip_permutation",
        assumptions=assumptions,
        mean_difference=statistics.fmean(differences),
        effect_size_cohens_dz=effect,
        p_value_two_sided=_sign_flip_p_value(differences),
        source_refs=refs,
    )


def _sign_flip_p_value(differences: Sequence[float]) -> float:
    observed = abs(statistics.fmean(differences))
    total = 2 ** len(differences)
    if len(differences) <= 20:
        extreme = sum(
            abs(statistics.fmean(sign * value for sign, value in zip(signs, differences))) >= observed - 1e-15
            for signs in itertools.product((-1.0, 1.0), repeat=len(differences))
        )
        return extreme / total
    rng = random.Random(0)
    samples = 100_000
    extreme = 0
    for _ in range(samples):
        permuted = [value if rng.getrandbits(1) else -value for value in differences]
        extreme += abs(statistics.fmean(permuted)) >= observed - 1e-15
    return (extreme + 1) / (samples + 1)


def _write_figures(
    analysis: AnalysisResult,
    root: Path,
    *,
    prefer_matplotlib: bool,
) -> dict[str, Path]:
    names = ("convergence", "pareto", "ablation")
    if prefer_matplotlib:
        try:
            return _write_matplotlib_figures(analysis, root)
        except ImportError:
            pass
    paths = {name: root / f"{name}.svg" for name in names}
    paths["convergence"].write_text(_convergence_svg(analysis), encoding="utf-8")
    paths["pareto"].write_text(_pareto_svg(analysis), encoding="utf-8")
    paths["ablation"].write_text(_ablation_svg(analysis), encoding="utf-8")
    return paths


def _write_matplotlib_figures(analysis: AnalysisResult, root: Path) -> dict[str, Path]:
    import matplotlib.pyplot as plt

    paths = {
        "convergence": root / "convergence.png",
        "pareto": root / "pareto.png",
        "ablation": root / "ablation.png",
    }
    convergence = _convergence_series(analysis)
    fig, axis = plt.subplots()
    for label, points in convergence.items():
        axis.plot([point[0] for point in points], [point[1] for point in points], marker="o", label=label)
    axis.set(xlabel="Round", ylabel="Metric mean", title="Convergence")
    if convergence:
        axis.legend()
    _save_figure(fig, paths["convergence"], analysis)

    pareto = _pareto_points(analysis)
    fig, axis = plt.subplots()
    for label, x, y in pareto:
        axis.scatter(x, y)
        axis.annotate(label, (x, y))
    axis.set(xlabel="ASR", ylabel="Utility", title="Security-utility Pareto view")
    _save_figure(fig, paths["pareto"], analysis)

    ablations = _ablation_points(analysis)
    fig, axis = plt.subplots()
    if ablations:
        axis.bar([item[0] for item in ablations], [item[1] for item in ablations])
        axis.tick_params(axis="x", rotation=30)
    axis.set(ylabel="Metric mean", title="Ablation comparison")
    _save_figure(fig, paths["ablation"], analysis)
    return paths


def _save_figure(figure: Any, path: Path, analysis: AnalysisResult) -> None:
    refs = json.dumps([ref.model_dump(mode="json") for ref in analysis.source_files], sort_keys=True)
    figure.savefig(path, dpi=160, bbox_inches="tight", metadata={"Description": refs})
    import matplotlib.pyplot as plt

    plt.close(figure)


def _convergence_series(analysis: AnalysisResult) -> dict[str, list[tuple[int, float]]]:
    groups: dict[tuple[str, str, str, int], list[float]] = defaultdict(list)
    for item in analysis.observations:
        if item.round_index is not None:
            groups[(item.experiment_id, item.arm, item.metric, item.round_index)].append(item.value)
    series: dict[str, list[tuple[int, float]]] = defaultdict(list)
    for (experiment, arm, metric, round_index), values in sorted(groups.items()):
        series[f"{experiment}/{arm}/{metric}"].append((round_index, statistics.fmean(values)))
    return dict(series)


def _pareto_points(analysis: AnalysisResult) -> list[tuple[str, float, float]]:
    indexed = {(item.experiment_id, item.arm, item.ablation, item.metric): item.mean for item in analysis.summaries}
    output = []
    for experiment, arm, ablation, metric in sorted(indexed):
        if metric != "asr":
            continue
        utility = indexed.get((experiment, arm, ablation, "utility"))
        if utility is not None:
            output.append((f"{experiment}/{arm}/{ablation}", indexed[(experiment, arm, ablation, metric)], utility))
    return output


def _ablation_points(analysis: AnalysisResult) -> list[tuple[str, float]]:
    candidates = [
        (f"{item.arm}/{item.ablation}/{item.metric}", item.mean)
        for item in analysis.summaries
        if item.ablation != "full"
    ]
    return sorted(candidates)


def _convergence_svg(analysis: AnalysisResult) -> str:
    return _line_svg("Convergence", _convergence_series(analysis), analysis)


def _pareto_svg(analysis: AnalysisResult) -> str:
    points = _pareto_points(analysis)
    return _scatter_svg("Security-utility Pareto view", points, analysis)


def _ablation_svg(analysis: AnalysisResult) -> str:
    points = _ablation_points(analysis)
    return _bar_svg("Ablation comparison", points, analysis)


def _line_svg(title: str, series: dict[str, list[tuple[int, float]]], analysis: AnalysisResult) -> str:
    width, height = 900, 520
    parts = _svg_start(title, width, height, analysis)
    colors = ("#2563eb", "#dc2626", "#059669", "#7c3aed", "#d97706")
    all_points = [point for points in series.values() for point in points]
    max_x = max((point[0] for point in all_points), default=1)
    values = [point[1] for point in all_points] or [0.0, 1.0]
    low, high = min(values), max(values)
    span = high - low or 1.0
    for index, (label, points) in enumerate(sorted(series.items())):
        coordinates = []
        for x, value in points:
            px = 70 + 760 * x / max(max_x, 1)
            py = 440 - 350 * (value - low) / span
            coordinates.append(f"{px:.2f},{py:.2f}")
        parts.append(f'<polyline points="{" ".join(coordinates)}" fill="none" stroke="{colors[index % len(colors)]}" stroke-width="2"><title>{_xml(label)}</title></polyline>')
    return _svg_end(parts)


def _scatter_svg(title: str, points: Sequence[tuple[str, float, float]], analysis: AnalysisResult) -> str:
    parts = _svg_start(title, 900, 520, analysis)
    xs = [item[1] for item in points] or [0.0, 1.0]
    ys = [item[2] for item in points] or [0.0, 1.0]
    for label, x, y in points:
        px = 70 + 760 * _scale(x, xs)
        py = 440 - 350 * _scale(y, ys)
        parts.append(f'<circle cx="{px:.2f}" cy="{py:.2f}" r="6" fill="#2563eb"><title>{_xml(label)}: asr={x:.6g}, utility={y:.6g}</title></circle>')
    return _svg_end(parts)


def _bar_svg(title: str, points: Sequence[tuple[str, float]], analysis: AnalysisResult) -> str:
    parts = _svg_start(title, 900, 520, analysis)
    values = [item[1] for item in points] or [1.0]
    high = max(max(values), 1e-12)
    width = 760 / max(len(points), 1)
    for index, (label, value) in enumerate(points):
        height = 350 * value / high
        x = 70 + index * width + width * 0.15
        parts.append(f'<rect x="{x:.2f}" y="{440-height:.2f}" width="{width*0.7:.2f}" height="{height:.2f}" fill="#7c3aed"><title>{_xml(label)}: {value:.6g}</title></rect>')
    return _svg_end(parts)


def _svg_start(title: str, width: int, height: int, analysis: AnalysisResult) -> list[str]:
    refs = json.dumps([ref.model_dump(mode="json") for ref in analysis.source_files], sort_keys=True)
    return [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        f"<title>{_xml(title)}</title>",
        f"<metadata>{_xml(refs)}</metadata>",
        '<rect width="100%" height="100%" fill="white"/>',
        f'<text x="40" y="38" font-family="sans-serif" font-size="22">{_xml(title)}</text>',
        '<line x1="70" y1="440" x2="830" y2="440" stroke="#334155"/>',
        '<line x1="70" y1="90" x2="70" y2="440" stroke="#334155"/>',
    ]


def _svg_end(parts: list[str]) -> str:
    parts.append("</svg>")
    return "\n".join(parts) + "\n"


def _scale(value: float, values: Sequence[float]) -> float:
    low, high = min(values), max(values)
    return (value - low) / (high - low) if high > low else 0.5


def _t_critical_95(degrees_of_freedom: int) -> float:
    table = {
        1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365,
        8: 2.306, 9: 2.262, 10: 2.228, 11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145,
        15: 2.131, 16: 2.120, 17: 2.110, 18: 2.101, 19: 2.093, 20: 2.086,
        21: 2.080, 22: 2.074, 23: 2.069, 24: 2.064, 25: 2.060, 26: 2.056,
        27: 2.052, 28: 2.048, 29: 2.045, 30: 2.042,
    }
    return table.get(degrees_of_freedom, 1.96)


def _ablation_label(switches: dict[str, Any]) -> str:
    disabled = sorted(key for key, enabled in switches.items() if enabled is False)
    return "full" if not disabled else "without-" + "-".join(disabled)


def _unique_refs(refs: Any) -> list[SourceRef]:
    unique: dict[tuple[str, str, str], SourceRef] = {}
    for ref in refs:
        unique[(ref.path, ref.sha256, ref.json_pointer)] = ref
    return [unique[key] for key in sorted(unique)]


def _source_label(ref: SourceRef) -> str:
    return f"`{ref.path}#{ref.json_pointer}` (`{ref.sha256[:12]}`)"


def _format_optional(value: float | None) -> str:
    return "not_applicable" if value is None else f"{value:.6g}"


def _pointer(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _xml(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


__all__ = [
    "AnalysisResult",
    "MetricSummary",
    "Observation",
    "SignificanceResult",
    "SourceRef",
    "analyze_files",
    "render_paper_tables",
    "write_analysis_artifacts",
]
