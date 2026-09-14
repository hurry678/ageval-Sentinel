from pathlib import Path
from redsentinel.evaluation.engine.bootstrap import setup_paths  # noqa: F401
"""输出安全深度评测 — 评估入口。

运行全量评估: 边界测试 + 三级粒度对比 + 安全幻觉检测
保存结果到 data/output_eval_results/
"""
import os
import json
from datetime import datetime

from redsentinel.evaluation.engine.benchmarks.output_eval import (
    BOUNDARY_SAMPLES, GRANULARITY_LEVELS,
    HALLUCINATION_PROBE_QUERIES,
    evaluate_output_filter, compute_refusal_matrix,
    compare_granularity_levels, detect_security_hallucinations,
)


def main():
    OUTPUT_DIR = os.path.join(str(Path(__file__).resolve().parents[2]),
        "data", "experiments", "output_eval_results",
    )
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("=" * 70)
    print("模型输出安全深度评测")
    print(f"边界样本: {len(BOUNDARY_SAMPLES)}")
    print(f"粒度级别: {len(GRANULARITY_LEVELS)}")
    print(f"幻觉探测: {len(HALLUCINATION_PROBE_QUERIES)} 查询")
    print(f"输出目录: {OUTPUT_DIR}")
    print("=" * 70)

    import warnings
    warnings.filterwarnings("ignore")

    # Run boundary test evaluation
    print("\n[1/3] 边界测试评估 (平衡粒度)...")
    boundary_results = evaluate_output_filter(BOUNDARY_SAMPLES)
    refusal_matrix = compute_refusal_matrix(boundary_results)

    print(f"\n  边界判定矩阵:")
    print(f"    安全内容正确放行: {refusal_matrix['summary']['correct_allow']}")
    print(f"    危险内容正确拦截: {refusal_matrix['summary']['correct_block']}")
    print(f"    误拦(FP): {refusal_matrix['summary']['wrong_block_fp']}")
    print(f"    漏拦(FN): {refusal_matrix['summary']['wrong_allow_fn']}")
    print(f"    准确率: {refusal_matrix['summary']['accuracy']}%")

    # Run granularity comparison
    print("\n[2/3] 过滤粒度三级对比...")
    granularity_results = compare_granularity_levels(BOUNDARY_SAMPLES)

    # Run hallucination analysis
    print("\n[3/3] 安全幻觉分析...")
    hallucination_results = detect_security_hallucinations(HALLUCINATION_PROBE_QUERIES)

    # Combine and save
    combined = {
        "timestamp": datetime.now().isoformat(),
        "config": {
            "boundary_samples": len(BOUNDARY_SAMPLES),
            "granularity_levels": list(GRANULARITY_LEVELS.keys()),
            "hallucination_probes": len(HALLUCINATION_PROBE_QUERIES),
        },
        "boundary": boundary_results,
        "refusal_matrix": refusal_matrix,
        "granularity": granularity_results,
        "hallucination": hallucination_results,
    }

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def clean(obj):
        if isinstance(obj, dict):
            return {k: clean(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [clean(i) for i in obj]
        return obj

    report_path = os.path.join(OUTPUT_DIR, f"output_eval_{timestamp}.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(clean(combined), f, ensure_ascii=False, indent=2)
    print(f"\n全量评估结果: {report_path}")

    # Save summary
    summary = {
        "timestamp": timestamp,
        "boundary": {
            "total_samples": boundary_results["total_samples"],
            "false_positive_rate": boundary_results["false_positive_rate"],
            "false_negative_rate": boundary_results["false_negative_rate"],
            "accuracy": refusal_matrix["summary"]["accuracy"],
        },
        "granularity_comparison": {
            level: {
                "label": r["label"],
                "block_rate": r["block_rate"],
                "fp": r["false_positives"],
                "fn": r["false_negatives"],
            }
            for level, r in granularity_results.items()
        },
        "hallucination": {
            "rate": hallucination_results["hallucination_rate"],
            "by_type": hallucination_results["by_type"],
        },
    }
    summary_path = os.path.join(OUTPUT_DIR, f"output_eval_summary_{timestamp}.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(clean(summary), f, ensure_ascii=False, indent=2)
    print(f"摘要: {summary_path}")


if __name__ == "__main__":
    main()
