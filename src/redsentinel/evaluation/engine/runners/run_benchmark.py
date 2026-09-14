from pathlib import Path
from redsentinel.evaluation.engine.bootstrap import setup_paths  # noqa: F401
"""业界基准对标 — 评估入口。

运行: HackAPrompt风格30样本 + Garak风格20探测 + OWASP覆盖度评估
保存结果到 data/benchmarks/
"""
import os
import json
from datetime import datetime

from redsentinel.evaluation.engine.benchmarks.benchmark import (
    HACKAPROMPT_SAMPLES, GARAK_STYLE_PROBES, OWASP_LLM_TOP10_COVERAGE,
    run_benchmark_evaluation, run_garak_evaluation,
)


def main():
    OUTPUT_DIR = os.path.join(str(Path(__file__).resolve().parents[2]),
        "data", "benchmarks",
    )
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("=" * 70)
    print("业界基准对标评估")
    print(f"HackAPrompt 样本: {len(HACKAPROMPT_SAMPLES)} (4类 × 8级)")
    print(f"Garak 风格探测:  {len(GARAK_STYLE_PROBES)} (6类)")
    print(f"OWASP Top 10:     {len(OWASP_LLM_TOP10_COVERAGE)} 项")
    print(f"输出目录:        {OUTPUT_DIR}")
    print("=" * 70)

    from redsentinel.defenses.engine.security.firewall.classifier import classify

    # Run HackAPrompt benchmark
    print(f"\n[1/3] HackAPrompt 风格基准...")
    hp_results = run_benchmark_evaluation(HACKAPROMPT_SAMPLES, classify_fn=classify)

    # Run Garak-style evaluation
    print(f"\n[2/3] Garak 风格探测...")
    garak_results = run_garak_evaluation(GARAK_STYLE_PROBES, classify_fn=classify)

    # OWASP coverage
    print(f"\n[3/3] OWASP Top 10 覆盖度:")
    covered = sum(1 for v in OWASP_LLM_TOP10_COVERAGE.values() if v["covered"])
    total = len(OWASP_LLM_TOP10_COVERAGE)
    print(f"  本项目覆盖: {covered}/{total}")
    for risk, info in OWASP_LLM_TOP10_COVERAGE.items():
        status = "[COVERED]  " if info["covered"] else "[NOT COVERED]"
        print(f"  {status} {risk} — {info['detail']}")

    # Combine and save
    combined = {
        "timestamp": datetime.now().isoformat(),
        "config": {
            "hackaprompt_samples": len(HACKAPROMPT_SAMPLES),
            "garak_probes": len(GARAK_STYLE_PROBES),
        },
        "hackaprompt": hp_results,
        "garak": garak_results,
        "owasp_coverage": {
            risk: {
                "covered": info["covered"],
                "module": info.get("module", ""),
                "detail": info["detail"],
                "gaps": info.get("gaps", ""),
            }
            for risk, info in OWASP_LLM_TOP10_COVERAGE.items()
        },
    }

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def clean(obj):
        if isinstance(obj, dict):
            return {k: clean(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [clean(i) for i in obj]
        return obj

    report_path = os.path.join(OUTPUT_DIR, f"benchmark_{timestamp}.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(clean(combined), f, ensure_ascii=False, indent=2)
    print(f"\n全量评估结果: {report_path}")

    # Save summary
    summary = {
        "timestamp": timestamp,
        "hackaprompt": {
            "overall_block_rate": hp_results["overall_block_rate"],
            "avg_latency_ms": hp_results["avg_latency_ms"],
            "by_category": hp_results["by_category"],
            "by_level": hp_results["by_level"],
        },
        "garak": {
            "overall_block_rate": garak_results["overall_block_rate"],
            "by_probe_type": garak_results["by_garak_probe"],
        },
        "owasp_coverage": f"{covered}/{total}",
    }
    summary_path = os.path.join(OUTPUT_DIR, f"benchmark_summary_{timestamp}.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(clean(summary), f, ensure_ascii=False, indent=2)
    print(f"摘要: {summary_path}")


if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore")
    main()
