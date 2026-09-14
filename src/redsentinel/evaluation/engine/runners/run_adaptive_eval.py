from pathlib import Path
from redsentinel.evaluation.engine.bootstrap import setup_paths  # noqa: F401
"""自适应攻击探索 — 评估入口。

运行全量评估: 5个多轮场景 + 11个角色 × 10个查询 + 3轮改进
保存结果到 data/adaptive_results/
"""
import os
import json
from datetime import datetime

from redsentinel.attacks.engine.adaptive_attack import (
    MULTI_TURN_SCENARIOS, ROLE_PERSONAS, BYPASS_QUERIES,
    run_multi_turn_evaluation, run_roleplay_evaluation,
    run_adaptive_improvement_cycle,
)


def main():
    OUTPUT_DIR = os.path.join(str(Path(__file__).resolve().parents[2]),
        "data", "experiments", "adaptive_results",
    )
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("=" * 70)
    print("自适应攻击探索 — 攻防评估")
    print(f"多轮场景: {len(MULTI_TURN_SCENARIOS)}")
    print(f"角色数:   {len(ROLE_PERSONAS)}")
    print(f"绕过查询: {len(BYPASS_QUERIES)}")
    print(f"输出目录: {OUTPUT_DIR}")
    print("=" * 70)

    from redsentinel.defenses.engine.security.firewall.classifier import classify

    # Run multi-turn evaluation
    print("\n[1/3] 多轮渐进式越狱评估...")
    print(f"{'场景':<16} {'总轮数':<8} {'拦截率':<10} {'触发轮捕获'}")
    print("-" * 52)
    mt_results = run_multi_turn_evaluation(
        scenarios=MULTI_TURN_SCENARIOS, classify_fn=classify
    )

    for sc in mt_results["by_scenario"]:
        blocked_count = sum(1 for t in sc["turns"] if t["blocked"])
        rate = round(blocked_count / len(sc["turns"]) * 100, 1)
        caught = "YES" if sc["trigger_caught"] else "NO"
        print(f"  {sc['name']:<14} {len(sc['turns']):<8} {rate}%{'':<6} {caught}")

    # Run role-play evaluation
    print("\n[2/3] 角色扮演绕过评估...")
    rp_results = run_roleplay_evaluation(
        personas=ROLE_PERSONAS, queries=BYPASS_QUERIES, classify_fn=classify
    )

    # Run improvement cycle
    print("\n[3/3] 自适应改进循环...")
    imp_history = run_adaptive_improvement_cycle(
        classify_fn=classify, rounds=3
    )

    # Combine and save
    combined = {
        "timestamp": datetime.now().isoformat(),
        "config": {
            "scenarios": len(MULTI_TURN_SCENARIOS),
            "personas": len(ROLE_PERSONAS),
            "queries": len(BYPASS_QUERIES),
        },
        "multi_turn": mt_results,
        "roleplay": rp_results,
        "improvements": imp_history,
    }

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def clean(obj):
        if isinstance(obj, dict):
            return {k: clean(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [clean(i) for i in obj]
        return obj

    report_path = os.path.join(OUTPUT_DIR, f"adaptive_eval_{timestamp}.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(clean(combined), f, ensure_ascii=False, indent=2)
    print(f"\n全量评估结果: {report_path}")

    # Save summary
    summary = {
        "timestamp": timestamp,
        "multi_turn": {
            "overall_block_rate": mt_results["overall_block_rate"],
            "trigger_turn_catch_rate": mt_results["trigger_turn_catch_rate"],
            "scenarios_tested": len(mt_results["by_scenario"]),
            "scenarios_caught": sum(
                1 for s in mt_results["by_scenario"] if s["trigger_caught"]
            ),
        },
        "roleplay": {
            "overall_block_rate": rp_results["overall_block_rate"],
            "overall_bypass_rate": rp_results["overall_bypass_rate"],
            "by_persona_block_rates": {
                p["role_name"]: p["block_rate"]
                for p in rp_results["by_persona"]
            },
            "by_category": rp_results["by_category"],
        },
        "improvements": imp_history,
    }
    summary_path = os.path.join(OUTPUT_DIR, f"adaptive_summary_{timestamp}.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(clean(summary), f, ensure_ascii=False, indent=2)
    print(f"摘要: {summary_path}")


if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore")
    main()
