"""COMP2 · Attack Agent 战役 demo —— 单命令产出 artifact 包。

落盘到 ``attack-runs/<timestamp>/``：

    attack-runs/<timestamp>/
      ├── attack_history.jsonl   # 每次攻击尝试的完整记录
      ├── reflection_log.json    # 失败反思 + 重规划/升级记录
      ├── coverage_table.json    # 7 类威胁覆盖表（结构化）
      ├── coverage_table.md      # 攻击面覆盖表（答辩用）
      └── campaign_summary.md    # 战役一页摘要（收敛/反思效果）

只编排 ``AttackAgent`` 的产出，不引入新攻击逻辑。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from redsentinel.attacks.engine.attack_agent import AttackAgent, CampaignResult
from redsentinel.attacks.engine.llm_client import SharedLLMClient
from redsentinel.attacks.engine.threat_taxonomy import THREAT_CATEGORIES, SyntheticTarget


@dataclass(frozen=True)
class Comp2DemoResult:
    run_dir: Path
    campaign: CampaignResult
    metrics: dict[str, Any]
    artifacts: dict[str, Path]


def run_comp2_demo(
    *,
    runs_root: str | Path | None = None,
    timestamp: str | None = None,
    max_rounds: int = 6,
    force_offline: bool = False,
    repo_root: str | Path | None = None,
) -> Comp2DemoResult:
    """运行 COMP2 攻击战役并写出 artifact 包。

    Args:
        runs_root: ``<timestamp>/`` 的父目录，默认 ``<repo_root>/attack-runs``。
        timestamp: 覆盖运行目录名（测试用，保证确定性）。
        max_rounds: 最大对抗轮数。
        force_offline: 强制离线确定性模式（测试/复现用）。
        repo_root: 仓库根目录，默认当前工作目录。
    """
    root = Path(repo_root) if repo_root is not None else Path.cwd()
    runs_root_path = Path(runs_root) if runs_root is not None else root / "attack-runs"
    stamp = timestamp or datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = runs_root_path / stamp
    run_dir.mkdir(parents=True, exist_ok=True)

    agent = AttackAgent(
        target=SyntheticTarget(),
        llm=SharedLLMClient(force_offline=force_offline),
        max_rounds=max_rounds,
    )
    campaign = agent.run()
    metrics = _compute_metrics(campaign)

    artifacts: dict[str, Path] = {}
    artifacts["attack_history"] = _write_attack_history(run_dir, campaign)
    artifacts["reflection_log"] = _write_reflection_log(run_dir, campaign, metrics)
    artifacts["coverage_table"] = _write_coverage_table_json(run_dir, campaign, metrics)
    artifacts["coverage_table_md"] = _write_coverage_table_md(run_dir, campaign)
    artifacts["campaign_summary"] = _write_campaign_summary(run_dir, campaign, metrics)

    return Comp2DemoResult(
        run_dir=run_dir,
        campaign=campaign,
        metrics=metrics,
        artifacts=artifacts,
    )


def _compute_metrics(campaign: CampaignResult) -> dict[str, Any]:
    total_categories = len(THREAT_CATEGORIES)
    timeline = campaign.coverage_timeline
    first_coverage = timeline[0]["breached_count"] if timeline else 0
    final_coverage = campaign.coverage_count
    escalations = sum(1 for r in campaign.reflections if r.escalated)
    return {
        "total_threat_categories": total_categories,
        "coverage_first_round": first_coverage,
        "coverage_final": final_coverage,
        "coverage_rate": round(campaign.coverage_rate, 4),
        "coverage_gain_from_reflection": final_coverage - first_coverage,
        "total_attempts": len(campaign.attempts),
        "successful_attempts": sum(1 for a in campaign.attempts if a.success),
        "total_reflections": len(campaign.reflections),
        "escalations": escalations,
        "rounds": campaign.rounds,
        "llm_mode": campaign.llm_mode,
        "coverage_target_met": final_coverage >= 6,
    }


def _write_attack_history(run_dir: Path, campaign: CampaignResult) -> Path:
    path = run_dir / "attack_history.jsonl"
    lines = [
        json.dumps(a.to_dict(), ensure_ascii=False, sort_keys=True)
        for a in campaign.attempts
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _write_reflection_log(
    run_dir: Path, campaign: CampaignResult, metrics: dict[str, Any]
) -> Path:
    path = run_dir / "reflection_log.json"
    payload = {
        "schema_version": "comp2-reflection-log-v0.1",
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "escalations": metrics["escalations"],
        "coverage_gain_from_reflection": metrics["coverage_gain_from_reflection"],
        "reflections": [r.to_dict() for r in campaign.reflections],
    }
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return path


def _coverage_rows(campaign: CampaignResult) -> list[dict[str, Any]]:
    breached = {e["category"]: e for e in campaign.experience_library}
    rows: list[dict[str, Any]] = []
    for category, cn in THREAT_CATEGORIES.items():
        exp = breached.get(category)
        attempts = [a for a in campaign.attempts if a.category == category]
        rows.append(
            {
                "category": category,
                "category_cn": cn,
                "breached": category in breached,
                "winning_strategy": exp["winning_strategy"] if exp else None,
                "winning_intensity": exp["intensity"] if exp else None,
                "round_breached": exp["round_breached"] if exp else None,
                "attempts": len(attempts),
            }
        )
    return rows


def _write_coverage_table_json(
    run_dir: Path, campaign: CampaignResult, metrics: dict[str, Any]
) -> Path:
    path = run_dir / "coverage_table.json"
    payload = {
        "schema_version": "comp2-coverage-table-v0.1",
        "metrics": metrics,
        "coverage_timeline": campaign.coverage_timeline,
        "rows": _coverage_rows(campaign),
        "experience_library": campaign.experience_library,
    }
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return path


def _write_coverage_table_md(run_dir: Path, campaign: CampaignResult) -> Path:
    path = run_dir / "coverage_table.md"
    rows = _coverage_rows(campaign)
    lines = ["# COMP2 · 攻击面覆盖表", ""]
    lines.append("| 威胁类别 | 是否攻破 | 制胜手法 | 强度 | 攻破轮次 | 尝试次数 |")
    lines.append("|---|---|---|---|---|---|")
    for r in rows:
        lines.append(
            f"| {r['category_cn']}({r['category']}) | "
            f"{'✅' if r['breached'] else '❌'} | "
            f"{r['winning_strategy'] or '—'} | "
            f"{r['winning_intensity'] or '—'} | "
            f"{r['round_breached'] if r['round_breached'] else '—'} | "
            f"{r['attempts']} |"
        )
    lines.append("")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _write_campaign_summary(
    run_dir: Path, campaign: CampaignResult, metrics: dict[str, Any]
) -> Path:
    path = run_dir / "campaign_summary.md"
    lines = ["# COMP2 · Attack Agent 战役摘要", ""]
    lines.append(
        "闭环：规划(plan) → 执行(execute) → 失败反思(reflect) → 重规划/升级(replan)。"
        "攻击 Agent 在 7 类威胁上迭代，失败即沿策略阶梯升级，成功即沉淀进经验库。"
    )
    lines.append("")
    lines.append("## 核心指标")
    lines.append("")
    lines.append("| 指标 | 数值 |")
    lines.append("|---|---|")
    lines.append(f"| LLM 模式 | {metrics['llm_mode']} |")
    lines.append(f"| 对抗轮数 | {metrics['rounds']} |")
    lines.append(
        f"| 攻击面覆盖 | {metrics['coverage_final']}/{metrics['total_threat_categories']} "
        f"({metrics['coverage_rate']:.0%}) |"
    )
    lines.append(f"| 首轮覆盖 | {metrics['coverage_first_round']} 类 |")
    lines.append(
        f"| 反思带来的覆盖增量 | +{metrics['coverage_gain_from_reflection']} 类 |"
    )
    lines.append(f"| 攻击尝试总数 | {metrics['total_attempts']} |")
    lines.append(f"| 成功攻击数 | {metrics['successful_attempts']} |")
    lines.append(f"| 失败反思次数 | {metrics['total_reflections']} |")
    lines.append(f"| 策略升级次数 | {metrics['escalations']} |")
    lines.append(
        f"| 覆盖达标(≥6/7) | {'是' if metrics['coverage_target_met'] else '否'} |"
    )
    lines.append("")
    lines.append("## 覆盖率随反思演进")
    lines.append("")
    lines.append("| 轮次 | 已攻破类别数 | 覆盖率 |")
    lines.append("|---|---|---|")
    for t in campaign.coverage_timeline:
        lines.append(
            f"| R{t['round']} | {t['breached_count']} | {t['coverage_rate']:.0%} |"
        )
    lines.append("")
    lines.append("## 产物")
    lines.append("")
    lines.append("- `attack_history.jsonl` — 每次攻击尝试完整记录")
    lines.append("- `reflection_log.json` — 失败反思 + 重规划/升级")
    lines.append("- `coverage_table.json` / `coverage_table.md` — 攻击面覆盖表")
    lines.append("- `campaign_summary.md` — 本摘要")
    lines.append("")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


__all__ = ["Comp2DemoResult", "run_comp2_demo"]
