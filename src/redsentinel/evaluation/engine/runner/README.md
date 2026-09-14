# Experiment Runner

**Experiment runner · v0.1**

串行实验调度与结果落盘 MVP。当前只支持串行执行；并行队列、复杂调度、大规模 diff 留到后续增强。

## 模块

| 路径 | 说明 |
|------|------|
| `core.py` | `ExperimentRunner`、`RunResult`、`diff_trajectories` |
| `paired_evaluation.py` | paired evaluation report skeleton 和 dry-run harness |
| `closed_loop.py` | Attack → Defense → Evaluation closed-loop runner |
| `__init__.py` | 导出 runner 公共接口 |

## 结果目录

默认写入根目录 `runs/`，该目录已加入 `.gitignore`：

```text
runs/{experiment_id}/seed_{seed}/{run_id}/
├── scenario.yaml
├── trajectory.json
└── metadata.json
```

## 职责

- 解析 `configs/scenarios/*.yaml`
- 串行执行 scenario，调用现有 sandbox / telemetry 链路
- 保存 scenario copy、trajectory、run metadata
- 同一 scenario 多次运行生成独立 run directory
- 提供最小 baseline diff：
  - step count
  - step type sequence
  - tool call sequence
  - final LLM output

## v0.1 限制

- `run_many()` 仅串行执行
- 如果 scenario 配置 `runner.parallel: true`，明确抛出 `NotImplementedError`
- 不实现 injector 调度逻辑
- `paired_evaluation.py` 只生成或校验 `not_run` 报告骨架，不运行 detector

## 验证

```powershell
.\.venv\Scripts\python.exe -m pytest tests\runner tests\integration -q
.\.venv\Scripts\python.exe -m ruff check src tests
```

## 被依赖

- `redsentinel.attacks.engine.injectors` — 注入实验
- `benchmark/` — AgentRiskBench 场景集

## Paired Evaluation Dry-run

T6 新增 `run_paired_evaluation_dry_run(...)`，用于交接时验证 T1-T4 产物仍能组成同一份 `paired-evaluation-report-v0.1` 骨架。

输入：

- detector acceptance fixture manifest
- repository root
- 可选 golden report fixture

行为：

- 复用 `build_paired_evaluation_report_skeleton(...)` 生成 `test_status="not_run"` 的报告骨架。
- 如果提供 golden report fixture，只读取并比较，不写回 fixture。
- 如果 golden fixture 与 dry-run 输出不同，抛出 `ValueError`。
- 不计算 MIS / GDM / TRS 分数，不调用 detector，不调用真实 API。

## TRS Acceptance Evaluation

T11 新增 `run_trs_acceptance_evaluation(...)`，用于把 T10 的 TRS baseline
接到 detector acceptance manifest 的单条 TRS fixture 上。

行为：

- 只选择 `metric="TRS"` 的 acceptance fixture，并要求恰好一条。
- 构造 `DetectorInput(metric="TRS")`，调用
  `redsentinel.evaluation.engine.detection.run_trs_baseline`。
- 返回 `expected_decision` / `actual_decision` / `passed` 对照，便于后续报告接线。
- 不执行 MIS / GDM detector，不调用真实 API，不写回 report fixture。

## TRS Paired Report Status

T12 新增 `build_trs_paired_report_with_status(...)`，用于把单条 TRS
acceptance evaluation 结果合并进 `paired-evaluation-report-v0.1` 骨架。

行为：

- 复用 `build_paired_evaluation_report_skeleton(...)` 生成原始报告骨架。
- 复用 `run_trs_acceptance_evaluation(...)` 获取 TRS expected / actual decision。
- 只更新 TRS 记录的 `test_status` 和失败说明；MIS / GDM 记录继续保持
  `test_status="not_run"`。
- 不新增 report schema 字段，不调用真实 API，不写回 golden report fixture。

T13 固定 `datasets/acceptance/reports/paired-evaluation-trs-status-v0.1.json`
作为该 helper 的可重放 fixture；它只记录 TRS `passed` 状态，MIS / GDM 仍为
`not_run`。

## GDM Acceptance Evaluation

T15 新增 `run_gdm_acceptance_evaluation(...)`，用于把 T14 的 GDM baseline
接到 detector acceptance manifest 的单条 GDM fixture 上。

行为：

- 只选择 `metric="GDM"` 的 acceptance fixture，并要求恰好一条。
- 构造 `DetectorInput(metric="GDM")`，调用
  `redsentinel.evaluation.engine.detection.run_gdm_baseline`。
- 返回 `expected_decision` / `actual_decision` / `passed` 对照，便于后续报告接线。
- 不执行 MIS detector，不扩展 TRS，不调用真实 API，不写回 report fixture。

## MIS Acceptance Evaluation

T19 adds `run_mis_acceptance_evaluation(...)` to connect the T18 MIS baseline
to the single MIS fixture in the detector acceptance manifest.

Behavior:
- Selects exactly one `metric="MIS"` acceptance fixture.
- Builds `DetectorInput(metric="MIS")` and calls
  `redsentinel.evaluation.engine.detection.run_mis_baseline`.
- Returns `expected_decision` / `actual_decision` / `passed` plus detector output.
- Does not generate paired report status, expand TRS / GDM, call real APIs, or write fixtures.

## MIS Paired Report Status

T21 fixes `datasets/acceptance/reports/paired-evaluation-mis-status-v0.1.json`
as the replayable fixture for this helper: MIS is `passed`, while GDM and TRS
remain `not_run`.

T20 adds `build_mis_paired_report_with_status(...)` to merge the single MIS
acceptance evaluation result into a `paired-evaluation-report-v0.1` skeleton.

Behavior:
- Reuses `build_paired_evaluation_report_skeleton(...)` for the original report.
- Reuses `run_mis_acceptance_evaluation(...)` for MIS expected / actual decision.
- Updates only the MIS record `test_status` and failure notes; GDM / TRS remain
  `test_status="not_run"`.
- Does not add report schema fields, call real APIs, write the golden report, or
  create a new JSON fixture.

## GDM Paired Report Status

T17 fixes `datasets/acceptance/reports/paired-evaluation-gdm-status-v0.1.json`
as the replayable fixture for this helper: GDM is `passed`, while MIS and TRS
remain `not_run`.

T16 新增 `build_gdm_paired_report_with_status(...)`，用于把单条 GDM
acceptance evaluation 结果合并进 `paired-evaluation-report-v0.1` 骨架。

行为：

- 复用 `build_paired_evaluation_report_skeleton(...)` 生成原始报告骨架。
- 复用 `run_gdm_acceptance_evaluation(...)` 获取 GDM expected / actual decision。
- 只更新 GDM 记录的 `test_status` 和失败说明；MIS 记录继续保持
  `test_status="not_run"`，TRS 状态 helper 不扩展。
- 不新增 report schema 字段，不调用真实 API，不写回 golden report fixture。

## Runner Handoff

T22 confirms the runner-side v0.1 handoff:

- `run_trs_acceptance_evaluation(...)`, `run_gdm_acceptance_evaluation(...)`,
  and `run_mis_acceptance_evaluation(...)` each replay exactly one detector
  acceptance fixture.
- `build_trs_paired_report_with_status(...)`,
  `build_gdm_paired_report_with_status(...)`, and
  `build_mis_paired_report_with_status(...)` each update only their own metric
  record.
- The golden `paired-evaluation-report-v0.1.json` remains the `not_run`
  skeleton; metric-specific status fixtures live under `datasets/acceptance/reports/`.

This handoff does not add report schema fields, run large experiments, or call
real APIs.

## Closed-loop Evaluation

T36 adds `run_closed_loop_evaluation(...)` as the deterministic offline
orchestration entry point for the integrated project.

Behavior:
- Loads the scenario manifest and detector acceptance manifest.
- Runs each clean / controlled pair with `ExperimentRunner`.
- Runs the matching MIS / TRS / GDM baseline on the generated controlled
  trajectory.
- Feeds detector attribution into the corresponding Memory / Tool / Goal Guard.
- Writes guard decisions into trajectory `metadata.defense_decisions` and emits
  `closed-loop-report-v0.1.json` under the provided results root.
- Uses an isolated per-pair defense audit log and verifies the audit hash chain.

This path stays offline and deterministic: it uses existing cassette/mock
scenarios, does not call real APIs, and does not change `trajectory-v1`.
