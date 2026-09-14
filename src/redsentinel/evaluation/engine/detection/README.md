# Detection & Trajectory Modeling

**Detection & trajectory modeling · v0.1**

基于受控轨迹数据的风险检测与建模。有效性完全依赖上游数据质量。

## 子模块

| 模块 | 指标 | 周期 |
|------|------|------|
| `trajectory_risk/` | TRS（Trajectory Risk Score） | W13–14 |
| `goal_drift/` | GDM（Goal Drift Metric） | W15–16 |
| `memory_integrity/` | MIS（Memory Integrity Score） | W17 |

## 评估

以受控注入实验为 ground truth，构建 ROC / precision-recall 框架。

## Detector Contract

T2 固定 `DetectorInput`、`DetectorOutput` 和 acceptance fixture manifest，作为未来 MIS / GDM / TRS detector 的共同验收入口。契约位于 `redsentinel.evaluation.engine.detection.contracts`，文档见 `docs/specs/detector-contract/`。

T10 新增最小 TRS baseline scaffold：`redsentinel.evaluation.engine.detection.run_trs_baseline`
消费 `DetectorInput(metric="TRS")` 和 tool tampering controlled trajectory，返回
`DetectorOutput(metric="TRS")` 与可解释 attribution。该 scaffold 只覆盖当前 TRS
acceptance fixture；MIS / GDM detector 仍不在本任务包实现。

T14 新增最小 GDM baseline scaffold：`redsentinel.evaluation.engine.detection.run_gdm_baseline`
消费 `DetectorInput(metric="GDM")` 和 goal perturbation controlled trajectory，返回
`DetectorOutput(metric="GDM")` 与可解释 attribution。该 scaffold 只覆盖当前 GDM
acceptance fixture；MIS detector 仍不在本任务包实现。

T18 新增最小 MIS baseline scaffold：`redsentinel.evaluation.engine.detection.run_mis_baseline`
消费 `DetectorInput(metric="MIS")` 和 memory poisoning controlled trajectory，返回
`DetectorOutput(metric="MIS")` 与可解释 attribution。该 scaffold 只覆盖当前 MIS
acceptance fixture；TRS / GDM detector 不在本任务包扩展。

## Completion Gate

T22 将 detector v0.1 收口为三条可重放小闭环：

- TRS：`run_trs_baseline` + `run_trs_acceptance_evaluation` + TRS status fixture。
- GDM：`run_gdm_baseline` + `run_gdm_acceptance_evaluation` + GDM status fixture。
- MIS：`run_mis_baseline` + `run_mis_acceptance_evaluation` + MIS status fixture。

该收口只确认 baseline API、contract、acceptance fixtures 和 report status helper 可交接；
不新增 detector、不改 trajectory schema、不做阈值校准或真实 API 实验。

## 依赖

- `redsentinel.runtime.engine.telemetry` — 轨迹输入
- `redsentinel.evaluation.engine.detection.contracts` — detector 输入输出契约
- `docs/specs/goal-drift/` — GDM 形式化定义
