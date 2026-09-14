# Risk Injectors

**Risk injectors · v0.1**

本模块实现受控风险注入，明确区分 controlled injection 与 observational run。注入结果通过 side-channel telemetry 进入 trajectory metadata / state_delta，不写入额外 agent context。

## Public API

- `InjectionEvent`
- `InjectionResult`
- `MemoryPoisoningInjector`
- `ToolTamperingProxy`
- `GoalPerturbationInjector`
- `GoalRepresentation`
- `GoalDriftProbe`
- `validate_goal_drift_spec`

## Injectors

| 模块 | 状态 | 能力 |
|------|------|------|
| `memory_poisoning/` | v0.1 | semantic substitution / authority fabrication / temporal manipulation |
| `tool_tampering/` | v0.1 | response replacement / simulated delay metadata / confidence degradation |
| `goal_perturbation/` | v0.1 | system prompt / user goal perturbation |

## Telemetry Contract

- 注入事件写入 `trajectory.metadata.injections`。
- 与具体 step 相关的注入写入 `step.state_delta.injection`。
- Memory poisoning 通过 `MemoryAuditRecord.to_payload()` 写入下一条 LLM step 的 `memory_ops`。
- Tool tampering proxy 不破坏 `ToolRegistry` 的 mock / real handler 切换。

## Scenarios

每类 injector 均有 clean / controlled Direct API replay scenario，位于 `configs/scenarios/`。

小型标注样例位于 `datasets/annotated/phase2/`。

## AttackSpec

T1 引入 `redsentinel.attacks.engine.attack_spec.AttackSpec` 和 scenario manifest，用于描述现有受控攻击与 clean / controlled scenario 配对。Injectors 仍只根据 `ScenarioConfig.injection` 执行受控注入；`AttackSpec` 不实现 mutation engine。

## Boundary

本模块不实现 `redsentinel.evaluation.engine.detection`，不计算 MIS / GDM / TRS，只生成可复现 ground truth 和 labeled trajectories。
