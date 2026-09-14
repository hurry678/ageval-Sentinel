# Telemetry

**Telemetry · v0.1**

Out-of-band 观测层，与 Agent 执行层完全解耦。

## 模块

| 路径 | 说明 |
|------|------|
| `emitter.py` | `TelemetryStepEmitter`，side-channel 收集 `StepEvent` |
| `recorder.py` | `TrajectoryRecorder`，从 session events 构建 schema-compatible trajectory |
| `__init__.py` | 导出 telemetry 公共接口 |

## 职责

- 按 `schemas/trajectory-v1.schema.json` 采集标准化 Trajectory
- 记录 LLM I/O、tool call 序列、memory read/write、时间戳
- 保留 `memory_ops`、`state_delta`，为后续 Memory Store / Runner 对接预留
- Telemetry overhead 监控
- 验证 telemetry 不修改 Agent context / LLM input messages

## 核心原则

观测层不得通过 context window 影响 Agent 决策。所有采集走 side-channel。

## v0.1 验收

- `TelemetryStepEmitter` 自动分配连续 `step_index`
- 超过 `max_steps` 时抛出 `MaxStepsExceeded`
- emit 时深拷贝事件，避免污染原始 event / messages
- `TrajectoryRecorder` 输出符合 `trajectory-v1` schema
- `metadata.telemetry_overhead_ms` 为非负数
- `memory_ops` 与 `state_delta` 可进入 trajectory step

## 验证

```powershell
.\.venv\Scripts\python.exe -m pytest tests\sandbox tests\telemetry -q
.\.venv\Scripts\python.exe -m ruff check src tests
```

## 依赖

- `redsentinel.runtime.engine.sandbox` — 执行环境 hook 点

## 被依赖

- `redsentinel.evaluation.engine.runner` — 实验结果持久化
- `redsentinel.evaluation.engine.detection` — 检测输入
