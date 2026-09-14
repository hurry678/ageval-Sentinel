# Sandbox SDK

**Sandbox SDK · v0.1**

多框架 Agent 隔离执行环境。

## 模块

| 路径 | 说明 |
|------|------|
| `config.py` | 场景 YAML → `ScenarioConfig` |
| `session.py` | 隔离 session（emitter / tools / llm / memory） |
| `llm/vcr_client.py` | Cassette 回放 LLM（按 turn index） |
| `replay.py` | `CassetteStore` 加载 YAML cassette |
| `tools/` | Mock Tool Registry |
| `backends/` | Direct API / LangGraph / Docker；AutoGen scaffold 仅保留内部占位，不是可运行 scenario framework |
| `trajectory.py` | `TrajectoryBuilder` 兼容壳（实际构建逻辑已迁移到 `redsentinel.runtime.engine.telemetry.TrajectoryRecorder`） |
| `run.py` | `run_scenario(path)` 入口 |

## 运行 5 步 smoke 场景

```powershell
pip install -e ".[all]"
python -c "from redsentinel.runtime.engine.sandbox.run import run_scenario; print(run_scenario('configs/scenarios/p1-sandbox-5step-direct-api.yaml')['steps'][0]['step_type'])"
```

## Cassette 回放

- Cassette 路径：`tests/cassettes/{framework}/{experiment_id}/seed_{seed}.yaml`
- 匹配策略：按 `X-ARL-Turn` header（0, 1, 2…），**不比对 request body**
- CI / 日常测试：无需 `OPENAI_API_KEY`
- 首次录制：`$env:VCR_RECORD='1'; $env:OPENAI_API_KEY='...'; pytest tests/sandbox/test_replay_direct_api.py`

## 稳定契约

Backend 只通过 telemetry emitter 发射 `StepEvent`，trajectory 构建由 `redsentinel.runtime.engine.telemetry.TrajectoryRecorder` 负责。Step 语义详见 [`docs/specs/step-semantics.md`](../../../docs/specs/step-semantics.md)。
