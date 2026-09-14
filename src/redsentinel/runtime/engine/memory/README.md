# Memory Store

**Memory store · v0.1**

本地 Memory Store MVP。当前目标是先稳定接口、namespace isolation、CRUD audit log 与 telemetry 对接；Chroma/Qdrant + PostgreSQL 双轨存储作为后续增强，不是 v0.1 门禁。

## 模块

| 路径 | 说明 |
|------|------|
| `store.py` | `InMemoryMemoryStore`、`MemoryRecord`、`MemoryAuditRecord` |
| `__init__.py` | 导出 memory 公共接口 |

## 职责

- 支持 short-term / long-term / episodic 三层 memory
- 按 namespace 隔离不同 session / experiment
- 提供 `write/read/delete/list_namespace/clear_namespace/audit_log`
- 每次 CRUD 写入 `MemoryAuditRecord`
- `MemoryAuditRecord.to_payload()` 可转换为 telemetry 使用的 `MemoryOpPayload`

## v0.1 验收

- 不同 namespace 之间读写隔离
- 不同 layer 中同名 key 互不污染
- 删除不存在 key 为幂等操作，并记录 audit
- audit payload 可进入 trajectory step 的 `memory_ops`
- memory 相关 trajectory 可通过 `schemas/trajectory-v1.schema.json`

## 验证

```powershell
.\.venv\Scripts\python.exe -m pytest tests\memory tests\integration -q
.\.venv\Scripts\python.exe -m ruff check src tests
```

## 被依赖

- `redsentinel.runtime.engine.sandbox` — session 级 memory store
- `redsentinel.attacks.engine.injectors.memory_poisoning` — 投毒入口
- `redsentinel.evaluation.engine.detection.memory_integrity` — MIS 计算
