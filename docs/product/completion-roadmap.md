# Sentinel-Guardian 全量补齐路线图（P0–P3）

> 目标：在现有 ~85% 成熟度基础上，补齐信任闭合、平台化存储、泛化验证与工程卫生四大差距，交付一个功能完善、界面友好、性能稳定的通用型 Agent 检测平台。
> 组织方式：本文件为总路线图；每个阶段（P0/P1/P2/P3）拆为独立 OpenSpec change，逐个 propose → apply → verify → archive。

---

## 一、项目目标与范围

### 1.1 目标
| 维度 | 现状 | 目标 |
|---|---|---|
| 竞赛闭环 (C1–C5) | 完整 | C6 现场验收落地 |
| 信任级别 | 正式制品强制 partial | 可达 complete（宿主侧独立观测） |
| 存储层 | 纯文件系统 | 引入关系型 DB，DB 级多租户隔离 |
| 验证面 | 1 Agent/1 模型/1 seed | ≥2 Agent × ≥2 模型横评 |
| 工程卫生 | 文档漂移、双轨混淆 | 文档一致、子项目定位清晰 |

### 1.2 范围
- **纳入**：P0–P3 全部差距项（见路线图第三节）
- **排除**：计费系统、复杂 RBAC、商业化 SaaS 运营（超出检测平台核心）

### 1.3 预期成果
1. C6 现场验收视频 + 可复现产物
2. 宿主侧行为观测器，画像信任级可闭合至 complete
3. DB 支撑的多租户隔离层 + 迁移脚本
4. 多 Agent/多模型横评报告
5. 文档零漂移，`ageval-security` 定位明确
6. 全链路测试通过（含并发/负载）

---

## 二、技术架构选型

| 领域 | 选型 | 理由 |
|---|---|---|
| 存储层 | SQLite（本地/桌面）→ 可切 PostgreSQL（部署） + SQLAlchemy 2.0 | 桌面零依赖，部署可平滑升级；与现有文件产物并存 |
| 数据迁移 | Alembic | 版本化 schema，支持回滚 |
| 宿主观测器 | Docker events API + eBPF 可选 / 进程+网络 syscall 采集 | 独立于容器内自报，实现信任闭合 |
| 后端 | 沿用 FastAPI + Pydantic v2 | 与现有栈一致，不引入新框架 |
| 前端 | 沿用 React + TS + Vite | 现有 C5 工作区扩展 |
| 测试 | Pytest + Vitest + Playwright + locust（负载） | 现有栈 + 补负载工具 |

**架构原则**：surgical——DB 层以适配器形式引入，文件产物保留为证据源；不重写现有闭环。

---

## 三、分阶段路线图与 OpenSpec change 映射

### P0 — 竞赛交付闭环（change: `p0-competition-delivery`）
| 任务 | 验收标准 |
|---|---|
| C6 现场验收：真实 OpenManus + 真实模型端到端 | 录像 + 可复现产物固化 |
| 文档漂移修复 | `docs/product/*` 中 `auto_evaluation_system.*`/`agent_integration_system.*` 全部更新为 `redsentinel.*` |
| Secret scan | artifact/日志/截图/视频过密钥扫描，0 泄露 |
| 清理 `attack_agent.py` 重复 TYPE_CHECKING 块 | 静态检查通过 |

### P1 — 信任闭合与泛化（change: `p1-trust-and-generalization`）
| 任务 | 验收标准 |
|---|---|
| 宿主侧独立行为观测器 | 画像信任级可从 partial → complete |
| 观测器 ↔ 画像闭合逻辑 | complete 判定单测覆盖 |
| 接入第二个 Agent + 第二个模型横评 | 横评报告产出，破除单点泛化 |

### P2 — 平台化存储与工程卫生（change: `p2-platform-storage`）
| 任务 | 验收标准 |
|---|---|
| 引入 SQLAlchemy + Alembic 存储层 | schema + 迁移脚本 |
| DB 级多租户隔离（替换目录路径校验） | 隔离单测 + 并发测试通过 |
| `ageval-security` 定位（统一到 platform_api，redsentinel 降为库） | README 已明确：`ageval-security/platform_api` 是唯一交付后端；`src/redsentinel` 保留为被测适配器、oracle、指标与报告公式库；`frontend/` 与 `/v1` 审计编排不再作为交付入口 |
| 已知规格缺口：`detection/configurable-policy` 要求 1/2 | `platform_api` 当前只有 `n_attempts` 与 `max_concurrent`，尚无攻击强度（light/medium/heavy）和可配置判定阈值；攻击集版本发现已由 ageval 数据集磁盘发现满足，强度/阈值需另起 OpenSpec 变更定义语义 |

### P3 — 收尾与增强（change: `p3-polish-enhancements`）
| 任务 | 验收标准 |
|---|---|
| 清理历史研究资产 `research/`、`configs/experiments/` | 死代码移除或归档 |
| 并行 runner 实现 | 替换 NotImplementedError |
| PDF 导出、JS/TS SDK 示例 | 功能可用 |
| 负载/压力测试 | locust 基线报告 |

---

## 四、界面设计规范（前端增量）

沿用现有 C5 审计工作区视觉语言，本轮新增：
| 页面/组件 | 规范 |
|---|---|
| 信任级别徽章 | partial=琥珀色、complete=绿色、attested=灰色，鼠标悬停展示闭合依据 |
| 宿主观测器时间线 | 与现有执行轨迹页并列，事件源标注 host/container |
| 多 Agent 横评对比视图 | 表格 + 雷达图，ASR/FPR/clean-utility 三指标 |
| 交互原则 | 攻击计划仍强制 `attack_review` 门禁；token/Key 不落盘 |

---

## 五、开发进度安排（建议顺序）

```
P0 (交付闭环)  ──►  P1 (信任+泛化)  ──►  P2 (平台化存储)  ──►  P3 (收尾)
   阻塞性             高优先级             中优先级            低优先级
```

每阶段独立 OpenSpec change，走 propose → 用户确认 → apply → verify → archive。前一阶段 verify 通过后再开下一阶段。

---

## 六、质量保障措施

1. **门禁**：每个 change 的 tasks.md 含独立"验证"章节，apply 完成必须跑对应测试
2. **回归**：沿用 `tests/regression/` 全量回归，不得下降（当前 1068 passed 基线）
3. **契约**：Pydantic `extra="forbid"` + `tests/contract/` 守护 API 边界
4. **前端**：Vitest 单测 + Playwright E2E 关键流
5. **安全**：secret scan 纳入 P0 与每次 archive 前
6. **进度审查**：每个 change verify 阶段做进度回顾，按需调整后续 change 范围

---

## 七、风险与应对

| 风险 | 应对 |
|---|---|
| 宿主观测器涉及 eBPF/权限，实现复杂 | P1 先用 Docker events + 进程/网络采集打底，eBPF 作为可选增强 |
| DB 引入影响现有文件产物流程 | 适配器模式并存，文件产物保留为证据源，分阶段切换 |
| 真实模型凭据依赖外部 | C6 与横评标记 external_model，凭据缺失时降级为 cassette 回放 |
| 全量范围周期长 | 严格按 P0→P3 串行，每阶段可独立交付验收 |
