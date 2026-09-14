## Context

探查确认（证据文件见 proposal）：`adapter_type` 是 Pydantic `Literal`（`application/contracts.py:239`），其合法集合在 `adapters/registry.py`、`adapters/agent.py` import 清单、`source_ingress.py` manifest 白名单三处各自重复；OpenManus 在 `app.py`、`service.py`、`audit_preflight.py`、`agent_asset_index.py` 5+ 处被 `== "openmanus"` 特判；框架识别（`profiling/frameworks/registry.py` 可插拔）识别结果不回流为 adapter_type（非 openmanus 一律降级 `external_sdk`，`agent_asset_index.py:297`）。配置面仅 `minimum_clean_utility` 可调，攻击集 `schema_version/benchmark` 被 `Literal` 锁死（`attack_pack.py:43-53`），`AuditTask` 无 attack_intensity。API 模型普遍 `extra="forbid"`，受 `tests/contract/` 快照守护。用户已决策：优先"可插拔适配器 + 配置化"。

## Goals / Non-Goals

**Goals:**
- 适配器类型的合法性/可运行性/前置条件/框架映射收敛到**单一注册表**，新增类型仅需一处登记。
- 用**能力标志**替代 OpenManus 等具体字符串特判。
- 画像识别的框架可**回流**为可运行 adapter_type（可扩展映射）。
- 检测策略可配置：审计攻击强度、至少一项判定阈值、攻击集版本数据驱动发现。

**Non-Goals:**
- 不引入宿主观测器 / DB / PDF 导出 / 多模型横评（属其他路线图 change）。
- 不新增真实可运行的框架 backend（如 AutoGen 仍为 scaffold）；本 change 只做"可扩展骨架 + 现有类型平移"。
- 不改变默认闭环的可观察行为与默认结论。
- 前端仅做最小适配（接入类型选项来源），不做 UI 重构。

## Decisions

### 决策 1：AdapterDescriptor 作为 adapter_type 域的单一事实来源（新建 catalog，非复用 registry.py）

**重要澄清**：代码中存在两套不同分类——`adapters/registry.py` 的 `RUNNABLE_ADAPTERS`（direct_api/langgraph/docker/http/sdk）是**运行时 sandbox backend** 注册表；而 API 层 `adapter_type`（ecommerce_demo/external_sdk/http_endpoint/openmanus）是**接入类型**枚举。二者是不同轴，`registry.py` 保持不动。

本 change 新建 `adapters/catalog.py`（纯数据模块，不 import 契约或适配器类，避免循环依赖），以 `AdapterDescriptor` 集中声明接入类型及其能力标志：`allow_source_ingest`、`requires_audit_infrastructure`（preflight 是否需 docker/镜像/模型）、`requires_hosted_model`（是否需就绪 hosted 模型）、`supports_openmanus_real`、`uses_builtin_adapter`、`builtin_adapter_kind`（openmanus/ecommerce）、`auto_onboard_demo_source`、`audit_benchmark_id`、`audit_runtime_mode`、`framework_ids`。合法集合、source_ingress 白名单、框架映射与各处 if/elif 均从 catalog 派生。理由：把散落四处的接入类型判断收敛到一处纯数据声明，消除漂移根因。备选"复用 registry.py"被否——那是运行时 backend 轴，语义不符。

### 决策 2：adapter_type 从 Literal 改为注册表校验的 str

`contracts.py` 中 `adapter_type` 字段类型由 `Literal[...]` 改为 `str` + `field_validator`，校验值属于注册表已登记键；默认值仍 `ecommerce_demo`。为保持 OpenAPI/前端可发现性，新增只读接口或常量导出返回"已登记类型清单"。理由：合法集合运行时可扩展，同时保留 `extra="forbid"` 模型语义。风险：`tests/contract/` 的 schema 快照会变（Literal→str），需同步更新快照并保留一条"拒绝未登记类型"的契约用例。

### 决策 3：能力标志替代字符串特判

逐处替换：`audit_preflight.py:47`（`!= "openmanus"`）→ `descriptor.requires_hosted_model`；`app.py:280,815,825` / `service.py:1035,1425,1431` 的 openmanus 分支 → `descriptor.framework_ids`/`requires_hosted_model`/`runnable` 查询；`agent_asset_index.py:297-304` 的 openmanus-else-external_sdk → 决策 4 的框架映射。逐处替换后跑回归确保行为等价。理由：新增同类能力的适配器零改动即被正确处理。

### 决策 4：框架识别 → adapter_type 的注册表映射

在注册表维护 `framework_id → adapter_type` 映射（由各 descriptor 的 `framework_ids` 反向构建）。`agent_asset_index` 解析时：识别框架命中映射则用之；未命中回退到通用类型（`external_sdk`）并记录一条明确的回退标注（limitation/日志），而非静默。理由：打通"可插拔框架识别"与"可运行接入"，且回退可观测。

### 决策 5：配置化检测策略（最小可用切片）

- `AuditTask` 增加可选 `attack_intensity: Literal["light","medium","heavy"] | None = None`；`None` 时映射为现状默认。复用 `EvaluationRequest.attack_intensity` 既有语义，避免新造概念。
- `AuditTask` 增加可选判定阈值（至少 `max_attack_success_rate`），带安全默认；审计结论门禁在 `audit_workflow` 现有判定处附加该阈值判定；报告体现所采用阈值。
- 攻击集版本：将 `attack_pack.py` 的 `schema_version/benchmark` `Literal` 校验改为"对已登记版本集合校验"，版本集合从资源目录 manifest 数据驱动发现（`RED_SENTINEL_RESOURCE_ROOT` 下），未登记版本明确拒绝。理由：数据驱动扩展，同时不放任意 yaml（保留登记边界）。

## Risks / Trade-offs

- **契约快照回归** → Literal→str 会改 OpenAPI；对策：更新 `tests/contract/` 快照 + 增"拒绝未登记类型"用例；前端类型清单改从接口/常量取。
- **行为漂移** → 逐处 if/elif 改写有等价性风险；对策：每替换一处立即跑 `tests/regression/` 全量（基线 1068 passed 不得下降）+ 针对 openmanus 路径的现有 e2e。
- **阈值/强度语义分裂** → `AuditTask` 与 `EvaluationRequest` 两套入参；对策：复用同名字段与枚举，映射集中在一处，不新造并行概念。
- **攻击集数据驱动引入坏版本** → 对策：仅接受 manifest 已登记版本，加载失败明确报错，不静默回退。

## Migration Plan

分两组串行，每组独立可回归：
1. **可插拔注册表（决策 1-4）**：先建 AdapterDescriptor + 派生现有集合（纯重构、行为不变，跑回归绿灯）→ 再逐处替换 openmanus 特判与框架映射 → 每步回归。
2. **配置化（决策 5）**：attack_intensity → 阈值 → 攻击集数据驱动，逐项加入且默认值保持现状行为，各加对应单测。

回滚：两组在同一 change 内分批提交，任一组回归失败即回退该组 commit，不影响前序。
