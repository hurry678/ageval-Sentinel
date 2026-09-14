## Why

当前平台号称"通用型 Agent 检测"，但接入类型 `adapter_type` 是硬编码 `Literal`，新增一种 Agent 需同步改 4–5 处（契约枚举、adapter import 清单、registry 映射、service 的 if/elif、source_ingress 白名单），且 OpenManus 在 5+ 处被 `if adapter_type=="openmanus"` 特判，扩展成本高、易漏、耦合重。同时检测策略几乎不可配置：仅 `minimum_clean_utility` 可调，攻击集 schema 被 `Literal` 锁死、`AuditTask` 无攻击强度入参、profile→攻击映射为硬编码字典。这两点直接阻碍"可灵活配置、可扩展、适应不同类型 Agent"的目标。

## What Changes

- 引入**单一事实来源的适配器注册表**（AdapterDescriptor + register），把 `adapter_type` 的合法集合、可运行性、能力标志（是否需镜像、是否需 hosted 模型、框架归属等）集中声明。
- **消除 OpenManus 散落特判**：将框架相关分支改为读取 descriptor 的能力标志/钩子，`service`/`app`/`preflight`/`asset_index` 不再直接比较 `adapter_type=="openmanus"` 字符串。
- **统一三处重复的 `integration_type` 定义与 source_ingress 白名单**，使其从注册表派生，消除不一致。
- **框架识别 → 可运行 adapter 的映射可扩展**：非 OpenManus 不再一律降级 `external_sdk`，而是按 descriptor 声明的框架映射解析。
- **配置化检测策略**：`AuditTask` 增加可选 `attack_intensity`；暴露少量可调判定阈值（在 `minimum_clean_utility` 之外）；攻击集加载支持数据驱动版本发现，放开 `Literal` 硬锁（仍校验 registry 已登记的版本）。
- **BREAKING（内部契约）**：`adapter_type` 从固定 `Literal` 改为"对注册表校验的字符串"。对现有取值（ecommerce_demo/external_sdk/http_endpoint/openmanus）行为不变，但 `extra="forbid"` 相关契约测试与快照可能需同步更新。

## Capabilities

### New Capabilities
- `agent-adapters/pluggable-registry`: 适配器注册表能力——集中声明/发现 Agent 接入类型与其能力标志，替代硬编码枚举与散落分支，使新增一种 Agent 类型只需一处注册。
- `detection/configurable-policy`: 可配置检测策略能力——攻击强度、判定阈值、攻击集版本等以入参/数据驱动方式配置，替代硬编码常量与 `Literal` 锁。

### Modified Capabilities
<!-- openspec/specs 为空，无既有能力需修改。 -->

## Impact

- **后端契约**：`application/contracts.py`（adapter_type / integration_type）、`application/audit_contracts.py`（attack_intensity / 阈值）。
- **注册与分派**：`adapters/registry.py`、`adapters/agent.py`、`application/engine/service.py`、`application/engine/source_ingress.py`、`application/engine/audit_preflight.py`、`application/engine/agent_asset_index.py`、`application/engine/app.py`。
- **攻击集与画像映射**：`application/engine/attack_pack.py`、`attacks/engine/profile_driven.py`、`profiling/frameworks/*`（识别→adapter 映射衔接）。
- **测试**：`tests/contract/`（extra="forbid" 快照）、`tests/regression/`（保持不下降）；新增注册表与配置单测。
- **前端**：Agent 接入类型选择项从静态列表改为读接口/常量派生（最小改动，非本 change 主体）。
- **非目标**：不引入宿主观测器/DB/PDF（属其他路线图 change）；不改变现有默认闭环行为。
