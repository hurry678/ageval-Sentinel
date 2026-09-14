## Why

平台目前**双后端并存且互相矛盾**：交付给用户的控制台（`ageval-security/platform_api/web`）只与 `platform_api`（`/api/*`）通信，而 README、`scripts/dev-start.bat`、`pyproject.toml` 的 5 个入口、`tests/` 与全部既有 spec 都指向 `src/redsentinel`（`/v1/*`）——后者的界面 `frontend/` 已在上一次变更中退役。结果是：**真正交付的那一半后端没有启动入口、没有文档、没有测试、没有规格**，只有一个硬编码 WSL 绝对路径与个人 venv 的 `_restart.sh`。

同时，「通用型 Agent 检测平台」这一核心主张只在 `platform_api` 这条链上成立：套件是磁盘发现（丢一份 `ageval.yaml` 数据集即可，`ageval-security/sentinel-security` 的 7 个手写 task 已验证），目标可接任意 OpenAI 兼容端点；而 `redsentinel` 的 `/v1` 审计链因 `_benchmark_is_compatible()` 锁死 ecommerce/openmanus 二选一，第三方 Agent 根本跑不出闭环。**能力已经实现在没有规格背书的那一半上。**

## What Changes

- **BREAKING**：确立 `ageval-security/platform_api` 为平台唯一对外后端。`src/redsentinel` 降级为**被复用的库**（被测适配器、判定 oracle、指标与报告公式），其 `/v1` 审计编排不再作为交付入口。
- 为 `platform_api` 建立正式启动入口：跨平台启动脚本（对齐现有 `scripts/dev-start.bat` 约定），替代 `_restart.sh` 里硬编码的 `/mnt/d/...` 与 `$HOME/.venvs/ageval`。
- README 定位重写：把「可选审计工作区」（`frontend/` + `redsentinel.apps.api`）改为平台后端 + 控制台的唯一上手路径，并明确 `redsentinel` 的库定位。
- **修复既有规格不符合项**：`platform_api` 的 inproc Agent 白名单目前硬编码在 3 处（`platform_api/targets.py:25` 的 `INPROC_AGENTS`、`plugins/sentinel-agent/.../executor.py:32` 的 `AGENT_KINDS`、同文件 `build_adapter()` 的 if/else 分派），违反已批准的 `agent-adapters/pluggable-registry`「新增一种接入类型只需一处登记」。收敛为单一注册表。
- 为 `platform_api` 补最小 pytest 覆盖（当前 `tests/` 下 0 处涉及它），纳入既有 `tests/` 约定。
- 为 `platform_api` 建立规格覆盖（当前它没有任何 spec）。

### 明确不在本次范围

- **不改 `redsentinel` 的 benchmark 白名单**（`service.py:1654` `_benchmark_is_compatible()`、`catalog.py` 中 `external_sdk`/`http_endpoint` 无 `audit_benchmark_id`）。既然 `/v1` 不再是交付入口，修它的收益是零；它属于「A 彻底退役或拆仓」的后续议题。
- **不删除 `frontend/` 与 `redsentinel.apps.api` 代码**，只改变定位与文档指向。
- **不引入 CI**。仓库当前无任何 `.github/workflows`，从零建 CI 是独立议题，不借本次变更夹带。
- **不把 `platform_api` 改造成可部署服务**。它的 `config.py` 明确声明「workspace tool, not a deployable service」，路径由仓库布局派生；本次只让它可被正式启动与验证，不改变这一取向。

### 已知不符合项（本次不解决，须记录并留待后续变更）

已批准的 `detection/configurable-policy` 要求：可指定攻击强度（要求 1）、可配置至少一项判定阈值（要求 2）、攻击集版本数据驱动发现（要求 3）。切换到 `platform_api` 后：

- 要求 3 **变得更符合**（`config.py:30` `suite_roots()` 的 glob 发现天然数据驱动，而 `redsentinel` 的 `_base_scenarios_for_benchmark()` 是两路硬分支）。
- 要求 1、2 在交付面上**不再被满足**：`platform_api` 只有 `n_attempts` 与 `max_concurrent`，没有 light/medium/heavy 语义的强度入参，也没有影响结论的可配置阈值。`n_attempts` 是重复试次而非强度，不应牵强对应。

本次**不**下调该规格、也**不**仓促补实现——补强度语义需要先确定它如何映射到 ageval 的用例选择，属于产品决策。此处显式记录为不符合项，作为紧随其后的变更的输入。

## Capabilities

### New Capabilities
- `platform/detection-backend`: 平台对外后端的交付契约——唯一入口与启动方式、能力自描述、检测目标接入方式（单一注册表 + OpenAI 兼容 HTTP 契约）、套件的数据驱动发现、运行编排委托给 ageval 及其状态可观测性，以及 `redsentinel` 作为库而非交付入口的定位。

### Modified Capabilities
<!-- 无。`agent-adapters/pluggable-registry` 的要求文本不变，本次是让 platform_api 回到符合状态（实现层修复，非规格变更）；
     `detection/configurable-policy` 的交付面缺口见上方「已知不符合项」，留待后续变更处理，不在本次下调其要求。 -->

## Impact

- `ageval-security/platform_api/targets.py`：`INPROC_AGENTS` 改为从注册表派生。
- `ageval-security/plugins/sentinel-agent/**/executor.py`、`factory.py`：`AGENT_KINDS` 与 `build_adapter()` 的 if/else 改为注册表查表。
- `ageval-security/platform_api/_restart.sh`：被跨平台启动脚本取代。
- `scripts/`：新增平台后端 + 控制台的启动脚本（对齐 `dev-start.bat`）。
- `README.md`：「可选审计工作区」段落重写；代码导航补 `ageval-security/`，并标注 `src/redsentinel` 的库定位。
- `tests/`：新增 `platform_api` 的最小覆盖（health 能力自描述、suite 发现、target 校验与注册表一致性）。
- `pyproject.toml`：`platform_api` 运行所需依赖（fastapi/uvicorn 已在 `product` extra 中）与测试可发现性，按需最小调整。
- 不改动 `src/redsentinel` 的任何运行时行为；不改动 `ageval` 检出本身。
