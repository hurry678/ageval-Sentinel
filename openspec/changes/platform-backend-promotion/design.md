## Context

动机见 `proposal.md`。这里只列塑造方案的现状约束：

- `ageval-security/platform_api/config.py:1-5` 明确声明自己是 **workspace tool, not a deployable service**，所有路径由 `__file__` 派生。
- `pyproject.toml` 的 `[tool.setuptools.packages.find] where = ["src"]` 只打包 `redsentinel`；`ageval-security` 目录名含连字符，不能作为 Python 包父目录，`platform_api` 只能靠 sys.path 上挂 `ageval-security` 才可导入。
- 内置 Agent 白名单的两个消费者**不在同一进程**：`platform_api`（校验 + `/api/health` 暴露）与 `sentinel_agent_plugin`（校验 + 实例化，跑在 `ageval` CLI 的子进程里）。但 `platform_api/_restart.sh:6` 显示两者实际共用同一个 venv。
- `plugins/sentinel-agent/plugin.yaml:5-7` 已声明 `host_requires: import: redsentinel`——宿主环境必须装 `redsentinel` 才能加载本插件。
- `executor.py:41-42` 刻意把适配器类的 import 放在函数内，理由是「ageval Core 必须在未安装 redsentinel 时仍可用」。
- 控制台侧已经从 `/api/health` 派生可选项（`web/src/pages/Targets.tsx:156`），并未硬编码副本。
- 端口已成事实约定：后端 `8010`（`vite.config.ts:10` 代理目标、`app.py:53` CORS 放行 `5174`）。
- `[tool.pytest.ini_options]` 的 `addopts = "-m fast"` 与 `pythonpath = ["src"]`：新测试必须打 `fast` 标记，且 `platform_api` 当前不可被 pytest 导入。

## Goals / Non-Goals

**Goals:**

- 让 `platform_api` 可被任何人在任一操作系统上按文档一条命令启动，且启动物在版本控制内。
- 让内置被测 Agent 的集合在**一处**声明，两个进程都从它派生，且不破坏 `executor.py` 现有的延迟导入契约。
- 让 `platform_api` 进入既有 `tests/` 与 `pytest` 约定。

**Non-Goals:**

- 不把 `platform_api` 变成 pip 可安装物或可部署服务（与 `config.py` 的自我定位冲突）。
- 不改端口、不改 `/api/*` 路由形状、不改 `targets.yaml` 格式——控制台与既有 run 记录必须继续可用。
- 不给 `redsentinel` 的 `/v1` 加运行时弃用告警（无外部使用者，纯仪式）。

## Decisions

### D1：内置 Agent 注册表落在 `redsentinel` 库层，纯数据

新增一个纯数据模块（形如 `src/redsentinel/adapters/inproc.py`），每个条目声明：Agent 标识、适配器类的导入路径（字符串）、展示标签。`platform_api.targets` 与 `sentinel_agent_plugin` 都从它派生。

**为什么是 `redsentinel`**：它是唯一被两个进程共同依赖的包——`platform_api` 已经 import 它（`suites.py:32`、`reports.py:37`），插件也已经通过 `plugin.yaml` 的 `host_requires` 强制要求它。这也正是「A 降级为库」的具体含义：A 提供数据与适配器，B 提供平台。

**否决的备选**：

- 放在 `sentinel_agent_plugin` 里：该包只安装在 ageval 的插件搜索路径上，`platform_api` 不保证能 import 它。
- 放在 `platform_api` 里：插件跑在 ageval 进程内，反过来依赖平台会把依赖方向倒置。
- 放成 YAML/JSON 数据文件由两侧读：跨检出的路径解析比 import 更脆弱，且失去类型与 IDE 可达性。

**导入路径用字符串 + `importlib` 延迟解析**：这样纯数据模块本身不 import 任何适配器类，保持 `catalog.py` 已建立的「可以在任何地方 import 而不产生环」的性质。

### D2：插件侧只做**函数级**惰性引用，模块级不 import `redsentinel`

`executor.py` 的 `AGENT_KINDS` 常量改为函数（如 `agent_kinds()`），在函数体内 import 注册表；`build_adapter()` 同样在函数体内 import 并用 `importlib` 解析类。`factory.resolve_agent_kind()` 改调该函数。

**为什么**：`executor.py:41-42` 的延迟导入不是随手写的，是显式契约。若把注册表 import 提到模块级，插件模块本身就会在缺 `redsentinel` 的环境里 ImportError，改变现有失败模式。函数级惰性引用让「一处登记」与「Core 可独立导入」同时成立。

**代价**：`AGENT_KINDS` 从常量变函数是插件内部的小型 breaking change；两个调用点都在本仓库内，一次改完。

### D3：启动入口 = 版本控制内的脚本，双平台，端口不变

新增 `scripts/platform-start.bat`（对齐既有 `scripts/dev-start.bat` 的写法与风格）与 `scripts/platform-start.sh`。两者都：以脚本自身位置推出仓库根、`cd` 到 `ageval-security`、执行 `python -m uvicorn platform_api.app:app --host 127.0.0.1 --port 8010`，并另起控制台 `npm run dev`（`5174`）。不含任何绝对路径、不指定具体 venv 位置（用当前环境的 `python`）。

`platform_api/_restart.sh` 由本变更取代，**删除**（它硬编码 `/mnt/d/...` 与 `$HOME/.venvs/ageval`，是本变更造成的孤儿）。同目录其余 `_smoke*.sh` / `_regress.sh` 等是既有调试脚本，本次不动。

**否决的备选**：加 `[project.scripts]` 控制台入口或 `package-dir` 映射把 `platform_api` 变成安装物——需要把一个自称 workspace tool 的东西打包，且会让 `config.py` 的路径推导依赖「必须以 editable 方式原地安装」这一隐含前提。

### D4：测试通过 `pythonpath` 接入，用 FastAPI `TestClient`，不启真实进程

在 `[tool.pytest.ini_options].pythonpath` 追加 `"ageval-security"`，新测试放 `tests/` 下并打 `fast` 标记。覆盖面只取**不需要跑 ageval 子进程**的部分：

- `/api/health` 自描述字段完整，且内置 Agent 清单与注册表逐项一致；
- 目标校验：未登记的内置 Agent 被拒且错误信息列出合法取值；非回环端点缺 `api_key_env` 被拒；回环端点免凭据通过；响应不含凭据明文；
- 套件发现：临时工作区放入一份最小数据集即被发现（通过 monkeypatch `config.WORKSPACE` 指向 tmp 目录）；未登记场景分类降级为覆盖缺失而非报错；
- 注册表一致性：`platform_api` 侧清单与插件侧 `agent_kinds()` 返回同一集合（这条正是防白名单再次分叉的回归闸门）。

**不覆盖**：`start_run` / 事件流 / 报告——它们需要真实 `ageval` CLI 与数据集，属于既有 `_smoke*.sh` 的职责，本次不改造成自动化测试。

### D5：`redsentinel` 的降级只体现在文档与入口，不动代码

README 的「可选审计工作区」段落改写为平台后端 + 控制台的唯一上手路径；代码导航补 `ageval-security/` 并注明 `src/redsentinel` 为库（适配器、判定 oracle、指标与报告公式）。`redsentinel.apps.api`、`frontend/`、`scripts/dev-start.bat` 的代码保留不删——它们不是本变更造成的孤儿，且 `frontend/tests` 仍在 `testpaths` 中。

## Risks / Trade-offs

- **注册表放进 `redsentinel` 会加深 B 对 A 的依赖，与「未来可能拆仓」的方向相反** → 依赖的是一个零依赖纯数据模块，拆仓时它是最容易搬走的一块；且当前 B 已经依赖 A 的 4 处更重的功能（指标、报告、oracle、适配器类），这一处不构成新的量级。
- **`AGENT_KINDS` 常量改函数可能漏改调用点** → 全仓库只有 `factory.py:14,29,31` 三处引用，改完以 `grep` 复核，并由 D4 的一致性测试兜底。
- **`pythonpath` 加 `ageval-security` 会让 pytest 收集到该目录下的意外文件** → 只影响 import 搜索路径，不改 `testpaths`；收集范围仍是 `tests` / `frontend/tests` / `experiments/tests`。
- **双平台脚本只在 Windows 上被实际验证**（开发机是 Windows） → `.sh` 走同一条命令与相对路径推导，逻辑等价；风险限于 shell 语法，脚本极短。
- **`platform_api` 无鉴权且绑定回环，被"提升为唯一后端"后可能被误读为可对外部署** → README 的定位段落必须明写「仅回环、无鉴权、workspace 工具」，与 `app.py:4-6` 的自述一致。

## Migration Plan

无数据迁移。`targets.yaml`、`.platform/runs/*` 格式不变，既有 run 记录继续可读。回滚方式：删除新增脚本与注册表模块、还原两处白名单常量即可，不涉及状态。
