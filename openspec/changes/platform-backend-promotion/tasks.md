## 1. 内置 Agent 注册表（单一登记）

- [x] 1.1 新增纯数据模块 `src/redsentinel/adapters/inproc.py`，登记 `ecommerce` 与 `openmanus-offline` 两项（标识 / 适配器类导入路径字符串 / 展示标签），并提供取 id 元组与按 id 取条目的函数；验证：模块不 import 任何适配器类或 contracts，`python -c "import redsentinel.adapters.inproc"` 成功
- [x] 1.2 `platform_api/targets.py` 的 `INPROC_AGENTS` 改为从 1.1 的注册表派生（保留同名导出以免动 `app.py:36,66`）；验证：`/api/health` 的 `inproc_agents` 仍返回原两项
- [x] 1.3 `sentinel_agent_plugin/executor.py` 的 `AGENT_KINDS` 常量改为函数 `agent_kinds()`，在函数体内 import 注册表；`build_adapter()` 改为查表并用 `importlib` 解析适配器类；验证：模块级不出现 `redsentinel` import，`python -c "import sentinel_agent_plugin.executor"` 在未装 redsentinel 时仍可导入
- [x] 1.4 `sentinel_agent_plugin/factory.py` 的 `resolve_agent_kind()` 改调 `agent_kinds()`，更新两处错误信息与 `__all__`；验证：`grep -rn "AGENT_KINDS" ageval-security` 无残留引用
- [x] 1.5 确认新增一个内置 Agent 只需改注册表一处：临时加一条假条目，验证 `/api/health` 清单、`validate()` 校验、`resolve_agent_kind()` 三处同时生效，然后移除该假条目

## 2. 启动入口

- [x] 2.1 新增 `scripts/platform-start.bat`，以脚本自身位置推出仓库根后 `cd ageval-security` 启动 `python -m uvicorn platform_api.app:app --host 127.0.0.1 --port 8010`，并另起 `web` 的 `npm run dev`（对齐 `scripts/dev-start.bat` 的写法）；验证：在干净 cmd 中执行，`http://127.0.0.1:8010/api/health` 返回 `ok: true`，`http://127.0.0.1:5174` 打开控制台
- [x] 2.2 新增等价的 `scripts/platform-start.sh`（同命令、同相对路径推导、无绝对路径无指定 venv）；验证：`bash -n scripts/platform-start.sh` 通过，且脚本内不含 `/mnt/` 或 `.venvs`
- [x] 2.3 删除被取代的 `ageval-security/platform_api/_restart.sh`；验证：`grep -rn "_restart.sh" .` 无引用残留
- [x] 2.4 两个脚本增加前置检查：`ageval-security/ageval`（浙大 ZJU-REAL/ageval 外部检出，未纳入本仓库 git）缺失时立即给出获取方式并退出，而非让 `ageval` 子进程报难懂的错；验证：临时改名该目录后运行脚本，得到明确的获取指引

## 3. 测试接入

- [x] 3.1 在 `pyproject.toml` 的 `[tool.pytest.ini_options].pythonpath` 追加 `"ageval-security"`、`"ageval-security/ageval/src"` 与 `"ageval-security/plugins/sentinel-agent/src"`；验证：`pytest --collect-only -q` 不报 `platform_api` 导入错误
- [x] 3.2 新增 `tests/` 下的 platform_api 测试文件，打 `fast` 标记，用 FastAPI `TestClient` 覆盖 `/api/health` 自描述字段完整性；验证：`pytest -k platform_api` 通过
- [x] 3.3 补目标校验用例：未登记内置 Agent 被拒且错误信息含合法取值、非回环端点缺 `api_key_env` 被拒、回环端点免凭据通过、响应体不含凭据明文；验证：4 个用例全绿
- [x] 3.4 补套件发现用例：monkeypatch `config.WORKSPACE` 指向 tmp 目录，放入一份最小 `ageval.yaml` + `tasks/` 即被发现；再放一条未登记场景分类的用例，断言套件仍可列出且覆盖信息为缺失而非报错；验证：2 个用例全绿
- [x] 3.5 补注册表一致性回归闸门：断言 `platform_api` 侧内置 Agent 清单与插件侧 `agent_kinds()` 返回同一集合；验证：故意改动任一侧后该用例失败

## 4. 文档定位

- [x] 4.1 重写 `README.md` 的「可选审计工作区」段落为平台后端 + 控制台的唯一上手路径（引用 2.1/2.2 的脚本、端口 8010/5174、`npm install` 与 `npm run build` 说明）；验证：段落内不再出现 `redsentinel.apps.api` 与 `frontend/` 作为启动入口
- [x] 4.2 README 明写平台的部署边界：仅回环、无鉴权、workspace 工具，不面向对外部署（与 `app.py:4-6` 自述一致）；验证：新读者能从文档判断不应把它暴露到公网
- [x] 4.3 README 代码导航补 `ageval-security/`（平台后端 + 控制台 + 数据集 + 插件），并注明 `src/redsentinel` 为库定位（被测适配器、判定 oracle、指标与报告公式）；验证：导航中每个顶层目录都有一句定位说明
- [x] 4.4 在 README 或 `docs/product/completion-roadmap.md` 记录 `detection/configurable-policy` 要求 1、2 在交付面上的已知不符合项（见 `proposal.md`「已知不符合项」）；验证：`completion-roadmap.md:28` 的「ageval-security 定位」条目状态被更新为已收口，并新增该不符合项条目
- [x] 4.5 README 写明依赖的评测引擎来自浙大 **ZJU-REAL/ageval**（当前 `0.8.0`，位于 `ageval-security/ageval`，**未纳入本仓库版本控制**），并给出获取与就绪步骤（clone、装依赖、`ageval plugin install plugins/sentinel-agent`、`ageval -V` 自检）；验证：按该段落在空目录从零准备一遍，`scripts/platform-start` 的前置检查通过

## 5. 端到端验证

- [ ] 5.1 全量回归：`pytest`（默认 `-m fast`）全绿，`ruff check .` 无新增问题（当前未完成：`pytest -q` 为 1039 passed / 62 failed / 1 skipped / 2 deselected；失败集中在既有 `/v1`、Windows symlink 权限、research 数据治理与 legacy image profile 路径。`ruff check .` 也命中既有 `ageval-security/ageval` 与未改 `platform_api/app.py` 问题。已完成本变更触达文件的 ruff 与新增测试）
- [x] 5.2 手工闭环：用 2.1 的脚本启动，登记一个 `inproc` 目标与一个回环 `http` 目标（`platform_api/mock_agent.py`），各跑一次最小套件，确认运行完成、事件流可见、报告可出；验证：两次运行在 `/api/runs` 中均为完成态且报告接口返回 200
- [x] 5.3 `openspec validate platform-backend-promotion --strict` 通过
