# Sentinel-Guardian：企业 Agent 上线前自主安全审计与自动加固智能体

Sentinel-Guardian 是“生成式大语言模型与智能体”赛题作品，解决企业 Agent 上线前
缺少自动化安全验收的问题。

桌面应用以同级 `agents/` 目录为唯一资产来源。每个 Agent 使用
`agent.json + image.tar`（Docker Archive）或 OCI Image Layout 交付；系统不执行镜像
即可提取镜像配置、Python 源码中的入口、依赖、框架、工具、权限、控制和数据流证据，并生成
`agent-profile-v0.2`。源码目录 onboarding 仍作为 API 兼容入口保留。

静态画像不要求 Docker 或模型 API。AI 语义补全没有完整配置时会明确跳过；离线归档
没有可信运行时镜像引用时，动态验证标记失败，但证据闭合的静态画像仍以 `partial`
发布。真实动态验证需要 Docker Desktop；模型凭据仅用于可选语义补全和真实审计执行。

离线回归与真实 Docker 画像验收是两条独立路径。离线命令不执行镜像、不需要 Docker，
只生成明确命名为 `task15-partial` / `task13-partial-*` 的 `partial` 制品：

```bash
python3 scripts/generate_task15_artifacts.py --mode partial
```

真实验收要求 Docker Desktop 可用，通过生产镜像解析、加载和动态探针重新生成两个
内置 Agent 的正式制品。当前容器内探针行为属于镜像自报证据，因此正式制品必须明确
保持 `analysis.status=partial` 和 `completeness.conclusion=partial`；只有接入
Sentinel 控制的宿主侧独立行为观测器后，画像才允许达到 `complete`：

```bash
python3 scripts/verify_task13_e2e.py
```

只复核已经生成的正式制品，不启动容器：

```bash
python3 scripts/verify_task13_e2e.py --existing
```

正式 Docker 制品位于 `artifacts/task15/` 和 `artifacts/task13-*.json`。每个 bundle manifest
绑定 `image_digest`、`config_digest`、`profile_id`、`profile_sha256`、完整度摘要和
四个内容文件的 SHA-256；任何文件或绑定缺失都会使验收失败。

本仓库当前只服务这场比赛，不再维护独立的研究、论文、投稿或求职路线。

对外产品名统一为 **Sentinel-Guardian**。现有 `redsentinel` Python 包、CLI、
`redsentinel.yaml` 和 artifact schema 作为兼容接口保留。

## 比赛任务

用户的统一任务是：

> 审计这个 Agent 是否可以上线；发现风险后生成最小化加固方案，并验证正常业务能力
> 是否保留。

Sentinel-Guardian 自主执行：

```text
静态解析镜像
  -> 识别 Agent、Prompt、Memory、Tool、MCP、权限和 Guard
  -> 重建输入到高风险 Sink 的路径
  -> 攻击 Agent 生成攻击集并标注预测 node_id/path_id
  -> 检查画像、Docker、运行镜像和三模型状态
  -> 用户审阅攻击范围并明确批准正式审计
  -> OpenManus 隔离容器逐条执行攻击
  -> 记录攻击成功状态和实际失效节点
  -> 防御 Agent 生成并挂载局部 Guard
  -> Guarded 复测并形成一轮审计结果
  -> 根据失败场景、绕过节点和最弱链路生成下一轮攻击集
```

最终决策固定为：

- `允许上线`
- `修复后复测`
- `高风险，禁止上线`
- `需要人工审批`

## 竞赛差异化

Sentinel-Guardian 不是普通问答、检索或报表 Agent，而是让一个智能体自主完成另一个
智能体的安全验收。

它同时展示赛题要求的：

| 赛题能力 | Sentinel-Guardian 对应实现 |
|---|---|
| 复杂任务理解 | 解析 Agent 源码、配置、工具、权限、正常任务和安全目标 |
| 任务规划 | 生成受 schema 约束的安全测试计划 |
| 环境感知 | 记录 LLM、文件、网络、工具、状态和 Guard 事件 |
| 自主决策 | 选择测试 case、防御节点、停止条件和上线结论 |
| 环境行动 | 从冻结源码构建 Docker/OpenManus 沙箱副本并执行工具和攻击 |
| 数据分析 | 计算 ASR、FPR、clean utility、失败归因和风险节点 |
| 场景决策 | 输出允许上线、修复复测、禁止上线或人工审批 |

## 当前状态

| 能力 | 状态 | 说明 |
|---|---|---|
| 镜像 Agent 接入 | 已实现 | 从同级 `agents/` 增量索引离线 Docker/OCI 制品 |
| Agent 镜像画像 | 已实现 | 从镜像配置、文件系统、框架和静态数据流生成证据闭合画像 |
| Source-only 兼容接入 | 已实现 | API 兼容入口冻结源码和构建清单 SHA-256 |
| 攻击生成与升级 | 已实现 | 支持画像、历史失败和策略反思 |
| Docker 隔离执行 | 已实现 | 支持真实 OpenManus runtime |
| 轨迹记录与失败归因 | 已实现 | 区分环境失败、模型拒答、攻击效果和 Guard 拦截 |
| 风险评测与节点定位 | 已实现 | 逐 case 结果、Oracle、trajectory 和 attribution |
| 局部防御与回归 | 已实现 | 生成 Guard 并执行 baseline/guarded 配对 |
| Manifest 与证据索引 | 已实现 | provenance、raw trajectory、evidence index |
| 统一审计任务契约 | 核心完成 | `AuditTask`、`AuditPlan`、`ReleaseDecision` |
| LLM 结构化自主规划 | 核心与页面完成 | 计划实际决定 case、预算和执行顺序 |
| 多轮闭环编排 | 已完成 | 静态画像、预测节点、攻击结果、失效节点、防御和下一轮反馈 |
| 企业知识助手案例 | 已完成 | 合成业务数据、四类攻击、局部 Guard 和正式审计 |
| C5 审计工作区 | 已完成 | 展示资产、时间线、轨迹、评分、四态决策和证据引用 |

## 当前证据

默认工程回归：

```text
1068 passed, 2 deselected
50 frontend tests passed
2 Playwright viewport flows passed
Ruff passed
```

OpenManus W2 rerun10 真实运行门禁：

- 15/15 Docker 进程成功，runtime failure rate 0%
- 五个适用 baseline 均产生注册攻击 effect
- 五个 guarded 运行均成功阻断
- baseline/guarded 可比完整度 5/5
- baseline ASR 100%，guarded ASR 0%
- clean utility 100%，FPR 0%
- manifest、provenance、trajectory 和 evidence index 完整

边界：

- 当前真实证据只覆盖一个 Agent、一个模型、一个 seed
- OpenManus 缺少等价邮件工具，场景适用范围为 5/6
- 历史离线协同进化结果只用于比赛演示与工程回归

## 当前比赛主线

```text
C0 统一口径              已完成
C1 审计任务契约          核心完成
C2 自主测试规划          核心与计划页面完成
C3 攻击-加固-复测编排    已完成
C4 企业知识助手案例      已完成
C5 竞赛产品展示          已完成
C6 提交与演示验收        进行中
```

详细任务、验收条件和非目标见 [竞赛 Roadmap](ROADMAP.md)。

当前开发焦点是使用真实模型凭据完成最终 OpenManus 现场验收，并录制 3–5 分钟
演示视频；产品闭环、自动化测试、架构图、截图和桌面交付包已经完成。

## 五分钟离线演示

安装：

```bash
python -m pip install -e ".[all,dev]"
```

运行：

```bash
redsentinel demo --output-dir artifacts --seed 42
```

现有兼容演示会执行：

```text
doctor -> profile -> paired evaluation -> defense loop -> evidence summary
```

主要输出为 `artifacts/p0-demo/p0-demo-summary-v1.json`。该入口用于验证底层链路；
比赛最终入口将收敛为单一 `audit` 命令。

## CLI

```bash
redsentinel --help
redsentinel demo --help
redsentinel profile --help
redsentinel evaluate --help
redsentinel report --help
redsentinel-agent --help
redsentinel-defense --help
redsentinel-openmanus --help
```

验证 Agent 配置：

```bash
redsentinel profile \
  examples/agents/simple_agent/redsentinel.yaml \
  --dry-run
```

运行确定性离线评测：

```bash
redsentinel evaluate --output-dir artifacts --seed 42
```

## 平台后端与控制台

当前交付入口统一为 `ageval-security/platform_api`。它是本地 workspace 工具：只绑定
`127.0.0.1`、无鉴权、不面向公网部署。`src/redsentinel` 保留为库，提供内置被测 Agent
适配器、判定 oracle、指标与报告公式；历史 `/v1` 审计编排不再作为控制台入口。

平台运行在浙大 **ZJU-REAL/ageval** 评测引擎之上。当前工作区约定把 ageval checkout 放在
`ageval-security/ageval`（本地版本 `0.8.0`）；该目录是外部依赖，未纳入本仓库版本控制。

首次准备（一键）：

```bash
scripts/platform-setup.bat   # Windows
bash scripts/platform-setup.sh # macOS / Linux / WSL
```

脚本会安装 Sentinel Python 依赖、拉取 `ZJU-REAL/ageval`、安装 ageval CLI、安装
`sentinel-agent` 插件，并安装控制台 Node 依赖。

手动准备：

```bash
python -m pip install -e ".[product,dev]"
git clone https://github.com/ZJU-REAL/ageval.git ageval-security/ageval
cd ageval-security/ageval
python -m pip install -e .
cd ..
ageval plugin install plugins/sentinel-agent
cd platform_api/web
npm install
npm run build
```

就绪自检：

```bash
ageval -V
python -c "import redsentinel, platform_api"
```

启动平台：

```bash
scripts/platform-start.bat   # Windows
bash scripts/platform-start.sh
```

打开 `http://127.0.0.1:5174/`。后端健康检查为
`http://127.0.0.1:8010/api/health`。

控制台支持两类检测目标：

- `inproc`：内置被测 Agent，当前由单一注册表声明 `ecommerce` 与 `openmanus-offline`
- `http`：任意 OpenAI Chat Completions 兼容端点；非回环地址必须填写 API Key 的环境变量名，不能填写明文密钥

检测套件来自 `ageval-security/*/ageval.yaml` + `tasks/` 的磁盘发现，新增第三方套件不需要改代码。
运行时平台生成 profile override 后调用 ageval CLI，状态、事件、回放和报告通过 `/api/*` 暴露。

已知规格缺口：`detection/configurable-policy` 中「攻击强度」与「可配置判定阈值」尚未映射到
`platform_api` 交付面；当前只有 `n_attempts` 与 `max_concurrent`，它们分别表示重复试次和并发，
不是攻击强度或判定策略。攻击集版本发现已由 ageval 数据集磁盘发现满足。

桌面主路径的 Agent 目录契约为：

```text
agents/<目录>/agent.json
agents/<目录>/image.tar
```

目录名可使用中文，`agent_id` 必须是稳定 ASCII 标识。`agent.json` 声明镜像类型、
相对路径、可选平台与预期框架；描述文件摘要与归档实际 SHA-256 不一致时拒绝索引。
列表严格映射该目录，不回退到应用内部隐藏资产。

打开 Agent 详情后，先触发画像，再轮询状态并读取发布画像：

```text
POST /v1/agents/{agent_id}/profiles
GET  /v1/agents/{agent_id}/profiles/{analysis_id}/status
GET  /v1/agents/{agent_id}/profiles/latest
```

画像发布时同时生成最小化 `attack-profile-v0.1` 和基于风险路径的 AttackSpec。攻击
规划只消费 `verified/supported` 风险路径；审计创建和恢复均校验
`image_digest`、`profile_id` 和 `profile_sha256` 三元绑定，镜像或画像漂移时必须
创建新审计版本。

源码兼容接入契约为：

```text
source_path
build_manifest_path  # agent-sandbox-build-v0.1 JSON，必须位于 source_path 内
```

Onboarding 会计算 `source_sha256`、`build_manifest_sha256` 和
`source_snapshot_sha256`。审计开始和恢复时都会重新校验快照；源码发生变化必须创建
新的审计版本。baseline 和 guarded 评测始终绑定同一个源码快照。

生产或共享环境不得使用开发 JWT 密钥。

## 代码导航

```text
ageval-security/
  platform_api/  # 唯一交付后端，提供 /api/*、运行编排、状态、回放和报告
  platform_api/web/ # 当前控制台（React + Vite），通过 /api/* 访问平台后端
  plugins/       # Sentinel 的 ageval 插件，内置 Agent executor 从 redsentinel 注册表派生
  sentinel-*/    # ageval 检测套件，按 ageval.yaml + tasks/ 磁盘发现
  ageval/        # ZJU-REAL/ageval 外部 checkout，未纳入本仓库 git
src/redsentinel/
  core/          # 领域模型、协议和转换器
  profiling/     # Agent 物料、源码分析和风险画像
  attacks/       # 攻击生成、变异、选择和数据加载
  defenses/      # Guard、策略、挂载和自动加固
  evaluation/    # Oracle、指标、轨迹风险和节点归因；被 platform_api 报告复用
  runtime/       # sandbox、telemetry、replay 和 Docker capture
  adapters/      # 被测 Agent 适配器与注册表；platform_api inproc 目标从这里派生
  application/   # 历史审计应用服务和本地 /v1 API；保留为兼容，不再作为交付入口
  reporting/     # 结构化报告、HTML 和证据导出；被 platform_api 报告复用
frontend/        # 历史审计工作区，已退役；当前控制台在 ageval-security/platform_api/web
configs/         # Agent、场景和运行配置
datasets/        # fixture、manifest 和数据划分
tests/           # unit、contract、integration 和 regression
docs/competition # 竞赛报告、答辩稿、复现和提交清单
```

`src/redsentinel/research/`、`research/`、`configs/experiments/` 和 `docs/research/`
暂时保留为历史算法与证据资产，避免破坏测试和已有 artifact。它们不再属于当前开发
路线，只有竞赛闭环直接依赖时才修改。

## 验证

```bash
python -m pytest -q
python -m ruff check . --select F401,F841,F821,F811
git diff --check
```

## 文档

- [竞赛 Roadmap](ROADMAP.md)
- [竞赛资料入口](docs/competition/README.md)
- [竞赛项目报告](docs/competition/final-report.md)
- [8 分钟答辩稿](docs/competition/defense-script-8min.md)
- [复现说明](docs/competition/reproducibility.md)
- [提交检查清单](docs/competition/submission-checklist.md)
- [产品口径与边界](docs/product/README.md)
- [C1-C4 代码审计与整改记录](docs/product/c1-c4-code-audit.md)

## 安全边界

- 所有攻击只能作用于授权、本地或明确隔离的目标
- 不连接真实支付、真实企业数据或未授权外部系统
- API key 不写入 manifest、报告、日志或 provenance
- 环境失败、模型拒答和 Guard 拦截必须分别统计
- 自动上线建议不能绕过企业已有人工审批和责任边界

## 许可证

Apache-2.0
