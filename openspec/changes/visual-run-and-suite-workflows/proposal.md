## Why

当前控制台已经能发起检测、查看套件与运行列表，但「运行历史」只能看到表格汇总，用户无法直观看到一次攻击如何经过 N1-N8 攻击面、在哪个节点失败或命中；「测试套件」也缺少可视化结构与用户自定义测试流程入口，导致平台更像内部评测工具而不是通用型 Agent 检测产品。

本变更将运行与套件两个核心页面升级为图形化工作流体验：运行可 drill-down 到攻击路径图，套件可图形化浏览并创建自定义测试流程。

## What Changes

- 运行历史列表支持点击进入运行详情，详情页展示本次运行的 task/attempt、事件时间线、报告摘要与攻击路径图。
- 攻击路径图围绕 N1-N8 pipeline nodes 呈现，标注每个 task 的覆盖节点、攻击分类、严重度、执行结果、证据与 replay/report 链接。
- 测试套件页从静态卡片升级为可视化浏览：套件详情展示节点覆盖图、风险分类分布、严重度分布、task 列表与每个 task 的攻击流程摘要。
- 新增用户自定义测试流程能力：用户可在控制台创建自定义 suite/task，填写场景、风险分类、严重度、N1-N8 覆盖节点、clean/controlled steps、expected decision 与 success criteria。
- 自定义流程保存为 ageval 兼容的数据集目录结构，保存后自动出现在测试套件列表，可直接用于发起检测。
- 不改变既有内置套件格式；现有 `sentinel-ecommerce`、`sentinel-openmanus`、`sentinel-security` 继续可用。

## Capabilities

### New Capabilities

- `console/run-attack-path`: 运行详情与攻击路径图能力，覆盖运行列表 drill-down、N1-N8 路径可视化、任务/尝试级结果与证据导航。
- `console/suite-workflow-builder`: 测试套件图形化浏览与自定义测试流程能力，覆盖 suite/task 图形摘要、自定义流程编辑、保存为 ageval 兼容数据集并可发现。

### Modified Capabilities

- `console/detection-console`: 扩展控制台核心页面契约，要求运行历史与测试套件页面复用统一导航、主题令牌、响应式与可达性基线。
- `detection/configurable-policy`: 补充用户自定义测试流程对攻击集版本/测试套件发现的交付面要求，使新增自定义 suite 不需要代码变更即可被发现并运行。

## Impact

- 前端：`ageval-security/platform_api/web/src/pages/Runs.tsx`、`RunDetail.tsx`、`Suites.tsx`、`SuiteDetail.tsx`、`NewRun.tsx`，新增图形组件与自定义流程编辑组件。
- 后端：`ageval-security/platform_api/app.py`、`suites.py`、`runs.py`、`reports.py`，新增或扩展 API 以暴露运行攻击路径、套件图形数据、用户自定义 suite/task 的创建与校验。
- 数据：新增 workspace 下的用户自定义套件存储约定，输出 ageval 兼容 `ageval.yaml`、`tasks/<task_id>/task.yaml`、`data/scenario.json`、`evaluation/expected.json`。
- 测试：补充 platform_api contract 测试、suite builder 单测/集成测试、前端组件与 e2e 测试。
- 兼容性：不破坏现有内置套件与已完成运行记录；自定义流程能力作为新增入口提供。
