> **归档说明（SUPERSEDED）**：本次改动虽已实现完成（31/31 任务），但其交付载体 `frontend/` 已不再作为平台控制台。
> 经评审，`frontend/` 的信息架构与审计流程强绑、样式在 `refinement.css` 中按特性堆叠导致视觉失控，
> 故由 `detection-console-visual-redesign` 取代：以 `ageval-security/platform_api/web`（第一版）为唯一控制台基线。
> 归档时使用 `--skip-specs`，本变更的 delta 规格**未**同步进主规格，`frontend/` 代码保留未删除。

## Why

现有前端信息密度高、图形化弱、对适配器/基准强绑两种类型(`NewAudit.tsx` 二值硬编码),多轮趋势图恒空、报告无导出、执行期无实时明细,交互学习成本高。需要一套**以图形化和最小输入为核心的现代工作台**,让用户直观地驱动 AI 安全审计能力、以可视化查看结果、低学习曲线地完成上线决策。本期不含登录/注册界面。

## What Changes

- **BREAKING**: 移除登录/注册界面(`/login`、`AuthPage`、账号菜单),前端启动时以固定 dev 身份**静默登录**获取 token;应用直接进入工作台。
- 推倒重建设计系统:统一 design tokens(配色/字体/间距/圆角/阴影/动效)、亮/暗双主题、风险面统一色板。
- 重建导航与信息架构:可展开侧栏(图标+文字)、顶栏面包屑+全局搜索+服务状态+主题切换;新增「报告中心」。
- **新建审计改为向导式**:3 步引导 + 数据驱动预填(选 Agent 自动带出 adapter_type/推荐基准/风险面)+ chips 选风险面 + 可增删业务任务卡 + 强度滑块实时预览,最小化输入。
- **审计执行实时化**:分阶段时间线 + 逐条攻击实时命中流,替代现状"中途停轮询、整轮才出报告"。
- **报告图形化交付**:攻击链有向图(@xyflow库:指标卡(带 sparkline)、进度环、ASR 对比/风险分布/趋势/完整度雷达/场景 delta/攻击链等图表共享主题与色板。

## Capabilities

### New Capabilities
- `frontend/design-system`: 统一的视觉设计系统与响应式框架——tokens、亮/暗主题、排版/间距/圆角/阴影/动效、无障碍与断点规则、图形化组件库的视觉一致性契约。
- `frontend/workbench-navigation`: 工作台外壳与信息架构——可展开侧栏、顶栏(面包屑/全局搜索/服务状态/主题切换)、路由结构、无登录直达。
- `frontend/audit-workflow-ux`: 审计工作流交互——向导式新建审计(数据驱动预填、最小输入)、攻击集审阅与授权、执行期实时命中流与阶段时间线。
- `frontend/reporting-visualization`: 报告与可视化——结论条、攻击矩阵、攻击链有向图、多轮趋势与轮次对比、证据链、PDF/JSON 导出。
- `frontend/session-access`: 会话接入——本期无登录 UI,前端以固定 dev 身份静默登录获取并附带后端所需 token。

### Modified Capabilities
<!-- 无既有前端 spec 的行为需求被修改;后端能力不在本变更范围。 -->

## Impact

- **前端**(推倒重建):`frontend/src/` 全量——`App.tsx`、`main.tsx`、`pages/*`、`components/*`、`charts/*`、`lib/*`、`styles.css`/`refinement.css`、`types.ts`、`api.ts`。移除 `pages/AuthPage.tsx` 与 `lib/auth.ts` 门禁逻辑(保留静默登录取 token)。
- **后端**:不改行为;沿用现有 `/v1` API 与 token 认证(静默登录复用现有登录端点)。
- **测试**:Vitest 组件/单测与 Playwright e2e 需随页面结构调整重写。
- **依赖**:沿用 React18/Vite/echarts/@xyflow/react/lucide-react;可能新增 PDF 导出所需库(待 design 决策)。
