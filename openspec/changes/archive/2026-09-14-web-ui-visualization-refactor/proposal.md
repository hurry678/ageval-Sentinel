> **归档说明（SUPERSEDED）**：本变更全部实现路径均位于 `frontend/`（`frontend/src/charts/*`、`refinement.css`、`frontend/e2e/competition.e2e.ts`），
> 而 `frontend/` 已由 `detection-console-visual-redesign` 决议退役，控制台基线改为 `ageval-security/platform_api/web`，故本变更按原文已不可实施。
> 剩余 2 个任务（5.2 图表移动端自适应、6.2 双视口 e2e 回归）验证的是已不再发布的界面，无产品价值，不再补做。
> 归档使用 `--skip-specs`，`web-ui/data-visualization` 与 `web-ui/report-navigation` 两项能力**未**同步进主规格；`frontend/` 代码保留未删除。
>
> **两项随之未落地的能力（新控制台确实缺失，需要时另起提案）**：
> 1. **报告页图表化**：新控制台 `components/ReportView.tsx` 仅有评分环、`MetricBar` 与表格，缺少防护前后 ASR 对比、多轮 ASR 趋势、画像完整度雷达、场景 delta 等图表。
>    注意 `detection-console-visual-redesign` 的 design **D6 已明确否决引入图表库**（改用手写 SVG），因此重启此能力须先推翻 D6，不能视为本变更的延续。
> 2. **报告页目录导航**：新控制台 `ReportView` 为长卡片堆叠，无锚点/侧栏目录与区块深链。

## Why

现有 Web 审计工作区已能完整覆盖闭环流程，但量化数据（ASR、业务效用、多轮趋势、风险分布、画像完整度）几乎全部以数字或手写 CSS 条形呈现，缺乏图形化表达，用户读取效率低、洞察成本高。同时全部页面耦合在单个 2700+ 行的 `App.tsx` 中，长报告页缺锚点导航，难以扩展与维护。本次改进引入专业数据可视化并优化信息架构，显著提升数据查看效率与操作体验。

## What Changes

- **前端模块化重构**：将 `frontend/src/App.tsx`（2700+ 行）按页面/组件拆分为独立模块（pages / components / charts），行为不变（先重构、后增强）。
- **引入 ECharts 图表能力**：新增统一图表封装层，落地关键量化图表——ASR 防护前后对比、多轮 ASR 趋势、风险面 × 严重度分布、画像完整度雷达、场景 delta 环形/瀑布、业务任务通过率分组柱。
- **报告页信息架构优化**：为长报告页增加锚点/侧栏目录导航，支持快速定位区块与深链。
- **导航与交互精简**：优化主导航与操作流程，减少定位成本。
- **视觉一致性**：统一图表主题到现有极简设计系统（CSS 变量），消除 `styles.css` 与 `refinement.css` 双套 `:root` 叠加。
- **响应式增强**：在既有多断点响应式基础上，确保新增图表在移动端自适应降级。

## Capabilities

### New Capabilities
- `web-ui/data-visualization`: Web 审计界面的数据可视化能力——用 ECharts 将审计与画像的量化指标以图表形式展示，含统一主题、响应式降级与无障碍。
- `web-ui/report-navigation`: 报告页信息层级与导航能力——锚点/侧栏目录、区块深链、快速定位。

### Modified Capabilities
<!-- 无既有 openspec/specs 需修改：当前 specs 目录为空，全部为新增能力 -->

## Impact

- `frontend/package.json`: 新增依赖 `echarts`（及按需 `echarts-for-react` 或自封装）。
- `frontend/src/App.tsx`: 拆分为 `pages/`、`components/`、`charts/` 多模块。
- `frontend/src/charts/*`: 新增图表封装层与主题配置。
- `frontend/src/refinement.css` / `styles.css`: 统一图表主题变量，消除双套 `:root`。
- `frontend/src/App.test.tsx` / `e2e/competition.e2e.ts`: 重构后回归对齐，新增图表与导航的渲染/无障碍断言。
- 后端 API 无改动（复用现有 `/v1/audits/*`、画像接口数据结构）。
