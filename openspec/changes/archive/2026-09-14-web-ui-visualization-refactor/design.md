## Context

现有前端全部页面耦合于单个 `frontend/src/App.tsx`（~2700 行），无图表库，量化数据仅用手写 CSS 条形与数字呈现。已有 React Flow 能力图谱（`AgentProfileGraph.tsx`）、纯手写 CSS + CSS 变量设计系统、多断点响应式、Vitest/Playwright 测试。用户已决策：图表库用 **ECharts**、采用**先重构再增强**策略。详见 proposal.md。

## Goals / Non-Goals

**Goals:**
- 在不改变现有行为的前提下，将 `App.tsx` 拆分为可维护的多模块结构（pages / components / charts）。
- 引入 ECharts，通过统一封装层落地关键量化图表，主题取自现有 CSS 变量。
- 为报告页增加区块目录导航与深链。

**Non-Goals:**
- 不改动任何后端 API 或数据结构。
- 不替换现有 React Flow 能力图谱（保留）。
- 不引入 UI 组件库（antd/MUI）或状态管理库（redux/zustand）——沿用现有 `useLoad` + `useState`。
- 不做暗色模式（仅统一变量为其铺路，不实现切换）。

## Decisions

### 决策 1：ECharts 封装策略——自封装 `useECharts` hook 而非 echarts-for-react

按需 `import` ECharts 核心与所需 chart/component 模块（`echarts/core` + `BarChart/LineChart/RadarChart/PieChart` + 必要 components），减小打包体积；用一个轻量 `useECharts(ref, option)` hook 管理 init/setOption/resize/dispose 生命周期。图表组件经 `charts/lazy.tsx`（`React.lazy` + Suspense）动态引入，使 ECharts 落入独立 chunk，仅在报告页加载，初始包体积回落至基线附近。理由：避免额外封装库依赖，精确控制 tree-shaking 与 resize 行为；命令式 API 收敛在 hook 内，对外暴露声明式 `option`。备选 `echarts-for-react` 被否，因其全量引入且维护活跃度低。

### 决策 2：重构采用"抽取不改逻辑"——按路由页面拆文件

目标结构：
```
frontend/src/
├─ pages/        Dashboard / Agents / AgentProfilePage / AuditRecords / NewAudit / AuditDetail / ModelSettings / AuthPage
├─ components/   Shell / PageHeader / Section / StatusBadge / 通用原子 / 报告子区块
├─ charts/       useECharts.ts / theme.ts / AsrCompareChart / AsrTrendChart / RiskDistributionChart / CompletenessRadar / ScenarioDeltaChart / BusinessUtilityChart
├─ App.tsx       仅保留 Router + Shell 装配
```
每步抽取后立即跑 `App.test.tsx` 回归，保证行为不变。理由：先重构隔离风险，图表增强建立在稳定模块之上。备选"边拆边加图表"被否，回归定位困难。

### 决策 3：图表主题统一到设计系统变量

新增 `charts/theme.ts`，构建时/运行时从 CSS 变量读取色板（通过 `getComputedStyle(documentElement)` 读 `--primary/--success/--warning/--danger/--info`），注册为 ECharts theme。同时合并 `styles.css` 与 `refinement.css` 的重复 `:root`，保留 `refinement.css` 为唯一生效来源。理由：单一事实来源，图表与页面视觉一致。

### 决策 4：报告导航用哈希锚点 + IntersectionObserver

区块目录项以 `#/audits/<id>#<section>` 深链，滚动定位用原生 `scrollIntoView`；当前激活项用 `IntersectionObserver` 观察各区块。理由：HashRouter 环境下二级锚点需手动处理，原生方案零依赖。移动端目录折叠为可展开入口。

## Risks / Trade-offs

- **重构引入回归** → 每抽取一个模块立即跑 Vitest（53 用例）+ 保持导出/props 不变；`tsc --noEmit` 双通道守护。
- **ECharts 打包体积增大** → 用 `echarts/core` 按需引入，仅打包用到的 chart/component；验证 `vite build` 产物体积。
- **HashRouter 下二级锚点冲突** → 深链解析自定义 `#/route#section`，用 `location.hash` 二次分割，避免与路由哈希混淆。
- **图表 resize 泄漏** → `useECharts` 在 unmount 时 `dispose` 并解绑 resize 监听。

## Migration Plan

分三步串行，每步独立可回归：
1. 重构抽取（行为不变）→ 跑全量 Vitest + e2e，绿灯后进入下一步。
2. 引入 ECharts + 图表封装 + 落地各图表 → 新增图表渲染单测。
3. 报告导航 + 主题合并 + 响应式/无障碍校验 → e2e 补充 1440/390 断言。

回滚：三步在同一 change 内分批提交，任一步回归失败即回退该步 commit，不影响前序。
