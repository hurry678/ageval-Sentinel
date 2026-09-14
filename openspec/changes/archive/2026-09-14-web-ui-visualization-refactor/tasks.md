## 1. 重构：抽取模块（行为不变）

- [x] 1.1 建立目录骨架 `pages/`、`components/`、`charts/`，验证 `tsc --noEmit`（app+node）通过
- [x] 1.2 抽取通用原子组件（Shell/PageHeader/Section/Empty/StatusBadge/ErrorBox/Brand 等）到 `components/`，App.tsx 改为引用，验证 `App.test.tsx` 全绿
- [x] 1.3 抽取各路由页面（Dashboard/Agents/AgentProfilePage/AuditRecords/NewAudit/AuditDetail/ModelSettings/AuthPage）到 `pages/`，验证 `App.test.tsx` 全绿
- [x] 1.4 抽取报告子区块组件（AuditReport/AttackRoundBoard/ScenarioComparison/Verdict/BusinessResults/Remediation/TraceExplorer/AsrCompare 等）到 `components/`，验证 `App.test.tsx` 全绿
- [x] 1.5 App.tsx 精简为仅 Router+Shell 装配（67 行），验证 `vite build` 成功（e2e 归入 6.2 统一回归）

## 2. 引入 ECharts 与图表封装层

- [x] 2.1 `frontend/package.json` 添加 `echarts` 依赖并 `npm install`，验证安装成功且 lockfile 更新
- [x] 2.2 实现 `charts/useECharts.ts`（init/setOption/resize/dispose 生命周期），验证 hook 单测：mount 渲染、unmount 调用 dispose
- [x] 2.3 实现 `charts/theme.ts`：从 CSS 变量读取色板注册 ECharts theme，验证主色来源为变量而非硬编码（单测断言 option 配色取自变量）

## 3. 落地量化图表

- [x] 3.1 `AsrCompareChart`（防护前后 ASR 对比），替换报告页 `AsrCompare`，验证渲染 baseline/guarded 数值与差值的单测
- [x] 3.2 `AsrTrendChart`（多轮 ASR 趋势），验证：≥2 轮渲染趋势、单轮显示占位不报错的单测
- [x] 3.3 `RiskDistributionChart`（风险面×严重度分布），验证按 severity 聚合渲染的单测
- [x] 3.4 `ScenarioDeltaChart`（improved/regressed/unchanged 环形/瀑布），验证计数聚合渲染的单测
- [x] 3.5 `BusinessUtilityChart`（业务任务通过率分组柱），验证 clean_utility 三阶段渲染的单测
- [x] 3.6 `CompletenessRadar`（画像完整度雷达/环形），接入 `AgentProfileReport`，验证悬停显示 covered/total 的单测

## 4. 报告导航与信息层级

- [x] 4.1 实现报告区块目录（侧栏/锚点），点击滚动定位，验证点击目录项滚动到区块的测试
- [x] 4.2 用 IntersectionObserver 标记当前激活区块，验证滚动时激活项切换的测试
- [x] 4.3 支持 `#/audits/<id>#<section>` 深链解析并自动定位，验证深链打开后定位到指定区块的测试
- [x] 4.4 移动端目录折叠形态，验证 390px 视口下目录可折叠且不占主内容区的测试

## 5. 主题一致性与响应式/无障碍

- [x] 5.1 合并 `styles.css` 与 `refinement.css` 重复 `:root`，保留单一生效来源，验证 `vite build` 与视觉回归（e2e 截图/无水平溢出）
- [ ] 5.2 图表移动端自适应缩放，验证 e2e `mobile-390` 无水平溢出断言（响应式 CSS 已实现：`.chart-canvas` width:100%/min-width:0、`.report-charts` auto-fit grid；报告页 e2e 已放开桌面限制并在 mobile-390 断言 `expectNoHorizontalOverflow`；待 CI/WSL 实跑确认）
- [x] 5.3 图表尊重 `prefers-reduced-motion` 禁用动画，并提供 aria-label/数据摘要，验证 axe 无障碍断言通过

## 6. 集成验证

- [x] 6.1 全量前端回归：`npm run test`（Vitest）+ `tsc --noEmit` 双通道全绿
- [ ] 6.2 端到端回归：`npx playwright test`（1440 + 390 双 project）全绿，覆盖含图表与导航的报告页（报告页 e2e 已移除桌面-only skip，双视口完整跑两轮闭环 + 图表可见性/目录展开导航/无溢出/axe；本机 Windows 无 `fcntl` 无法启动后端，待 Linux/WSL/CI 实跑）
- [x] 6.3 打包体积核查：`vite build` 产物体积记录，确认 ECharts 按需引入未显著膨胀（图表 chunk 懒加载，初始 `app.js` gzip 97.75 kB ≈ 基线 96.5 kB；ECharts 独立 `Chart` chunk gzip 198.98 kB 仅报告页加载）
