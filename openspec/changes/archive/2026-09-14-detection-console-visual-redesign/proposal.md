## Why

仓库内并存两套前端：`ageval-security/platform_api/web`（通用检测控制台：检测目标 / 测试套件 / 发起检测 / 运行历史 / 横向对比）与 `frontend/`（围绕"安全审计"的专用界面）。后者在多轮迭代中把每个新功能都追加到 `refinement.css`，样式与信息架构逐步失控，且其 IA 绑定在审计模型上，偏离了"通用型 Agent 检测平台"的定位。

`ageval-security/platform_api/web` 的信息架构（目标 / 套件 / 运行 / 对比）本身就是通用的检测语义，结构干净（9 页 + 3 个 CSS 文件），应确立为唯一前端基线；但它目前只有一套硬编码暗色令牌、平铺导航与偏薄的总览页，视觉成熟度不足。本次以 `D:\Sec\BalanceLee_AI`（CyberStrikeAI）的设计语言为参照补齐视觉层。

## What Changes

- **确立唯一前端基线**：以 `ageval-security/platform_api/web` 为后续唯一演进的控制台前端；`frontend/` 停止演进（**BREAKING**：不再作为交付界面），`frontend-redesign-visual-workbench` 标记为 superseded 后归档，保留历史不删除。
- **引入可切换主题体系**：现状 `:root` 硬编码 `color-scheme: dark`。改为暗色为默认令牌、`[data-theme="light"]` 覆盖亮色，新增顶栏主题切换并持久化用户选择；亮暗两套均需满足对比度要求。
- **对齐 BalanceLee_AI 设计语言**：统一强调色与品牌渐变（`#0066ff → #7c3aed`）、补齐三级阴影层级（现仅单一 `--shadow-card`）、统一卡片/圆角/间距刻度的使用方式。
- **导航改为分组式**：现 6 项平铺导航改为带分组标题的侧边栏（工作台 / 检测作业 / 分析对比），并保留底部平台服务状态与版本信息。
- **总览页升级为仪表盘**：在现有 `Stat` 行之外，补充风险严重度分布图与右栏面板（运行队列、最近发现），空态必须显式呈现而不虚构数据。
- **响应式与可达性基线**：桌面 / 平板 / 移动三档断点下无横向溢出与布局破裂，键盘可达、可滚动区域可聚焦。

不在本次范围：后端统一（第一版走 `ageval-security/platform_api`，被弃用的 `frontend/` 走 `src/redsentinel`）属于独立议题；本次不改后端契约，也不新增检测能力。

## Capabilities

### New Capabilities

- `console/detection-console`: 通用 Agent 检测控制台的前端呈现契约——导航信息架构与分组、主题体系（暗色默认 + 亮色切换 + 持久化）、总览仪表盘的构成与空态、以及响应式与可达性基线。

### Modified Capabilities

（无。本次不改变检测策略与适配器注册的既有需求。）

## Impact

- **代码**：`ageval-security/platform_api/web/src/styles/{base,app,pages}.css`（令牌与主题层）、`src/App.tsx`（分组侧边栏 + 顶栏主题切换）、`src/pages/Overview.tsx`（仪表盘）、`src/components/ui.tsx`（卡片/空态等共用件）。
- **不受影响**：`ageval-security/platform_api` 后端接口、`src/redsentinel` 全部后端逻辑、既有两个 backend 能力规格。
- **停止演进**：`frontend/`（含其 Playwright e2e 与 Vitest 套件）不再作为交付目标；相关 OpenSpec change 归档时标注被本次取代。
- **依赖**：沿用现有 React + Vite + lucide-react 技术栈，不新增运行时依赖。
