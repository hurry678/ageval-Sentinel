## Context

动机见 `proposal.md` — Why。本节只记录影响技术方案的现状约束。

基线 `ageval-security/platform_api/web` 的现状：

- **令牌层**：`src/styles/base.css` 的 `:root` 直接写死 `color-scheme: dark` 与一整套暗色令牌，已具备 `--radius-*` / `--space-*` 刻度，结构良好，但没有第二套主题的位置。
- **暗色泄漏**：`src/styles/app.css` 中约 9 处直接写死了仅适用于暗色的十六进制值（`.button:hover` 的 `#3d465a`、`.error-note` 的 `#55282d`、`.info-note` 的 `#244457`、各 `.badge.*` 的 `#1f5b41`/`#5c2a2f`/`#574318`/`#5c3a2a`/`#2c1d12`、`.brand-mark` 渐变的 `#b06bff`）。这些值不随令牌切换，是亮色主题落地的主要障碍。
- **骨架**：`App.tsx` 的 `Shell` 只有 `aside.sidebar` + `div.workspace > main`，**没有顶栏**，因此主题切换入口无处安放；导航是 6 个 `NavLink` 平铺，无分组结构。
- **布局**：`.app-shell` 为 `grid-template-columns: 232px minmax(0,1fr)` 固定两列，无断点收起逻辑。
- **依赖**：仅 `react` / `react-dom` / `react-router-dom` / `lucide-react`，**无图表库、无任何测试框架**。
- **总览页**：`Overview.tsx` 已有 `Stat` 行与 `card` 组合，但缺少严重度分布与侧栏面板。

参照对象 `D:\Sec\BalanceLee_AI\web\static\css\style.css` 是 Go 模板 + 静态 CSS，采用「亮色为 `:root` 默认 + `html[data-theme="dark"]` 覆盖」的分层，令牌命名为 `--bg-primary/secondary/tertiary`、`--text-primary/secondary/muted`、`--border-color`、`--accent-color`、`--shadow-sm/md/lg`，品牌渐变为 `#0066ff → #7c3aed`。

## Goals / Non-Goals

**Goals:**

- 在不改变基线信息架构（目标 / 套件 / 运行 / 对比）的前提下，补齐主题层、分组导航、仪表盘与阴影层级。
- 消除暗色泄漏，使「同一组件在双主题下无需重复定义」在物理上成立。
- 为规格中可机械验证的场景（三档溢出、双主题对比度、主题持久化）建立自动化门禁。

**Non-Goals:**

- 不迁移 BalanceLee_AI 的技术栈（Go 模板/其 CSS 文件），只借鉴设计语言。
- 不改后端接口，不新增检测能力，不动 `src/redsentinel`。
- 不重命名既有页面路由与导航语义，避免与用户已认可的第一版观感产生偏移。
- 不做侧边栏折叠记忆、多语言等未被要求的能力。

## Decisions

### D1：令牌分层采用「暗色为 `:root` 默认 + `[data-theme="light"]` 覆盖」

沿用基线既有令牌命名（`--canvas` / `--surface` / `--text` / `--border` / `--primary` …），仅新增亮色覆盖块，而**不**改名成 BalanceLee 的 `--bg-primary` 体系。

- 理由：用户认可的是第一版观感，暗色是默认态；把默认态放在 `:root` 可避免首屏闪白。保留既有命名可使 9 个页面与 `ui.tsx` 零改动即获得双主题，改动面最小。
- 备选：改用 BalanceLee 的命名并以亮色为 `:root`（被否——需要重写全部页面样式引用，且与「暗色默认」冲突，首屏会闪白）。

### D2：新增 `--*-border` / `--brand-gradient` 等语义令牌以消除暗色泄漏

把 app.css 中写死的 9 处十六进制值提升为语义令牌（如 `--success-border` / `--danger-border` / `--warning-border` / `--info-border` / `--risk-high-*` / `--border-hover` / `--brand-gradient`），在两套主题中各自赋值。

- 理由：这是「统一设计令牌来源」要求能被验证的前提；否则亮色主题下徽章与提示条会出现暗色描边。
- 备选：给亮色主题单独写一份 `.badge.*` 覆盖规则（被否——正是这种「为局部再补一块样式」的做法导致上一版失控）。

### D3：主题初始化在渲染前同步写入 `<html data-theme>`，避免闪烁

在 `index.html` 内联一小段脚本（或 `main.tsx` 中在 `createRoot` 之前）读取 `localStorage`，无记录时取暗色，随即设置 `document.documentElement.dataset.theme`。React 侧仅持有当前主题状态用于切换按钮的图标与 `aria-label`。

- 理由：若等到 React 挂载后再应用主题，亮色用户会看到一帧暗色闪烁。
- 备选：纯 React 状态 + `useEffect`（被否——必然闪烁）；跟随 `prefers-color-scheme`（被否——规格要求首访为暗色且以用户显式选择为准）。

### D4：新增顶栏承载主题切换，服务状态保留在侧边栏底部

`Shell` 增加 `header.topbar`（内含面包屑/页面上下文位与主题切换按钮），侧边栏底部的「平台服务在线/不可用 + 版本号」原样保留。

- 理由：规格要求侧边栏常驻服务状态；主题切换属于全局控件，放顶栏符合 BalanceLee 参照，也不挤占导航区。
- 备选：把切换按钮塞进侧边栏底部（被否——与状态区语义混杂，移动端收起侧边栏后将无法访问）。

### D5：导航分组用数据结构声明，而非在 JSX 里硬写分组

以 `NAV_GROUPS: { label: string; items: NavItem[] }[]` 声明「工作台 / 检测作业 / 分析对比」，`Shell` 遍历渲染 `<nav>` 内的分组标题与链接。

- 理由：分组与顺序是会反复调整的产品决策，数据化后调整不触碰渲染逻辑。
- 备选：JSX 内直接分段（被否——每次调整都要改结构，易引入不一致）。

### D6：严重度分布图用手写 SVG 圆环，不引入图表库

以 `stroke-dasharray` 驱动的 SVG donut 呈现严重度占比，配 `role="img"` + `aria-label` 文本摘要，并在右侧以列表给出各等级数值。

- 理由：`proposal.md` 明确不新增运行时依赖；单个圆环用图表库属于杀鸡用牛刀，且图表库会带来主题联动的额外复杂度（上一版正是在图表主题联动上花了大量成本）。
- 备选：引入 echarts（被否——为一个圆环增加数百 KB 依赖与主题桥接层）；纯 CSS `conic-gradient`（被否——难以给出可达性文本与分段描边）。

### D7：响应式采用单断点收起侧边栏

在窄视口下 `.app-shell` 由两列变单列，侧边栏转为横向导航条（或抽屉），确保三档视口下无横向溢出。

- 理由：规格只要求三档不破裂、无溢出，不要求完整的移动端导航体验；单断点是达标的最小手段。
- 备选：多断点 + 抽屉动画（被否——超出要求）。

### D8：验证方式为最小 Playwright + axe（单个 spec）

新增 `@playwright/test` 与 `@axe-core/playwright` 作为 **devDependencies**，只写一个 e2e spec，覆盖三条机械可验证的场景：三档视口无横向溢出、暗/亮双主题 axe 无违规、主题切换后重载仍保持。视觉与文案仍由人工核对。

- 理由：这三条是规格里唯一能被自动判定的部分；纯手工核对正是上一版偏移失控的成因。控制在单个 spec 可避免测试自身变成新的复杂度来源。
- 备选：不加测试只靠 build（被否——对比度与溢出回归只能靠人眼）；加 Vitest 组件测试（被否——测不到对比度与真实布局溢出，收益低于浏览器级检查）。

## Risks / Trade-offs

- **[亮色主题下既有 9 个页面出现未预期的对比或描边问题]** → 令牌化（D2）后逐页在亮色下过一遍 axe 与目视；`pages.css` 中若发现新的暗色泄漏，一并提升为令牌而不是加覆盖规则。
- **[新增顶栏挤压纵向空间，长表格页面可用高度减少]** → 顶栏保持紧凑高度并不吸顶固定；`workspace` 的现有内边距相应下调。
- **[引入 Playwright 带来新的工具面与 CI 依赖]** → 只保留单个 spec 与最小配置；不引入多浏览器矩阵，仅用 chromium 与三个视口 project。
- **[手写 SVG 圆环在极端数据（全 0 或单一等级 100%）下退化]** → 全 0 时按规格走显式空态而非画 0 值环；单一等级时整环单色并由 `aria-label` 说明。
- **[「统一令牌来源」缺乏自动化约束，未来仍可能被硬编码破坏]** → 本次不引入 CSS lint（超出范围），改为在设计中固定「新增样式必须引用令牌」的约定，并在 review 时把硬编码色值视为缺陷。

## Migration Plan

1. 先做令牌层与暗色泄漏消除（D1/D2），此时界面外观应与第一版基本一致——作为「未引入回归」的基线校验点。
2. 再加主题初始化与顶栏切换（D3/D4），验证首屏无闪烁、切换与持久化正常。
3. 然后是分组导航（D5）与仪表盘（D6），最后处理响应式断点（D7）。
4. 最后接入 Playwright + axe 门禁（D8）。
5. 回滚策略：各步均为前端纯呈现改动且互相独立，按提交粒度回退即可；后端与其它前端不受影响。`frontend/` 保持原样不删除，必要时仍可回退查看历史实现。

## Open Questions

- 侧边栏分组的最终标题与归属（例如「运行历史」归入「检测作业」还是「分析对比」）可在实现时按视觉密度微调，不影响规格与任务拆分。
