## 1. 令牌层与暗色泄漏消除

- [x] 1.1 在 `src/styles/base.css` 中将现有暗色令牌保留在 `:root` 作为默认，并新增 `[data-theme="light"]` 覆盖块（canvas/surface/text/border/primary 及各语义色），验证：手动在 devtools 给 `<html>` 加 `data-theme="light"` 后整体底色与文字反转且无残留深色区块
- [x] 1.2 新增语义令牌 `--border-hover`、`--success-border`、`--danger-border`、`--warning-border`、`--info-border`、`--risk-high-bg`、`--risk-high-fg`、`--risk-high-border`、`--brand-gradient`，两套主题各自赋值，验证：`base.css` 中两套主题下这些令牌均有定义
- [x] 1.3 用上述令牌替换 `src/styles/app.css` 中 9 处写死的十六进制值（`.button:hover`、`.error-note`、`.info-note`、各 `.badge.*`、`.brand-mark` 渐变），验证：`grep` `app.css` 不再出现 `#3d465a`/`#55282d`/`#244457`/`#1f5b41`/`#5c2a2f`/`#574318`/`#5c3a2a`/`#2c1d12`/`#b06bff`
- [x] 1.4 排查 `src/styles/pages.css` 中剩余的硬编码色值并提升为令牌，验证：亮色主题下逐页目视无深色描边或深色背景残留
- [x] 1.5 引入 `--shadow-sm/md/lg` 三级阴影替代单一 `--shadow-card`，并统一 `.card` 与浮层的用法，验证：两套主题下卡片阴影可见且亮色下不过重
- [x] 1.6 暗色主题下逐页目视回归，确认外观与第一版基本一致（未引入视觉回归），验证：`npm run build` 通过且暗色下各页面与改动前一致

## 2. 主题初始化与顶栏切换

- [x] 2.1 新增主题模块（读取 `localStorage`、无记录时取暗色、写入 `document.documentElement.dataset.theme`、提供 `setTheme`），验证：模块导出初始化与设置两个入口且类型检查通过
- [x] 2.2 在渲染前同步应用主题（`index.html` 内联脚本或 `main.tsx` 于 `createRoot` 之前调用），验证：以亮色为已存选择时刷新页面无深色闪烁
- [x] 2.3 在 `App.tsx` 的 `Shell` 中新增 `header.topbar`，放入主题切换按钮（含随主题变化的图标与 `aria-label`），并保留侧边栏底部服务状态与版本号，验证：点击可在暗/亮之间切换且 `<html data-theme>` 随之变化
- [x] 2.4 调整 `.workspace` 内边距以适配新增顶栏，验证：三档视口下顶栏与内容不重叠、无双重留白

## 3. 分组导航

- [x] 3.1 将 6 个导航项改为 `NAV_GROUPS` 数据结构（工作台 / 检测作业 / 分析对比），验证：新增或调整分组只需改数据不改渲染逻辑
- [x] 3.2 `Shell` 渲染分组标题与链接，保持当前页选中态与 `aria-label="主导航"`，验证：进入各路由时对应导航项为选中态
- [x] 3.3 为分组标题与链接补齐样式（沿用令牌），验证：暗/亮双主题下分组标题与链接层级清晰

## 4. 总览仪表盘

- [x] 4.1 新增手写 SVG 严重度分布圆环组件（`stroke-dasharray` 分段 + `role="img"` 与文本摘要 `aria-label`），验证：给定各等级数值时环形分段比例正确
- [x] 4.2 圆环处理退化情形：全 0 时走显式空态、单一等级时整环单色，验证：两种输入下均不渲染误导性图形且有对应文案
- [x] 4.3 在 `Overview.tsx` 中组合关键指标行、严重度分布与右栏面板（运行队列、最近发现），验证：有数据时三部分均呈现
- [x] 4.4 各区块无数据时呈现显式空态文案且不使用占位假数据，验证：在无任何运行记录的环境下总览页各区块显示空态说明

## 5. 响应式

- [x] 5.1 为 `.app-shell` 增加单断点：窄视口下由两列变单列、侧边栏转为横向导航，验证：移动视口下导航可见且可点击
- [x] 5.2 消除三档视口下的横向溢出（表格与长 ID 等易溢出处补 `min-width: 0` / 换行处理），验证：三档视口下 `document.documentElement.scrollWidth` 不超过视口宽度

## 6. 验证门禁

- [x] 6.1 添加 `@playwright/test` 与 `@axe-core/playwright` 到 devDependencies 并新增 Playwright 配置（chromium + 桌面/平板/移动三个 project，自动拉起 dev server），验证：`npx playwright test --list` 能列出用例
- [x] 6.2 编写单个 e2e spec 覆盖三条机械场景：三档视口无横向溢出、暗/亮双主题 axe 无违规、切换主题后重载仍保持，验证：`npx playwright test` 全绿
- [x] 6.3 修复 e2e 暴露的对比度与可滚动区域可聚焦问题（含为可滚动区块补可聚焦能力），验证：axe 不再报出对比度与 `scrollable-region-focusable` 违规
- [x] 6.4 在 `package.json` 增加 `test:e2e` 脚本，验证：`npm run test:e2e` 可直接执行且通过

## 7. 收尾

- [x] 7.1 类型检查与构建，验证：`npm run build`（含 `tsc --noEmit`）无错误
- [x] 7.2 将 `frontend-redesign-visual-workbench` 归档并在归档说明中标注被本次取代（superseded），验证：该 change 不再出现在 `openspec list` 的在flight列表中且 `frontend/` 代码未被删除
- [x] 7.3 暗/亮双主题 × 三档视口对核心页面做一次人工目视核对，验证：无布局破裂、无文字截断、观感与第一版一致
