## Purpose

Web 审计界面的数据可视化能力：用 ECharts 将审计与画像的量化指标以图表形式直观展示，覆盖统一主题、响应式降级与无障碍，降低用户读取复杂数据的成本。

## ADDED Requirements

### Requirement: 审计报告量化图表

系统 SHALL 在审计报告页以图表形式展示核心量化指标，至少包含：防护前后 ASR 对比、多轮 ASR 趋势、风险面与严重度分布、场景 delta 汇总、业务任务通过率。图表数据 MUST 来源于现有 `/v1/audits/*` 接口返回的字段，不得引入后端改动。

#### Scenario: 展示防护前后 ASR 对比

- **WHEN** 用户打开一份已完成审计的报告页
- **THEN** 页面渲染防护前（baseline_asr）与防护后（guarded_asr）的对比图表
- **AND** 图表标注两者数值与差值

#### Scenario: 展示多轮 ASR 趋势

- **WHEN** 审计包含多轮攻击记录（AuditRound 数量 ≥ 2）
- **THEN** 页面渲染各轮 baseline/guarded 命中率的趋势图

#### Scenario: 单轮审计不渲染趋势图

- **WHEN** 审计仅有一轮记录
- **THEN** 趋势图区域不渲染或显示"暂无多轮数据"占位，不报错

### Requirement: 画像完整度可视化

系统 SHALL 在 Agent 画像报告页以图形（雷达或环形）展示 `completeness` 各维度覆盖率，替代纯文本 `covered/total`。

#### Scenario: 展示画像完整度图形

- **WHEN** 用户查看某 Agent 的 v0.2 画像报告
- **THEN** 页面以雷达/环形图展示各维度覆盖率
- **AND** 悬停可见每个维度的 covered/total 明细

### Requirement: 图表主题一致性

所有新增图表 SHALL 复用现有设计系统的 CSS 变量（色板/圆角/字体），与极简主题保持视觉一致。系统 MUST 消除 `styles.css` 与 `refinement.css` 中重复的 `:root` 变量定义，仅保留单一生效来源。

#### Scenario: 图表配色取自设计系统

- **WHEN** 任一图表渲染
- **THEN** 其主色、成功/警告/危险色取自 CSS 变量而非硬编码色值

### Requirement: 图表响应式与无障碍降级

图表 SHALL 在移动端（≤720px）自适应缩放且不产生水平溢出；当用户开启 `prefers-reduced-motion` 时 MUST 禁用图表入场动画。每个图表 MUST 提供文本可读的等价信息（aria-label 或可访问的数据摘要）。

#### Scenario: 移动端无水平溢出

- **WHEN** 在 390px 视口打开含图表的报告页
- **THEN** 图表宽度自适应容器，页面无水平滚动条

#### Scenario: 减少动效偏好被尊重

- **WHEN** 用户系统开启 prefers-reduced-motion
- **THEN** 图表不播放入场动画
