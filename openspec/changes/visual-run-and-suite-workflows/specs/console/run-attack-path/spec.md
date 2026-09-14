## Purpose

定义检测运行详情的图形化攻击路径能力，使用户能从运行历史进入具体 task/attempt，理解攻击经过哪些 Agent 攻击面、在哪里命中或失败，并快速跳转证据、回放与报告。

## ADDED Requirements

### Requirement: 运行历史可进入运行详情

控制台 SHALL 允许用户从运行历史列表选择任一运行并进入该运行的详情页面。运行详情 MUST 展示运行基础信息、目标、套件、状态、进度、结果计数、耗时以及任务级结果列表。

#### Scenario: 打开已完成运行详情

- **WHEN** 用户在运行历史中点击一个已完成运行
- **THEN** 系统展示该运行的详情页面
- **AND** 页面包含目标、套件、状态、进度、结果计数、耗时和任务列表

#### Scenario: 打开不存在的运行

- **WHEN** 用户访问一个不存在的运行详情
- **THEN** 系统展示明确的未找到状态，不显示虚假的运行数据

### Requirement: 攻击路径图展示 N1-N8 覆盖与结果

运行详情 SHALL 为每个可分析的运行展示攻击路径图。路径图 MUST 以 N1-N8 pipeline nodes 为节点基础，标注本次运行中每个 task 覆盖的节点、攻击分类、严重度与最终结果。未覆盖节点 MUST 可见且以未命中状态呈现。

#### Scenario: 展示命中节点

- **WHEN** 运行中的任务声明覆盖 N1、N4、N7
- **THEN** 攻击路径图中 N1、N4、N7 被标记为已覆盖
- **AND** 其余 pipeline nodes 仍展示为未覆盖

#### Scenario: 展示任务结果

- **WHEN** 某个 task 的检测结果为 FAIL
- **THEN** 攻击路径图和任务列表均展示该 task 的失败状态
- **AND** 用户能区分 PASS、FAIL、ERROR 与运行中状态

### Requirement: 任务与尝试级攻击流程可检查

运行详情 SHALL 允许用户查看 task/attempt 级流程信息，包括阶段时间线、关键事件、工具调用摘要、证据链接与可用 replay/report 链接。敏感内容 MUST 按平台现有脱敏规则呈现，不能在图形界面中新增明文凭据泄露面。

#### Scenario: 查看任务流程

- **WHEN** 用户选择运行详情中的某个 task
- **THEN** 系统展示该 task 的关键事件时间线与 attempt 结果
- **AND** 如存在 replay 或 report，系统提供对应跳转入口

#### Scenario: 证据尚未就绪

- **WHEN** 运行仍在进行或对应 task 尚无 report/replay 产物
- **THEN** 系统展示明确的未就绪状态
- **AND** 不使用占位假数据填充事件或证据
