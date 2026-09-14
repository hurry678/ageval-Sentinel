## Purpose

定义测试套件的图形化浏览与用户自定义测试流程能力，使平台用户能理解套件覆盖面，并能在不改代码的情况下创建 ageval 兼容的自定义检测流程。

## ADDED Requirements

### Requirement: 套件详情图形化展示覆盖结构

控制台 SHALL 为每个测试套件提供详情页面。套件详情 MUST 图形化展示 N1-N8 节点覆盖、风险分类分布、严重度分布、task 列表以及每个 task 的攻击流程摘要。

#### Scenario: 查看套件覆盖图

- **WHEN** 用户打开一个测试套件详情
- **THEN** 系统展示该套件覆盖的 N1-N8 pipeline nodes
- **AND** 展示风险分类分布、严重度分布和 task 列表

#### Scenario: 套件无任务

- **WHEN** 用户打开一个合法但没有 task 的套件
- **THEN** 系统展示空态说明
- **AND** 不展示虚假的覆盖率、分类或严重度数据

### Requirement: Task 攻击流程摘要可视化

套件详情 SHALL 允许用户查看每个 task 的攻击流程摘要。摘要 MUST 包含 task id、场景、风险分类、严重度、覆盖节点、clean steps 数量、controlled steps 数量、预期决策与成功条件摘要。

#### Scenario: 查看 task 摘要

- **WHEN** 用户在套件详情中选择一个 task
- **THEN** 系统展示该 task 的场景、风险分类、严重度、覆盖节点与预期决策
- **AND** 展示 clean steps 与 controlled steps 的数量或明细入口

### Requirement: 用户可创建自定义测试流程

控制台 SHALL 提供创建自定义测试流程的入口。用户 MUST 能填写 suite 标识、task 标识、场景描述、风险分类、严重度、覆盖节点、clean steps、controlled steps、expected decision 与 success criteria。系统 MUST 在保存前校验必填字段、标识格式、严重度、节点编号和 steps 结构。

#### Scenario: 创建合法自定义流程

- **WHEN** 用户填写合法的自定义 suite/task 流程并保存
- **THEN** 系统创建一个可被平台发现的自定义测试套件
- **AND** 新套件出现在测试套件列表中
- **AND** 用户可以用该套件发起检测

#### Scenario: 拒绝非法自定义流程

- **WHEN** 用户提交缺少 task id、非法严重度或非法节点编号的流程
- **THEN** 系统拒绝保存并展示明确校验错误
- **AND** 不创建半成品套件目录

### Requirement: 自定义流程保存为 ageval 兼容数据集

用户创建的自定义测试流程 SHALL 保存为 ageval 兼容目录结构，至少包含 `ageval.yaml`、`tasks/<task_id>/task.yaml`、`tasks/<task_id>/data/scenario.json` 与 `tasks/<task_id>/evaluation/expected.json`。保存后 MUST 复用既有套件发现逻辑，而不是需要新增代码枚举。

#### Scenario: 保存后可发现

- **WHEN** 用户保存一个自定义测试流程
- **THEN** 平台的套件发现接口返回该自定义套件
- **AND** 该套件可作为发起检测的 suite 选项

#### Scenario: 避免覆盖内置套件

- **WHEN** 用户创建自定义 suite 时使用与内置套件相同的 suite id
- **THEN** 系统拒绝保存并提示标识冲突
