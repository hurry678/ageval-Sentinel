## Context

`platform_api` 已有 suite/run 基础能力：`/api/suites`、`/api/suites/{suite_id}`、`/api/suites/{suite_id}/tasks/{task_id}`、`/api/runs`、`/api/runs/{run_id}`、`/api/runs/{run_id}/events`、`/api/runs/{run_id}/report` 与 replay 接口。当前前端已有 `RunDetail.tsx` 的 live/report tab 与 `SuiteDetail.tsx` 的 task 展开面板，但图形化表达仍停留在局部覆盖点与表格，缺少统一攻击路径模型，也没有用户创建 ageval 数据集的入口。

关键约束：平台必须继续把 ageval CLI 作为唯一执行路径；自定义流程必须落成 ageval 兼容目录，而不是引入新的私有执行格式；界面必须复用现有设计令牌与轻量 React/Vite 栈，不新增重型图可视化依赖。

## Goals / Non-Goals

**Goals:**

- 从运行历史进入运行详情后，能看到 task/attempt 级攻击路径图和事件时间线。
- 在套件详情中用图形方式展示 N1-N8 覆盖、风险分类、严重度与 task 流程摘要。
- 提供用户自定义测试流程创建入口，并保存为可被现有 suite discovery 发现的 ageval 数据集。
- 保持内置套件、现有运行记录、report/replay API 兼容。

**Non-Goals:**

- 不重写 ageval runner，不在平台中实现第二套执行引擎。
- 不引入复杂图编辑器、拖拽 DAG 引擎或数据库。
- 不在本变更实现攻击强度/判定阈值的完整策略系统；这里只做自定义流程和数据驱动发现。
- 不让用户上传任意 Python evaluator 代码；第一版自定义流程只生成数据与标准 expected 判据，避免远程代码执行风险。

## Decisions

### 1. 统一攻击路径 ViewModel

新增后端 ViewModel：`attack_path`。它不替代现有 report/replay，而是从现有 run record、suite task summary、scenario、events 和 report 中聚合 UI 所需数据。

形状建议：

```json
{
  "run_id": "...",
  "nodes": [{ "id": "N1", "label": "用户输入", "covered": true, "status": "FAIL" }],
  "edges": [{ "source": "N1", "target": "N6", "count": 3 }],
  "tasks": [{ "task_id": "...", "attempt": 0, "category": "...", "severity": "high", "nodes": ["N1"], "status": "FAIL" }],
  "events": [{ "kind": "task", "task_id": "...", "seq": 12 }]
}
```

理由：前端只负责渲染，不在浏览器里推断安全语义。替代方案是在前端组合 `/runs`、`/events`、`/suites`、`/report`；这会让页面产生多源竞态，也难以在测试中稳定断言。

### 2. 图形渲染使用自研轻量 SVG/HTML 组件

攻击路径图和套件覆盖图使用现有 React 组件 + CSS/SVG 实现，不引入 React Flow、D3 等依赖。N1-N8 是固定小图，节点少、关系稳定，重型图库收益低。

替代方案是引入 React Flow。拒绝原因：增加包体与样式复杂度，且第一版不需要拖拽编辑或任意 DAG。

### 3. 套件图形页复用现有 suite discovery

`SuiteDetail` 继续以 `suite_detail()` 返回的数据为基础，新增可视化字段只做后端派生或前端派生，不改变内置 ageval 数据集格式。task 展开继续调用 `/api/suites/{suite_id}/tasks/{task_id}`，避免一次性加载所有 scenario 明细。

### 4. 自定义流程保存到 workspace 子目录

新增自定义 suite 根目录建议：`ageval-security/.platform/custom-suites/<suite_id>/` 或由 `config.WORKSPACE` 派生的等价目录。`suite_roots()` 将该目录纳入发现范围。

保存文件：

```text
ageval.yaml
tasks/<task_id>/task.yaml
tasks/<task_id>/data/scenario.json
tasks/<task_id>/evaluation/expected.json
```

理由：保存为 ageval 原生结构后，发起检测、报告和 replay 仍走现有 ageval 路径。替代方案是保存 JSON 草稿并运行时转换；会制造第二套状态机，不利于可复现。

### 5. 自定义流程 API 分两层

- `POST /api/custom-suites`：创建 suite 或追加 task，输入结构化 JSON，后端校验后写文件。
- `POST /api/custom-suites/validate`：只校验不写入，用于 UI 即时反馈。

第一版不支持上传压缩包和任意 evaluator。后续可加导入导出，但必须先做路径穿越、大小限制和代码执行边界设计。

### 6. UI 信息架构

- `Runs.tsx`：运行 ID/目标/套件列变为可点击，进入 `/runs/:runId`。
- `RunDetail.tsx`：增加 `攻击路径` tab，保留 `实时观测` 与 `报告`。
- `Suites.tsx`：增加「新建自定义流程」按钮；卡片保留，但提供更明显的详情入口。
- `SuiteDetail.tsx`：增加顶部图形摘要区，task 展开显示流程摘要。
- 新页面 `CustomSuiteBuilder.tsx`：表单/分步编辑，保存后跳转套件详情。

## Risks / Trade-offs

- [Risk] 从 ageval 输出中恢复完整攻击因果链可能不完整 → Mitigation：第一版图使用 suite 声明节点 + task 结果 + events，不声称展示模型内部真实思维链。
- [Risk] 自定义流程写文件存在路径穿越或覆盖内置套件风险 → Mitigation：suite/task id 只允许安全 slug，写入 custom-suites 根目录，拒绝与内置套件同名。
- [Risk] 用户误以为自定义流程可以执行任意 evaluator → Mitigation：第一版 UI 文案明确只支持标准 scenario/expected；不暴露 Python 上传。
- [Risk] 小屏图形不可读 → Mitigation：固定 N1-N8 图在小屏降级为可滚动节点列表，仍保留状态和证据入口。
- [Risk] 自定义 suite 结构生成后 ageval CLI 校验失败 → Mitigation：保存前做 schema 级校验，保存后调用现有 suite summary 读取做二次校验。

## Migration Plan

1. 先补后端 ViewModel 和自定义 suite 写入 API，保持现有接口不变。
2. 再加前端路径图/套件图组件，默认从现有数据渲染，缺数据时显示空态。
3. 最后接入自定义流程 builder，并把新 suite 纳入发现列表。
4. 回滚时可隐藏前端入口；已保存的自定义 suite 是普通 ageval 数据集，不影响内置套件运行。
