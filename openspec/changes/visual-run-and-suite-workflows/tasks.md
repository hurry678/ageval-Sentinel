## 1. 后端攻击路径 ViewModel

- [x] 1.1 新增运行攻击路径聚合逻辑，从 run record、suite task summary、scenario、events 和 report/replay 可用性生成 `attack_path`；验证：新增 contract 测试断言 N1-N8 节点、task 结果、覆盖节点和 evidence/replay 可用性字段完整
- [x] 1.2 新增 `GET /api/runs/{run_id}/attack-path`，运行不存在返回 404，运行存在但证据未就绪时返回空态字段而非假数据；验证：`pytest -q tests/contract/test_platform_api.py -k attack_path`
- [x] 1.3 确保攻击路径输出不包含明文凭据、环境变量值或未脱敏敏感字段；验证：新增测试构造含 `api_key_env` 的目标后断言 attack-path 响应不含密钥明文

## 2. 后端自定义测试流程

- [x] 2.1 新增自定义 suite/task 输入 schema 与校验：suite id、task id、安全 slug、严重度、N1-N8 节点、risk category、expected decision、steps、success criteria；验证：合法输入通过，缺字段/非法节点/非法严重度被拒
- [x] 2.2 新增 `POST /api/custom-suites/validate`，只校验不写入磁盘；验证：合法输入返回规范化预览，非法输入返回明确 422 错误
- [x] 2.3 新增 `POST /api/custom-suites`，写入 workspace 下自定义套件目录并生成 `ageval.yaml`、`task.yaml`、`data/scenario.json`、`evaluation/expected.json`；验证：保存后文件存在且 YAML/JSON 可解析
- [x] 2.4 将自定义 suite 根目录纳入 `suite_roots()` 发现，但拒绝与内置套件同名；验证：保存后 `/api/suites` 能看到新 suite，同名内置 suite 创建被拒
- [x] 2.5 保存后复用现有 suite summary 读取做二次校验，结构不完整时回滚半成品目录；验证：模拟写入失败后目录不残留半成品 suite

## 3. 前端运行详情与攻击路径图

- [x] 3.1 扩展前端 API/types，加入 `getRunAttackPath(runId)` 与攻击路径类型定义；验证：`npm run build` 类型检查通过
- [x] 3.2 新增轻量 `AttackPathGraph` 组件，使用统一设计令牌展示 N1-N8 节点、连线、覆盖状态、PASS/FAIL/ERROR 状态和图例；验证：`npm run build` 通过
- [x] 3.3 在 `RunDetail.tsx` 增加「攻击路径」tab，展示 path graph、task/attempt 列表、事件时间线和 report/replay 跳转；验证：打开已完成 run 可看到攻击路径，未完成 run 显示未就绪空态
- [x] 3.4 运行历史列表行支持点击进入详情且保留勾选对比行为不冲突；验证：构建通过且 checkbox 阻止行点击冒泡

## 4. 前端测试套件图形化与自定义流程

- [x] 4.1 新增 `SuiteCoverageGraph` 组件，在 suite 列表/详情展示 N1-N8 覆盖、严重度分布和风险分类摘要；验证：`npm run build` 通过
- [x] 4.2 升级 `SuiteDetail.tsx`，在顶部展示图形摘要，task 选择后展示攻击流程摘要、clean/controlled steps 和 gold 判据；验证：现有内置 suite 详情可正常展开 task
- [x] 4.3 新增 `CustomSuiteBuilder` 页面与路由，支持填写 suite/task 元数据、N1-N8 节点、risk category、severity、steps、expected decision、success criteria；验证：表单校验覆盖必填与非法值
- [x] 4.4 在 `Suites.tsx` 增加「新建自定义流程」入口，保存成功后跳转新 suite 详情；验证：端到端创建流程后列表出现新 suite
- [x] 4.5 自定义流程编辑器在移动视口下以分段表单和可滚动节点列表呈现；验证：`npm run build` 通过

## 5. 集成验证与发布

- [x] 5.1 后端 contract 测试覆盖攻击路径 API、自定义 suite validate/create、suite discovery 与冲突拒绝；验证：`pytest -q tests/contract/test_platform_api.py tests/contract/test_platform_visual_workflows.py` 通过
- [x] 5.2 前端构建与单测通过；验证：`cd ageval-security/platform_api/web && npm run build` 通过
- [ ] 5.3 手工闭环：创建一个自定义测试流程，用 inproc 目标发起检测，运行完成后进入运行详情查看攻击路径图，报告接口返回 200；验证：浏览器可完成全流程
- [x] 5.4 `openspec validate visual-run-and-suite-workflows --strict` 通过
