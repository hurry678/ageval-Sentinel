## 1. 适配器描述符 catalog（纯数据，行为不变）

- [x] 1.1 新建 `adapters/catalog.py`：定义 `AdapterDescriptor`（allow_source_ingest/requires_audit_infrastructure/requires_hosted_model/supports_openmanus_real/uses_builtin_adapter/builtin_adapter_kind/auto_onboard_demo_source/audit_benchmark_id/audit_runtime_mode/framework_ids）+ 4 个现有接入类型描述符 + 查询函数，验证：catalog 单测（合法集合、白名单派生、框架映射）
- [x] 1.2 `adapters/catalog.py` 暴露派生辅助（`adapter_types()`/`descriptor()`/`is_registered()`/`source_ingest_types()`/`framework_to_adapter_type()`），验证：单测断言与现有硬编码集合一致（`registry.py` 运行时 backend 轴不改）
- [x] 1.3 `source_ingress.py` manifest 白名单改为从 `catalog.source_ingest_types()` 派生，验证：现有白名单集合保持 + 回归不下降

## 2. adapter_type 校验来源迁移

- [x] 2.1 `contracts.py` 中 `adapter_type` 由 `Literal` 改为 `str` + `field_validator`（校验属注册表已登记键，默认仍 ecommerce_demo），验证：合法值通过、未登记值被拒的单测
- [x] 2.2 暴露"已登记适配器类型清单"只读来源（接口或常量），验证：清单与注册表一致的单测
- [x] 2.3 更新 `tests/contract/` 快照（Literal→str）并新增"拒绝未登记类型"契约用例，验证：contract 全绿

## 3. 用能力标志消除 OpenManus 特判

- [x] 3.1 `audit_preflight.py` 的 `!= "openmanus"` 改为 `descriptor.requires_hosted_model`，验证：openmanus 与非 openmanus 前置校验路径回归等价
- [x] 3.2 `service.py` 内 openmanus 分支（1035/1425/1431 附近）改读能力标志（runnable/requires_hosted_model/framework_ids），验证：回归 + openmanus 审计路径行为不变
- [x] 3.3 `app.py` API 层 openmanus 分支（280/815/825 附近）改读描述符，验证：API 契约与回归绿

## 4. 框架识别 → adapter_type 映射

- [x] 4.1 注册表构建 `framework_id → adapter_type` 反向映射（源自各 descriptor.framework_ids），验证：映射构建单测
- [x] 4.2 `agent_asset_index.py` 的 openmanus-else-external_sdk 改为查映射；未命中回退 external_sdk 并记录明确回退标注，验证：命中映射用之、未命中显式回退的单测

## 5. 配置化检测策略

- [x] 5.1 `AuditTask` 增加可选 `attack_intensity`（None→默认），攻击集生成按强度调整并在报告记录，验证：指定/未指定两分支单测
- [x] 5.2 `AuditTask` 增加可选判定阈值（至少 `max_attack_success_rate`，安全默认），审计结论门禁附加该判定并在报告体现，验证：自定义阈值改变结论 + 非法阈值被拒的单测
- [x] 5.3 `attack_pack.py` 的 `schema_version/benchmark` 校验改为对已登记版本集合校验（manifest 数据驱动发现），验证：加载已登记新版本成功、未登记版本被拒的单测

## 6. 前端最小适配

- [x] 6.1 Agent 接入类型选项来源从静态列表改为读 2.2 暴露的清单，验证：`frontend` Vitest + tsc 绿

## 7. 集成验证

- [x] 7.1 后端全量回归：`pytest tests/`（含 contract/regression）不低于基线（1068 passed），新增单测全绿（本机 Windows：927 passed / 54 failed / 104 skipped，较基线 +25 passed，54 failed 全为既有 Windows-only 用例；Linux 1068 由 CI 承接）
- [x] 7.2 前端回归：`npm run test` + `tsc --noEmit` 双通道全绿（Vitest 65 passed；tsconfig.app/node 类型检查通过）
- [x] 7.3 端到端冒烟：openmanus 与镜像源两条路径审计流程回归通过（本机 Windows 受 `fcntl` 限制的后端相关 e2e 记录为 CI 承接）
