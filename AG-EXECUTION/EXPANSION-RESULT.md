# OpenHarmony 6.0 静态自主审计扩面实验账本

> 本文件是 `AG-EXECUTION/EXPANSION-PLAN.md` 的实验记录，不是第二份规范。裁决规则以 `AGENT-ARCHITECTURE-GUIDE.md`（1.0.33）为准。
> 记录原则：只写实际执行过的命令、实际得到的数字和实际存在的文件；未执行标 `not-run`，失败写失败原因；旧 run 只读，不追加重写。

## 阶段状态（2026-10-25 11:00 校正）

| 阶段 | 状态 | 依据 |
|---|---|---|
| E0 清点与同机基准 | **已验证** | 固定输入清单、三条旧 run `check`、208 生产入口清点、冷/热/doctor/check 原始测量（本文件 E0 节） |
| E1 第二组件纵向路径 | **已验证** | `RUN:b352c4fba543a23c` 17 入口、0/0/15/2、`check` 0/0；冷/热隔离 run 同语义哈希；复算非空转与 pilot 回归 |
| E2 剖面与优化 | **已测量、未触发新增优化** | 冷/热、索引、check 与每任务边际成本已测；未达自定瓶颈门槛，未实施重构 |
| E3 效果评测 | **已完成（受限口径）** | 8 家族给定变异体判定 8/8；IAM scoped excluded；IAccount 16 入口 off/check；CES `ICommonEvent` 17 入口 off/check；**冻结跨组件无种子盲测** `RUN:cf05827a914570e3`（18 案例 / 2 组件；在 Builder-LLM 受控标签内一致性：状态 18/18、家族 18/18、提名 8/8、合规 7/7、歧义 3/3、错误确定 0、漏提名 0、错误排除 0）；真实 finding 0、真实召回 `null`、独立准确率 `null`。不得把该一致性写成真实漏洞召回 |
| 全范围基线（第一层） | **已完成** | `tools/oh6-full-scope-inventory.js`：190 组件 / 60,268 生产代码文件 / 57,250 C-C++ 文件 / 3,018 其他语言 / 245 IDL / 3,234 方法 / 155 SA profile / 812 构建 features / 291 外部声明依赖 / 201 无 bundle 文件。函数、操作、绑定、变体组合、依赖审计仍标未做，不称已审计 |
| 第三轮 live/静态补路径/分层 | **已完成（授权内）** | IAM live `RUN:282b88d0b994ec32`（5 请求/0 失败/0 finding/check 0/0）+ replay `RUN:92670c6fce4dcdc7`（0 远端/同语义/check 0/0）；IAccount `RUN:45f304aa5fea2fbf`、CES `RUN:5961cae1af3c49fb` 各 1 excluded 完整静态路径、check 0/0；access_token/init/ipc 分层测量完成（默认 20k calls 截断、重复 build 近似冷跑）；全量 257/257。仅覆盖 5/17、1/16、1/17 入口 |
| 第四轮 全入口/绑定/增量 | **已完成** | IAccount v2 `RUN:f05c85e0379a2054`（16 入口，1 excluded/15 observation）、CES v2 `RUN:01caf9305d77b70c`（17 入口，1 excluded/16 observation），check 0/0；仅 2 个目标入口变化，其余逐条不变；access_token 绑定 79/2/4（2 个类型重载 suspect、4 个 SA 无模型）；IPC 清点 7 个 OnRemoteRequest 等；单文件增量四场景与全量 13 表 sha256 一致；锚点审计 0 真实 finding；全量 257/257 |

## 2026-10-25 E0 起点

### 环境与工作区状态

| 项 | 实际值 |
|---|---|
| 工作目录 | `D:\oh6.0\OpenHarmony-v6.0-Release\oh6-surface-audit` |
| 宿主 | Windows 原生；Node `v25.2.1`（`win32` / `x64`） |
| git 状态 | 开工时大量未提交实现改动（见 §0.1 基线），另有未跟踪 `EXPANSION-PLAN.md`、`FULL-SCOPE-ROADMAP.md`、`autonomy-security-anchors.json`、`gates.js`、`policy.js` 等；**未 reset/checkout/stash**，未修改 `OpenHarmony/out/` |
| 模型密钥 | `doctor.apiKeyPresent=false`（当前进程未注入 `OH6_LLM_API_KEY`）；本阶段 0 次 live 外发 |
| 旧 run | `RUN:4d94dc5ce617dc24`（off）、`RUN:c1bb7f187359b2c2`（live）、`RUN:2ef312b6d35e2550`（replay）三条 `check` 全部 `ok:true`、0 error / 0 warning（只读复算） |

### 固定输入清单（E0 开工实测 sha256）

| 输入 | sha256 |
|---|---|
| 事实快照 `sha256:2142c229d142bdacc472969fe96d73a36da4554f3775dee4f710b79878997a1e`（5 roots） | `manifest.json` = `cec0d62e0922b6c7f4b590c89fe4d924b694a065444a1eb6b4f517025e2d6013` |
| `K/policies/autonomy-pilot-scope.json` | `7754249176cf75d685b303b376aa18dd7d530b2e910821f4b89003269c9aacb5` |
| `K/policies/autonomy-pilot-budget.json` | `dbb1ff4563732981685a1148d602b78e120be7593a333dc40ec1831702f07982` |
| `K/policies/autonomy-security-anchors.json` | `00e0ed14883e4eb467b7579a23129bf22bdacc8aa7e037144b4cf6bdbbaa9508` |
| `K/norms/050e10d7…/knowledge.json`（`NORM:298088535ea57095`，SET_SANDBOX_POLICY） | `6297e67ba54ec3375caaee6776a03a5adc04f2c0655f67f607cee7a3d12bdc47` |
| `K/norms/7b1ad465…/knowledge.json`（`NORM:aa1295d063607f4d`，FILE_ACCESS_PERSIST，14 方法） | `8b4b2f0bfd71aa26cdb64227906c87185d94f77d2ac28fb83a286b3debb67e8a` |
| `eval/autonomy/security-verdict-mutants.json` | `5244fd20eb7ef87d768d347828a19302b76f0ef0e1b39264ecada798a8423f26` |

### 三条现存 canonical run（只读核验）

| run | 模式 | `check` | 任务/工具/模型 | 裁决计数 | 语义哈希 | `report-model.jsonl` sha256 |
|---|---|---|---|---|---|---|
| `RUN:4d94dc5ce617dc24` | off | ok / 0 / 0 | 25 / 162 / 0 | 0 finding / 0 candidate / 14 excluded / 11 observation | `sha256:acd50012b4f940a8caef2a0b8e00dd00f5199414c014d54d1c34ce16fed51bcb` | `9ee90606daa98e985651760946b45f05ac33401e6c70261e9032ef8db92d2123` |
| `RUN:c1bb7f187359b2c2` | live | ok / 0 / 0 | 25 / 162 / 17 | 同上 | `sha256:f6a192cc774201ac8503528e492e44b4be47f2488b109b0f25b798ea141eac10` | `49489c6ebec4d3972cfd3ec00c128367f7a6a32acc7762ff82c6204554062416` |
| `RUN:2ef312b6d35e2550` | replay | ok / 0 / 0 | 25 / 162 / 0 | 同上 | `sha256:f6a192cc774201ac8503528e492e44b4be47f2488b109b0f25b798ea141eac10` | `df8d023589aa516dd57b9bdef18acfa32d91243769a003b9f548d584421d14f7` |

`counts` 一致：events 441/441/442、tasks 25、questions 123、missing 38、toolResults 162、assessments 123、contexts 25、reportRows 25。`out/autonomy` 中不存在 §24.4-24.27 的其他 run；历史丢失记录只作文本背景，不进入分母。

## E0 第二组件入口清点与冷/热基准

### 入口清点（`base/account/os_account`）

只读工具 `tools/autonomy-entry-inventory.js`（新增，不建索引、不写 run）：

```powershell
node tools/autonomy-entry-inventory.js --scope=K/policies/autonomy-pilot-scope.json `
  --root=base/account/os_account --interface=Account --max-candidates=3 `
  --out=out/autonomy/inventory/os-account-idl-raw.json
```

实测（`out/autonomy/inventory/os-account-idl-raw.json` sha256 `2231121e…`，2026-10-25 口径修正后）：1,025 源文件、7,014 函数、**208 个生产入口** = 203 IDL 方法 + 1 SA + 3 NAPI + 1 生产 `OnRemoteRequest`（`OsAccountUserCallback::OnRemoteRequest`）；另有 **11 个名字含 `OnRemoteRequest` 的 HWTEST 测试函数**，不计入口。19 个 IDL 接口，最大 `IOsAccount` 72、`IAppAccount` 42、`IDomainAccount` 22、`IAccountIAM` 17、`IAccount` 16。

**口径修正记录**：首版清点把接口过滤器套到了所有入口类型，并把名字匹配 `OnRemoteRequest` 的 HWTEST 宏函数当成入口，得到“213 入口 / 10 个 OnRemoteRequest”；索引 reconciliation 也曾报 `on-remote-request=12`（1 个生产 + 11 个测试）。现统一为“生产函数 + 接口过滤只作用于 IDL”：入口 208、生产 OnRemoteRequest 1、测试名匹配 11 单列。`lib/autonomy/index.js` 与 `tools/autonomy-entry-inventory.js` 已同步修正；pilot 根无 OnRemoteRequest，pilot 19 入口不受影响。沿用 pilot 的 `implOwnerSuffix=SandboxManagerService` 时 203/203 方法 unbound，证明第二组件必须有自己的 scope 数据。

**选中接口**：`OHOS.AccountSA.IAccountIAM`（17 个 IDL 方法），唯一实现类 `OHOS::AccountSA::AccountIAMService`（`services/accountmgr/src/account_iam/account_iam_service.cpp`）。每个方法的服务体通过私有成员 `CheckPermission(CONST)` 一跳委托 `AccountPermissionManager::VerifyPermission`，拒绝分支返回 `ERR_ACCOUNT_COMMON_PERMISSION_DENIED`；敏感操作形态为 `InnerAccountIAMManager::GetInstance().<Method>(...)`。这是与 pilot 不同的门禁形状，不能复用 pilot 词表直接判定。

| 入口方法组 | 权限常量 | 数量 |
|---|---|---|
| `OpenSession/CloseSession/AddCredential/UpdateCredential/Cancel/DelCred/DelUser` | `PERMISSION_MANAGE_USER_IDM` | 7 |
| `GetEnrolledId`（及未映射的 `GetCredentialInfo`） | `PERMISSION_USE_USER_IDM` | 1（+1 未映射） |
| `PrepareRemoteAuth/AuthUser/CancelAuth/GetAvailableStatus/GetProperty/GetPropertyByCredentialId/SetProperty` | `PERMISSION_ACCESS_USER_AUTH_INTERNAL` | 7 |
| `GetAccountState` | 无 | 1 |

### 冷/热测量（Windows 原生，隔离输出根）

测量工具：`tools/autonomy-bench.js` + `tools/autonomy-bench-preload.js`（新增，`--require` 预载统计 wall/CPU/峰值 RSS/fs 读写字节；`stdio: inherit`，不捕获管道）。隔离根通过 `OH6_AUTONOMY_ROOT` 指定（`lib/autonomy/store.js` 新增，未设置时行为不变），因此**未删除**任何既有索引或 run。

| 实验 | 输出根 | wall ms | CPU user+sys ms | 峰值 RSS | 读字节 | 写字节 | 读/写调用 |
|---|---|---:|---:|---:|---:|---:|---:|
| doctor（仅元数据/快照检查） | 主根只读 | 32 | 0+16 | 51 MB | 471,478 | 0 | — |
| 冷索引 `index` | `out/autonomy-exp-e0-index` | 882 | 859+360 | 357 MB | 381,104,608 | 28,821,099 | 1,388 / 3 |
| 冷 off ×1 任务（索引内建） | `out/autonomy-exp-e0-one` | 1,103 | 734+406 | 314 MB | 498,882,101 | 28,914,757 | — |
| 冷 off（索引+17 任务） | `out/autonomy-exp-e0-coldoff` | 1,603 | 1,313+610 | 356 MB（MaxRSS 407 MB） | 512,073,881 | 31,480,870 | 2,599 / 997 |
| 热 off（复用索引，17 任务） | 同上 | 1,314 | 672+594 | 289 MB（MaxRSS 309 MB） | 483,254,354 | 2,659,772 | 2,597 / 994 |
| `check` 复算 canonical run | 主根只读 | 1,162 | 875+391 | 282 MB | 745,510,807 | 0 | — |

原始 JSON：`out/autonomy/bench/e0-doctor.json`、`e0-cold-index.json`、`e0-one-task-off.json`、`e0-cold-off.json`、`e0-hot-off.json`、`e0-check.json`（汇总副本 `out/autonomy/inventory/e1-summary.json` 只含前三项 off/index 与 smoke，后三项以各自 bench JSON 为准）。

**分阶段成本（由同一套实测推导，不是 instrumentation 计时）**：doctor 32 ms（不读 L1）；冷索引 882 ms / 读 381 MB；off 的固定成本约 1.1 s（进程启动 + L1 重扫 + 入口发现 + 报告），每任务边际成本约 (1,603−1,103)/16 ≈ 31 ms；`check` 复算 1,162 ms / 读 746 MB（重扫 L1 + 重读证明/源码）。

**结论**：冷→热 wall −18.0%（1,603→1,314 ms）、CPU −34.2%、峰值 RSS −18.8%、写字节 −91.6%；差分主要来自跳过索引重建/写盘。三条 run（canonical 主根 + 冷/热隔离根）语义哈希全部为 `sha256:8593fbb294ca279d92d2b94b2181d82a9a9e25d85c76cb7933e99d471b4dab2c`，裁决与缺口完全一致。热路径仍读 483 MB，因为 `facts.index()` 在每次进程内重新扫描 `l1/calls.jsonl`（254 MB）+ `functions.jsonl`（46 MB）；索引缓存只避免重建/写盘，未避免 L1 重扫。

## E1 第二组件完整纵向路径

### 新增/修改的实现

| 文件 | 变更 | 保持的性质 |
|---|---|---|
| `K/policies/autonomy-os-account-iam-scope.json`（新，sha256 `4bf0c5df…`） | 第二组件 scope：单 root、`entryFilter` 只含 `IAccountIAM` 17 个 IDL 方法、接口级 owner `AccountIAMService`、`operationRecipe`、`staticSuite=true`、`dependencyReadRoots` 登记文档、`limits` 实测容纳 7,014 函数/42,631 calls | pilot scope 文件未改；旧 run 只读 |
| `K/policies/autonomy-os-account-iam-budget.json`（新，`f22cc687…`） | `maxModelRequests=0`（本轮 off-only）、`maxTasks=40`、`maxToolCalls=500` | 不产生未授权 live |
| `K/policies/autonomy-security-anchors-os-account.json`（新，`38e294bc…`） | os_account 三个权限 + accountmgr SA profile（200/process accountmgr），按 sha256 固定 | 与 pilot 锚点文件分离 |
| `lib/autonomy/discovery.js` | 接口级绑定 owner 覆盖；`entryFilter`（接口/入口类型）；`fraction=0` 明确不抽样 | 未配置时 pilot 行为不变 |
| `lib/autonomy/index.js` | registers 关系按接口级 owner 计算 | pilot 索引输出不变 |
| `lib/autonomy/vertical.js` | 操作识别改为 `scope.operationRecipe`（默认仍是 `PolicyInfoManager`/`SandboxManagerService`） | pilot 操作候选不变 |
| `lib/autonomy/gates.js` | 新门禁家族：本地 helper 一跳委托的调用方权限检查（`if (!Helper(CONST))` + helper 体 `VerifyPermission` + `return false`）；拒绝码族扩为 `*_PERMISSION_DENIED`；未解析 helper 登记 `permission-helper-unresolved` / `permission-helper-not-caller-scoped` | pilot 直接门禁与拒绝码输出逐字节不变 |
| `lib/autonomy/permission-argument.js` | 支持 helper 形状与 `const char SYMBOL[]` 常量表；直接形状不新增字段（旧 run 复算不变） | pilot 载荷不变 |
| `lib/autonomy/static-proof.js` | 常量表解析兼容 `const char …[]`；把 helper resolver 传入门禁枚举 | pilot 证明不变 |
| `lib/autonomy/knowledge.js` | 第二组来源描述符（3 个权限）、章节锚点定位、`docSet` 选择、`reviewedMethods` 驱动的 Builder 审核规则；pilot 描述符不变 | 已发布 pilot 知识逐字节复算不变 |
| `bin/autonomy.js` | 静态套件以 `scope.staticSuite===true` 显式 opt-in（不再硬编码 pilot）；`knowledge propose --doc-set=os-account-iam`；run manifest 固定 `scopePolicy{file,sha256}`；`check` 按 manifest 的 scope 复算（旧 run 无该字段时回退 pilot） | pilot 三条 run `check` 不变 |
| `lib/autonomy/store.js` | `OH6_AUTONOMY_ROOT` 隔离实验根（未设置时不变） | 既有索引与 run 未被触碰 |

### 发布的 Builder 来源知识（3 条）

| 权限 | 文档声明（文件:行） | 提案版本 | 发布版本 | 审核文件 |
|---|---|---|---|---|
| `ohos.permission.MANAGE_USER_IDM`（7 方法） | `docs/.../js-apis-osAccount-sys.md:4468` | `sha256:a7fc5a89…` | `K/norms/71191d8b…`（`a995075a…`） | `K/reviews/os-account-manage-idm-builder.json` |
| `ohos.permission.USE_USER_IDM`（仅 `GetEnrolledId`） | 同文件 `:5080` | `sha256:234bbba…` | `K/norms/ffed41e7…`（`09a05156…`） | `K/reviews/os-account-use-idm-builder.json` |
| `ohos.permission.ACCESS_USER_AUTH_INTERNAL`（7 方法） | 同文件 `:2318` | `sha256:49b1a20d…` | `K/norms/2046964c…`（`2a626e9c…`） | `K/reviews/os-account-auth-internal-builder.json` |

文档位于五根事实快照之外，已在 scope 的 `dependencyReadRoots` 登记；提案把整文件 sha256 + 声明行文本/行号固定进 `knowledgeVersion`，发布/复算时重新核对。三个权限均为 `system_basic / system_grant / provisionEnable=true`：ACL 使能，静态快照不能判定 normal 应用是否实际持有。**因此本轮真实锚点下正向安全 finding 的上限是 `candidate`，15 个受调查入口的实际出口全部是 scoped `excluded`（缺权主体被实际门禁拒绝），0 finding / 0 candidate。**

### canonical off run

命令（Windows 原生）：

```powershell
node bin/autonomy.js run --mode=off --scope=K/policies/autonomy-os-account-iam-scope.json `
  --budget=K/policies/autonomy-os-account-iam-budget.json --max-tasks=0 `
  --knowledge=K/norms/71191d8b…/knowledge.json,K/norms/ffed41e7…/knowledge.json,K/norms/2046964c…/knowledge.json `
  --security-anchors=K/policies/autonomy-security-anchors-os-account.json
```

`RUN:b352c4fba543a23c`：17 任务 / 100 问题 / 135 工具调用 / 0 模型请求；语义哈希 `sha256:8593fbb294ca279d92d2b94b2181d82a9a9e25d85c76cb7933e99d471b4dab2c`；报告 0 finding / 0 candidate / 15 excluded / 2 observation；`check` 0 error / 0 warning。冷/热隔离 run `RUN:159206aa1147b53d`、`RUN:8a2ad57cb9364fe7` 与 canonical 语义哈希相同，`check` 同为 0/0。

计数：binding resolved 17/17；操作唯一 15/17（2 个无适用规范入口未进入安全命题）；门禁可判 15/17；缺口分布 `dominance-unproven=17`（该问题恒 insufficient，符合现行模板）、`entry-or-builder-norm-unresolved=2`（`GetCredentialInfo`、`GetAccountState`）。逐入口证据见 `out/autonomy/inventory/e1-entry-evidence.json`（sha256 `23803776…`）：

| 方法 | 契约 | 实际门禁（helper） | 操作（唯一） |
|---|---|---|---|
| 7 × MANAGE_USER_IDM 方法 | compliant | `ohos.permission.MANAGE_USER_IDM`，早退 `ERR_ACCOUNT_COMMON_PERMISSION_DENIED` | `InnerAccountIAMManager::<同名>` |
| `GetEnrolledId` | compliant | `ohos.permission.USE_USER_IDM` | `InnerAccountIAMManager::GetEnrolledId` |
| 7 × ACCESS_USER_AUTH_INTERNAL 方法 | compliant | `ohos.permission.ACCESS_USER_AUTH_INTERNAL` | `InnerAccountIAMManager::<同名>` |
| `GetCredentialInfo` | 具名缺口 | 未评估（无适用规范；未把 `getAuthInfo` 文档映射强加给该 IDL 方法） | 未评估 |
| `GetAccountState` | 具名缺口 | 未评估（内部入口，公开文档无权限声明） | 未评估 |

### 复算非空转验证

把 canonical run 复制到 `out/autonomy/inventory/tamper-b352`，只篡改 `static-proofs.json` 一个条目状态后执行 `check`，实际得到 `static-proof-drift` + `report-model-drift` + `checksum-mismatch` 并退出 1；证明新 scope 的 `check` 不是因 scope 不匹配而跳过全部任务（此前 `check` 硬编码 pilot scope 会跳过第二组件入口）。副本已按绝对路径核验后删除。修复后 `check` 按 run manifest 的 `scopePolicy{file,sha256}` 复算；旧 run 无此字段时回退 pilot 默认，三条旧 run 仍 0/0。

### pilot 回归

- 三条 canonical run `check` 全部恢复 `ok:true`、0 error / 0 warning（曾在修改 `permission-argument` 后出现 12 个 `static-permission-drift`，原因是为直接形状新增了 `checkShape` 字段改变旧载荷；已改为仅 helper 形状携带该字段）。
- `node --test --test-concurrency=1`：**247/247**（指南 §24.28 登记的 232/232 是本会话开始前的参考值，未在改动前重跑；新增 os_account 11 + 受控变异体 2 + bench 1 + 锁语义 1 = 15，232+15=247 与实测一致）。加入第三组件 3 项与跨组件盲测 3 项回归后，默认并发全量 **253/253**、串行 **253/253** 均通过。
- 默认并发 `node --test`：修复后连续 **3/3 次 247/247** 通过（CES 测试加入前）。加入 CES 3 项与盲测 3 项后默认并发、串行均 **253/253** 通过。先前 4 次全量中 2 次 `autonomy-resume` 瞬时失败的根因已定位并修复：崩跑 fixture 保留真实 pid，Windows 会把该 pid 复用给无关进程，`afterCrash` 的 `process.kill(pid,0)` 因此把复用者当成原 writer 而保守拒绝。两个崩溃 fixture 现在在退出前把 `run.lock.pid` 写成 **-1**（确定性“已死 owner”哨兵）；`store.acquireLock({afterCrash})` 对非正 pid 跳过存活检查，对真实 pid 仍拒绝（新增单测：pid=-1 可恢复、pid=当前进程必须拒绝）。没有移除真实运行所需的锁保护。

## E2 剖面与优化决策

| 观察 | 实测 | 判定 |
|---|---|---|
| 快照/元数据解析 | doctor 32 ms / 读 0.47 MB（不读 L1） | 可忽略 |
| 索引成本 | 冷索引 882 ms / 读 381 MB / 写 28.8 MB / 峰值 357 MB | 未达资源门槛（<5 s、<1 GB 读、<1 GB RSS） |
| 每次 off 的固定成本 | 1 任务冷 off 1,103 ms；17 任务冷 off 1,603 ms；边际约 31 ms/任务 | 固定成本约 1.1 s，任务成本线性且很小 |
| 每次 off 的 L1 重扫 | 热 off 仍读 483 MB，其中约 455 MB 来自 `l1/calls.jsonl`+`l1/functions.jsonl` 等表的按 repo 预过滤扫描 | 读放大成立，但绝对成本 1.3 s；当前 17 任务规模未构成瓶颈 |
| 索引缓存净收益 | 冷→热：wall −18%、CPU −34%、写 −92%、峰值 RSS −19%，语义哈希与缺口完全一致 | 净收益成立，保留现有索引复用；未新增优化 |
| `check` 复算成本 | 1,162 ms / 读 746 MB / 峰值 282 MB（IAM）；1,003 ms / 读 735 MB / 峰值 252 MB（IAccount） | 与一次 off 同量级，未达瓶颈 |
| 规模增长（16 任务 IAccount） | 冷 off 1,395 ms / 读 503 MB / 写 30.6 MB / 峰值 352 MB；热 off 1,403 ms / 读 474 MB / 写 1.8 MB / 峰值 303 MB；两者语义哈希同为 `43c107cd…` | 热路径写字节 −94%、峰值 RSS −14%，wall 在噪声内；固定 L1 重扫仍主导，未达瓶颈 |
| 第三组件（CES，18 任务） | 冷 off 703 ms / 读 98 MB / 写 15.3 MB / 峰值 217 MB；热 off 557 ms / 读 85 MB / 写 2.2 MB / 峰值 189 MB；`check` 339 ms / 读 67 MB / 峰值 164 MB | 热路径 wall −21%、写 −86%、峰值 RSS −13%，语义哈希一致（`1de58217…` 级别的 report 计数不变）；快照小，未达瓶颈 |
| 同一调用点重复证明 | `summary-reused=0`（17 个入口各有独立调用点）；无重复证明可缓存 | 无需缓存优化 |
| 调度/模型成本 | 17 任务 135 工具调用、0 模型请求、无预算停止；每任务约 8 次工具调用 | 预算充足；未触发入口数导致的模型膨胀 |
| `indexTruncated` | functions/calls 均 false；对账 7,014/1,025/42,631/203/1/3 全等 | 未截断，索引可用于本轮完整性结论 |

**决策：不实施 E2 索引/缓存重构。** 依据是实测未达自定瓶颈门槛（wall >5 s、读 >1 GB 或 RSS >1 GB），且现有索引复用已证明有净收益、无结论漂移。若下一步扩到 `os_account` 全部 203 个 IDL 或五根范围，优先项是让发现/绑定消费已建索引而不是每次 `facts.index()` 重扫 L1；该方向已登记，但不在本轮无收益证据下实施。未删除任何既有索引或 run；冷路径在 `OH6_AUTONOMY_ROOT` 隔离根生成。

## E3 效果评测（部分完成：有来源、分母、未覆盖量）

### 受控变异体（Builder-LLM 来源，非独立真值）

新增 8 个隔离家族（`test/fixtures/autonomy/os-account-mutants/`，标签 `eval/autonomy/os-account-mutants.json` sha256 `7548cf34…`，评测记录 `out/autonomy/eval/os-account-mutants.json` sha256 `b303ddd4…`）：

| 家族 | 期望出口 | 期望安全家族 | 实测 |
|---|---|---|---|
| compliant-manage-idm | excluded | scoped-gate-rejection | 一致 |
| weakened-use-idm | excluded | scoped-gate-rejection（契约差异 permission-mismatch） | 一致 |
| different-stronger | excluded | scoped-gate-rejection（permission-mismatch） | 一致 |
| no-gate | candidate | no-analyzable-gate | 一致 |
| non-early-return | candidate | gate-non-blocking | 一致 |
| subject-mismatch | candidate | gate-subject-mismatch | 一致 |
| unrecognized-guard | insufficient | unrecognized-caller-guard | 一致 |
| combined-gate | insufficient | combined-gate-unsupported | 一致 |

指标：8 样本 / 8 家族 / 8 判定一致 / 8 安全家族一致 / 6 个可比较契约家族 6 一致；`falseCertaintyRate=0/2`；正向 finding 分母 0，故 `findingPrecision=null`、`givenMutantFindingRecall=null`；`discoveryRecall=null`、`independentAccuracy=null`；A/B/C/D 模型对照 `not-run`。未覆盖：17 个 IAM 入口中仅 `OpenSession` 进入受控样本；`GetCredentialInfo` 与 `GetAccountState` 无已发布规范，保持具名缺口。

### 无种子真实入口运行

`RUN:b352c4fba543a23c` 只给 scope/知识/预算，不给目标方法或标签：17 个入口全部被自主枚举与绑定；提名 0 candidate / 0 finding；15 个 scoped excluded，2 个规范缺口。对 15 个 excluded 逐条核对（`e1-entry-evidence.json`）：文档声明权限 = 实际门禁权限、操作唯一解析到 `InnerAccountIAMManager`、拒绝分支早退且常量来自真实 `account_iam_service.cpp`。真实正向策略锚点（证明“此入口此对象本应要求该权限”的独立材料）仍不存在；ACL 使能也使 `MANAGE/USE/ACCESS_USER_AUTH_INTERNAL` 不能单独支撑 finding。因此本轮真实安全发现召回为 `null`，0 finding 不代表“无问题”，只代表没有取得满足 §15.4 的证据链。

### 与 pilot 的对照口径

- pilot：25 任务 / 0 finding / 14 excluded / 11 observation（旧 run，只读）。
- 第二组件：17 任务 / 0 finding / 15 excluded / 2 observation。
- 两者都是“负例纠偏与候选/排除机制闭环”证据；不是真实漏洞发现能力证据，不能相加成跨组件召回。

### E3 完成后的限制（不是未完成项）

1. **第二接口**：`IAccount` 已走 off→report→check（`RUN:aa04ab7d6d479d97`，16 入口，14 绑定 resolved / 2 overload suspect，0 操作唯一，0 门禁可判，0 excluded / 16 observation），但只有分母与具名不足，没有完整 excluded/candidate 路径；E3 的“两个组件完整路径”由 pilot 与 IAM 满足，IAccount 是第二接口的缺口账本，不是完成前提。
2. **第三组件**：CES `ICommonEvent` 已走 off→report→check（`RUN:d0f9c45816f0add5`，17 入口 / 4 重载 suspect / 操作唯一 1/17 / 门禁 0/17 / 0 excluded / 18 observation），但只有分母与具名不足，没有完整 excluded/candidate 路径；需要 `VerifyNativeToken`/`IsSystemApp`/内联 `VerifyAccessToken` 门禁族或改用门禁形状更简单的 CES 入口。快照仍有 12 个生成头不可见、dirty 44 entries 的限制。
3. **冻结跨组件无种子实验已完成**（`RUN:cf05827a914570e3`，18 案例 / 2 组件，`out/autonomy/eval/blind-cross-component.json`）；但语料是受控变异体 + Builder-LLM 标签，不是真实漏洞真值；真实 finding 0、真实召回与独立准确率为 `null`，不得把 8/8 当成真实发现能力。

## 2026-10-25 第二轮：状态校正、锁回归修复、第二接口与第三组件研究

### 1. 阶段状态校正

按 EXPANSION-PLAN 的 E3/完成判据复核后，本文件顶部的状态表改为：E0、E1 **已验证**；E2 **已测量、未触发新增优化**；E3 **部分完成**（缺第二接口、第三组件、冻结跨组件无种子盲测）。此前把 E3 写成完成是不准确的，已改正。**OnRemoteRequest 口径**也已统一：`base/account/os_account` 共 12 个名字含 `OnRemoteRequest` 的函数，其中 **1 个生产入口**（`OsAccountUserCallback::OnRemoteRequest`）和 **11 个 HWTEST 测试函数**；早先账本的“6/12”分别来自错误的接口过滤与未过滤 `role` 的名字匹配，现已改为“生产入口 1、测试名匹配 11 单列”，`lib/autonomy/index.js` 与 `tools/autonomy-entry-inventory.js` 同步修正。pilot 根没有 OnRemoteRequest，19 入口不受影响。

### 2. 默认并发回归：已复现、已修复、已重复验证

- **复现与根因**：默认并发 `node --test` 的 4 次全量中 2 次 `autonomy-resume` 退出 3。崩溃 fixture 把真实 `pid` 留在 `run.lock`；Windows 会把该 pid 复用给同时段密集生成的其它 Node 进程，`resume --afterCrash` 的 `process.kill(pid, 0)` 于是把复用者误判为原 writer 并保守拒绝（错误信息 `original writer may still be running`）。
- **修复（未移除锁保护）**：两个崩溃 fixture（`tools/fixtures/crash-after-vertical-task.js`、`crash-tool-intent.js`）在退出前把 `run.lock.pid` 写为 **-1** 的确定性“已死 owner”哨兵；`lib/autonomy/store.js` 的 `acquireLock({afterCrash})` 只对 `pid > 0` 做存活检查，非正 pid 直接视为 stale。真实 writer 永远写正整数 pid，所以真实并发写保护不变；新增单测同时验证“哨兵可恢复”和“真实存活 pid 必须拒绝”。
- **验证**：默认并发 `node --test` 连续 **3/3 次 247/247**（CES 测试加入前）；加入 CES 3 项与盲测 3 项后默认并发与串行均 **253/253** 通过。旧三条 run、IAM run、IAccount run、CES run、盲测 run `check` 均 0/0。已知生产边界保留：真实崩溃后若原 pid 恰好被无关进程复用，`resume` 仍会保守拒绝直到该进程退出（安全优先）。

### 3. 第二接口：`IAccount`（16 入口，含 2 个重载）

新增 scope `K/policies/autonomy-os-account-account-scope.json`（sha256 `4e1a10f0…`）、budget `db573023…`、Builder 规范 `NORM:0a81a774a980cf15`（`MANAGE_DISTRIBUTED_ACCOUNTS`，来源 `docs/.../js-apis-distributed-account-sys.md:126-136`，发布版本 `sha256:efc1de30…`，审核文件 `K/reviews/os-account-distributed-manage-builder.json`）。运行：

`RUN:aa04ab7d6d479d97`：16 任务 / 81 问题 / 109 工具 / 0 模型；报告 **0 finding / 0 candidate / 0 excluded / 16 observation**；`check` 0 error / 0 warning；语义哈希 `sha256:43c107cd8350a3e20faf553c3b71f80a8341dfe90b4e023a849f281115748ad4`。

| 量 | 实测 | 说明 |
|---|---|---|
| 入口分母 | 16 | `IAccount` 全部 IDL 方法；不含 SA/NAPI/OnRemoteRequest 与文件抽样 |
| 绑定 resolved | 14/16 | `QueryDistributedVirtualDeviceId` 两个 IDL 方法各匹配到 2 个同名实现 → **suspect**（`binding-ambiguous=2`） |
| 操作唯一 | 0/16 | IAM 的 `OhosAccountManager::GetInstance().X` recipe 只对 `SetOsAccountDistributedInfo` 生效，但 `OhosAccountStateChange` 有两个 argc=3 重载 → `call-chain-or-operation-ambiguous=1`；其余方法使用 `innerManager_.X`/`InnerQueryOsAccountDistributedInfo`/`GetOsAccountDistributedInfoInner` 等成员调用或多操作路径，不套用 IAM recipe |
| 门禁可判 | 0/16 | 主要形状是 `HasAccountRequestPermission(PERM)`（helper 内含 `#ifndef IS_RELEASE_VERSION` 的 root 旁路 + `VerifyAccessToken == PERMISSION_GRANTED`）、`PermissionCheck(PERM, CONSTRAINT)` 与 `CheckSystemApp()` 前置；本轮词表不能安全判定，保持缺口 |
| 缺口分布 | `entry-or-builder-norm-unresolved=15`、`call-chain-or-operation-ambiguous=1`、`binding-ambiguous=2`、`dominance-unproven=16` | 15 个方法没有已发布规范（其中 2 个重载同时 binding ambiguous）；1 个有规范但操作歧义 |

**结论**：`IAccount` 能给出真实入口分母与具名不足，但**没有**形成第二条完整 excluded/candidate 路径；原因是操作形态（成员调用/重载）与门禁 helper 形状都超出当前能力。没有为了凑数把 IAM recipe 套到 `IAccount` 上。下一步要形成完整路径，需要新增“成员调用/重载消歧”操作 recipe 与 `HasAccountRequestPermission`/`PermissionCheck`/`CheckSystemApp` 门禁族（或改用有更简单门禁形状的接口）。

### 4. 第三组件选择研究（结论：当前快照内不可选）

对现有五根快照的其他根做了只读清点（`tools/autonomy-entry-inventory.js`）：

| root | IDL 文件 | 生产入口 | 入口形态 | 现有策略/文档材料 | 可否进入双命题路径 |
|---|---:|---|---|---|---|
| `foundation/communication/dsoftbus` | 0 | 1 SA + 2 NAPI + 4 生产 OnRemoteRequest | SA/NAPI 元数据无方法体；`SoftBusServerStub` 为 `memberPermissionMap_`/`memberFuncMap_` 表驱动，`BusCenterExObjStub`/`TransSpecObjectStub` 经 `dlsym` 函数指针间接派发 | IDL 无；dsoftbus 权限为代码常量与系统权限文档，未登记到本 Agent 的规范 | **否**：元数据入口 unbound；OnRemoteRequest 是表/间接派发，操作目标与对象语义不可唯一绑定 |
| `foundation/communication/ipc` | 0 | 13 生产 OnRemoteRequest | `IPCObjectStub`/RPC skeleton/NAPI 回调等框架内部 | 无服务授权策略材料 | **否**：不是带权限门禁的业务入口 |
| `base/notification/eventhandler` | 0 | 1 NAPI | NAPI 模块元数据无方法体 | 无 | **否**：unbound |

结构性原因：`bin/autonomy.js` 只为 `anchor.kind === 'idl'` 生成 `contract-deviation`/`security-decision` 问题，SA/NAPI/OnRemoteRequest 入口不会进入双命题裁决。因此“在现有五根快照的其他根中选第三组件”在**不新增能力**的前提下不可行；这不是暂时没找到，而是快照内容（其他根 0 IDL）+ 入口模型（非 IDL 不生成双命题）共同决定的。

**可行但未实施的使能项**（需另行决定/授权，不在本轮伪造）：
1. 为 `SoftBusServerStub` 增加“per-code 表派发入口”模型：解析 `memberPermissionMap_`/`memberFuncMap_`，把一个 code 作为锚点，绑定权限常量与 handler，再分析 handler 内操作；需要独立策略材料，否则上限 candidate。
2. 在五根之外选一个 IDL 组件并重建**补充事实快照**（如 `base/notification/common_event_service` 3 个 IDL、`base/security/access_token` 6 个 IDL）；现有 `compdb-win.jsonl` 对 common_event_service/useriam 无覆盖、access_token 仅 3 条，需先补 compdb 才能满足事实与构建变体要求。
3. 先做全范围清点（FULL-SCOPE-ROADMAP），从有 IDL + 文档 + compdb 的组件中选第三组件，再建快照；这是下一步全范围基线的自然产物。

因此 E3 仍为**部分完成**：第三组件与冻结跨组件无种子实验尚无产物。

### 5. 本轮性能观察

`IAccount` 16 任务 off：canonical `wallMs=366`（索引已热）、109 工具调用、0 模型；隔离根冷 off 1,395 ms / 读 503 MB / 写 30.6 MB / 峰值 352 MB，热 off 1,403 ms / 读 474 MB / 写 1.8 MB / 峰值 303 MB，语义哈希均为 `sha256:43c107cd…`；`check` 1,003 ms / 读 735 MB / 峰值 252 MB。CES 18 任务 off：冷 703 ms / 读 98 MB / 写 15.3 MB / 峰值 217 MB，热 557 ms / 读 85 MB / 写 2.2 MB / 峰值 189 MB，`check` 339 ms / 读 67 MB / 峰值 164 MB。规模从 17→33（IAM+IAccount）与 18（CES）任务后，固定 L1 重扫仍占主导；CES 快照较小，热路径 wall −21%、写 −86%、峰值 RSS −13%，语义与缺口不漂移（canonical/隔离 run `check` 均 0/0）。未达 §E2 自定瓶颈门槛（wall >5 s、读 >1 GB 或 RSS >1 GB），不触发重构。待第三组件/更多接口扩大后再复测。

### 6. 第三组件底座：common_event_service 补充事实快照（用户选定方案 A）

按用户 2026-10-25 决定，为第三组件 `base/notification/common_event_service` 建立**独立于五根 d4-r1** 的补充事实快照；旧五根快照与旧 run 不改写、不重算。事实范围策略：`K/policies/scope-ces-r1.json`（sha256 `ec56fab1…`），compdb 使用 `OpenHarmony/out/rk3568/compdb_parts/notification`。

| 项 | 实测 |
|---|---|
| snapshotId | `sha256:9bbb04f8f62e125dd747e2dc410b46a0634d50515bebac6248166b3483a5f29f` |
| inputManifestId | `AM-090f640f8ea0c40c` |
| root / head | `base/notification/common_event_service` / `ba2ad592b863de66291719fa385a405769c2d88e`；工作树 dirty（44 entries）—快照按文件 sha256 固定，dirty 状态必须记录 |
| 源文件 | 288（生产 142） |
| compdb | notification part 1,801 entries；root 内 176 文件有编译命令；生成头可见性 25 referenced / 12 missing → **构建变体信息不完整** |
| 元数据 | IDL 3 文件 / 19 方法（`ICommonEvent` 17、`IEventReceive` 1、`IStaticSubscriber` 1）；SA 1；NAPI 2；permission 表 726 行（外部权限定义） |
| L1 | 3,232 functions / 19,200 calls / 2,966 guards / 486 sinks / 288 files；`AutonomyFacts` 打开无缺表，functions/calls 未截断 |
| 生成命令 | `fact-snapshot --scope=ces-r1` → `fact-metadata --scope=ces-r1` → `fact-build --scope=ces-r1 --jobs=4`（解析 2.5 s） |

配套修正：
- `bin/fact-snapshot.js` 的 `payload.scope`/`snapshot.scope` 改为 `policy.snapshotScope || 'd4-r1'`，因此 d4-r1 快照 ID 不变，ces-r1 记录自己的 scope。
- `AutonomyFacts` 的 `latest` 解析改为**按 scope roots 选择覆盖该 scope 的最新快照**；否则新补充快照会成为 `latest`，把五根 scope 的 `--snapshot=latest` 误指向 CES。`test/fact-scope.test.js` 固定检查 d4-r1 产物，不依赖“最新 = d4”。
- 该快照只是第三组件**底座**：尚未建 CES 静态套件 scope、未发布 CES 规范、未跑 off/check。构建变体缺失（12 个生成头不可见）必须作为后续结论的具名限制。

### 7. 第三组件 `ICommonEvent` 首条 off→report→check（仍为缺口路径）

在 CES 补充快照上新增静态套件 scope `K/policies/autonomy-ces-icommonevent-scope.json`（sha256 `96696790…`）、budget `3eb4d3de…`、CES 策略锚点 `f83e4d49…`、Builder 规范 `NORM:e4c0b23915ea5157`（`COMMONEVENT_STICKY`，发布版本 `sha256:d820f377…`，审核 `K/reviews/ces-remove-sticky-builder.json`）。为 CES 增加了**组件局部词表**：`gateVocabulary.checkCallees/gateTokens/identityTokens` 与 `conditionLinesOnly`，默认不配置时 pilot 复算逐字节不变；`operationRecipe.kind=member-call` 支持 `innerCommonEventManager_->X` 形态。

| 项 | 实测 |
|---|---|
| 入口分母 | 17 个 `ICommonEvent` IDL 方法（另有 1 SA + 2 NAPI 未纳入；27 个名字含 OnRemoteRequest 的测试函数不计入口） |
| 绑定 | 13 resolved / **4 suspect**（4 个 `PublishCommonEvent` 重载同名） |
| 操作唯一 | 1/17：`RemoveStickyCommonEvent` 唯一解析到 `InnerCommonEventManager::RemoveStickyCommonEvent`（argc=2）；其余方法为异步队列/lambda、`PublishCommonEventDetailed` 或多操作路径，不冒充唯一 |
| 门禁可判 | 0/17：`RemoveStickyCommonEvent` 的实际门禁是 `VerifyNativeToken`/`IsSystemApp` 组合 + `VerifyAccessToken` 内联字面量，登记 `combined-gate-unsupported` + `unrecognized-caller-guard`；其余方法无已发布规范 |
| run | `RUN:d0f9c45816f0add5`：18 任务（17 入口 + 1 `operation-target` 子视图）/ 87 问题 / 108 工具 / 0 模型；**0 finding / 0 candidate / 0 excluded / 18 observation**；`check` **0 error / 0 warning**；语义哈希 `sha256:1de582174ed8c40a2fd32b5a93bafbc87040b66d33d8211b599fb8f57ca31bc7` |
| 缺口分布 | `binding-ambiguous=4`、`entry-or-builder-norm-unresolved=16`、`combined-gate-unsupported=1`、`permission-check-ambiguous=1`、`permission-argument-unresolved=1`、`operation-semantics-unproven=1`、`dominance-unproven=17` |

这是第三组件的**真实入口分母 + 具名不足**产物，不是完整 excluded/candidate 路径。`RUN:d097d3ccf8db5e45`（加词表前）已被本次修复取代，只作背景，不作为当前复算基线。CES 快照的 12 个生成头不可见与 dirty 44 entries 仍是限制。

### 8. 冻结跨组件无种子盲测（E3 关键产物）

**语料与冻结顺序**：先按 `eval/autonomy/blind-corpus-spec.json`（sha256 `44a2b860…`）构建受控快照 `sha256:13f40945a59d89f3635c164ffe472367d36ab248d5e068245641a2c90e0e052e`（`AM-0994164b71720125`；18 入口 / 2 组件 / 24 函数 / 33 calls）；再冻结标签 `eval/autonomy/blind-cross-component.json`（sha256 `16bcd1f0…`，18 案例 = 8 正例 / 7 合规排除 / 3 歧义；`labelSource=builder-llm-oracle`）。运行阶段只读取 scope/知识/预算，**不读取标签**；评分阶段才由 `tools/autonomy-blind-eval.js` 读取冻结标签。

**运行**：`RUN:cf05827a914570e3`（off）：18 入口 + 1 个 operation-target 子视图 = 19 任务 / 109 问题 / 163 工具 / 0 模型；报告 **8 candidate / 7 excluded / 4 observation / 0 finding**；`check` 0 error / 0 warning；语义哈希 `sha256:113b76029364d6c9827b8da1c8969f133772e35b70f756a1e593298ba3886914`。工具 `tools/autonomy-blind-corpus-build.js`（sha256 `e4dd35c3…`）与 `tools/autonomy-blind-eval.js`（`39b19e24…`）；盲测 scope/预算/锚点/3 条 `sourceSalt` 知识见 `K/policies/autonomy-blind-cross-component-scope.json`（`ef31560d…`）、`autonomy-blind-cross-component-budget.json`（`b0575b92…`）、`autonomy-security-anchors-blind.json`（`a6087c09…`）、`K/norms/6f3b2f2e…`、`8aa1f147…`、`395d9b17…`。

**评分**（`out/autonomy/eval/blind-cross-component.json` sha256 `bf2dbe7c…`）：

| 指标 | 值 | 分母/说明 |
|---|---|---|
| statusAccuracy | **1.0** | 18/18（候选↔candidate、排除↔excluded、歧义↔observation） |
| securityFamilyAccuracy | **1.0** | 18/18（insufficient 案例按 `missing` 中的具名 reasonCode 比较） |
| 无种子提名 | **8** | 8/8 正例被提名；sandbox 5、os_account 3 |
| nominationPrecision（对冻结标签） | **1.0** | 8/8 提名均为期望正例；wrongNominations 0 |
| positiveRecall（对冻结 Builder 标签） | **1.0** | 8/8；不是独立真值召回 |
| excludedRecall（合规排除） | **1.0** | 7/7 |
| ambiguityHoldRate | **1.0** | 3/3 歧义例保持 observation |
| falseCertaintyRate | **0** | 0/3 歧义例被误判 excluded/finding |
| missedNominations / wrongExclusions / wrongNominations | **0 / 0 / 0** | 逐条见评测 JSON |
| realFinding | **0** | 受控语料没有真实入口；真实 finding 召回 `null` |
| discoveryRecall / independentAccuracy | **null** | 无独立真值；8/8 只称“与冻结 Builder 标签一致” |

**盲测专用绑定/调用隔离**：受控语料把同一入口的多个变体放在不同文件，`scope.binding.preferSameFile` 在同一 owner 的同名候选中优先选与 IDL 元数据同文件的实现；`scope.binding.callerKey=fact` 用 factId 隔离同名变体的调用事实。两者默认关闭，pilot/IAM/IAccount/CES 旧 run 复算不变；`sourceSalt` 只用于盲测知识版本，避免同一文档在不同快照下撞提案。没有把 `OpenSession` 8/8 或任何给定变异体结果并入本表；给定变异体判定仍由独立评测器统计。

**表述边界（必须随数字一起引用）**：上表 18/18、8/8、7/7、3/3 只表示**在冻结 Builder-LLM 标签的受控变异体语料内的一致性**，不是真实漏洞召回，也不是独立人工准确率；`realFinding` 为 0，真实 finding 召回与 `independentAccuracy` 仍为 `null`，直到有真实入口、独立标签和相应分母。

**限制**：这是受控变异体 + Builder-LLM 标签的盲测，不是真实组件漏洞召回，也不是独立人工准确率；受控语料的“入口”由变异体文件构造，不能冒充真实入口发现。E3 因此只能称“受限口径下的流程与负例纠偏验证完成”，真实安全效果指标仍为 `null`。

### 9. 全范围基线（FULL-SCOPE-ROADMAP 范围清点第一层）

只读清点工具 `tools/oh6-full-scope-inventory.js`（sha256 `2624d5b5…`），扫描 `OpenHarmony/base`、`OpenHarmony/foundation`，按最近 `bundle.json` 归属组件，区分生产/测试/生成/构建/文档/配置，不解析 AST、不建事实、不做裁决。输出：

- `out/autonomy/inventory/full-scope-baseline.json`（sha256 `56484e86…`）
- `out/autonomy/inventory/full-scope-baseline.md`（sha256 `a3fd6678…`）
- 命令：`node tools/oh6-full-scope-inventory.js`；扫描 9.7 s。

| 量 | 实测 | 口径 |
|---|---:|---|
| 组件（bundle.json） | 190 | 最近祖先 bundle.json 归属 |
| 生产代码文件 / 字节 | 60,268 / 577,776,263 | 排除测试/生成路径；含非 C/C++ |
| C / C++ / 头文件 | 2,166 / 23,530 / 31,554 | 当前事实层可解析的语言 |
| 其他语言生产文件 | 3,018（arkts 577、javascript 272、rust 370、python 124、shell 34、typescript 1620、java 21） | **unsupported-language**，不能声称已抽取 |
| 测试代码文件 / 字节 | 39,874 / 593,882,786 | 不计生产分母 |
| 生成代码文件 | 1,538 | 计入生成列，不重复生产分母 |
| IDL 文件 / 接口 / 方法 | 245 / 220 / 3,234 | 生产路径内的 .idl |
| SA profile / systemability | 155 / 154 | sa_profile JSON |
| 构建文件 | 12,284 | BUILD.gn / .gni |
| bundle 声明 features | 812 | 构建开关清单，不是实际变体组合 |
| 有 compdb part 的组件 | 189 / 190 | 按 subsystem 名匹配；未扫 GB 级 compdb |
| 声明外部依赖（去重/引用） | 291 / 4,079 | 只解析 `bundle.json` 的 `deps.components` |
| 无 bundle.json 归属文件 | 201（其中生产代码 134：cpp 37、header 57、js 1、ts 17、arkts 22） | 单列 not-analyzed，不静默丢弃 |

**明确未做（不得称 base/foundation 已审计）**：函数/操作分母未提取；入口绑定未运行；实际构建变体组合与宏未解析；外部依赖只清点声明、未审计；include/链接级依赖未清点；201 个无 bundle 文件未归属分析；E3 的受控盲测不等于真实组件召回。下一层应按组件/子系统抽样提取事实并测量清点与提取成本，再决定分片与增量。

### 10. 第三轮：授权 IAM live、两个组件静态补路径、分层测量（2026-10-25）

**授权与配置。** 用户授权仅在已有 IAM/IAccount/ICommonEvent 研究 scope 内发真实模型请求，每 run `maxModelRequests ≤ 30`，不扩展到 `base/`、`foundation/` 其他源码。`tools/autonomy-model.ps1 show` 显示 provider=commandcode、model=`xiaomi/mimo-v2.6-pro`、`keyFilePresent=true`；`probe` 返回 `status=ok`、finishReason=stop、17/24 tokens（profile sha256 `d6463b21…`）。密钥正文未读取输出；live 子进程临时从既有 key 文件注入 `OH6_LLM_API_KEY`，结束后清除。

**IAM live→replay→check。** 独立 scope `K/policies/autonomy-os-account-iam-live-scope.json`（5 入口：OpenSession/GetEnrolledId/SetProperty 三个已有 scoped excluded + GetCredentialInfo/GetAccountState 两个具名缺口）；预算 `autonomy-os-account-iam-live-budget.json`：全局 6、每任务 2，低于授权 30。

| 项 | 结果 |
|---|---|
| live run | `RUN:282b88d0b994ec32`，5 任务 / 28 问题 / 39 工具 / **5 模型请求** / 0 模型失败；41.5 s |
| 语义 | 3 excluded / 2 observation / 0 candidate / 0 finding；语义哈希 `sha256:f24ac46c…`；`check` 0/0 |
| token/耗时 | 5,769 input + 1,563 output；模型调用墙钟合计 41,258 ms |
| 模型意见 | supported 3（OpenSession/GetEnrolledId/SetProperty，均为门禁阻断）；insufficient 2（GetCredentialInfo/GetAccountState，保持缺口）；**gate accepted=0**（证据门只接受 refuted/conflict；没有模型意见改变裁决） |
| 与 off 差异 | 5 个入口的 reportability、securityFamily、decision 与 IAM off run **逐条一致**；无 finding 升级 |
| replay | `RUN:92670c6fce4dcdc7`：5 个归档调用、**0 远端请求**、239 ms、语义哈希相同、`check` 0/0 |

**IAccount 单入口静态路径。** 选择 `SetOsAccountDistributedInfo`（不是 16/16 全接口）：新增有界 `argument-type` 重载消歧（入口签名实参类型 vs 目标签名，无法唯一即不出候选），新增 `CheckSystemApp` 的 system-app 门禁（赋值变量 + `if (var != ERR_OK) return var;`），扩展 `HasAccountRequestPermission` helper（`VerifyAccessToken(..., param)` + `PERMISSION_GRANTED` + root 旁路）。`RUN:45f304aa5fea2fbf`：1 入口，**excluded**，contract compliant（`MANAGE_DISTRIBUTED_ACCOUNTS`），门禁 `system-app-check:208` + `permission-check:212`，`check` 0/0；原有 16 入口 `RUN:aa04ab7d6d479d97` 保持 0/16 不变。

**ICommonEvent 单入口静态路径。** 选择 `RemoveStickyCommonEvent`：新增 `system-app-or-native`（`VerifyNativeToken` + `IsSystemApp` 组合）、native 旁路权限门禁、`funcResult = ...; return ERR_OK;` 拒绝分支、函数内 `const std::string` 权限字面量契约。`RUN:5961cae1af3c49fb`：1 入口，**excluded**，contract compliant（`COMMONEVENT_STICKY`），门禁 `system-app-or-native:589` + `permission-check:597`，`check` 0/0；原 17 入口 `RUN:d0f9c45816f0add5` 保持 0 excluded / 18 observation。报告 schema 增加这两个 gate kind；新形状只在显式 `gateVocabulary.systemAppShape` / `systemAppOrNativeShape` 的 scope 启用，pilot/IAM/IAccount/CES 旧 run 复算不变。

**新增形状的最小测试**（`test/autonomy-gate-shapes.test.js`，4 项）：system-app 门禁成立（普通应用拒绝/系统应用通过）、不成立（无 return 不阻断）、无法判定（常量未解析）；system-app-or-native + native 旁路三态；inline literal 契约 supported；argument-type 消歧唯一/不唯一。全量 **257/257** 通过。

**分层扩面与性能测量。** 从全范围清点选择 3 个形态不同的组件，各自建独立补充快照（不改变 d4）：

| 组件 | 生产文件/C-C++ | 快照/元数据/build | 函数 / calls | 默认 20k 截断 | 入口（IDL/SA）绑定 | 声明依赖闭包 |
|---|---|---:|---|---|---|---|
| `@ohos/access_token` | 446 / 435 | 1,794 / 558 / 4,958 ms（热 4,742） | 4,861 / 33,119 | **是**（33,119>20k） | 85（81/4）：resolved 2 / suspect 79 / unbound 4 | 145 组件，深度 5，132 外部 |
| `@ohos/init` | 325 / 315 | 949 / 542 / 2,732 ms | 3,623 / 20,743 | **是**（20,743>20k） | 9（8/1）：1 / 7 / 1 | 145，深度 5，132 外部 |
| `@ohos/ipc` | 247 / 229 | 1,096 / 451 / 4,805 ms | 5,851 / 32,201 | **是**（32,201>20k） | 0（0/0；OnRemoteRequest/表派发未建入口） | 145，深度 6，132 外部 |

- 快照 `--check` 重复扫描：access_token 1,476 ms、init 665 ms、ipc 1,087 ms；`fact-build` 重复运行与冷跑接近（4.7 s vs 5.0 s），**没有跨 run 缓存收益**。
- 把 scope `maxIndexCalls` 提到 50,000 后三个样本均不截断；默认 20,000 会静默截断 calls，不能在这种情况下声称入口/调用分母完整。
- 绑定成本主要来自逐接口 owner 映射：access_token 无映射时 79/85 suspect；这不是覆盖率。ipc 的 0 入口是“入口形态未建模”，不是已审计。
- 依赖闭包按 `bundle.json deps.components` 去重 BFS：三个组件都可达 145 个组件、深度 5–6、132 个外部依赖；依赖审计仍未做，不能把闭包当已分析范围。
- 非 C/C++ 3,018、无 bundle 201（生产 134）、未知变体 1/190 继续单列；首层清点/本轮抽样都不是已审计覆盖率。
- 决策：按组件/子系统分片事实快照并给每个 shard 独立 calls 上限；增量索引尚未实现（重复 build 近似冷跑），需按文件哈希/mtime 只重建受影响 shard；不做未测出的通用缓存重构。产物 `out/autonomy/inventory/layered-sample-bench.json`（sha256 `4a411bbe…`）；三个 scope 描述符 `scope-access-token-r1.json`（`d1110646…`）、`scope-init-r1.json`（`a3d22afe…`）、`scope-ipc-r1.json`（`8982fac3…`），均显式设 `maxIndexFunctions=9000` / `maxIndexCalls=50000`，避免默认 20k 截断。

**范围与未解决缺口。** IAccount 只证明 `SetOsAccountDistributedInfo` 一个受控入口，其余 15 入口仍 0 操作/0 门禁；CES 只证明 `RemoveStickyCommonEvent`，其余 16 入口仍 0 excluded；IAM live 只覆盖 5/17，剩余 12 未 live；依赖闭包/未知变体/非 C/C++/无 bundle 仍未审计；无真实入口正向 finding，真实召回与独立准确率为 `null`。

### 11. 第四轮：全入口接线、绑定/派发/截断、增量实验与锚点审计（2026-10-25）

**全入口接线（旧 run 只读）。** 新 scope 复制原 16/17 入口集合，仅追加显式形状开关，不修改 v1 scope：`autonomy-os-account-account-scope-v2.json`（`744f86c8…`，argument-type + `systemAppShape`）、`autonomy-ces-icommonevent-scope-v2.json`（`aaa8b043…`，`systemAppOrNativeShape` + inline literal）。两 scope 均重新走 off→report→check。

| 组件 | v1 run | v1 结果 | v2 run | v2 结果 | 变化入口 |
|---|---|---|---|---|---|
| IAccount | `RUN:aa04ab7d6d479d97` | 16 入口，0 excluded / 16 observation | `RUN:f05c85e0379a2054` | 16 入口，**1 excluded / 15 observation** / 0 candidate / 0 finding | 仅 `SetOsAccountDistributedInfo`：observation→excluded |
| ICommonEvent | `RUN:d0f9c45816f0add5` | 17 入口 + 1 operation 分支，0 excluded / 18 observation | `RUN:01caf9305d77b70c` | 17 入口，**1 excluded / 16 observation** / 0 candidate / 0 finding | 仅 `RemoveStickyCommonEvent`：observation→excluded |

- 两个 v2 run `check` 均 0/0；除上述两个入口外，其余入口的 reportability/securityFamily/decision 逐条不变。没有发现“原先 unknown/insufficient 被误判 excluded”的第三个入口。
- 两个新 excluded 的 proof 均 `unanalyzable=[]`、contract compliant、门禁 caller-scoped 且 `blocksOperation=true`：IAccount 为 `system-app-check:208` + `permission-check:212`（subject 持有 `MANAGE_DISTRIBUTED_ACCOUNTS`，仍被 system-app 身份门禁拒绝）；CES 为 `system-app-or-native:589` + `permission-check:597`（subject 持有 `COMMONEVENT_STICKY`，仍被身份门禁拒绝）。这是**限定主体+路径的 scoped identity exclusion**，不是权限错配，也不是正向 finding。
- 表述纪律：原全入口 v1 仍是 0 excluded；新 v2 与独立单入口 run（`RUN:45f304aa5fea2fbf`、`RUN:5961cae1af3c49fb`）各有一条 excluded，三者不能混写。

**access_token 绑定。** 三个 IDL 接口显式 owner 映射（`El5FilekeyManagerService` / `AccessTokenManagerService` / `PrivacyManagerService`），并新增仅在同名多候选时使用的 IDL `paramCount` tie-breaker（`binding.matchArgc` 默认关闭）。85 个入口 = 81 IDL + 4 SA；before **2 resolved / 79 suspect / 4 unbound**，after **79 resolved / 2 suspect / 4 unbound**。79 个 resolved 的目标全部是 `*Service::` 实现，无 test 文件；剩余 2 个是 `VerifyAccessToken` 同 argc、不同参数类型的重载，保留 suspect，不按名字硬猜；4 个 SA 仍无绑定模型。产物 `out/autonomy/inventory/access-token-binding.json`（`7fa889af…`）。

**IPC 派发路径。** 单独清点 `foundation/communication/ipc`：生产 `OnRemoteRequest` 7 个、`SendRequest` 6 个、`ProcessProto` 4 个；`OnRemoteRequest` 有 154 个 name-only 调用点、仅 1 个 exact callee；`SendRequest` 1,134 name-only / 3 exact；`ProcessProto` 140 name-only / 4 exact。该组件 0 IDL/SA 入口元数据，0 anchors 是“入口形态未建模”，不是无生产入口；虚函数/表派发尚未映射到具体对象与 code。产物 `out/autonomy/inventory/ipc-dispatch.json`（`90a6c9dd…`）。

**截断口径。** 三个分层样本在默认 `maxIndexCalls=20,000` 下均截断（access_token 33,119、init 20,743、ipc 32,201），且 unsupported 分别为 148/296/191；因此 `completeExtraction=false`、`truncatedShards=3`、`completeExtractionShards=0`，截断 shard 不进入“完整提取”分母。提到 50,000 只消除 calls 截断，不消除解析缺口；三个 scope 描述符已显式写入 50k 上限。`layered-sample-bench.json` 已加 `truncatedAtDefault` / `completeExtraction` 字段。

**最小增量实验。** 在 access_token 可写副本（未改 OpenHarmony 源码）上做单文件 `parse-worker` 重解析 + 按 file 替换 L1 行：

| 场景 | 增量耗时（tool/墙钟） | 全量 fact-build | 读字节 | 13 表 + unsupported sha256 对比 |
|---|---:|---:|---:|---|
| 未变 | 625 / 778 ms | 4,741 ms | 964 B | 完全一致 |
| 改一个文件 | 612 / 758 ms | 4,425 ms | 1,002 B | 完全一致 |
| 删除一个文件 | 552 / 706 ms | 4,795 ms | 0 B | 完全一致 |
| 新增一个文件 | 716 / 881 ms | 5,846 ms | 56 B | 完全一致 |

- 入口 81 IDL（El5FilekeyManager 11 / IAccessTokenManager 54 / IPrivacyManager 16）、绑定 79 resolved / 2 suspect、unsupported 148 在四场景均不变；输入表完全一致，报告语义一致。
- 决策：文件级 shard 重建可推广到同组件；跨组件/头文件依赖变更仍需扩大失效范围；未预建全仓缓存。产物 `out/autonomy/inventory/incremental-bench.json`（`52c66d3e…`），工具 `tools/autonomy-incremental-shard.js`。

**独立策略锚点审计。** 选 3 个“入口—主体—对象—操作”命题核对权限定义、调用方门禁、对象归属与 ACL/配置：

| 命题 | 主体 | 对象/操作 | 调用方门禁 | 结论 |
|---|---|---|---|---|
| IAM `OpenSession` | normal app 持 `MANAGE_USER_IDM` | InnerAccountIAMManager / OpenSession | `CheckPermission` | **insufficient**：对象归属未证明；文档允许 normal APL 经 ACL 跨级申请，不能断言不持有 |
| CES `RemoveStickyCommonEvent` | normal app 持 `COMMONEVENT_STICKY` | InnerCommonEventManager / RemoveSticky | `system-app-or-native` + `VerifyAccessToken` | **excluded**（身份门禁拒绝）；不是正向 finding |
| IAccount `SetOsAccountDistributedInfo` | normal app 持 `MANAGE_DISTRIBUTED_ACCOUNTS` | OhosAccountManager / OhosAccountStateChange | `CheckSystemApp` + helper | **excluded**（身份门禁拒绝）；不是正向 finding |

- 权限定义：`MANAGE_USER_IDM` / `MANAGE_DISTRIBUTED_ACCOUNTS` 为 system_basic、SYSTEM、provisionEnable；`COMMONEVENT_STICKY` 为 normal。官方 ACL 文档（`docs/zh-cn/application-dev/security/AccessToken/declare-permissions-in-acl.md`，sha256 `6ad99ed4…`，第 10–12 行）明确 normal APL 可通过 ACL 跨级申请，故权限等级本身不能推出“主体绝不可能取得”。
- 未找到同时满足调用方、对象归属、权限定义与独立 ACL/配置的完整正向锚点；`realFindings=0`、真实 finding 召回与 `independentAccuracy` 仍为 `null`。产物 `out/autonomy/inventory/policy-anchor-audit.json`（`00a25b4a…`）。

**文档收尾。** [FULL-SCOPE-ROADMAP.md](FULL-SCOPE-ROADMAP.md) §4 已把 CES 的 **原全入口 v1：0 excluded / 18 observation（17 入口 + 1 分支）** 与 **v2：1 excluded / 16 observation**、**独立单入口：1 excluded** 分列；IAccount 同样分列 v1 与 v2。

### 12. R1 范围基线：逐文件可对账清单、第二层清点与成本测量（2026-10-25）

**起点固定（R1-A）。** win32 10.0.26200、Node v25.2.1。`base/`、`foundation/` 共 190 个 bundle 组件、190 个 git 子仓（repo 管理，无单一整树 commit）。首层基线 `out/autonomy/inventory/full-scope-baseline.json`（sha256 `56484e8611913bb8…`，602,587 B，2026-10-25T03:47:46Z）只读核对，未覆盖。`tools/oh6-r1-source-version.js` 逐仓记录 HEAD 与两级 dirty 口径：原始 `diff-index` 186/190 dirty，全部是 NTFS 丢 exec 位（100755→100644）与 autocrlf CRLF checkout 噪声，不作为改动证据；内容口径（`-c core.filemode=false diff --ignore-cr-at-eol --quiet HEAD`）**6 个子仓有真实内容差异**：tee_os_kernel（测试 resource +39 行 .s）、dmsfwk（tests/BUILD.gn +33 行）、netstack（test/BUILD.gn +1 行）、ace_engine（删 122 行 .ets sample）、av_codec（测试视频资源二进制变大）、av_session（`services/session/server/avsession_service.cpp` 一处日志格式改动，唯一触及生产文件的差异；本轮未修改产品源码，按 R1 约束保留现状）。审计工具仓 `main@7439196379a0`、105 个未提交条目（含本轮新增工具/测试/产物）。产物 `out/autonomy/inventory/r1-source-version.json`。

**逐文件清单（R1-B）。** `tools/oh6-r1-scope-inventory.js` 复用首层 role/lang/bundle 识别规则（TEST_RE/GEN_RE/CODE_EXT/DOC_EXT 逐字一致）与 `lib/facts` 的 idl/sa/napi 解析器，单遍历扫过 **147,561 个文件 / 10.14 GB**（含 16 个符号链接、0 个不可读文件），12 类互斥角色全覆盖：production-code 60,446 / test-code 40,324 / generated-code 1,758 / idl 246 / sa-profile 155 / build 12,290 / component-metadata 190 / config 14,335 / doc 3,376 / other 14,425 / symlink 16 / unreadable 0。生产语言：C 2,166 / C++ 23,530 / 头文件 31,554 / 其他语言 3,196（typescript 1,620、arkts 622、rust 370、javascript 351、cangjie 54、python 124、java 21、shell 34）。无 bundle 归属 203 = 201（与首层一致）+ 2 个无 bundle 祖先的符号链接（首层静默跳过：`base/accesscontrol/_codeql_detected_source_root`、`foundation/ai/mindspore`），其中生产 134。解析失败 idl/proto/sa/bundle 全 0、读失败 0。明细流式落盘 `r1-files.jsonl`（147,561 行，路径严格升序且唯一，每行含 p/s/r/l/c/b 与分类依据）；汇总 `r1-scope-baseline.json` 确定性（无时间戳；两次全量运行 sha256 一致：`650e81f7b8cb562b` / `dd232dfefbf4da7a` / `f294b72037821b75`）。四条对账恒等式（总文件=Σ角色、生产=Σ语言、生产=组件+无归属、路径唯一）在清单内断言全过。

**第二层清点（R1-C，全部标 observed/candidate，未知单列）。** IDL（`lib/facts/idl` 解析器口径）：245 个 .idl → **210 接口 / 3,212 方法候选**（首层正则口径 220/3,234，差异为解析口径）；.proto 1 个（service/rpc 正则候选）。SA profile **155 / 154 systemability**（与首层一致，`lib/facts/sa` JSON 解析）。NAPI 注册点候选 **497 个**（`napi_module_register`，490 文件 / 106 组件，含模块名）+ NAPI_MODULE 宏候选 15。IPC 派发候选：生产 `::OnRemoteRequest(` **1,116 处 / 580 文件 / 98 组件**，头文件限定引用 7 处 / 5 文件；`@ohos/ipc` 组件复测 **7 个生产 OnRemoteRequest**，与 R0 `ipc-dispatch.json` 一致。入口候选逐条可定位：`r1-entry-candidates.jsonl` 1,638 行（NAPI 含模块名，OnRemoteRequest 含行号）。未知形态显式登记不填零：虚函数/表派发 code 映射（分母未知；类内非限定虚声明不在 needle 内）、非 C/C++ 生产入口（3,196 文件分母未知）、SA libpath→dlopen 绑定、生成 stub 派发（1,758 个生成文件不计入生产入口候选）、函数/操作分母（未提取）。

**构建与依赖（R1-C）。** bundle features 812 个声明；adapted_system_type 并集 {mini, small, standard}；BUILD.gn/.gni 12,290 个文件、**22,480 个可见 `if(` 条件**（observed 文本计数，语义未评估）；compdb 53 个 part、189/190 组件按 subsystem 名映射 part-present（存在≠已编译）。未解析组合三项单列：实际变体组合未枚举、GN 条件语义未评估、逐文件宏未清点。依赖：bundle.json 声明外部组件 **291 个（4,079 引用）** + third_party 111 引用（top：hilog 152、c_utils 149、ipc 146、samgr 129、access_token 120）；include/链接/运行时注册/调用闭包四类未解析，逐类登记，不与主范围重复计数。

**首层差额逐项解释（R1-D）。** 组件数 190、SA 155/154、无 bundle 生产 134、生产 C/C++/原词表语言计数全部一致。差额全部来自规则扩展，无源码变化：productionFiles 60,268→60,446（+178：.cj 54、.mjs→javascript 79、.sts→arkts 45，原在首层静默 other）；testFiles 39,874→40,324（+450：446 个 test 路径下 .idl 首层漏计 + 4 个新词表扩展）；generatedFiles 1,538→1,758（+220 新词表扩展）；idl 245→246（+1 proto）；build +6、config 10,746→14,335（+23 无 bundle、+3,566 词表扩展 .json5/.te/.para/.toml）、doc +13；未支持语言 3,018→3,196；IDL 接口/方法 220/3,234→210/3,212（正则→项目解析器）。首层 unscoped 抽样 20 条全部可在 R1 无归属清单定位。明细见 `r1-verify-result.json#firstLayerDiff`。

**抽样复核与重算（R1-D）。** `tools/oh6-r1-verify.js` 独立流式重算 `r1-files.jsonl`：总文件/字节、逐角色、逐语言、190 组件 production.files 逐项与汇总一致（0 失败）；入口候选按 (组件， 形态) 重算 218 个键与汇总 0 不一致。确定性抽样 39 个（每角色 + 无 bundle 生产 ×2 + 双层测试目录嵌套 ×2）：**0 失败、1 个信息性警告**（generated/bridges.cc 前 4KB 无生成标记，路径属 generated/ 目录，角色保持）；全部样本 stat 字节一致、classify 回放同角色；生产文件 gtest/gmock 探针 0 命中。

**成本（同机实测，Windows 原生）。** 首次冷跑 60.8 s（遍历 2.7 s + 逐文件读 42.4 s）；验收全量运行 **47.2 s**（walk 2,273 ms / read 28,750 ms / write 133 ms），峰值 RSS **34 MB**（25 ms 采样）；遍历 10.14 GB，内容读取 0.616 GB（仅生产代码+构建+idl+sa；test/gen/doc/config/other 不读内容）。无变更重跑 50.7 s、`--measure-only` 49.3 s：**重跑≈全扫描成本**，不建跨 run 缓存（收益上限≈内容读取的 29 s，需变更检测基础设施，属 R2 增量分片范畴）；单次运行内单遍历、每文件至多读一次，无重复目录/元数据开销。产物 `r1-scan-cost.json` / `r1-scan-cost-rerun.json` / `r1-scan-cost-measure-only.json`。

**测试。** 新增 `test/oh6-r1-inventory.test.js`（2 用例）：classify 优先级与词表扩展；端到端 fixture 覆盖生产/测试/生成/无 bundle/解析失败（bundle.json、sa_profile）/入口候选（NAPI、OnRemoteRequest 实现+头文件引用）/对账恒等式/两次运行字节级确定性/符号链接。阶段验收 `node --test` 全量 **259/259 通过**（既有 257 用例无回归）。本轮仅改独立清点脚本与新增测试，未触及共享事实与裁决路径，按指南免重跑旧 run；存量 3 个分层样本 shard 维持 `completeExtraction=false`，不计入"完整提取"分母。

**R2/R3 待办登记（数量、来源、下一步）。**

| 待办 | 数量 | 来源 | 下一次可执行实验 |
|---|---|---|---|
| IDL 同 argc 类型重载 | 2（`AccessTokenManagerService::VerifyAccessToken`，accesstoken_manager_service.cpp:179/205） | `access-token-binding.json#remaining` | R2 建参数类型区分的绑定模型，消歧后重跑 access_token 绑定 |
| SA 入口绑定缺失 | 4（access_token）+ 全域 154 个 SA 声明仅部分有绑定口径 | `access-token-binding.json#saAnchors`；R1 `sa.detail` | R2 建 SA libpath→dlopen→注册链模型，先在 access_token 试点 |
| IPC 对象/code 绑定 | @ohos/ipc 7 OnRemoteRequest / 4 cases / 154 name-only；全域候选 1,116 处 / 98 组件 | `ipc-dispatch.json`；`r1-entry-candidates.jsonl` | R3 补对象与 code 表绑定，从 @ohos/ipc 与 @ohos/ability_runtime（58 文件）开始 |
| 虚函数/表派发 | 未知（needle 仅捕获限定引用 7 处头文件命中） | `r1-scope-baseline.json#entryUniverse.unknownForms` | R3 决定是否引入类作用域解析；先抽样量化类内虚声明密度 |
| 跨组件头文件增量失效 | 未闭合（R0 仅同组件单文件 shard） | EXPANSION-RESULT §11；`incremental-bench.json` | R2 做 include 影响面实验，确定失效边界与回退全量重建的条件 |
| 非 C/C++ 提取 | 3,196 生产文件（入口分母未知） | `r1-files.jsonl`（r+lang 可查询） | R3 按语言做有界入口探针（先 typescript/arkts）再定解析器投入 |
| 依赖闭包 | 声明外部 291 组件 / 4,079 引用，仅 bundle 层 | `r1-scope-baseline.json#depsUniverse` | R2 在 shard 内做 include 级解析实验，分类 include/链接/运行时 |

**R1 结论。** 五项验收全部有可核验产物（逐文件对账、入口/构建/依赖第二层、样本复核与重算、成本实测、待办登记）。范围基线不是审计完成：函数/操作分母、入口绑定、实际变体组合、依赖审计与安全裁决仍未做，`notRun` 逐项保留；`@ohos/ipc` 0 个 IDL/SA 入口元数据是"入口形态未建模"，不是无生产入口。无新增 live 外发、未修改产品源码与旧 run、未提交/未推送。

**口径修正与重新验收（v1.2，2026-10-25 同日）。** 按复审意见补四项，v1.1 段落中与之冲突的数字以下文为准；清点器版本升为 `r1-scope-baseline-v1.2`，最终产物哈希 `r1-files.jsonl a882a58319042cf8` / `r1-entry-candidates.jsonl dd232dfefbf4da7a` / `r1-scope-baseline.json e75cc73bee03f6ff`（无变更重跑复算一致）。

1. **other 生产角色漏计已修正。** 对 14,425 个 v1.1 other 文件按扩展名+路径生成完整直方图（172 类扩展）逐类核实：新增生产语言/扩展 `.s`（含大写 `.S`，26 个汇编源，如 `getcontext_x86_64.S`、tee_os_kernel `head.S`）、shader 族 146 个（`.shader/.frag/.vert/.comp/.shaderpl/.shadervid/.shadergs/.shaderrs`，graphic_3d 计算着色器等）、`.hml/.css/.scss`（Lite UI 界面源，test 路径下的自动归 test-code）、`.inl/.tpp`（C++ 内联，+21 cpp）、`.in`（代码生成模板）、`.mm/.l/.y/.pegjs/.bat/.cmd/.pyw`；新增接口定义 `.taihe` 38 个（idl 角色）；新增构建输入 `.map`（131 个全部为链接器 version map，无 `.js.map` 混入）/.versionscript/.mk/.cmake/.gradle/.pro/.ld/.def/.gn/.build/.pydeps 与 Makefile/hvigorw 文件名（+380 build）；新增配置 `.rc`（init 服务定义）/.dac/.policy（seccomp）/信任链证书（.0/.pem/.crt/.cer/.p7b/.cert/.p12/.sf）/.pluginmeta/.properties/.config/.enforce/.permissive 与 `*_contexts`/`attributes`/`hiview_*_config`/`*_plugin_config` 文件名（+4,376 config，含无归属 31 个；其中 296 个 `.p7b` 在 v1.2 首轮曾因扩展集合漏配落入 other，见下方 v1.2.1）；`LICENSE*` 按名入 doc（+217）。确认非生产的 other（媒体/二进制/fuzz corpus/预编译路径/VCS 元数据）11,721 个。**production-pending 新角色 116 个**（无扩展名 102 + .spt 5 + .csv 3 + .mf 2 + .inc 2 + .profile/.ui 各 1，如 hiview `EventloggerPipeline`、i18n `prefabrication`），不计入生产分母也不默认非生产，逐文件可查 r1-files.jsonl。最终生产 **60,678**（首层 60,268 + 词表扩展 410），未支持语言 3,407；测试 41,262（首层 39,874 + 446 个 test 路径 .idl + 942 个新词表测试文件）；idl 284 = 245 .idl + 1 .proto + 38 .taihe。真实样例分类断言已入 `test/oh6-r1-inventory.test.js`（classify 27 例含 .S/.comp/.taihe/.map/.rc/.dac/file_contexts/LICENSE_Fonts/zic 等）。
2. **目录扫描失败可见 + 范围闭合标记。** bundle 搜索与主遍历的 `readdirSync` 失败不再吞掉：逐条记录 {phase, path, code}（`deps.readdir` 可注入做受控失败），汇总新增 `scopeClosure`（closed/dirReadErrors/fileReadErrors/unclosedReasons）；文件读失败沿用 readErrors 并纳入闭合判定。受控失败测试断言两个 phase 都登记、`closed=false`、失败目录内容不进入任何分母。本轮真实扫描 **closed=true（0 目录失败、0 文件失败）**。16 个符号链接全部登记目标与分类（不跟随、不重复计数）：范围内别名 5（如 safwk `system_ability.h`→services 实现）、测试材料 10（player_framework fuzz corpus→unittest 资源）、范围外依赖候选 1（`foundation/ai/mindspore → third_party/mindspore`，登记为跨目录依赖候选）、未知 0；见 `r1-scope-baseline.json#symlinkRegistry`，JSONL 行含 `t` 字段。
3. **内存峰值改用内核 maxRSS。** 原"峰值 34 MB"来自 25ms 定时器采样——纯同步扫描期间定时器不触发，数值无效且误导；工具内采样已移除并在 cost 记录中注明。用现有 `tools/autonomy-bench.js` 包裹一次 `--measure-only` 扫描，取 `process.resourceUsage().maxRSS`（对同步代码有效）：**maxRssBytes 223.1 MB**（同 run 采样值 215.5 MB、实测读 619.5 MB≈逐角色估算 616 MB、wall 41.4 s、cpu user+sys 22.8 s，数值互洽）。产物 `r1-scan-cost-bench.json`。保留"全部记录驻留后排序"的实现：223 MB 远低于瓶颈阈值，改为流式排序/外部归并属 R2 增量分片时一并考虑。
4. **未跟踪文件口径补齐。** `r1-source-version.json`（v2）逐仓 `git ls-files --others --exclude-standard`（不哈希内容）并与 r1-files.jsonl production-code 路径交叉：190 仓共 **6 个未跟踪文件，0 个进入生产清单**——dmsfwk `interfaces/innerkits/tests/dms_set_state_poc.cpp`（tests 路径→test-code）与 netstack `test/fuzztest/tlvdecode_fuzzer/` 5 个（fuzz 材料）；其余 188 仓登记为零。6 个内容 dirty 子仓结论不变（5 测试/资源侧 + av_session 一处日志格式改动）。

**v1.2 重新验收结果。** 分类样例与目录失败单测通过（4/4）；新清单自身对账恒等式全过、`tools/oh6-r1-verify.js` 独立重算 12 项检查全过、44 个确定性抽样 0 失败（1 个信息性警告不变）、入口候选 218 键 0 不一致、@ohos/ipc 复测 7/7；旧（首层 60,268）新（60,678）分母差额逐项解释（见 `r1-verify-result.json#firstLayerDiff`，production-pending 单列新分母）；成本报告以 maxRSS 223.1 MB 为准；`node --test` 全量 **261/261 通过**。四项修正完成，范围基线验收通过，转入 R2；真实 finding 仍为 0 不构成阻塞。

**v1.2.1 补充（2026-10-25 复审发现）。** §12 与清点器注释曾声称 `.p7b` 归 config，但 `CONFIG_EXT` 集合实际漏配，296 个 `.p7b` 全部落入 other（23 个不在测试路径，含 `SystemResources.p7b`）。按实际用途核实（文件头为 PKCS#7 signedData，OID 1.2.840.113549.1.7.2；随系统资源与系统弹窗发布、决定安装信任行为）后补入集合，真实样例断言入 `test/oh6-r1-inventory.test.js`。修正后 config 15,122（首层差额 +4,376）、other 11,721；**生产 60,678 与 production-pending 116 不变**；清单重生成并复算（哈希 `a882a583…`/`e75cc73b…`），verify 12 项检查与 44 抽样仍全过，全量 `node --test` 261/261 重跑通过。已登记局限：verify 与清点器共享分类词表，汇总重算只能发现记账不一致，不能发现分类规则本身的语义错误——此类错误只能靠逐类样例核实暴露，`.p7b` 即为一例；R2 启动时优先判明 production-pending 中的待定项（如 SELinux 相关文件），但不为 R1 再开展全量分类工程。

### 13. R2 可扩展事实层：分片、增量失效与有界绑定实验（2026-10-25）

**R2-A 起点核对与基线。** R1 v1.2.1 原件（`r1-files.jsonl a882a583…`、`r1-scope-baseline.json e75cc73b…`）只读复核一致；代表性 run 只读 `check`（`RUN:01caf9305d77b70c`，CES v2）0 错误 0 警告。三个样本（`K/policies/scope-{access-token,init,ipc}-r2.json`，snapshotScope 独立，不改写 r1 快照）新建快照：access-token `sha256:eedbad92…`、init `sha256:1fd6ef5c…`、ipc `sha256:562bf189…`。bench 基线（内核 maxRSS）：冷 snapshot 1.19/0.54/0.93 s、`--check` 1.29/0.57/1.23 s（access_token/ipc 的 check 重读 138/117 MB compdb）、metadata 0.49/0.50/0.49 s、冷 build 5.15/3.29/4.63 s（maxRSS 403/326/391 MB）。产物 `r2-bench-*.json`。

**R2-A2：production-pending 116 → 75（41 项家族判明）。** 内容核实后修分类：`lib*_map` 链接器 version script 7 个 → build（含三样本内的 `libprivacy_map`/`libipc_core_map`/`libipc_single_map`/`librpc_map`）；`/sepolicy/` 路径 SELinux 策略源 17 个（access_vectors/initial_sids/*.spt 等）→ config；hiview `plugins/**/config/` 10 个 → config；init `etc(_lite)/{passwd,group}` 4 个 → config；`.gitee/`、`hooks/`、` CODEOWNERS` 3 个 → other(VCS)。刷新清单**另存** `out/autonomy/inventory/r1-refresh/`（不覆盖已验收原件；verify 12 检查全过、44 抽样 0 失败），角色差额：config 15,122→15,153、build 12,664→12,671、other 11,721→11,724、pending 116→75（余 75 项中 66 个无扩展名逐文件保留待定）。生产 60,678 不变。**事故记录**：刷新时因 `--out-dir` 未解析误写默认目录、覆盖了 v1.2.1 原件；当即回退分类改动重跑，三个产物 sha256 逐字节复原后再重放改动——原件现与验收哈希一致；默认目录的 `r1-verify-result.json` 重跑后仅剩 1 个家族文件回放漂移（预期版本偏差，以刷新目录全过结果为准）。同日修掉 verify 工具 `--src-root` 的潜在参数错位。

**R2-B：三样本 shard 清单与上限可见性。** `lib/autonomy/facts.js` 的 index() 改为先全量计数再截断保留：每 shard 输出 calls/functions 的 seen/retained/truncated/limit。`tools/autonomy-fact-shards.js` → `r2-shard-manifest.json`：access-token-r2 生产 439（scope policy 口径，与 R1 词法口径 446 的差异为 test 判定规则不同）、calls 33,119/33,119（50k 上限未触发）、unsupported 148；init-r2 313、20,743/20,743、296；ipc-r2 229、32,201/32,201、191。三样本**无未标记截断**；unsupported 按 reason/kind 具名分册；extractionUntruncated 与 parseComplete 分列，"50k 未截断"不写成"全部抽取"。

**R2-C：增量引擎与依赖失效（`lib/facts/incremental.js`）。** 分层失效模型：L1 解析事实 file-local（parse-worker 只读目标文件，由构造证明 + 场景对照实证）；metadata 层按 metadata-manifest 逐文件 sha256；compdb/build 输入按 build-manifest sha256（漂移 ⇒ 回退全量）；include 边在增量运行时提取（相对/父目录/根相对/范围内后缀匹配），引号 include 无法解析 ⇒ `dependency-unknown` ⇒ 回退全量；变更检测逐文件 sha256（可靠变更清单），不信任 mtime/size。零改动走快速路径（仅哈希遍历，不重解析、不重写 13 表）。每场景在**相同最终文件集合**上独立做干净全量构建，`tools/fact-compare.js` 逐表对照（13 表 + unsupported + metadata + includes）；身份字段按合同归一：snapshotId 剥离、factId/metadataId 派生校验后整段占位——sinks/guards 的 locator 内嵌 fn 引用使 factId 稳定段也随 snapshotId 变化，这是对照合同的一部分。

**场景对照（受控副本 `<workspace>/r2-work`，仓库外——修正后不再被 `node --test` 误发现、不污染审计仓 git 状态）：** access_token 8 场景（unchanged/modified/same-size-same-mtime/added/deleted/same-component-header/include-removed/metadata-source-change）+ ipc 3 场景（same-size/cross-component-header/quoted-unresolved-fallback），**两轮共 18 次全部 pass**（与相同输入的干净全量逐表一致，无身份字段外漂移）。跨组件真实边：ipc 源 `#include "hilog/log.h"` 36 处经后缀匹配解析到 hilog 副本（1,796 条 include 边入 `includes.jsonl`）；hilog 头文件变更仅其自身 1 文件重解析，ipc 行不变且与干净全量一致。回退两例（scope-input-changed / dependency-unknown）扩大的全量重建与干净全量一致。单测 `test/r2-incremental.test.js` 2/2（include 解析、快速路径、同大小同 mtime 检出、删除行移除、两类回退）。

**R2-D：绑定/派发有界实验。**
1. **重载消歧（`tools/autonomy-r2-binding.js` → `r2-binding-overloads.json`）**：scope opt-in `binding.matchParamTypes`（IDL 类型族 List/Map/String vs C++ 签名类型族；别名 AccessTokenID 等归 other 不参与判定；role=test 不作候选）。85 入口 before **79/2/4**（=R1 §11 after 口径复现）→ after **81/0/4**；仅两条 `VerifyAccessToken` 变动：ipcCode=80 → `accesstoken_manager_service.cpp:205`（enforced=2：List<String>/List<int> vs std::vector）、ipcCode=1 → `:179`（enforced=1：String）。正反单测 `test/r2-binding-types.test.js` 5/5。
2. **SA 归属链（`tools/autonomy-r2-sa-chain.js` → `r2-sa-chain.json`）**：profile→构建目标→ID 常量→注册调用逐步取证。3503/3504/3505 **closed**（如 3503：`accesstoken_manager_service.cpp:87` 常量 + `:103` MakeAndRegisterAbility + `services/accesstokenmanager/BUILD.gn` ohos_shared_library）；8250（el5）**closed-external**——`REGISTER_SYSTEM_ABILITY_BY_ID(…, EL5_FILEKEY_MANAGER_SERVICE_ID)` 的常量定义在组件外 `foundation/systemabilitymgr/samgr/.../system_ability_definition.h:326`，即 SA-ID 绑定存在**跨组件头依赖**（逐条登记，R3 边界案例）。4 条 entry 状态仍 `unbound`（SA 无方法体可绑）；不把同名函数当服务实现。
3. **IPC 派发探针（`tools/autonomy-r2-ipc-probe.js` → `r2-ipc-dispatch-probe.json`）**：分母收敛为精确名 `OnRemoteRequest` 生产实现 **7 条**（=R0 口径；另 6 条 `*OnRemoteRequest*` 辅助函数单列为分派邻接）。2 条 **resolved-dispatch**（DBinderServiceStub：`GET_PROTO_INFO→ProcessProto`、`DBINDER_OBITUARY_TRANSACTION→ProcessDeathRecipient`，code 常量定义 `rpc_types.h:32/35`、handler 实现行号俱在），其余 5 条 unbound 并注明形状。全域 1,116 处 per-code 绑定属 R3，不在此冒充完成。

**R2-E：成本与净收益（同机、两轮）。** access_token：单文件增量（哈希遍历 4.85 MB + 13 表拼接 114 MB 读写 + 1 文件重解析）**1.26–1.61 s** vs 干净全量（snapshot+metadata+build）**4.7–7.1 s**，净收益 ~3.4–5.5 s（≈3.2–4.8×）；未变增量 **0.66–0.75 s**（快速路径）vs 5.3–6.3 s；回退全量 = 干净全量成本（无额外惩罚）。**决策记录**：13 表整表拼接是增量主导固定 I/O——按文件偏移的原位替换可省，但需行级偏移索引；当前净收益已成立且单 shard 表 ≤60 MB，不引入该复杂化（R3 若表大到分钟级再评估）；compdb 全量 sha 校验（138 MB 读/次增量）保留——构建输入漂移必须回退，不允许 mtime 信任；未变更快速路径消除的正是此前每次 ~0.6 s 的无收益重写。

**回归与边界。** 全量 `node --test` **268/268 通过**（新增 r2-incremental 2 例、r2-binding-types 5 例；场景副本迁出仓库后 test 发现恢复干净）；`RUN:01caf9305d77b70c` 复算 0 错误（index()/discovery 变更均为增量语义：计数补账 + 默认关闭的 opt-in）。R1 分母保持可对账（r1-refresh verify 全过）。**R3 移交**：ipc per-code 全域绑定（`r2-ipc-dispatch-probe.json` 已列 5 条 unbound 的形状与原因）；非 C/C++ 入口与 75 个待定文件的逐文件判明（`r1-refresh/r1-files.jsonl` r=production-pending 可查询）；跨组件 SA-ID 头依赖（samgr `system_ability_definition.h`）纳入依赖闭包；`maxIndexCalls=50,000` 是三样本实测上限，不是普适常数。R2 交付为事实可复用与失效正确，不宣称任何组件已审计；真实 finding 仍为 0。

**复审修正（2026-10-25 同日，修正后重新验收）。** 复审指出三处准确性问题，全部修复后重跑：

1. **对照器漏报（`tools/fact-compare.js`）**：旧 `canon` 用 `JSON.stringify` 的 replacer 数组，会在所有嵌套层过滤键——只改嵌套字段（如 `sourceRange.file`）的行被判相等；Map 收行还会折叠重复行。修正为全深度键排序序列化 + 按键计数对照（重复行数量差异计为漂移）。反例单测 `test/r2-fact-compare.test.js` 5/5（嵌套字段检出、重复行计数、单侧缺表、归一不吞差异、相同输入相等）。修正后场景全部重跑。
2. **IPC 误绑定（`tools/autonomy-r2-ipc-probe.js`）**：旧实现把 owner 类名再切最后一段（前缀砍成 `OHOS`），且 handler 找不到同对象方法时退回任意同名函数——`DBinderServiceStub::OnRemoteRequest` 的 ProcessProto 被误指到 DBinderCallbackStub。修正为 owner 即类前缀、handler 必须同对象（C++ 同 owner 类前缀；C 无命名空间时同翻译单元），禁止同名回退，每条边带 unresolvedReason。修正后 7 条入口中 **2 条 resolved-dispatch**：DBinderServiceStub 的 `GET_PROTO_INFO→OHOS::DBinderServiceStub::ProcessProto @dbinder_service_stub.cpp:105` 与 `DBINDER_OBITUARY_TRANSACTION→…ProcessDeathRecipient @:183`（复审所指的同对象实现行号），DBinderCallbackStub 的 1 条边同对象成立；其余 5 条 unbound 逐条注明原因。旧产物已被修正版覆盖。
3. **增量引擎 scope-only 漂移与产物身份**：引擎补两类检测——(a) role 重算对照（文件字节未变但基线 role 与当前 policy 判定不一致 ⇒ `scope-policy-drift` 回退，覆盖 test 路径/文件名规则变化）；(b) 指纹链（调用方传入上一次增量的 policyFingerprint，不一致 ⇒ 回退）。新增 `promoteToSnapshot` 模式：派生 id = sha256(基线 id + policy 指纹 + 全部文件版本)，L1 行 snapshotId/factId 按派生 id 重算（locator 内嵌引用先做 snap12 替换）、metadata 前缀替换、写新 snapshot.json——输出成为 AutonomyFacts 可直接消费的新版本快照（单测验证打开/index/factId 前缀/派生确定性）。默认不开启（原型模式保留基线 id），交付声明相应限定：默认输出是增量原型产物，promote 后才是可复用快照。单测扩为 4/4（含两类漂移回退与 promote 消费）。
4. **对照范围补齐**：场景驱动器新增派生层对照——index 计数/截断账目、入口候选分布、metadata 绑定分布（resolved/suspect/unbound）、unsupported 行数；18 次运行的派生层全部相等。**场景计数控勘**：为 **11 个不同场景、其中 7 个复跑、共 18 次运行**（非"11 场景 ×2"）。
5. **修正后重跑结果**：11 场景（access_token 8 + ipc 3）+ 7 个复跑 = 18 次运行，逐表与派生层全部相等；成本口径不变（增量 1.3–1.6s vs 干净全量 ~6.9–7.9s，含 includes 生成；未变 0.75s；回退场景 13.9–15.8s = 两次全量）。全量 `node --test` **275/275**（新增 fact-compare 反例 5 例 + r2-incremental 增至 4 例）；`RUN:01caf9305d77b70c` 复算 0 错误。§13 正文中与上述冲突的旧数字（IPC 误绑证据、对照器口径、18 次计数）以本节为准。

**复审第二轮修正（2026-10-25，promoteToSnapshot 一致性）。** 复审指出 promote 的三处问题，全部修复并以真实样本验证：

1. **factId 可复算不变式**：promoteRows 现在把行内**所有** F:/M: 引用（sinks/guards 的 `locator.fn`、calls 的 `caller`、sinks/guards 的 `function` 字段）先做 snap12 前缀重写并**写回存储行**，factId 再由写回后的 locator 整体重算——`factId === factIdOf(derivedId, row.kind, 存储的 locator)` 对每一行成立。真实样本验证：access_token promoted 输出 **98,342 条 fact 行**（含 317 sinks + 4,719 guards）全部复算一致、零基线 snap12 残留。单测同不变式（fixture 含 memcpy sink + if guard）并覆盖 metadata 无残留。
2. **派生快照的来源清单与 manifest**：promote 现在重建 `snapshot.json` 的 source 段（逐 root 的 files/bytes/sourceManifestHash，与 `scope.enumerateRoot` 同式，按当前文件版本计算）并生成 `manifest.json`（manifestId = manifestIdOf(derivedId, artifactRefs)，artifactRefs 含 13 表 + unsupported + includes + 三个 manifest）——`inputManifestId` 为合法 `AM-<16hex>`，可作为 run 固定输入；build-manifest/metadata-manifest/compdb-win 从基线复制并重写 snapshotId。单测断言 manifestId 一致、source.files=当前集合、inputManifestId 合法。
3. **默认指纹绑定**：scope 级输入校验升级为默认全开——metadata 源**集合**按当前 policy 重新枚举并与基线 metadata-manifest 比对（glob 收窄/放宽、源增删都拒绝，不再只查基线清单内 sha）；输出目录残留不同指纹的前次增量状态 ⇒ 回退（链式复用默认保护）；显式 `expectedFingerprint` 仍支持。新增单测：metadata 源集合漂移默认回退、链式指纹保护回退。
4. **快速路径 promote**：未变更快速路径同样支持 promote（此前漏掉，输出会停留在基线 id），修正后 unchanged+promote 也产出派生 id。
5. **真实样本验证与成本**：`tools/autonomy-r2-scenarios.js --promote` 在 access_token 上跑 modified/unchanged 两场景：promoted 输出与同输入干净全量**逐表 + 派生层全部相等**；含 promote 的端到端成本——modified 4.5s（增量 1.9s + promote 2.2s）vs 干净全量 ~7.9s，unchanged 3.8s（0.9s + promote 2.9s）；promote 成本 ≈2.2–2.9s（约 101MB 表重写 + 6 万行 factId 重算），已计入 costs.promoteMs。派生 id 确定性复验一致。产物 `r2-promote-validation.json`。
6. **回归**：全量 `node --test` **277/277**（r2-incremental 扩至 6 例）；`RUN:01caf9305d77b70c` 复算 0 错误。本节与路线图 R2 状态以此为准。

**复审第三轮修正（2026-10-25，promote 收尾三处）**。修复后重跑 promote → 正式 snapshot ID 消费 → run/check：

1. **读取失败 ≠ 删除**：`diffAgainstSnapshot` 的读取失败不再进 `deleted`（会移除旧事实生成看似有效的快照），改为具名 `readFailures` ⇒ 增量在**任何写盘之前**返回 `source-read-failed` 回退；`opts.readFile` 可注入供受控测试。单测断言：EACCES 注入下 `fallback=true`、detail 含路径与错误码、**outDir 不产出 l1 产物**。
2. **解析规则版本默认绑定**：`PARSE_RULES_VERSION`（'K-1.0.0'）提升为 `lib/facts/manifest.js` 共享常量（fact-snapshot 同源引用，值不变）；增量默认比较基线 `manifest.json.rulesVersion` 与当前值，不一致 ⇒ `parse-rules-changed` 回退；同时比较基线 `snapshot.tools.treeSitter` 与当前 tree-sitter 版本（L1 内容的实际依赖），不一致同样回退。不再依赖调用方传指纹。单测：篡改基线 rulesVersion ⇒ 回退。
3. **promote 清单与来源补齐**：`artifactRefs` 逐表列入存在的 `metadata/*.jsonl`（复审实测 modified 产物目录 7 个 metadata 表而清单 0 引用的问题）；`snapshot.json` source 行重建 **productionFiles**（fileVersions 现带 role；role 语义与 facts 层一致——无 test 判定即 production，头文件计入）。单测：metadata 引用数 = 目录表数、13 表全在列、productionFiles 正确（含 test 规则基线下的 3/4 变体）；role 变化的 policy 仍按 scope-policy-drift 回退（不产出 promote 快照）。
4. **正式消费路径验证（run/check）**：modified+promote 的派生快照（`sha256:d24060f9…`）放入 FACTS_ROOT 正式消费位，`bin/autonomy.js run --scope=…r2inc-base --budget=…r2-promote-budget --mode=off --snapshot=<派生 id> --max-tasks=2` 经**官方解析路径**打开（run 载荷 `snapshotId` = 派生 id、`inputManifestId` = AM-1d97fb9b3232edf7 与派生 manifest 一致），off 完成task 2 项（0 模型调用，missing 具名：binding-ambiguous/dominance-unproven/operation-unbound，findings=0），`bin/autonomy.js check --run=RUN:213ea8ddab5e24fa` **0 错误 0 警告**。首跑曾因测试 scope 缺 run 合同的 `scopeId` 字段 check 失败——补字段后重跑通过（失败 run 为当次自建，已删除重造，不涉及旧归档）。"可作为 run 固定输入"由该 run/check 证明，不再只是直接构造 AutonomyFacts 打开目录。
5. **回归**：r2-incremental 扩至 **9/9**（新增读取失败回退、规则版本绑定、清单完整性三例）；全量 `node --test` **280/280**；`RUN:01caf9305d77b70c` 复算 0 错误。全域 IPC per-code 绑定、非 C/C++ 入口、真实 finding 仍属 R3，不构成阻塞。

**复审第四轮修正（2026-10-26，正式消费证据闭合）**。复审指出第三轮的两处证据缺口——正式 run 消费的是修复前的派生快照（该 ID 下 manifest 仍 0 个 metadata 引用、snapshot 无 productionFiles），且工具版本回退检查读了错误字段（`tools` 而非 `toolVersions`）实际未生效。修复与验证：

1. **字段修正**：工具版本回退改读 `snapshot.toolVersions.treeSitter`（正式快照合同字段；正式快照不把 rulesVersion 写进 snapshot.json——规则版本在 manifest 中，promote 的派生 manifest 现按此写入）。新增单测：基线 toolVersions.treeSitter 漂移 ⇒ parse-rules-changed 回退（detail 记 baseline/current），一致时不误回退。
2. **PROMOTE_VERSION 入派生 id**：派生 id 载荷加入 promote 产物身份版本（当前 `r2-incremental-promoted-v2`），修好的 promote 产物拿到**新 id** `sha256:337554b3294b…`，不原地替换旧 ID——旧派生快照 `d24060f9…`（RUN:213ea8ddab5e24fa 的固定输入）原样保留，其 0 metadata 引用状态即该 run 固定时的真实状态。
3. **新派生快照核对**：manifest 的 metadata 引用 **7/7 与目录一致**；snapshot.json source 行 `files=929、productionFiles=439`（按当前文件集合重建）；`derivedFrom.kind=r2-incremental-promoted-v2`。
4. **正式消费复验**：`bin/autonomy.js run --mode=off --snapshot=sha256:337554b3… --max-tasks=2`（scope 补 run 合同必填的 scopeId，并固化到 writeScopePolicy 生成器——此前手改会被场景驱动器重生成抹掉）→ `RUN:09104ee71a49cd28`，载荷绑定派生 id 与其 manifestId（AM-61b67f352851ed25），`check` **0 错误 0 警告**。全过程不触碰旧 ID 快照与旧 run。
5. **事故记录**：本轮一次一次性脚本失误把测试文件内容误写入 lib/facts/incremental.js（引擎被覆盖）；当即按既有设计与全部已登记修正完整重写引擎，r2-incremental 10/10 + 全量回归 + 场景/promote 验证重跑全过后恢复。教训：不对多次编辑的核心文件用一次性脚本做正则替换。
6. **回归**：全量 `node --test` **281/281**（r2-incremental 10 例）；`RUN:01caf9305d77b70c` 与 `RUN:213ea8ddab5e24fa` 的固定输入均未触碰。R2 以本节口径正式收尾进入 R3。

## 失败与限制

1. 新组件没有真实正向策略锚点；`MANAGE/USE/ACCESS_USER_AUTH_INTERNAL` 均 ACL 使能，安全命题上限 `candidate`。本轮 0 candidate 是因为受控入口全部命中匹配的实际门禁，不是因为锚点合格。
2. live/replay 未做：无模型密钥、无第二组件外发授权；`budget.maxModelRequests=0` 使越界 live 在预算校验处失败。
3. 只覆盖 `IAccountIAM` 一个接口；`os_account` 其余 18 个接口（186 个 IDL 方法）与 1,025 个文件中除本接口/操作目标外的部分**未分析**，不进入分母。
4. 文档在五根事实快照之外，只能按 `dependencyReadRoots` + knowledgeVersion 的 sha256 固定；不是事实快照覆盖。
5. 测试并发回归已修复（崩溃 fixture 的 pid=-1 哨兵 + 真实 pid 仍做存活检查），默认并发连续 3/3 全量通过；仍保留一个生产边界：真实崩溃后若原 pid 被无关进程复用，`resume` 会保守拒绝直到该进程退出（安全优先，未绕过）。
6. E2 未实施优化，依据是自定瓶颈门槛未达到；若后续把全部 203 个 IDL 入口纳入，需重测 L1 重扫成本再决定。

## 下一动作

1. **第二接口能力**：为 `IAccount` 增加受控的成员调用/重载消歧操作 recipe 与 `HasAccountRequestPermission`/`PermissionCheck`/`CheckSystemApp` 门禁族，或改用门禁形状更简单的接口；先补正负样例，再 off→check，不以“0 结果”当完成。
2. **第三组件**：先在候选使能项中选定一条——(a) dsoftbus `SoftBusServerStub` 的 per-code 表派发入口模型，或 (b) 五根之外的 IDL 组件 + 补充事实快照（需 compdb 覆盖）。选择前先做 FULL-SCOPE-ROADMAP 清点，用分母驱动，不为凑数。
3. **冻结跨组件无种子实验**：第三组件路径可复算后，冻结正例/合规例/歧义例来源与分母，只给 scope/知识/预算盲跑，逐条复核提名、漏提名与错误排除；与给定变异体判定分开报告。
4. **live**：第二组件仍无外发授权，继续 off 与本地回放；真实 live 单独等待授权，不阻塞 1-3。
5. **性能**：任务数跨 33 后重测冷/热 off、索引、check；只有重复 L1 扫描成为瓶颈且同语料结论不漂移时才保留优化。

## 14. R3 第一轮：R2 核对与 IPC 精确入口基线（2026-10-26）

**阶段状态：部分完成，五项出口均未验收。** 本轮只读复核 R2，不重建 R1/R2：`r1-refresh/r1-scope-baseline.json` sha256 `df5f41e94a9fa656e7edbff6d494c0e325e87805371ba9bae6a6a78931b121a0`，生产代码 60,678、pending 75、非 C/C++ 3,407；`r2-shard-manifest.json` sha256 `b139c449…`，`r2-sa-chain.json` `dd208875…`，`r2-ipc-dispatch-probe.json` `5ead296a…`。派生快照 `sha256:337554b3294bb985a2185f4c3f7106782036783e090a9a5d3f5efd51850c7f` 的 `derivedFrom.kind=r2-incremental-promoted-v2`、929/439 files/productionFiles 和 toolVersions.treeSitter=0.21.1 仍在；旧消费 `RUN:09104ee71a49cd28`、CES IDL `RUN:01caf9305d77b70c` 只读 `check` 均 0 error / 0 warning。旧 run 未更改；CES 的 1/17 scoped excluded 仅作 IDL 回归，不推成 R3 新形态成果。

**本轮固定输入。** `K/policies/autonomy-r3-ipc-scope.json` 仅选择 `foundation/communication/ipc` 的精确生产 `OnRemoteRequest`，快照 `sha256:562bf189f6cb08f1bbdc4cb4838aae7f9e50ebcc8b54450b9cc875d18ddec5ca`；源码仓 HEAD `0b8767a26bbd03924b283e3dba31cda99d90c6b9`，工作树原已有测试文件和 `ipc/native/c/manager/include/ipc_skeleton_pri.h` 修改，未触碰它们，跨头文件构建影响尚未知。R1 刷新清单中 ipc 842 文件：247 production-code（header 126/C 32/C++ 71/Rust 17/ArkTS 1），另 306 test；R2 快照按其不同 role 规则为 518 files/229 productionFiles、5,851 functions、32,201 calls（函数/calls 上限 9k/50k，未截断）。这两种文件分母不可相加或互换。

`lib/autonomy/index.js` 对本 scope 增加精确函数名 opt-in，保留旧 scope 包含匹配语义；`test/r3-entry-index.test.js` 1/1 通过。新索引 reconciliation 通过，7 个入口（R2 探针还另列 6 个名称相近 helper，不计入口）；索引路径 `out/autonomy/index/sha256-562bf189f6cb08f1bbdc4cb4838aae7f9e50ebcc8b54450b9cc875d18ddec5ca/ca346f5e1a27cdfe5720890215a91875fbc215b6b6d78f20e2bc0cb60f9eed88/`。正式 off→report→check `RUN:ef2822b20f628476`：7 task/35 tool calls/0 model requests，report-model sha256 `bf9eb639a5851f65e0529d016ae74bbfb253affc1045f9f1201af0d0cd97ce1a`，语义哈希 `sha256:374b121cbbfa68495d6aa15ce5903015efc40c907b50527b86cb629d12df11c9`，0 error / 0 warning。7 条均 observation，缺 `delegation-incomplete`、`dominance-unproven`、`operation-unbound`；本 run 无适用知识套件、无 per-code 操作和双命题裁决，**只验收入口/工具路径**，不算 R3 出口 1/3/4 的纵向完成。

| 精确入口（`RUN:ef2822b20f628476` 的 entryRef） | 当前互斥状态 | per-code / 缺口 |
|---|---|---|
| `IPCAniStub` `ENT:45ee2148b14e4408` | 证据不足 | ANI 动态 `onRemoteMessageRequestSync`，code 与实际 ArkTS 对象方法未绑定 |
| `DBinderServiceStub` `ENT:2f59945925be2d19` | 证据不足 | 探针 `GET_PROTO_INFO→ProcessProto`、`DBINDER_OBITUARY_TRANSACTION→ProcessDeathRecipient` 可定位，但未入正式 operationRef/门禁/策略裁决 |
| `OHIPCRemoteServiceStub` `ENT:87df3bc13d7d4438` | 证据不足 | 回调/动态转发未绑定 code 边 |
| `IPCObjectStub` `ENT:5e9617a52370f593` | 证据不足 | `#ifndef CONFIG_IPC_SINGLE` 下 `DBINDER_OBITUARY_TRANSACTION` 分支与 `NoticeServiceDie`，变体未固定；探针 switch-unparsed |
| `DBinderCallbackStub` `ENT:55b88cab0049793d` | 证据不足 | 探针 `GET_PROTO_INFO→ProcessProto` 可定位，尚未入正式裁决 |
| `RemoteServiceStub` `ENT:991b057b272c4331` | 证据不足 | C++ `inner_->on_remote_request` 跨 cxx::bridge 到 Rust `RemoteStubWrapper`，动态 trait 实现对象未确定 |
| `NAPIRemoteObject` `ENT:a9625a2d7935f99c` | 证据不足 | JS 回调 code/对象与 handler 未绑定 |

上表分母是 7 个对象入口，**不是 per-code 边分母**；R2 已知 3 条 resolved dispatch 边也未获安全裁决。SA 仍为 4 profile 归属链 / 0 方法绑定（3 closed、1 closed-external），不能当作 4 个已裁决入口。Rust 样本 `interfaces/innerkits/rust/BUILD.gn` 中 `ohos_rust_shared_library("ipc_rust")` 以 `src/lib.rs` 构建，`RemoteServiceStub::OnRemoteRequest` 在 `src/cxx/remote_object_wrapper.cpp:142` 经 `src/remote/wrapper.rs` 调用 `dyn RemoteStub`，trait 声明位于 `src/remote/stub.rs`；当前 17 个 ipc Rust 生产文件全部不在 C/C++ 事实解析内，具体 trait 实现的入口/操作分母**未知**，不得用 0。全域 1,116 IPC 候选、其余 3,407 非 C/C++ 文件、75 pending、未固定编译变体和必要依赖继续留在总账。

**失败与下一动作。** 正式 off 的 `operation-unbound` 说明探针到任务/证据/报告的接线尚不存在，不能以 check=0 代替修复。下一轮先为 DBinder 的对象+code+可见分支+同对象 handler 建有界绑定并检验默认分支，再追 `ProcessProto` 的实际 UID/PID 门禁与具体主体/对象；对 `IPCObjectStub` 的条件编译分支记录变体失败或改善。另择 SA/NAPI 方法链和可解析的非 C/C++ 生产入口，各自冻结完整分母及正/反/未知测试。性能目前只有此 run `executed.wallMs=166`（不含冷事实/索引/report/check），**不能**据此作端到端优化结论；后续在同输入测分段成本及等价输出。无真实正向策略锚点，真实 precision/recall/independentAccuracy 仍为 `null`。本轮不更新路线图 R3 状态。

### 第二轮：形态候选核查与同输入局部成本（2026-10-26）

**验收/回归。** 修改共享入口索引后全量 `node --test` **282/282**，R2 `RUN:09104ee71a49cd28`、`RUN:01caf9305d77b70c` 只读 check 均 0/0。R3 正式基线 `RUN:ef2822b20f628476` 的 7 条仍是 operation-unbound observation，不因测试通过升级。预算与 scope 均离线，0 模型请求。

**真实 SA 候选，尚非受支持形态。** `base/security/access_token/services/tokensyncmanager/sa_profile/3504.json` 的 3504 / `libtoken_sync_manager_service.z.so` 经 `services/tokensyncmanager/BUILD.gn` 的 shared library 与 `token_sync_manager_service.cpp` 的 `MakeAndRegisterAbility`、`SystemAbility(3504)` 归属；`token_sync_manager_service.h` 同时继承 `SystemAbility` 和 `TokenSyncManagerStub`，`token_sync_manager_stub.cpp:33` 的三个 code 分支分别走 `GetRemoteHapTokenInfoInner` / `DeleteRemoteHapTokenInfoInner` / `UpdateRemoteHapTokenInfoInner`，再到服务方法 `token_sync_manager_service.cpp:112/139/169`。入口前有 `IsLocalCalling` 和 descriptor 检查，三个 Inner 在 root/native 组合失败时早退；`IsRootCalling` 在 `ATM_BUILD_VARIANT_USER_ENABLE` 分支恒 false。构建仅 `is_standard_system && token_sync_enable` 收进 group，宏 `EVENTHANDLER_ENABLE` 等另有变化；本轮没有固定完整编译变体、代码常量定义与具体调用方/对象的预期策略，因此 3 个可见 code 边均**证据不足**，不能把 R2 的 SA profile 归属链自动转成方法裁决。其它 3 个 SA 仍 metadata-only unbound，方法边分母未知。

**非 C/C++ 候选，尚非受支持形态。** ipc 的 17 个 Rust 生产文件中 `interfaces/innerkits/rust/BUILD.gn` 的 `ohos_rust_shared_library("ipc_rust")` 构建 `src/lib.rs`；C++ `RemoteServiceStub::OnRemoteRequest` (`src/cxx/remote_object_wrapper.cpp:142`) 调 `inner_->on_remote_request`，`src/remote/wrapper.rs` 的 `RemoteStubWrapper` 转发到 `dyn RemoteStub`，`src/remote/stub.rs` 声明 trait。具体 trait 实现未在固定 scope 内唯一确定，当前 L1 只解析 C/C++，Rust 操作/门禁分母未知。ipc 唯一 ArkTS 生产文件 `ipc/native/src/ani/rpc/ets/@ohos.rpc.ets` 声明 `RemoteObject.onRemoteMessageRequestSync` 转发可覆写的 `onRemoteMessageRequest`；C++ ANI 桥 `rpc_ani_class.cpp:148` 用字符串动态调用，实际子类/敏感操作未唯一定位。CES 的两个生产 JS 文件虽经 `es2abc_gen_abc`/`gen_js_obj` 纳入构建，`static_subscriber_extension_context.js` 的 `startAbility` 仅转发 `__context_impl__`，跨 native 目标和授权门禁未绑定。不能用这些文件扩展名或同名关系补齐出口 1。

**同输入热路径成本**（`out/autonomy/inventory/r3-ipc-*.json`，bench 外壳 wall/CPU/fs/maxRSS；同一 IPC 快照/scope，独立新 run 保留）：显式 index 414.6 ms / 61.34 MB read / 20.93 MB write / 246.0 MB RSS；7 task off `RUN:804071ce4aa28fc7` 507.6 ms / 126.44 MB read / 0.42 MB write / 239.6 MB RSS，report/check 后 0/0，语义哈希与基线相同；1 task off `RUN:445d7bfcf783a32d` 378.8 ms / 124.89 MB read / 0.06 MB write / 217.9 MB RSS，report/check 后 0/0。7 与 1 的差 128.8 ms / 1.55 MB read 是六任务的**一次非隔离估计**，不能外推为稳定吞吐；report 83.5 ms / 25.85 MB read / 20.6 KB write，check 95.7 ms / 21.91 MB read / 0 write。显式 index 即使已有索引仍重写；run 复用索引。冷事实、热事实、完整端到端及正式安全裁决尚未同输入测齐，无可验收的优化收益，暂保留现有验证。下一步仍是 per-code 正式接线、SA 变体固定及非 C/C++ 可定位操作与策略；本节不改变 R3 部分完成状态。

**R2 探针锚点复核失败（不得沿用其 codeDef）。** 组件内 `GET_PROTO_INFO` / `DBINDER_OBITUARY_TRANSACTION` 均同时定义于 `interfaces/innerkits/ipc_core/include/ipc_types.h:49/55` 和 `ipc/native/c/manager/include/rpc_types.h:32/35`。R2 探针为三个 resolved-dispatch 边都填了后一文件；但 `DBinderCallbackStub` 的 `dbinder_callback_stub.cpp:25` 显式包含 `ipc_types.h`，所以其 `GET_PROTO_INFO→ProcessProto` 边的 **handler 同对象定位可作线索，codeDef 源文件证据却不成立**。`DBinderServiceStub` 的定义可能经其头文件传递，尚未核实。上表两处“探针可定位”仅描述 R2 原始声称，不能读作本轮接受的完整派发证明；正式 R3 要求 include/变体绑定唯一的 code 定义或具名歧义，并核对默认分支。R2 原件只读，不回写探针。

### 第三轮：NAPI 注册→导出→回调绑定（2026-10-26）

**限定成果，R3 仍部分完成。** 新增 `lib/autonomy/napi.js` 的显式 opt-in 形状，由快照的 `metadata/napi` 注册行、同文件 `napi_module_register(&g_module)`、该对象 `.nm_modname`/`.nm_register_func=Init`、`Init` 内 `napi_define_properties` 与 `DECLARE_NAPI_FUNCTION` 调用行，按源码哈希核对后连接字面量导出名到**唯一**的同 NAPI 目录/命名空间生产回调；缺注册、源码漂移、索引截断、同名不唯一均不自动绑定。`index` 为唯一回调增 `registers` 关系，关系包含注册行、Init factRef、导出宏 factRef 和目标函数实体；不解析任意 NAPI 宏/动态 descriptor。旧 scope 的索引指纹和 v1 缓存保持不变，仅带 `napiBindings`/IPC 精确 opt-in 的新 scope 使用修订指纹。曾尝试全局 indexVersion=2，导致并行全量测试中旧 scope 同时重建索引的偶发内部错误（固定 `.tmp` 写入争用）；已收窄到 opt-in 指纹，原旧索引不覆盖。此失败及修正保留在本记录，不据单独重跑通过忽略。

**固定样本/分母。** access_token 源码仓 HEAD `fdfc93e722826f40ddc1f618a0ab123638e49f05`，既存 dirty 为 `frameworks/common/include/accesstoken_klog.h` 和两份 common Python 文件；本轮 NAPI 源文件未改。R1 刷新口径 446 生产代码（header 251/C++ 184/C 5/ArkTS 4/Python 2），R2 access-token shard `sha256:eedbad92272908c63ab64dc1396d3709647dba00f3cb16dadeefb7b59fecbd80` 是 929 files/439 productionFiles、4,861 functions/33,119 calls、3 个 NAPI 模块注册（另外 81 IDL/4 SA，不在此轮任务分母）。scope `K/policies/autonomy-r3-napi-scope.json` 仅对 `privacyManager` 一个模块的 literal descriptor 形状启用；`native_module.cpp:22-46` 的 `Init` 有 10 个函数导出，实际枚举 **10/10 唯一回调**，另外 `abilityAccessCtrl` 与 `ability.screenLockFileManager` 两个模块仍 metadata-only，导出/操作分母未知，不说 0。全域 497 个 NAPI 注册候选不受此样本代表。

| `privacyManager` 实际导出（`native_module.cpp:29-38`） | 当前互斥状态 / 缺口 |
|---|---|
| `addPermissionUsedRecord`, `startUsingPermission`, `stopUsingPermission`, `getPermissionUsedRecord`, `getPermissionUsedRecords`, `getPermissionUsedTypeInfos`, `setPermissionUsedRecordToggleStatus` | 各 1 条证据不足：唯一 NAPI 回调绑定，但 `operation-unbound`、`dominance-unproven`、`check-call-weak-only`；其中两个 get 导出共同绑定 `GetPermissionUsedRecords`，仍为不同入口 |
| `on`, `off`, `getPermissionUsedRecordToggleStatus` | 各 1 条证据不足：唯一回调绑定，但 `operation-unbound`、`dominance-unproven`、`delegation-incomplete` |

**正式路径。** `RUN:8c5332b0cec8e1b0` 的索引在 `out/autonomy/index/sha256-eedbad92272908c63ab64dc1396d3709647dba00f3cb16dadeefb7b59fecbd80/f61a2289d764f9d5590e3f3f6975eed628eb27291d29af2b801324d33724a42f/`，reconciliation 通过（10 `napi-export`、10 新 `registers`，原 metadata NAPI 3）。10 task/43 tool calls/0 模型请求，report/check 0 error / 0 warning，语义哈希 `sha256:abec2140124e1a2d91554041b2cceb1d0b02b4977ca27a62ed82a875befbde6e`，10 observation/0 candidate/0 excluded/0 finding。`test/r3-napi-binding.test.js` 真实成立、源码/注册缺失反例、同 owner 双候选未知 3/3；全量修正后 **285/285**。前两次 NAPI 探索 run `RUN:9359ae1f218ce488`、`RUN:6fa7b7c5b389d58c` 保留原件且只读 check 0/0，前者/后者同上述语义哈希。CES `RUN:01caf9305d77b70c`、IPC `RUN:ef2822b20f628476` 只读 check 0/0。

**安全链未闭合。** `startUsingPermission` 在 `permission_record_manager_napi.cpp:777` 排队 `StartUsingPermissionExecute`，其 `PrivacyKit::StartUsingPermission` 在同文件约 755 行；`on` 在该文件约 1117/1135 行同步调用 `PrivacyKit::RegisterPermActiveStatusCallback`。`PrivacyManagerService::RegisterPermActiveStatusCallback` (`services/privacymanager/src/service/privacy_manager_service.cpp:307-324`) 对 HAP 非 system-app 早退，又查 `PERMISSION_USED_STATS`，再进 `PermissionRecordManager`；这些是下一轮待验证的 operation/实际门禁线索，**尚未证明 NAPI→Kit→IPC→服务的精确 code、调用方 token 传递、对象和策略适用性**。当前 off 没有 NAPI 的 contractDeviation/securityDecision，不能把十条绑定变成 scoped excluded；`DECLARE_NAPI_FUNCTION` 宏定义/构建依赖也待核对。R3 出口 1/3/4 均未因该 run 验收，路线图状态不变。下一动作：优先选同步 `on` 作有界纵向路径，核对宏定义与 IPC 传播、`PERMISSION_USED_STATS` 的独立锚点及替代门；如果调用方身份无法闭合则记具名失败，继续 SA/IPC/非 C/C++。

### 第四轮起点：CES ArkTS→ANI→既有 IDL 候选（2026-10-26）

**定位但未接线，非 C/C++ 出口仍未验收。** CES 仓 HEAD `ba2ad592b863de66291719fa385a405769c2d88e` 且原已有多个测试及 CJ/NAPI 文件 dirty，本轮只读。`interfaces/kits/ani/common_event/BUILD.gn` sha256 `bc15e61d6c34a35e75ec7b2d8b5d58efba1f15bad0edd26801d317965b200189` 的 `generate_static_abc("common_event_manager")` 将 `ets/@ohos.commonEventManager.ets` 生成/安装到 `/system/framework/common_event_manager.abc`，native `ani_commoneventmanager` 依赖 CES innerkit。ArkTS 源 sha256 `1a6139f19bdf9f1c55842fd50c5e566ca9dafca813173848d0d9aa94ded1f9b0`，`removeStickyCommonEvent` 在 195/208 行有 callback/Promise 两个生产重载，均调用 `taskpool.execute(commonEventManager.removeStickyCommonEventExecute, event)`。ANI C++ 源 sha256 `1178732e4c687ae5765638bb18b78181aeb578b4890eacee94754ebd5b995936`，表项 713-714 行将该符号绑定 `OHOS::EventManagerFwkAni::removeStickyCommonEventExecute`，721 行 `Namespace_BindNativeFunctions`；函数 251-260 行调用 `CommonEventManager::RemoveStickyCommonEvent`，经 `frameworks/native/src/common_event_manager.cpp:140` 与 `frameworks/core/src/common_event.cpp:421` 的 proxy 到已有 `ICommonEvent.RemoveStickyCommonEvent` IDL。R1 刷新中 CES ArkTS 7/JS 2 个生产文件仍全是语言入口未分析，不能以这两个重载代表九文件或全域 3,407 非 C/C++ 文件。

本机已有 TypeScript 4.9.5 解析器；直接解析整个 `.ets` 有 20 个 ArkTS `native` 语法诊断，但 195/208 行两个函数 AST 均保留、函数范围内诊断 0。这是**局部解析可行性**，不是完整事实提取：尚无 `.ets` 文件事实、入口/调用 factRef、ANI 表与 IDL 的形式化关系、两个重载的独立任务分母及真实 off→report→check。下一动作在版本化新 scope/snapshot 中只支持该无诊断的 ArkTS export+taskpool 调用子集，显式登记其余语法诊断和构建变体；复用既有 IDL scoped excluded 只能在 ANI/IPC 主体与对象传递有证据时，不得把 IDL 结论直接继承给 ArkTS。若无法证明该跨语言链，保留两个重载证据不足并继续 SA/IPC。路线图不更新。

### 15. R3 第四轮：CES ArkTS 有界事实与入口索引（2026-10-26）

**本轮已核验，非 R3 形态出口。** `lib/facts/arkts.js` 用已安装 TypeScript `4.9.5-r10` 的 AST 仅提取无局部诊断的 `export function` 及其语法调用，调用保持 `name-only`；文件级全部解析诊断进入 `unsupported.jsonl`。新 `ces-r3-arkts` scope 使用独立快照 `sha256:dfef986b671e1f51be558bab1389cd69bf04529bd1355e6f2f444a99d72fb359`（CES HEAD `ba2ad592b…`、原有 44 dirty entries，295 源文件/149 production；构建投影 1801 entries、生成目录 25 中 12 不可见）。`snapshot.json` 固定 TypeScript 版本、`manifest.json` 的规则版本为 `K-1.1.0-arkts-subset`；旧 C/C++ scope 与快照标识不变。7 个 `.ets` 文件均有 file/quality 行，3 文件 partial，诊断分别 1/20/13；14 个无局部诊断的导出函数、91 条 ArkTS 调用事实，其中两个 `removeStickyCommonEvent` 分别在 195/208 行，`taskpool.execute` 调用在 199/213 行，`callee=null`。其他 ArkTS 声明、非导出函数及 2 个 CES JS 生产文件的入口分母**未分析/未知**，不能从 14 推断全文件覆盖。全快照 L1 295 files、3246 functions、19291 calls；调用去重 14 条，尚未归因到 ArkTS（其 91 条事实的定位键无重复），此项继续核对。metadata 派生层 19 IDL 方法、1 SA、2 NAPI 注册与 726 外部权限定义，未算作 ArkTS 已裁决入口。

**逐入口互斥登记。** `out/autonomy/index/sha256-dfef986b671e1f51be558bab1389cd69bf04529bd1355e6f2f444a99d72fb359/34993303b5296e50972d3a0c6beb04f560b3fd22c053c0c05a12337b514477b9/` 的全索引 36 入口（IDL 19/SA 1/NAPI 2/ArkTS 14）、14 `arkts-export` registers、reconciliation=true、functions/calls 无截断；审计 scope 仅接纳下列 14 个 ArkTS 候选，均为 **证据不足（observation）**，非 candidate、已裁决或不适用。每条的共同缺口为 `operation-unbound`、`dominance-unproven`、`delegation-incomplete`；`report-model.jsonl` 按 entryRef 逐条引用。代码位置均在 `interfaces/kits/ani/common_event/ets/@ohos.commonEventManager.ets`：

| 行 / 入口 | entryRef | 行 / 入口 | entryRef |
|---|---|---|---|
| 45 `publish` | `ENT:9da13b1bacb3def9` | 64 `publish` | `ENT:93f3561d157086de` |
| 83 `publishAsUser` | `ENT:e64c304ef998ecc9` | 101 `publishAsUser` | `ENT:55d48a65c2c6a263` |
| 120 `createSubscriber` | `ENT:87052d432030a9b0` | 135 `createSubscriber` | `ENT:4d2ccd76a108c722` |
| 150 `createSubscriberSync` | `ENT:e5f9d4b2aede33e2` | 155 `subscribe` | `ENT:7410df9fc5d8b542` |
| 172 `unsubscribe` | `ENT:f9670b15361b7580` | 195 `removeStickyCommonEvent` | `ENT:898578a38367afdb` |
| 208 `removeStickyCommonEvent` | `ENT:46c2f5ae47f80791` | 224 `setStaticSubscriberState` | `ENT:f0d58d7a18109f13` |
| 234 `setStaticSubscriberState` | `ENT:8da40da62092ef34` | 247 `setStaticSubscriberState` | `ENT:93f9183a3b909ebc` |

**正式路径与失败。** 首次 `RUN:c2336ae968a00347` 在 metadata 派生前执行（14/14 observation，语义哈希 `sha256:2b58f7e1…`），其后补全同快照 metadata，索引新增 22 个非 ArkTS 元数据入口，故最终 run 语义哈希变化，不是安全裁决变化。最终 `RUN:e5b81739be255021` off→report→check：14 task/42 question/70 tool calls/0 模型请求，14 observation、0 candidate/excluded/finding，0 error/0 warning；语义哈希 `sha256:b84c5e68fe18594a39e3b854e9aaae196ac3b5a8151a65809`。两 run 的只读 check 均 0/0；CES `RUN:01caf9305d77b70c`、NAPI `RUN:8c5332b0cec8e1b0`、IPC `RUN:ef2822b20f628476` 旧 run 只读 check 均 0/0。`test/r3-arkts-facts.test.js` 覆盖导出重载成立、非导出反例、局部语法错误未知及事实 schema；共享全量 **287/287**。初次全量测试因旧 CES `latest` 固定旧快照、通用事实测试取最新未建 metadata 的快照、`facts-v1` 未枚举 `arkts` 而失败，已修复并复测；版本载荷补记前的一次性快照 `6b9591a7…` 已核实归属后清理。

**未验收/下一动作。** 当前仅有 ArkTS 入口→本体→`taskpool.execute` 的可定位语法事实；`native` 声明含解析诊断，ANI 表 713-721 行、native 函数 251-260 行及旧 IDL 服务门禁尚未成为同一可复算的跨语言/IPC operationRef、调用方与对象证明。不能继承旧 CES 的 scoped excluded；安全与契约双命题、正/反/未知门禁测试均未通过新形态出口。继续验证 ANI 注册和 IPC 身份/对象传播；如无法闭合则保持此 14 条证据不足，并推进 NAPI 同步 `on` 和 IPC per-code 的独立路径。R3 五项出口仍未同时满足（形态纵向路径、跨组件逐入口分母、双命题、有界端到端性能、R4 移交表），`FULL-SCOPE-ROADMAP.md` 状态不变。此次仅有局部 wall：事实构建 2.79s、索引 0.37s、最终 off 0.27s；非同输入冷/热端到端 CPU/I/O/RSS 测量，不能作性能出口或收益声明。

### 16. R3 第五轮：IPC DBinder 逐 code 派发绑定（2026-10-26）

**已核验的派发事实，非安全纵向出口。** 复用 R2 `ipc-r2` 快照 `sha256:562bf189f6cb08f1bbdc4cb4838aae7f9e50ebcc8b54450b9cc875d18ddec5ca`（旧事实/归档只读）。`lib/autonomy/ipc-dispatch.js` 在新 `autonomy-r3-ipc-code-scope` opt-in 中以 C++ AST 定位同一 `OnRemoteRequest` 的唯一 `switch(code)`、case 及同 owner 唯一 handler；源码由 L1 哈希核对。构建证明限定 `ipc_single/BUILD.gn`（sha256 `6d0dabf5…`）与 `libdbinder/BUILD.gn`（`699b9afc…`）的源与 `ipc_core/include`，头文件 `interfaces/innerkits/ipc_core/include/ipc_types.h`（`920ab13f…`）也经 L1/策略哈希核对。R2 探针将 `GET_PROTO_INFO` 与 `DBINDER_OBITUARY_TRANSACTION` 错锚到 C 侧 `rpc_types.h:32/35`；这两处 C++ 目标应锚定 `ipc_types.h:49/55`。R2 产物保留原样，此修正仅进新索引，其他构建变体不外推。

**固定分母与逐项状态。** 新索引 `out/autonomy/index/sha256-562bf189f6cb08f1bbdc4cb4838aae7f9e50ebcc8b54450b9cc875d18ddec5ca/c7c1c9ab1b6121fff093aa738ba3a37162e424637be295521773e39db8bf5a94/` 对账 5851 functions/518 files/32201 calls、无截断，7 个生产精确名入口（相邻 6 个不算入口）+ 3 条 code 边、3 条 registers。下表 10 项均为 **证据不足（observation）**，每项在 `report-model.jsonl` 有独立 entryRef；不是 10 个不同对象，也不把派发已解析写作双命题已裁决。未选构建证明的 5 个对象保留已观察的形状，而非写成无入口。

| entryRef | 对象/行或 code | 派发/缺口 |
|---|---|---|
| `ENT:2f59945925be2d19` | `DBinderServiceStub:160` | `switch(code)` 2 边已绑定；对象入口本身仍无 operationRef |
| `ENT:55b88cab0049793d` | `DBinderCallbackStub:152` | `switch(code)` 1 边已绑定；对象入口本身仍无 operationRef |
| `ENT:adac3c75bd6631aa` | service `GET_PROTO_INFO:165` | `ipc_types.h:49` → 同对象 `ProcessProto:105`，调用行 166；operation/门禁未知 |
| `ENT:7d401429e4dd2015` | service `DBINDER_OBITUARY_TRANSACTION:169` | `ipc_types.h:55` → 同对象 `ProcessDeathRecipient:183`，调用行 170；后续 ADD/REMOVE 分支未闭合 |
| `ENT:a51b18defcae5ca4` | callback `GET_PROTO_INFO:158` | `ipc_types.h:49` → 同对象 `ProcessProto:87`，调用行 159；下游 `ProcessData`/`SendRequest` 未闭合 |
| `ENT:45ee2148b14e4408` | `IPCAniStub:148` | 构建证明未选；实际为 ANI 动态方法调用，无唯一 `switch(code)` |
| `ENT:87df3bc13d7d4438` | `OHIPCRemoteServiceStub:65` | 构建证明未选；无唯一 `switch(code)` |
| `ENT:5e9617a52370f593` | `IPCObjectStub:130` | 构建证明未选；目标 AST 不完整，`#ifndef CONFIG_IPC_SINGLE` 下存在条件 code 分支，变体未知 |
| `ENT:991b057b272c4331` | `IpcRust::RemoteServiceStub:142` | 构建证明未选；Rust/C++ 委托，无唯一 `switch(code)` |
| `ENT:a9625a2d7935f99c` | `NAPIRemoteObject:717` | 构建证明未选；目标 AST 不完整，动态 `OnJsRemoteRequest`，JS 方法目标未知 |

**正式 run/回归。** 初次 `RUN:a78a0feb20bc6de0` 后新增上述五项形状记录，索引指纹单独升至 `r3-ipc-code-v2`；最终 `RUN:ff4fbe6cc537a3fc` off→report→check：10 task/30 question/48 tool calls/0 模型请求、10 observation/0 candidate/excluded/finding、0 error/0 warning，语义哈希 `sha256:ff18c84be915d895b4518ac856e05ca22cb29c91b380be480434eb49dc59504d`。两 run 只读 check 0/0。`test/r3-ipc-code.test.js` 真实 3 边及缺定义、重复定义、异 owner、条件编译 AST 不完整的反/未知；旧 IPC 索引 6376 entities/32201 relations 的 ID+payload 逐行只读对照为 0 drift。初次全量回归因顶层加载 tree-sitter 原生绑定早于 Windows 平台拒绝而失败，已改成按需加载；最终全量 **289/289**，旧 `RUN:ef2822b20f628476`、NAPI `RUN:8c5332b0cec8e1b0`、ArkTS `RUN:e5b81739be255021` 的 check 均 0/0。

**尚未验收/下一动作。** 三条 per-code entry 的 binding 可复核，但现有 off 的 `operation-unbound` 为 10/10；两条 `ProcessProto` 仅有 weak check 线索，未证明调用方身份、对象、实际阻断、替代门、策略适用性或独立 `securityDecision`，不能宣称 IPC 形态完整支持。下一轮选择 service `GET_PROTO_INFO` 的具体 reply/session 操作及 `uid/pid` 拒绝分支，逐调用核对；若对象/策略仍无法闭合，保留具名不足并推进 NAPI `on`。全域 1116 个 IPC 候选与其他构建变体仍在总账未分析。本轮局部 index ~0.59s/off ~0.23s 不是同输入端到端成本；R3 五项出口仍未同时满足，路线图状态不变。

**同轮边界复审（替代上段的最终 run）。** 仅有同对象 handler 还不足以排除 case fallthrough；`ipc-dispatch.js` 现要求 case 的最后语句为 `break`，否则 `fallthrough-unknown`，并加入删除真实 `break` 的受控反例。索引指纹升至 `r3-ipc-code-v3`，新索引位于 `out/autonomy/index/sha256-562bf189f6cb08f1bbdc4cb4838aae7f9e50ebcc8b54450b9cc875d18ddec5ca/1e9d65731204b75ec6d1620de61ce10bc0b3fd83c239902445101b2e90041442/`；实际三条 case 均终止，10 项状态未变。**本轮最终** `RUN:0483e20da5b8cf2b` off→report→check 0 error/0 warning、10 observation/0 candidate/excluded/finding、48 tool calls/0 模型请求，语义哈希仍为 `sha256:ff18c84be915d895b4518ac856e05ca22cb29c91b380be480434eb49dc59504d`。先前 `RUN:ff4fbe6cc537a3fc` 与旧 CES run 只读 check 0/0；全量回归 289/289。此修正没有补齐 operation/门禁/策略，R3 状态不变。

### 17. R3 下一独立形态：NAPI `privacyManager.on` 纵向链调查（2026-10-26）

**调查产物，尚未接入正式裁决。** 现有 `RUN:8c5332b0cec8e1b0` 的 10 个 NAPI 导出入口仍为 10 个证据不足，未变成已裁决。`native_module.cpp:34` 的字面量 `on` 指向 `RegisterPermActiveChangeCallback`；该函数在 `permission_record_manager_napi.cpp:1117-1153` 同步调用 `PrivacyKit::RegisterPermActiveStatusCallback`（1135），`privacy_kit.cpp:199-202` 直达 `PrivacyManagerClient`，`privacy_manager_client.cpp:284-317` 在包装 callback 与校验列表后调用 `proxy->RegisterPermActiveStatusCallback`（310）。`services/privacymanager/idl/IPrivacyManager.idl:33` 声明 `[ipccode 9]` 的同名方法（sha256 `2331225a…`），服务实现 `privacy_manager_service.cpp:307-324`（`5547eb4e…`）取 `IPCSkeleton::GetCallingTokenID`，非 system HAP 返回 `ERR_NOT_SYSTEM_APP`，随后 `VerifyPermission(PERMISSION_USED_STATS)` 失败返回 `ERR_PERMISSION_DENIED`，最后才调用 `PermissionRecordManager::RegisterPermActiveStatusCallback`（323），后者经 `PermissionListFilter` 到 `ActiveStatusCallbackManager::AddCallback`。`IsSystemAppCalling`（540-544）读取 `GetCallingFullTokenID`；`VerifyPermission`（546-554）读取 `GetCallingTokenID` 并调用 `AccessTokenKit::VerifyAccessToken`，从服务侧看都是 IPC 调用方，而不是回调对象的 token。

独立 SDK 声明 `interface/sdk-js/api/@ohos.privacyManager.d.ts:310-334`（sha256 `956b9654…`）对 `on` 记载 `PERMISSION_USED_STATS`、非 system app 错误 202、`@systemapi`，可作为契约比较与限定主体的待审核来源；它不在当前 `access_token` 事实快照内，不能只凭文档转为实际安全证明。`DECLARE_NAPI_FUNCTION` 宏定义尚未在 access_token 头内定位，NAPI 编译目标的外部头依赖、IDL 生成代理的 code 9 实际收发、调用方身份跨 IPC 保真以及 callback 对象的归属仍须固定。虽然上述直线调用未见 `ResetCallingIdentity`，这不是跨生成代码的穷尽证明。下一动作在版本化新 scope/策略内补齐注册宏与 build、代理 code 9、调用方/对象传播和拒绝路径，给正常应用且持有权限的 scoped negative、system app 正/未知反例做双命题测试，再正式 off→report→check；不能把旧 10/10 observation 直接升级。另两个 access_token NAPI 模块的导出分母仍未知，全域非 C/C++ 与 75 个 pending 数不因本调查变化。R3 状态不变。

### 18. R3 第六轮：`privacyManager.on` 依赖链与逐入口分母复核（2026-10-26）

**已核验的有限事实。** `native_module.cpp:34` 的 `on` descriptor 经 `native_module.h:22,24`、`napi_context_common.h:22-23`、`napi_common.h:21`、`foundation/arkui/napi/interfaces/inner_api/napi/native_node_api.h:25` 引入 `native_common.h:98-101` 的 `DECLARE_NAPI_FUNCTION`，宏把第二参数放在 descriptor callback 位置；`native_module.cpp:118` 构造函数注册模块。NAPI `frameworks/js/napi/privacy/BUILD.gn:18-48` 编入三个源文件并依赖 privacy SDK 和 `napi:ace_napi`；SDK `interfaces/innerkits/privacy/BUILD.gn:22-72` 在 standard system 下编入 client 并依赖 IDL 生成 proxy；`services/privacymanager/BUILD.gn:17-91,124-205` 从同一 IDL 生成 proxy/stub，服务目标条件为 `is_standard_system && ability_base_enable == true`。这些跨组件材料不在旧 access_token 快照内，本轮仅做固定源码级依赖复核。

`IPrivacyManager.idl:33` 的 `[ipccode 9] RegisterPermActiveStatusCallback` 经 `build/config/components/idl_tool/idl.gni:53-61,212-244` 使用 C++ 生成器：`sa_cpp_code_emitter.cpp:297-316` 写方法命令枚举值 9，`sa_cpp_client_proxy_code_emitter.cpp:389-391` 用该枚举 `SendRequest`，`sa_cpp_service_stub_code_emitter.cpp:157-171,238-260,310-354` 用同一枚举派发、解包 callback 并调用服务方法。生成规则不是目标构建的 `*_proxy.cpp`/`*_stub.cpp` 原件，不能据此证明实际产物或跨 IPC 身份保真。sha256：IDL `2331225a4618aa21d8bac808eb7c9b9bddef2346c8964d30f2262ac9df178334`；宏 `cce98204dd6ef5465cdb6fad7e8f508546e3af9b43d871f7c0f413b9c66b7465`；`idl.gni` `1d8cce1d76bf478be278b9d7ca8165251d9712bbf626098fdddfb05a08ceca04`；三份 emitter 依次为 `5fca6e84…` / `73dcc3e3…` / `8b25bc20…`。

服务 `privacy_manager_service.cpp:307-324` 对非 system HAP 先返回 `ERR_NOT_SYSTEM_APP`，再对 `PERMISSION_USED_STATS` 验证失败返回 `ERR_PERMISSION_DENIED`，然后把 `IPCSkeleton::GetCallingTokenID()`、permList、callback 交给记录管理器；`540-554` 的 system 检查读取 `GetCallingFullTokenID`，权限检查读取 `GetCallingTokenID`。`permission_record_manager.cpp:1663-1671` 过滤列表后调用 `ActiveStatusCallbackManager::AddCallback`；`active_status_callback_manager.cpp:66-91` 储存 `registerTokenId/callbackObject_/permList_`，`136-159` 按 permissionName 筛选后回调。对象限定为**注册方提供的 callback 及其登记记录**，不推导只能观察自身 token 的事件。SDK `interface/sdk-js/api/@ohos.privacyManager.d.ts:310-334` 声明权限及错误 201/202；权限定义 `permission_definitions.json:938-945` 为 `system_basic / SYSTEM / system_grant / provisionEnable=true`，不能仅凭等级推出 normal 应用不可持有，亦无独立锚点证明跨 token 事件本应不可见。服务/记录/callback 管理器/SDK sha256 依次为 `5547eb4e…` / `c8f67140…` / `d86b284f…` / `956b9654…`；正式裁决前须在新 scope 固定完整哈希。

**逐入口账本。** `RUN:8c5332b0cec8e1b0` 的 `entities.jsonl` 有 10 个 `napi-export`，各有唯一同归属 handler；`report-model.jsonl` 是 10 observation，全部 `decision=insufficient`、`operation-unbound`。本轮深入的 `on` 列“证据不足”，其他九项虽有入口绑定但未追操作，列“未分析”。此覆盖分类不追溯更改旧 run 的出口。

| 导出（`native_module.cpp` 行） | entryRef | 状态与原因 |
|---|---|---|
| `addPermissionUsedRecord` 29 | `ENT:ba8d834438f88961` | 未分析：操作/门禁未追 |
| `startUsingPermission` 30 | `ENT:4c75232ea544c784` | 未分析：操作/门禁未追 |
| `stopUsingPermission` 31 | `ENT:840e415ab0057229` | 未分析：操作/门禁未追 |
| `getPermissionUsedRecord` 32 | `ENT:375cb2aa5dc4988c` | 未分析：操作/门禁未追，与下一导出共用 handler |
| `getPermissionUsedRecords` 33 | `ENT:8ad86c0dbe7fa2bf` | 未分析：操作/门禁未追 |
| `on` 34 | `ENT:c2705b986e6a3aed` | 证据不足：有注册操作和服务拒绝分支，生成产物/IPC 身份/策略适用性与正式双命题未闭合 |
| `off` 35 | `ENT:29546942a326277c` | 未分析：操作/门禁未追 |
| `getPermissionUsedTypeInfos` 36 | `ENT:fcedc5f878d8c8bd` | 未分析：操作/门禁未追 |
| `setPermissionUsedRecordToggleStatus` 37 | `ENT:0017395c43402533` | 未分析：操作/门禁未追 |
| `getPermissionUsedRecordToggleStatus` 38 | `ENT:904b598db5609bbc` | 未分析：操作/门禁未追 |

合计已裁决 0 / candidate 0 / 证据不足 1 / 未分析 9 / 不适用 0 = 10，仅是 `privacyManager` 导出分母。旧 run 本轮只读 `check --run=RUN:8c5332b0cec8e1b0` 为 10 task/10 report row、0 error/0 warning；**没有新 run 或双命题问题**，不验收 NAPI 形态出口。实际限制：没有目标构建的生成 C++ 原件，现有 `1.0.20-security-verdict` 只为有已接受 Builder norm 的 IDL 入口建双命题；不能伪造 norm 或把局部服务拒绝写成全入口安全。下一动作：先登记新架构版本，再把固定 SDK 契约、主体/回调对象、独立策略适用性接入真实 NAPI proof、report/check，做正/反/未知及替代门测试和正式 off→report→check；继续独立 IPC、ArkTS 形态。R3 五出口与路线图状态不变。

### 19. R3 第七轮：DBinder `GET_PROTO_INFO` 的操作与门禁边界（2026-10-26）

**真实入口与操作。** 保持 §16 的 code/header、build proof 和 10 项分母不变；已绑定的 `ENT:adac3c75bd6631aa` 在 `dbinder_service_stub.cpp:165-166` 调同对象 `ProcessProto:105`。后者 `114-120` 用 `reinterpret_cast<binder_uintptr_t>(this)` 查询 `SessionInfo`，空 session 即早退；`139-154` 仅在 `DATABUS_TYPE` 下把协议、`stubIndex`、serviceName、设备 ID、`localBusName`、session tokenId 和 descriptor 写入 reply，任何写失败则早退。`DBinderService::QuerySessionObject` 在 `dbinder_service.cpp:1264-1273` 仅按 stub 指针查 `sessionObject_`；`1145-1185` 的 session 来自 DBinder reply 并挂到 stub。故本轮可命名的操作是**向请求方返回该 stub 的 session/protocol 元数据**，对象为该 stub 映射的 session，而不是尚未证明的任意远端对象。源码 sha256：`dbinder_service_stub.cpp` `e741ec4643bc3a1254d2776bc059c76a9dc86d56596dda1909218c71a3fdb6d5`，`dbinder_service.cpp` `cadc0f5fbbf67b6dc28e4b164dd2e27a8739c5363d9de80ec06e37073e43b6bc`。

**门禁与未闭合依赖。** `ProcessProto:123-130` 从 `IPCSkeleton` 取调用方 uid/pid，任一负数则在 reply 操作前返回；这只证明“无效 uid/pid 被拒”，不证明某个有效调用方对 session 的授权。`132-137` 的 `CreateDatabusName(uid,pid)` 空结果也阻断 reply；`dbinder_service.cpp:812-820` 先按 uid/pid 生成名字，调用 `DBinderSoftbusClient::DBinderGrantPermission` 成功才返回。该 grant 是 reply 前的**另一潜在敏感操作/副作用**，不是一个现成的授权检查；故不能只凭 reply 给此入口指定唯一 `operationRef`。`ipc/native/src/core/dbinder/source/dbinder_softbus_client.cpp:28,43-83` 动态加载 `libsoftbus_client.z.so` 并 `dlsym("DBinderGrantPermission")`；当前快照没有该实现/变体的闭包。`DBinderServiceStub:39,75-80` 虽保存 `peerUid_/peerPid_`，本轮 `ProcessProto` 中没有看到与 IPC 当前 uid/pid 比较；不能由局部未命中断言全链无替代门或入口对任意主体可达。`ENT:a51b18defcae5ca4` 的 callback 同 code 路径另在 `dbinder_callback_stub.cpp:87-142` 获取调用方 uid/pid、SA sessionName，执行 `DBINDER_ADD_COMMAUTH` 并回写 reply，但下游处理方与对象授权仍未闭合。

**状态/失败/下一动作。** 两条 per-code 的操作现有源码级定位，正式 `RUN:0483e20da5b8cf2b` 的 `operationRef` 仍为空，10 observation/0 candidate/excluded/finding 未更改；本轮只读 `check --run=RUN:0483e20da5b8cf2b` 仍 10 task/10 report row、0 error/0 warning，未产生新正式 run。service `GET_PROTO_INFO` 保持证据不足，原因是有效调用方对 session 的可达/授权、softbus 动态依赖、构建变体及独立预期策略未核验；callback 同 code 亦不足。下一动作先找 stub 对象交付给客户端的调用链和 softbus 符号实现/调用主体，再决定可否形成限定安全命题；若不能闭合，保持不足并推进非 C/C++ ANI/ArkTS。不能把 uid/pid 有效性检查当作授权排除。R3 五项出口与路线图状态不变。

### 20. R3 第八轮：`privacyManager.on` 调用方门禁的受限识别（2026-10-26）

**已实现但尚未宣称形态支持。** `lib/autonomy/gates.js` 新增仅在 `gateVocabulary.privacyManagerShape=true` 时启用的服务方法形状：同文件/同 owner 的 `IsSystemAppCalling` 必须从 `IPCSkeleton::GetCallingFullTokenID()` 判断 system app，`VerifyPermission` 必须从 `GetCallingTokenID()` 验 `permission` 并在失败时返回 false；两者由事实快照哈希核对、完整函数窗口与具体调用方变量约束。服务方法的 `TOKEN_HAP && !IsSystemAppCalling()`、`!VerifyPermission(PERMISSION_USED_STATS)` 只在各自 `PrivacyError::ERR_NOT_SYSTEM_APP` / `ERR_PERMISSION_DENIED` 早退且在注册操作前时标为阻断。对明确 `tokenType=hap`、`isSystemApp=false` 且持有该权限的主体，第一门拒绝；system HAP 持权通过两门、缺权在第二门拒绝；native 非 HAP 不受第一门约束但仍需权限。未知 tokenType/system 状态返回 unknown，helper、常量、条件或拒绝形状不闭合则保留具名未知。该识别只适用于 `PrivacyManagerService::RegisterPermActiveStatusCallback` 的局部路径，不能证明 IPC 身份保真、其它条件/异步路径或全入口安全。

**测试与失败。** `test/r3-napi-gates.test.js` 使用 `sha256:eedbad92272908c63ab64dc1396d3709647dba00f3cb16dadeefb7b59fecbd80` 的真实服务函数与权限常量，覆盖上述正/反/未知：删除拒绝 return 不再阻断、helper 换成非调用方 token 或插入替代分支均未知、`&&` 改 `||` 不识别、权限常量未解析与 token 类型不明均未知。初跑 20/22：日志 `%{public}` 中花括号被误当结构，helper 误报 unresolved；只在 helper 形状检查前剥除字符串/行注释后，局部 22/22，全量 **291/291**。`RUN:8c5332b0cec8e1b0`、`RUN:0483e20da5b8cf2b`、`RUN:e5b81739be255021`、`RUN:ef2822b20f628476` 只读 `check` 仍各 0 error/0 warning。没有新正式 run 或报告语义变化；旧 scope 均未启用此形状。

**未验收/下一动作。** 当前 `1.0.20-security-verdict` 仍只为 IDL + 已接受 Builder norm 建双命题；NAPI 入口的 SDK 契约不是 Builder norm，不能伪造 norm 通过硬前置。先在架构指南登记**新版本**与无适用契约时的 insufficient/not-applicable 语义，然后固定生成器/SDK/权限定义/构建变体和跨 IPC 身份边，给真实 NAPI `on` 的入口→操作及主体/对象建立可复算 proof，接入 run、report、check 与正/反/未知正式测试。未证实生成产物、调用方传播与替代门前 `on` 仍为证据不足，10 项分母及 R3 路线图状态均不变；下一独立形态继续 ANI/ArkTS。

### 21. R3 第九轮：CES ArkTS→ANI→IDL 实际链的源码调查（2026-10-26）

**生产入口和跨语言链。** 固定 §15 的两条 `removeStickyCommonEvent` 导出（`ENT:898578a38367afdb`、`ENT:46c2f5ae47f80791`），`@ohos.commonEventManager.ets:195-218` 两个重载分别经 `taskpool.execute(commonEventManager.removeStickyCommonEventExecute, event)` 调用 `:42` 的 `export native function`；`:31` 声明 `loadLibrary("ani_commoneventmanager.z")`。`interfaces/kits/ani/common_event/BUILD.gn:38-72,74-88` 同时将 `ani_common_event.cpp` 编入该共享库，并把该 ETS 编为生产 `common_event_manager.abc`；源码 sha256 依次为 ETS `1a6139f19bdf9f1c55842fd50c5e566ca9dafca813173848d0d9aa94ded1f9b0`、C++ `1178732e4c687ae5765638bb18b78181aeb578b4890eacee94754ebd5b995936`、GN `bc15e61d6c34a35e75ec7b2d8b5d58efba1f15bad0edd26801d317965b200189`。`ani_common_event.cpp:713-714` 的 `ani_native_function` 把唯一字面量名及 `Lstd/core/String;:I` 映到 `OHOS::EventManagerFwkAni::removeStickyCommonEventExecute:251`，`:721` 向 `kitNs` 注册；`:730-748` 的 `ANI_Constructor` 查找 `L@ohos/commonEventManager/commonEventManager;` 并调用注册函数。`:257` 将 `eventIdStr` 交给 `CommonEventManager::RemoveStickyCommonEvent`。

`frameworks/native/src/common_event_manager.cpp:140-143` 委托 `CommonEvent::RemoveStickyCommonEvent`，`frameworks/core/src/common_event.cpp:421-435` 经 `ICommonEvent` proxy 调 `RemoveStickyCommonEvent(event, funcResult)`；`ICommonEvent.idl:40` 声明该方法。服务 `common_event_manager_service.cpp:577-604` 检查就绪、从 IPC 调用方 token 判 native subsystem 或 system app，再核 `COMMONEVENT_STICKY` 权限，失败均在操作前返回，最后传 `IPCSkeleton::GetCallingUid()` 给 inner manager；`common_event_sticky_manager.cpp:237-250` 只在记录的 `eventRecordInfo.uid == callerUid` 时擦除该 event。局部操作为**删除由调用方 UID 拥有的指定 sticky event 记录**，不能把这一点扩展成“可删其他 UID 记录”。native/core/service/sticky/IDL sha256 分别为 `a6bc1dce…` / `c45505d2…` / `5a6ac864…` / `ded37d81…` / `3587fda0…`，正式 scope 应固定完整哈希和变体。

**状态/失败/下一动作。** 本轮只读源码调查，不修改旧 `RUN:e5b81739be255021`（14 observation，两个入口仍为证据不足）；上节全量 291/291 与该 run 的 `check` 0/0 不等于跨语言裁决。当前事实层的 ArkTS 调用仍是 `name-only`、`callee=null`，ANI 表/构建目标未成为同入口的机器可复算绑定边。`taskpool.execute` 的线程/IPC 调用方身份传播、ANI 注册的目标运行库、IDL 生成 proxy/stub 产物与服务构建变体尚未闭合，旧 IDL `RemoveStickyCommonEvent` 的 scoped excluded 不得传递到 ArkTS。下一步用现有 TypeScript AST 和 C++ ANI 表建立**仅对固定 `taskpool.execute(namespace.nativeMethod, arg)` 形状**的唯一导出→native→函数边，负例覆盖同名异 namespace/重复表项/构建缺失与解析错误；随后验证身份/对象门禁并版本化接入双命题 off→report→check。未支持的其他 ArkTS 声明、JS 文件与全域语言分母不变，R3 路线图状态不变。

### 22. R3 第十轮：CES ANI 绑定边的独立验证（2026-10-26）

**验收边界。** 新增独立 `autonomy-ces-ani-scope.json`，只对快照 `sha256:dfef986b671e1f51be558bab1389cd69bf04529bd1355e6f2f444a99d72fb359` 中的两个 `removeStickyCommonEvent` ArkTS 导出启用 ANI 探针。`lib/autonomy/ani.js` 在原入口的 TS AST 中定位唯一 `taskpool.execute(commonEventManager.removeStickyCommonEventExecute, event)`，核对同 namespace 的 native 声明、固定哈希的 `BUILD.gn`、ANI 表唯一签名与同一生产 C++ 函数事实。opt-in 索引指纹 `r3-ani-v2`；新索引 `fb64e92f2778d54c76ec2011784a982c296012ee96d6d4743f692e5de91044da` 对账 36 入口实体（IDL 19、SA 1、NAPI 2、ArkTS 14）、3246 函数、295 文件、19291 calls，2 条 `bridges-to-native` 从上述两入口指向同一个 native function fact，未截断。它只证明此固定源/目标的静态绑定，**不等于已证明操作/主体/对象或安全裁决**。

**正反未知与正式路径。** `test/r3-ani-binding.test.js` 用真实两重载核对 table 行 713、native 行 251、唯一目标；同名声明搬到另一 namespace、taskpool 调用改为另一 namespace、重复 ANI 表项、缺构建目标、局部语法错误、缺 native fact 均退回具名未知。局部 5/5（含既有 ArkTS/索引测试），全量 **293/293**。`RUN:d59f202e05a0ddf2` 按新 scope 离线 off→report→check：14 task/42 question/70 tool calls/0 模型请求；14 observation、0 candidate/excluded/finding；`check` 0 error/0 warning，语义哈希 `sha256:b84c5e68fe18594a39e3b854e9aaae196ac3b5af37450aba556b5a8151a65809` 与旧 `RUN:e5b81739be255021` 相同，因为当前正式裁决没有消费 bridge。旧 run 只读 `check` 0/0。探索 run `RUN:f3ee8b70142400c9` 在更严格的同 namespace 核对及指纹升级前生成，保留原件，不作最终证据。

**失败与下一动作。** 探索 run 的 `report` 与 `check` 被同时启动，`check` 曾读到写入中的 manifest 而报一次 `checksum-mismatch`；写入完成后串行 `check` 0/0。后续同 run 的写报告与检查必须串行。当前 `operation-unbound`、`dominance-unproven`、`delegation-incomplete` 各 14；两条 ANI bridge 不能改变这些缺口。ETS taskpool 工作线程到生成 IDL proxy/stub、服务 IPC 调用方 token/UID 的身份传播和构建变体尚无可复算证明；服务权限门存在 native subsystem 的 `supportCheckSaPermission_` 条件旁路，不能泛化成统一拒绝。先固定生成器/构建/身份及对象链并按架构指南登记新版本双命题；若闭合失败，继续 NAPI 同步 `on` 或 IPC per-code 独立形态。其余 12 ArkTS 导出、非 C/C++ 全域量、SA/NAPI 与 5 条未闭合 IPC、75 个待定文件仍在原账本，R3 五项出口及路线图状态不变。本轮未测同输入冷/热端到端成本或 R4 批量吞吐，不能报性能验收。

### 23. R3 第十一轮：CES ANI 固定输入的分段成本（2026-10-26）

固定 §22 的 snapshot/scope、Windows Node v25.2.1、现成 `tools/autonomy-bench.js`，各阶段独立进程、串行执行；原始指标在 `out/autonomy/inventory/r3-ani-{facts-read,index,off-14,off-one,report,check}.json`。新进程读取事实 `AutonomyFacts.index()` 97.0 ms / 25.45 MB read / 93.4 MB sampled RSS；显式 index 377.8 ms / 47.41 MB read / 13.23 MB write / 215.7 MB RSS；复用该索引的 14-task off `RUN:24106fbb7ca3ced9` 592.8 ms / 91.37 MB read / 1.07 MB write / 223.6 MB RSS；同输入 1-task off `RUN:d4c86bb2de0eeabe` 390.4 ms / 87.96 MB read / 0.062 MB write / 198.0 MB RSS。14-task report 206.6 ms / 24.88 MB read / 0.034 MB write / 73.7 MB RSS；随后 check 215.7 ms / 22.67 MB read / 0 write / 72.6 MB RSS、0 error/0 warning。14-task 的显式 index→off→report→check **分段 wall 和 1.393 s**，合计 186.33 MB read / 14.34 MB write；事实读取已包含在 index/off 中，97 ms 不重复加总。`RUN:24106fbb7ca3ced9` 与 §22 完整 run 同语义哈希，1-task run 的只读 `check` 也为 0/0。

单次 14 与 1 task 的差值 202.4 ms / 3.41 MB read，即约 15.6 ms / 0.26 MB 每增加一 task；它只是**非隔离边际估计**，不等于 R4 吞吐。各进程的 CPU user/system、read/writeCalls、maxRSS 及命令原件均在六个 JSON；OS 文件缓存未清，所谓新进程事实读取不等于 OS 冷盘。`run` 内已生成报告，独立 `report` 命令是显式重渲染；上述 1.393 s 是实际 CLI 序列而非互斥内部阶段之和。同一作用域没有可比较的优化前后语义哈希及重复试验；run 已复用索引，显式 index 重建的 13.23 MB 写入不能自动当作 run 中重复写。暂不加缓存或删证据检查；下一轮对同输入冷/热、多个任务量及实际裁决路径重复测量后再决定。性能出口 4 仍未验收，其余 R3 状态不变。

### 24. R3 第十二轮：DBinder `GET_PROTO_INFO` 的跨组件门禁边（2026-10-26）

**局部操作与实际分支。** §16 已绑定的 service `GET_PROTO_INFO` (`ENT:adac3c75bd6631aa`) 落到 `DBinderServiceStub::ProcessProto` (`dbinder_service_stub.cpp:105-156`, sha256 `e741ec4643bc3a1254d2776bc059c76a9dc86d56596dda1909218c71a3fdb6d5`)：按本 stub 指针查询 SessionInfo，缺失则返回；从 `IPCSkeleton` 获取原始调用方 UID/PID，负值早退；随后 `CreateDatabusName(uid,pid)`，为空早退；仅 `DATABUS_TYPE` 分支把 session 的 stubIndex/serviceName/设备 ID/tokenId、该 bus 名及 descriptor 写回 reply。这里的可定位对象是**本 stub 关联的 SessionInfo 与发给原始调用方的协商 reply**；不把负值检查说成授权门，也不据 `peerUid_` 未比较即宣称越权。另一个 callback `GET_PROTO_INFO` 有独立 `GetSessionNameForPidUid` 与 `ProcessData`/远端授权路径，未沿用本结论。

**依赖和身份边。** `DBinderService::CreateDatabusName:812-822` (sha256 `cadc0f5fbbf67b6dc28e4b164dd2e27a8739c5363d9de80ec06e37073e43b6bc`) 调 `DBinderGrantPermission(uid,pid,busName)`；IPC wrapper `dbinder_softbus_client.cpp:28,55,67-84` (sha256 `c795836a03e6fe54667698504bfb6d71ec99ca3912e7f4d4f1b4613cf8d1e910`) 用 `dlopen("libsoftbus_client.z.so")`/`dlsym`，动态库缺失或非零返回会阻断 reply。固定源码向下为 dsoftbus `client_trans_socket_service.c:226-229` (sha256 `8ed966de4692bbba5056298108f02c0e7273b78825e7e42ceb61addcfe8ee694`)、`client_trans_socket_manager.c:913-928` (sha256 `db0eca5d7e55fa61468192a05f0f1b9bacac4cdf6b780e579e2172063211a3e1`)、standard `trans_server_proxy_standard.cpp:659-695` (sha256 `d0add564984a95fa7e0641929bf1239be7ca4034b53631c8c8488294149d6ed7`) 的 `SERVER_GRANT_PERMISSION` 第二次 IPC。服务 `softbus_server_stub.cpp:242,270-318,1439-1465` (sha256 `60d3f22501b9fb223b94eecec87d56eccd81c097d21b7c6768209804ddcd3822`) 将该 code 映到 `DISTRIBUTED_DATASYNC` 并在调用 handler 前检查第二跳 `IPCSkeleton::GetCallingTokenID()`，handler 再 `SoftBusCheckDynamicPermission`；真实 adapter `softbus_access_token_adapter.cpp:156-172` (sha256 `9dd7b646584c35a0aacd8f4290ae17f43815ffb3c1396048534d61af00f99fce`) 只接受 native、`GetNativeTokenInfo.processName == samgr`，虚拟 adapter (sha256 `0988ee4f45e0dbff58827712acf581f2fd623e658be04c46458c9d50b8f61a15`) 返回 denied。**第二跳受检的是发起 SoftBus IPC 的中间进程 token，而非传入 grant 的原始 `uid,pid`；两者不能合并为原始调用方身份门。**

**未闭合/下一动作。** 上述 dsoftbus 文件和动态库构建选项没有进入既有 `sha256:562bf189...` IPC 事实快照；`dsoftbus_access_token_feature`、standard/small/mini、`libsoftbus_client.z.so` 导出与进程归属仍需固定目标变体，原始调用方持有 DBinder stub handle 的前置能力及 SessionInfo 归属也未穷尽。没有独立策略锚点推出某个具体 UID 对本对象本应禁止，故当前不能判 candidate/finding 或 scoped excluded；旧 `RUN:0483e20da5b8cf2b` 只读 `check` 仍 0/0，10 项 observation 不变。下一步固定 standard 目标 GN 与第二跳进程身份、SoftBus 动态实现及 handle 获取链，建立两条独立主体变量的负例；若这些仍不闭合，明确保留 `external-dynamic-dependency`/`caller-identity-not-transitive` 缺口并推进 NAPI。R3 出口与路线图状态不变。

### 25. R3 第十三轮：CES SA 3299 方法级双命题（2026-10-26）

**边界与版本。** 新 `1.0.21-sa-method-verdict` 只对 `autonomy-ces-sa-method-scope.json` 的 `RemoveStickyCommonEvent` 启用（scope sha256 `7acf4e76194f056250aae8ee43beecb7f19d529899265499f513a6b01f07dbcf`）；旧 `1.0.20` 路径不加 SA 前置条件。事实快照仍为 `sha256:9bbb04f8f62e125dd747e2dc410b46a0634d50515bebac6248166b3483a5f29f`，CES 已发布 norm `sha256:d820f377…` 与原策略锚点未改。真实 `3299.json`（foundation / `libcesfwk_services.z.so`）经唯一注册 `common_event_manager_service_ability.cpp:25`、`OnStart:43-54` 的 `GetInstance`/`Init()==ERR_OK`/`Publish(service_)`，连到 `CommonEventManagerService : CommonEventStub`、GN 生成 `ICommonEvent` stub 和服务实现 `RemoveStickyCommonEvent:577`；跨组件 SA 定义/宏及三份 GN 的哈希在 scope 中固定。此为声明的 CES standard shared-library 变体，未实际构建或运行，不覆盖其他 SA。

**索引与正式出口。** 独立索引 `out/autonomy/index/sha256-9bbb04f8f62e125dd747e2dc410b46a0634d50515bebac6248166b3483a5f29f/4261eda0bcfd2a32b3bc99a437a0ca6be25c41034d2284c4333971c394fde79a/`：3232 函数/288 文件/19200 calls、19 IDL/1 SA/2 NAPI、无截断，新增 1 条 `sa-exposes-method` 且 reconciliation 成立。受审的独立分母为筛选的 **1 条 IDL 方法**，不是 22 条索引入口全部获裁决；metadata SA 自身仍非方法裁决入口。`RUN:958a100c25039b96` off→report→check：1 task/6 questions/8 tools/0 模型，1 scoped excluded/0 candidate/finding/observation，0 error/0 warning；语义哈希 `sha256:8419543b7e17745a57766efaec6564a5d6b29c650d2edc2941ce4b8f5f19294c`。proof 文件 sha256 `01ab6a05867b1bc0ab0431fbcc8969bccbce8d1da1ec961635339511ded2c0b1`；profile ref `M:9bbb04f8f62e:sa:969b67e7dc49b3fe`、服务方法 `F:9bbb04f8f62e:function:0d5b64b81fd44f43`、操作 `F:9bbb04f8f62e:function:60f19bb775b336f2` 均可回查。契约为 `COMMONEVENT_STICKY` compliant；实际门禁在 589 行 system-app/native、597 行对 `callingTokenId` 校验该权限；构造的普通应用虽持有文档权限，仍被前一门禁拒绝。`securityDecision=excluded` 仅反驳这一主体/对象/路径命题，不能推出整个 SA/IDL 接口安全或真实正向 finding。proof 的 `saMethod` 附 profile/注册/发布/实现位置，`check` 同 scope 复算。

**反例、回归与未完成。** `test/r3-sa-method-binding.test.js` 覆盖真实链、错误 SA ID、缺初始化成功条件、GN/依赖漂移、重复注册/实现与缺 profile；proof 层删除/破坏 SA 链或替换实现 fact 均保持 `sa-method-binding-unresolved`，不会继承纯 IDL 排除。相关 13/13、全量 **297/297**；旧 CES v2 `RUN:01caf9305d77b70c` 与 ANI `RUN:d59f202e05a0ddf2` 只读 check 均 0/0，旧语义哈希分别仍为 `sha256:ab52e62864823b33edec5e3a5782f4f4f8ab9604c95bdd702299edc74da0cd78`、`sha256:b84c5e68fe18594a39e3b854e9aaae196ac3b5af37450aba556b5a8151a65809`。新实现尚未跨第二个 SA 形状验证；其余 18 个 CES IDL 方法、metadata SA、NAPI、IPC 和 ArkTS 不因本轮被计入已裁决。无新 live、无产品源码改动。下一轮推进 NAPI 同步 `on` 的真实主体/对象与 IPC 边；不能闭合则登记具名不足并继续非 C/C++、IPC per-code。端到端同输入冷/热成本与 R4 移交表仍缺，五项 R3 出口未齐，路线图状态不变。

### 26. R3 第十四轮：NAPI `privacyManager.on` 下游复核（2026-10-26）

**只读证据，尚非新 run。** `native_module.cpp:34` 将 `on` 注册为 `RegisterPermActiveChangeCallback`；该函数在 `permission_record_manager_napi.cpp:1117-1151` 解析订阅者、排除重复后同步调用 `PrivacyKit::RegisterPermActiveStatusCallback`，结果非成功则抛 JS 错，成功后才登记本进程回调。Kit `privacy_kit.cpp:199-202` 转至 `PrivacyManagerClient::RegisterPermActiveStatusCallback`，client `privacy_manager_client.cpp:284-316` 包装 callback、取 proxy、限制权限列表大小，调用 `proxy->RegisterPermActiveStatusCallback(permList, callbackWrap->AsObject())`；IDL `IPrivacyManager.idl:33` 声明 `[ipccode 9]`。服务 `privacy_manager_service.cpp:307-324` 对 `IPCSkeleton::GetCallingTokenID()` 的 HAP 非 system-app、`VerifyPermission(PERMISSION_USED_STATS)` 失败分别早退，再把 calling token、列表和 callback 交给 `PermissionRecordManager::RegisterPermActiveStatusCallback:1663` / `ActiveStatusCallbackManager::AddCallback`。API 文档 `docs/en/application-dev/reference/apis-ability-kit/js-apis-privacyManager-sys.md:713-723` 对 `on` 声明 `PERMISSION_USED_STATS` 且限系统应用；它是契约材料，不单独证明某个回调对象的安全预期。

上述 NAPI/Kit/client/IDL/service/record/docs 文件 sha256 依次为 `d77558ff…`、`2bdd1986…`、`89b65358…`、`2331225a…`、`5547eb4e…`、`c8f67140…`、`a92fbbdd…`（完整值可按固定源码复算；`native_module.cpp` 为 `3d4a5fa9…`）。原 NAPI 离线 `RUN:8c5332b0cec8e1b0` 的只读 check 仍 0/0，10 个导出仍各为 observation，未重跑或改写。服务局部门禁的正/反/未知单测 2/2 在本轮全量 297/297 中通过，但不等于 NAPI `on` 已获得 operationRef 或双命题。**实际失败：**生成 proxy/stub 的 ipccode 9 请求、进程边界与原始 calling token 传递还未作为同一可复算绑定证明；`AddCallback` 中按订阅者对象的权限列表过滤/归属未纳入本快照的 operation/策略裁决。下一步固定 GN 生成/链接变体、IDL 生成器语义、callback 对象与身份传递，再决定是否新建 NAPI 专属双命题版本；若不闭合，保持 `on` 证据不足，推进 ArkTS→ANI 或 IPC 的独立路径。本轮没有新的 NAPI run ID，R3 状态不变。

### 27. R3 第十五轮：同输入 SA 成本与一次重复读取消除（2026-10-26）

**同输入测量。** 两轮固定 `sha256:9bbb04f8…`、`r3-ces-sa-3299-remove-sticky`、CES norm/锚点与 1 task，原件 `out/autonomy/bench/r3-sa-{index,off,report,check}-{a,b}.json`。显式 index→off→report→check 分段 wall（ms）A=312.4/330.6/136.3/309.5、B=313.7/331.5/138.3/326.3；分段和 1088.9/1109.8 ms，读 233.64 MB、写 13.28 MB。index 47.09 MB read / 13.17 MB write / 峰值约 208 MB；off 88.28 MB read / 0.10 MB write / 峰值 196–197 MB；report 24.20 MB read / 0.012 MB write / 峰值 72–73 MB；check 74.07 MB read / 0 write / 峰值 204 MB。各 JSON 保留 CPU user/system、read/writeCalls、RSS 与命令。相同输入的进程内分解另见 `r3-sa-stages-{a,b}.json`：fact open/index 85.3/82.0 ms、index build 81.8/86.9 ms、入口枚举+绑定 2.5/2.5 ms、知识/比较/proof 8.8/9.3 ms，均产生 `excluded`；这是局部耗时，不能再加到 CLI 总耗时。两轮 index 的 19214 relations/无截断及 `RUN:093d328e2393b34d`、`RUN:b9433140a43a76ce` 的语义哈希 `sha256:8419543b…` 一致，report/check 0/0。新进程不等于 OS 冷盘；未清文件缓存，不能称设备冷启动。

**局部优化与验收。** 读取探针 `RUN:6dc83b28a94ec0f1` 的一轮 off 中，run 归档 `relations.jsonl` 被读三次（约 32.19 MB）、`entities.jsonl` 三次（约 7.31 MB），主要是 report checksum、随后只为列出 `artifactRefs` 再算 checksum、最后因事件/manifest 改动做最终 checksum。只去掉中间一遍：`writeReport` 返回已经计算的文件名，run 用它列出 artifactRefs；最后一次全量校验与 check 原样保留。优化后 `RUN:4d50c80563c1a5c3`、`RUN:2906ed172e0635df` 的 off 读均为 75.03 MB（各少 **13.25 MB / 15.0%**）、写量同为 0.10 MB、语义哈希同上，独立 report/check 0/0；两轮 off wall 320.9/344.8 ms，对照 330.6/331.5 ms **无可靠 wall 收益**。优化后的 report/check wall 194.1/388.7 与 221.8/422.0 ms，高于先前两轮，受进程/缓存/系统负载影响，不宣称端到端加速。命令及 CPU/I/O/RSS 留在 `r3-sa-{off,report,check}-opt-{a,b}.json`。全量 **297/297**，旧 CES `RUN:01caf9305d77b70c` 和优化前 SA `RUN:958a100c25039b96` 只读 check 仍 0/0。没有削弱证据、checksum 或 scope 固定；1 task 的边际成本不能外推 R4。下一步需跨多个入口量测索引复用、check 固定成本与实际新形态吞吐；不为此加入通用缓存。五项 R3 出口仍未齐，路线图不变。

### 28. R3 第十六轮：R4 首批移交草表与未覆盖分母（2026-10-26）

**口径。** 以 `out/autonomy/inventory/r1-refresh/r1-scope-baseline.json`（角色闭合、60,678 生产文件、75 `production-pending`）及对应 `r1-entry-candidates.jsonl` 为固定选择输入，不重扫产品树。本轮没有新生产文件分类：75→75，关联本轮 SA/NAPI/IPC 的待定项变化为 0；待定不是零风险。全域非 C/C++ 生产文件 **3,407**（ArkTS 622/JS 351/Rust 370/Python 125/TS 1,620 等），文件覆盖尚不能转成入口分母；CES 14 个 ArkTS 导出 observation 不扣减 3,407 个待审文件。全域 IPC `OnRemoteRequest` 候选 1,116 仍是候选，已抽样 7 个对象仅有 2 个对象的 3 条 code 边具名绑定，均无双命题裁决；不把全域剩余写成 `1116-7` 个已验证缺口。

| 形态/样本 | 当前可用范围、变体 | 未支持与 R4 必带依赖 |
|---|---|---|
| IDL 既有 scoped 路径（IAM/IAccount/CES） | 已发布规范且目标入口操作/调用方门禁唯一时有真实 scoped excluded；CES v2 `RUN:01caf9305d77b70c` 17 入口仅 1 已裁决 | 同接口其余入口 observation，类型别名/重载、生成 stub 与目标变体逐条复核；不能复用一个方法的结论 |
| CES SA-backed `RemoveStickyCommonEvent` | `RUN:958a100c25039b96`，3299 foundation process、声明的 GN standard shared library/IDL stub，1/1 筛选方法 scoped excluded | SA metadata 自身非方法；access_token 4 个 SA 仍仅 profile 归属（3 closed + 1 closed-external），方法分母未知；全域 154 systemability 不以 1 个方法作覆盖率。samgr/safwk、IDL 生成器是必要依赖 |
| access_token `privacyManager` NAPI | 一个模块 10 literal exports 唯一 handler，`RUN:8c5332b0cec8e1b0` 10 observation；`on` 的服务门禁只读定位 | 10/10 尚无 NAPI 双命题；同 shard 另 2 模块 metadata-only，导出数未知；全域 497 NAPI 注册候选不是已绑定导出数。NAPI 宏、SDK、IDL generator、IPC 身份是依赖 |
| DBinder IPC per-code | `RUN:0483e20da5b8cf2b`，两个 `switch(code)` 对象共 3 条边、GN ipc_single/libdbinder 标准声明 | 3/3 observation，SoftBus 动态第二跳检查中间进程 token，不代替原始调用方；`IPCAniStub` 动态 ANI、`OHIPCRemoteServiceStub` 无唯一 switch、`IPCObjectStub` 条件分支 AST 不完整、`IpcRust::RemoteServiceStub` Rust/C++ 委托、`NAPIRemoteObject` 动态 JS 分派，这 5 个对象仍无可裁决 per-code 分母；IPC ABI/变体、SoftBus 库和 SessionInfo 归属是依赖 |
| CES ArkTS→ANI | `RUN:d59f202e05a0ddf2`，两条真实 `removeStickyCommonEvent` 重载到同 ANI native 方法；14 个导出 observation | 尚无贯穿 proxy/IDL/SA 的调用方和对象证明或双命题；CES 9 个非 C/C++ 文件及全域 3,407 文件继续登记，其他语言入口总数未知 |

**R4 首批十组件的实验顺序（不是已审计名单）。** 下表是同一刷新清单的词法候选量，均需先核实产品变体/编译图和依赖；每一步才决定后一步的工具限额。选择从已有快照的小/中样本、Rust/动态 IPC、跨组件与大样本逐步增加形态和规模，覆盖 base/foundation 两树。

| 顺序 | 组件（根目录末段） | 生产文件/非 C/C++ | 选择依据、先验边界 |
|---|---|---:|---|
| 1 | `common_event_service` | 152/9 | 已有 IDL/SA scoped 回归及 ArkTS 缺口，先校准逐入口状态 |
| 2 | `access_token` | 446/6 | 81 IDL、4 SA、3 NAPI 注册候选，检验多个入口宇宙与 ACL 依赖 |
| 3 | `os_account` | 332/0 | 203 IDL 方法候选和 IAM/IAccount scoped 负例，检验同组件未分析分母 |
| 4 | `init` | 325/10 | C 主导及 Python、SA/NAPI 条件，验证 shard 与系统类型 |
| 5 | `asset` | 102/54 | Rust 54 文件、小体量；现有 Rust 入口未支持，先做语言可行性门 |
| 6 | `ipc` | 247/18 | C/C++、Rust/ArkTS 与 7 `OnRemoteRequest` 候选，验证 per-code/动态边界 |
| 7 | `samgr` | 102/6 | SA/IPC 基础依赖及 Rust，避免把调用框架当已审计 |
| 8 | `data_share` | 176/5 | 无 IDL、4 NAPI/8 IPC 候选，检验无 IDL 元数据的入口发现 |
| 9 | `bundle_framework` | 876/39 | 2 SA/15 NAPI/37 IPC 候选，检验多变体和生成依赖 |
| 10 | `ability_runtime` | 2318/136 | 6 SA/82 NAPI/116 IPC 候选和 TS/JS/ArkTS，检验大 shard 拆分与吞吐上限 |

这十组件合计 **5,076** 个词法生产文件、**283** 个非 C/C++ 文件，仅为 R4 计划分母，不是 R3 已审计范围。必要外部边至少包括 `ipc/samgr/safwk`、`access_token` 权限定义、IDL 生成器、NAPI/ANI runtime、SoftBus 动态库及目标构建条件；声明依赖数量不是已完成的代码闭包。吞吐假设暂限定每 shard 保持无截断并以同输入 1/4/16 task 冷/热及完整 check 实测后滚动调预算；当前 SA 1 task 与 ANI 14 task 的不同形态计时不能给可信的跨组件可持续 rate，记 `unknown`。本表是可更新草表，出口 5 的完整移交仍依赖 IPC/非 C++ 真实纵向路径和构建适用性；R3 状态不变。

### 29. R3 第十七轮：CES ANI 快照的独立契约版本（2026-10-26）

**实际失败与修正。** 对 `sha256:dfef986b671e1f51be558bab1389cd69bf04529bd1355e6f2f444a99d72fb359` 执行 `knowledge propose --doc-set=ces-icommonevent` 首次失败 `EEXIST`：同一 API 文档和服务实现 sha256 令 proposalVersion 与旧 9bbb 快照的 `e2312d4f…` 相同，但提案含不同 snapshotId，不能覆盖旧归档。只为 dfef 快照在 `knowledge.js` 增加 `sourceSalt=ces-ani-r3-v1` 的来源描述符和独立 doc-set；旧描述符/已发布规范/旧 run 均不变。新 proposal `sha256:c064c00d4fe955f985f2fbaab58038a859c721f488fa8e333790bf0bbf5e69c8`（原件 sha256 `42d387c95e0a2da0522e4ba873b8c8a26d149a67117e53a77b06024ab5a74c8e`）与 review `K/reviews/ces-remove-sticky-ani-builder.json`（sha256 `00220a1a4390bdf185b0a68490e2055d5dcf62aa53914cb85d315b04ff0d7e96`）发布 `NORM:39d6004c0532bcc1`、版本 `sha256:e919ff121693aca7b6ade83b05426e9eb2434ac3e3d98bf354b1094cfc8e7088`（原件 sha256 `c73776a632a4b1ed3192ce1f736be84cdbf4b724e4dd0627c77ea8e6c9fc9a0d`），新快照 `loadKnowledgeSuite` 可重建并加载。review 只认可固定文档的 `COMMONEVENT_STICKY` 与服务 IDL 方法之契约映射，明确不证明 ArkTS 的调用方/IPC 身份或安全 finding。

**尚未贯通。** dfef 事实含两个 ArkTS `removeStickyCommonEvent` 重载、唯一 ANI native handler、`CommonEventManager::RemoveStickyCommonEvent:140`、`CommonEvent::RemoveStickyCommonEvent:421`、唯一服务实现 `:577` 与 IDL 元数据。源码 `GetCommonEventProxy:482-503` 用 SA ID 3299 获取 `ICommonEvent` proxy，CES ANI→native→core 的 GN deps 与生成 proxy/stub 声明均可定位；TaskPool 文档说明 worker thread，但未代替 IPC 进程身份传播和目标生成产物核验。新契约存在**不等于**这两个 ArkTS 入口获得 `operationRef` 或 `securityDecision`；本轮没有新的 ANI run ID，原 `RUN:d59f202e05a0ddf2` 仍 14 observation、只读 check 0/0。新旧 proposal 版本不同且文档/实现哈希相同的局部测试 3/3，全量 **298/298**；旧 CES `RUN:01caf9305d77b70c` 只读 check 0/0。下一动作：先登记新 run 语义，再把 ANI→native→core→IDL/SA 实现和原始调用方身份按固定源码/构建条件接到双命题；对缺边保留具名不足，正/反/未知测试与 off→report→check 后才可宣称非 C/C++ 形态出口。R3 状态和路线图不变。

### 30. R3 第十八轮：ANI 身份边复核与 TokenSync enum-code 派发（2026-10-26）

**ANI 的具名不足。** 固定的 CES ArkTS `removeStickyCommonEvent` 两个重载（`@ohos.commonEventManager.ets:195,208`，sha256 `1a6139f1…`）均在 `:199,213` 交给 `taskpool.execute`，ANI 表 `ani_common_event.cpp:713` 指向 native `:251-259`（sha256 `1178732e…`），再经 native `common_event_manager.cpp:140-143`（sha256 `a6bc1dce…`）→ core `common_event.cpp:421-434,482-503`（sha256 `c45505d2…`）按 SA 3299 取得 `ICommonEvent` proxy。GN 的 ANI→innerkits→core→生成 IDL proxy/stub 和服务依赖可定位；服务 `common_event_manager_service.cpp:577-603`（sha256 `5a6ac864…`）检查 caller token/system-app/`COMMONEVENT_STICKY`，用 `GetCallingUid()` 删除该 UID 拥有的 sticky 记录（`common_event_sticky_manager.cpp:237-247`，sha256 `ded37d81…`）。这定位了操作和对象，但**未**证明两个 ArkTS 调用的原始主体到服务端 IPC 身份无替换。TaskPool 固定实现有 `execute:909-940` 的 EAWorker 与 launch 两种路径（sha256 `df9d49c4…`），不能只引用 worker 文档；Binder 接收路径 `binder_invoker.cpp:783-829,1379-1386`（sha256 `d05264ff…`）从 transaction/driver 取 sender token，token 0 回退 UID，`ipc_skeleton.cpp:148-157`（sha256 `4a8c00e8…`）还在无 active invoker 时回退 self token。这些是条件化 IPC 机制，不代替目标生成 proxy/stub、TaskPool 两变体和发送边的固定证明。只读查找 `OpenHarmony/out/rk3568` 未找到 CES 生成 proxy/stub，未修改或生成产品 out。两个 ArkTS 入口状态均为 **证据不足**（identity/variant/generated-edge）；契约差异和安全双命题均未裁决，14 个导出中其余 12 个仍为未分析。旧 ANI `RUN:d59f202e05a0ddf2` 只读 check 0 error/0 warning、14 observation，不能作新裁决。

**独立 per-code 样本及失败修正。** 选中 `TokenSyncManagerStub::OnRemoteRequest:33`（sha256 `6e62cd2d…`），而非沿用 DBinder 的 SoftBus 中间进程门禁。`token_sync_service_ipc_interface_code.h:23-26`（sha256 `e0106d4b…`）从 `0x0000` 顺序定义三项 enum；`OnRemoteRequest:37-59` 先拒绝非 local calling 和错误 descriptor，三个 `static_cast<uint32_t>(TokenSyncInterfaceCode::...)` 分支分别到同对象的 `Get/Delete/UpdateRemoteHapTokenInfoInner:81,97,109`。每个 handler 在操作前以 `!IsRootCalling() && !IsNativeProcessCalling()` 拒绝；user 变体禁用 root 例外，其他变体有 UID 0 例外（`:62-123`），不能把任何 native 进程等同于特定授权服务。`services/tokensyncmanager/BUILD.gn`（sha256 `c64aa679…`）限定 `is_standard_system && token_sync_enable`，shared SA 依赖 `ipc:ipc_single`，`build_variant==user` 设宏；尚未实际构建/验证 profile→注册→发布与跨组件 token 对象效果。

受限 `tokensync-enum` 派发解析只接受上述唯一、顺序 enum、同对象唯一 handler、终止分支、显式 default 和固定 GN/source 哈希；不同 enum、数值别名、重复声明、跨对象 handler、fallthrough 和条件化 case 均不给 resolved。首次局部测试发现索引按实体 ID 排序而非源码顺序（仅测试断言问题），又发现旧 `defaultLine` 算法把 cast case `:47` 误认成 default `:56`（真实证据错位）；已修正并验证原 DBinder parser 不漂移。新 scope `K/policies/autonomy-r3-tokensync-code-scope.json` 对 R2 原快照 `sha256:eedbad92272908c63ab64dc1396d3709647dba00f3cb16dadeefb7b59fecbd80` 索引 4,861 函数/33,119 calls 无截断，入口 81 IDL/4 SA/3 NAPI/11 OnRemoteRequest/新增 3 ipc-code，reconciliation `ok=true`。其中只有本对象 3 条 code 边获绑定；其余 10 个 OnRemoteRequest 为 `build-proof-not-selected`、未分析，不从全域 1,116 候选扣为已审计。

正式离线 **`RUN:23214f0119cd1ce1`**（off、0 model requests）筛选 3 个 ipc-code task，3 observation/0 candidate/0 excluded/0 finding，语义哈希 `sha256:791c743041aa6c1140f75d9a6cdf09a45e381ed545a9634efc72f5bb075d52d9`；`check` 0 error/0 warning。它只是绑定探针，报告仍有 `operation-unbound`/`dominance-unproven`/`delegation-incomplete` 各 3，**不是** per-code 双命题或出口 1。最终局部新旧派发测试 4/4、全量 `node --test` **300/300**、`git diff --check` 通过；DBinder `RUN:0483e20da5b8cf2b` 和 ANI `RUN:d59f202e05a0ddf2` 只读 check 均 0/0。无新 live、无产品源码/旧归档修改，R3 五项出口仍未齐、路线图不动。

**下一动作。** 先核 TokenSync SA 3504 profile/注册、目标 build 变体和 `DeleteRemoteHapTokenInfo` 的实际效果及对象；在架构指南先登记与旧 `1.0.20/1.0.21` 隔离的新 run 语义，再接 per-code 操作、实际 local/descriptor/native/root 门禁和 caller/object 的有界正/反/未知双命题，跑正式 off→report→check。ANI 需固定 TaskPool 两路径与生成 IPC 发送边；无法闭合时保持上述两个具名不足而继续其他形态。用同输入补齐事实到 check 的端到端成本和逐入口账本后才评估 R3 出口。

### 31. R3 第十九轮：TokenSync 单 code 的双命题离线出口（2026-10-27）

**同输入成本补测。** 两轮相同 `eedbad…` 快照、verdict scope、1 code/5 问题，显式 index→off→report→check；原始 JSON 为 `out/autonomy/bench/r3-tokensync-{index,off,report,check}-{a,b}.json`，两轮正式 `RUN:30fc40c3ffa1d08a` / `RUN:7eb48140b927e54b` 均 1 excluded、同语义哈希 `sha256:37ba36bb…`、check 0/0。分段 wall A=594.9/465.4/164.0/368.5 ms，B=543.2/511.2/174.2/371.7 ms，和为 1592.6/1600.2 ms；各轮读 298,078,420 B、写 22,325,291 B，CPU user/system A=1344/500 ms、B=1310/562 ms，采样 RSS 峰值 333.1/332.3 MB（index）。index 72.49 MB read/22.25 MB write，off 117.93 MB read/69 KB write，report 34.83 MB read，check 72.83 MB read/0 write。诊断性进程内 `r3-tokensync-stages-{c,d}.json` 分别将事实 open 1.0/1.0 ms、事实表 index 148.2/157.2 ms、入口枚举 33.9/32.0 ms、绑定 0.43/0.56 ms、单条 proof 17.9/18.2 ms 分开；该诊断另读 50.05 MB，**不加到**上述 CLI 总量。没有清 OS 缓存，A/B 不是物理冷盘/热盘；单入口边际和多入口吞吐仍未知。首次 benchmark 漏 `index --snapshot` 返回 exit 2、无有效 index 数据，随即以固定 ID 重测；不能把这次失败算入成本。前轮 §27 已有一次实测减少 13.25 MB off 重读而无可靠 wall 收益；本轮未证明额外缓存或省略 check 有净收益，保留固定校验成本与复算边界。

**证明边界复核。** 追加重复 `MakeAndRegisterAbility` 的受控反例后，将注册、构造 SA ID 和 `OnStart` 的 Publish 校验从“存在”收紧到固定源码内唯一；相关 4/4、最终 run 与一条成本 run 的只读 check 均 0/0，语义哈希未变。变更后全量 `node --test` **305/305**。

**版本边界补验。** 通用 schema 为新问题状态容纳 `not-applicable` 后，check 另限定只有 1.0.22 的 `contract-deviation` 可用该值；隔离 run 中把 `security-decision` 篡成 `not-applicable` 会得到 exit 3 / `bad-enum`，原始 off→report→check 仍 0/0。相关测试 4/4，旧 1.0.21 `RUN:958a100c25039b96` 只读 check 0/0；补验后全量 `node --test` **305/305**。下一动作仍是其他 code/形态与多入口成本。

**最终复核：**集成测试加入后全量 `node --test` **305/305**；最终 `RUN:7ee2e10ac1d5ef70` 再次只读 check 0 error/0 warning，`git diff --check` 通过。下文的 304/304 是集成测试加入前的实测，不作最终计数。

**已验收的限定路径。** 固定 R2 access_token 快照 `sha256:eedbad92272908c63ab64dc1396d3709647dba00f3cb16dadeefb7b59fecbd80`，独立 verdict scope `K/policies/autonomy-r3-tokensync-verdict-scope.json`（sha256 `77764ceef9ecf68796fd80852b9f34a4cfc96cb09dd26454246aedaeaae9f0cc`）从三条已绑定 enum code 边只选择 `DELETE_REMOTE_HAP_TOKEN_INFO`。`1.0.22-ipc-code-verdict` 仅允许无知识套件的离线 off：3504 profile `M:eedbad922729:sa:1d18500c4f30b4ef`、GN standard + token_sync_enable/shared SA、唯一注册/初始化成功后 Publish、同对象派发 `:50-52`→handler `:97`、parcel `tokenID`→服务 `DeleteRemoteHapTokenInfo` 调用 `F:eedbad922729:call:694a27631df015dd` / 操作 `F:eedbad922729:function:9fb35edc4a1bca96`、本地 IPC/descriptor 和 root/native 身份 helper 均有固定源码/依赖哈希及源码形状校验。`ROOT_UID` 在非 user 分支仅 UID 0 有例外，user 分支返回 false；限定主体是 **local、valid descriptor、非 root、TOKEN_HAP**，对象只到 parcel 所指 tokenID 的 Delete 调用，不证明远端删除成功或其他主体/变体。无已发布适用文档契约，契约问题与 report `contractDeviation` 均为 `not-applicable`；安全问题反驳该主体到达操作的命题，`root-or-native@99` 的拒绝分支在读对象/调用前早退，`check-presence` 和限定 dominance 均 supported。没有独立入口/对象专属正向策略锚点，不产 finding。

正式 **`RUN:7ee2e10ac1d5ef70`**（off、1 task/5 questions/5 tools/0 model requests）经 report→check 为 1 scoped excluded / 0 candidate / 0 observation / 0 finding、0 error / 0 warning，语义哈希 `sha256:37ba36bbc04c7cdc1dca12f4070d11e19c457ad66649d703f849d6aa9cbf509a`；proof 文件 sha256 `2db540152d9272ad58bd02396f6e1ff51939d70b90f7afd7a161969fcc67bb92`。`check` 重算 scope、profile/依赖、proof、tool answer、契约/安全/check-presence/dominance assessment、operationRef 与报告。受控文本变异覆盖原件 excluded、去掉拒绝早退的 candidate（仍受 doc-only 锚点上限）、错误绑定/enum/identity/门禁/profile/GN 的 insufficient；集成测试在隔离根目录重跑真实入口 off→report→check 并拒绝 live。局部 4/4、全量 `node --test` **304/304**（集成测试加入前）、`git diff --check` 通过；旧 SA `RUN:958a100c25039b96`、DBinder `RUN:0483e20da5b8cf2b` 只读 check 均 0/0。

**本轮失败与修正。** 初版证明器只对比 handler fact，enum 定义漂移仍可能被接受；补 `resolved-dispatch`、定义行/调用行/默认分支校验，正反未知测试回归。中间 `RUN:3551c7577fbeb81b` 虽 check 0/0，却沿用通用 `dominance-unproven`；`RUN:5c06f823b1249881` 删除了该矛盾，但其 `check-presence=refuted` 来自旧通用词表漏掉 root/native helper。两 run 原件保留为失败迭代，不作为出口；新版本只在证明器有实际门禁证据时覆盖 generic 问题。首次全量 303/304 因 eager 加载 tree-sitter 抢在 Windows 平台预检之前，改为按需加载后相关 5/5、全量 304/304。未修改旧 run、产品源码或产品 out，未做 live、提交或推送。

**逐入口与下一动作。** TokenSync 三条 per-code 分母：`GET_REMOTE_HAP_TOKEN_INFO` `ENT:bfae7b5999c6acf6` 为**未分析**（§30 只证明派发，尚无操作/门禁/主体双命题）；`DELETE_REMOTE_HAP_TOKEN_INFO` `ENT:a793f6ff3ce5f65e` 为**限定 excluded**；`UPDATE_REMOTE_HAP_TOKEN_INFO` `ENT:e494a230a67b0879` 为**未分析**（同前）。同快照另 10 个 `OnRemoteRequest` 是 `build-proof-not-selected`、未分析；SA profile 是注册元数据而非独立方法入口，不适用该方法裁决。单 code 验收不等于全 IPC 形态或 1,116 候选已审计。下一轮应复核本轮的 schema/版本边界和 report/check 反篡改测试，补 TokenSync 另外两个 code 的逐项裁决或具名不足；继续独立 NAPI/ANI 的生成 IPC 身份边，不能闭合就保留证据不足；再用同输入测事实→索引→入口→裁决→check 总成本和全范围账本。真实正向效果指标继续 `null`，R3 五项出口未齐，路线图状态不变。

### 32. R3 第二十轮：Asset Rust 入口与 CES 多入口成本（2026-10-27）

**Rust 调查，未验收。** `r1-refresh/r1-files.jsonl` 逐行重算 `@ohos/asset` 为 102 个生产代码文件（Rust 54/C 6/C++ 17/头文件 25），组件待定 0。HEAD `b3f4c98a3e6ebcd4a1b75aa4fe765eebb35d559e`，GN/Cargo 等原有 dirty，本轮未改产品源码。SA 8100 profile 指向 `libasset_service.dylib.so`；`services/core_service/BUILD.gn` 声明 Rust shared library 和 `ipc_rust`、`safwk`、`samgr`、C++ `asset_os_dependency`。`lib.rs:207-220` 成功 publish，`:277-279` 的 query 经 `execute!` 调 `operations::query`；`stub.rs:40,109-156` 的 RemoteStub 校验 descriptor、解析 code/map/调用者，七个 `IpcCode` 分支中 `Query:141` 调 `stub.query(&calling_info,&map)`。`frameworks/ipc/src/lib.rs` 的 enum 位于 `impl_enum_trait!` 内，首项为 `ipc::FIRST_CALL_TRANSACTION`，宏展开和数值未核定。

`operation_query.rs` 的 query 在数据库查询前以 `?` 调 `check_arguments`→`check_system_permission`；`permission_check.rs` 对含 `Tag::UserId` 的请求先查 system HAP、`INTERACT_ACROSS_LOCAL_ACCOUNTS`，再限调用 UID 范围，失败早退。`process_info.rs` 从 `Skeleton::calling_uid()` 与 C FFI `GetCallingProcessInfo` 建主体；`calling_info.rs` 将请求 `Tag::UserId` 用作目标用户；C++ `access_token_wrapper.cpp` 从 IPC calling token 检权限。上述 stub/lib/query/permission/process/calling/C++/GN/profile/IPC enum 的 sha256 前缀依次为 `5bd9e30f`、`bf58611f`、`c4ea2a80`、`ed304378`、`6afa6547`、`2c06efb3`、`3a3a4237`、`0e03f9a7`、`d26529a2`、`d0a72fce`（原件可重算）。这只是源码线索，尚无正式绑定、跨 FFI 身份/变体和双命题 proof。

**失败与分母。** 已装 Node 只有 tree-sitter C/C++，Cargo 缓存无 `syn`/`tree-sitter-rust`；`rustfmt` 可检查语法但无结构化 AST，`rustc -Zunpretty=ast-tree` 需 bootstrap 且输出不稳定调试文本。现有 `parse.js` 会把 `.rs` 误当 C++；故没有接事实层或产生 Asset run。七个服务 code 均无正式入口事实，`Query` 为具名**证据不足**（可见局部链，正式绑定/FFI 身份与变体未闭合），另六个**未分析**；54/54 Rust 文件仍为未支持语言分母。下一步须取得可靠语法树或实现带反例的受限解析器，接 facts→index→discovery 与版本化 proof；若不可得，继续独立 NAPI/ANI。

**17 入口同输入成本。** 固定 CES `sha256:9bbb04f8f62e125dd747e2dc410b46a0634d50515bebac6248166b3483a5f29f`、v2 scope/budget、已发布 `d820f377...` 知识及 CES anchors；`out/autonomy/bench/r3-ces17-{index,off,report,check}-{a,b}.json` 保留 CPU/I/O/RSS。纯函数 facts.index/index.build/入口绑定 A=91.97/108.28/1.65 ms、B=95.87/90.64/1.60 ms，33,417,989 B read、0 write，17 入口 13 resolved/4 suspect、19,213 relations、对账成立。正式 `RUN:84b8d3cdce5f2a14` 与 `RUN:078d84827239a17c` 均 17 task/86 questions/107 tools/0 模型，1 excluded/16 observation、0 candidate/finding，语义哈希同历史 CES v2 `sha256:ab52e62864823b33edec5e3a5782f4f4f8ab9604c95bdd702299edc74da0cd78`；各 report/check 0 error/0 warning。两轮 off/report/check wall A=565.1/189.1/393.1 ms、B=591.6/185.7/381.4 ms，分段和 1147.4/1158.7 ms；每轮合计读 178,876,523 B、写 2,057,876 B，sampled 峰值约 209 MB。17 task 内摊 off 约 33-35 ms/入口，不可跨不同 SA scope 直接相减作边际；纯函数索引不另加到正式 run 总时。check 仍读约 75 MB，未见可凭此新增跨进程缓存的净 wall 收益。

**事实阶段边界。** `fact-snapshot --scope=ces-r1 --check` 首次在沙箱因 Git ownership 报 `repo-head-missing`（失败 bench `r3-ces17-fact-check-a.json`）；进程内临时 safe.directory 后 `CHECK-OK`（`r3-ces17-fact-check-a-retry.json`，859.2 ms/100,316,872 B read），但产出 `sha256:ed62de81...`，与正式 run 的 `9bbb04f8...` 不同：两份 snapshot 描述的已见区别是 `toolVersions.clang` 为旧 `15.0.4`、本机 `null`。此事实成本**不能**相加冒充同输入全链；旧快照/run 未改，新 ID 只是未建 L1 的检查副产物。下轮先固定工具版本再量事实→索引→入口→裁决→check 和 1/4/16 task 边际。R3 五项出口未齐，非 C/C++、逐入口对账、同输入完整事实成本及 R4 移交仍待补；路线图不变。没有新 live、提交或推送。

### 33. R3 第二十一轮：ArkTS 同步 ANI 条件绑定与 IDL 生成探针（2026-10-27）

**事实和入口。** `lib/facts/arkts.js` 对 `export default namespace` 作等长语法归一后由 TypeScript AST 提取，解析规则按语言分别取版本。新快照 `sha256:1a2bc61ea705f9a01a25a8a8dd9cce2be6b3dd1e55b14f75e7aaea4be7754cc4` 的 manifest 规则 `K-1.1.1-arkts-default-namespace`；933 个目标文件、4 个 ArkTS 生产文件，索引 114 entries / 33,222 relations、无截断且对账通过。`@ohos.privacyManager.ets:278` 的 `on` 在 `:280` 同步直调 `onExecute`，经唯一 ANI 表项 `privacy_manager.cpp:907` 条件绑定到 `RegisterPermActiveStatusCallback:315`；仅在注册返回 `ANI_OK` 时成立。声明诊断 9 条仍在 unsupported。`abilityAccessCtrl.ets` 仍有 16 个语法诊断、0 函数事实；`permissions.ets`、`PermissionRequestResult.ets` 未选作可裁决入口，不能因文件进入快照而计已审计。

**正式离线 run 与失败。** 独立 `K/policies/autonomy-access-token-arkts-direct-scope-v2.json` 的 `RUN:46ae635ab3a15b53` 走 off→report→check：1 task/3 questions/5 tools/0 模型请求，1 observation、0 candidate/excluded/finding，语义哈希 `sha256:edb5f98de7472ecdbaccbd012adee559748cb546715f91ef16f9820a1e20c888`，check 0 error/0 warning。通用路径仍给 `operation-unbound`、`delegation-incomplete`、`dominance-unproven`，**条件化绑定不等于双命题裁决**。初版快照 `sha256:463a8b56…` 错沿用旧 ArkTS 规则号，`RUN:c888583cecfc4834` 虽 check 0/0，仅是失败迭代，原件保留只读。错调用、重复表项、缺初始化/构建和源码漂移均有反/未知测试；本轮最终全量 `node --test` 309/309。旧 CES ANI `RUN:d59f…`、TokenSync `RUN:7ee…`、SA `RUN:958…` 和初版 run 只读 check 均 0/0；`git diff --check`、新文件 BOM/U+FFFD 检查通过。

**15 个导出逐入口账。** `privacyManager` 的 `on` 为 1 个**证据不足**（有条件绑定，操作/跨 IPC 主体与对象/实际门禁/策略适用性未进入 proof）；其余 14 个**未分析**：`addPermissionUsedRecord` 2 个重载、`stopUsingPermission` 3、`startUsingPermission` 3、`getPermissionUsedRecord` 2、`getPermissionUsedTypeInfos` 1、`setPermissionUsedRecordToggleStatus` 1、`getPermissionUsedRecordToggleStatus` 1、`off` 1。15=1+14，重载按独立真实入口计；其他 ArkTS 文件和变体仍在全范围未支持/未分析账本，不以 0 代替未知。

**离线生成探针与下一动作。** 仓内 SDK host `idl 1.0` 经 Debian WSL 从真实 `IPrivacyManager.idl` 重生成 proxy/stub，仅写 `out/autonomy/idl-probe/r3-privacy-manager/probe.json` 及其五个哈希固定的生成文件；code 9 proxy 同步 `SendRequest`，stub 解包 `permList`/callback 并派发服务方法。它不是产品 `out` 的实际生成目标，尚未证明目标构建等价、3505 standard + `ability_base_enable` 的 GN 链、Binder 传递的 caller token、callback 对象归属或安全策略锚点。下一轮把生成模板、GN、IPC 身份及服务 `RegisterPermActiveStatusCallback:307-324` 合并成可复算 proof；不能闭合则保留不足并推进独立形态。随后测同输入事实→索引→入口→裁决→check（§32 的事实探针输入不同不可相加）、补逐入口账与 R4 移交。R3 五项出口仍未齐，路线图不变；未做 live、产品源码/out 修改、旧归档修改、提交或推送。

### 34. R3 第二十二轮：同输入事实至裁决/check 完整成本（2026-10-27）

**可加总的 TokenSync 实验。** `access-token-r2` 源集合/compdb/工具版本（本机 clang=`null`）形成新快照 `sha256:5b484c6ba49e0b68eb85af1650d806164efe9092021776d00aa55d56e68730e3`，929 个目标文件、439 生产文件；`CHECK-OK`，L1 4,861 函数/33,119 calls，metadata 81 IDL/4 SA/3 NAPI。独立 `K/policies/autonomy-r3-tokensync-verdict-scope-v2.json` 只更换快照和 scope 标识，保留原 code/构建/依赖哈希；索引 5,892 entities/33,124 relations/102 entries、reconciliation ok、0 截断，从三条 TokenSync code 中选择 Delete 一条。两轮完整 `fact-snapshot --check`→`fact-build --jobs=4`→`fact-metadata`→`index`→`off`→`report`→`check` 的逐进程原始指标在 `out/autonomy/bench/r3-tokensync-e2e-{fact-snapshot,fact-build,fact-metadata,index,off,report,check}-{a,b}.json`。A/B run **`RUN:7c583a5d5d336026` / `RUN:1f5d9a05407a821c`** 均 1 task/5 questions/5 tools/0 模型、1 scoped excluded/0 candidate/observation/finding；语义哈希同为 `sha256:402de4b954273ab80f39fbe759ca948e00deea1a7d479428bd9a963dd4222331`，proof 文件 sha256 同为 `a635b39e6ec4cabdfc4f0f3463aaa1e124015cdb09405da4821774ab37f955c9`，report/check 0 error/0 warning。B 重建事实后 A 的只读 check 仍 0/0；变更快照导致与旧 `RUN:7ee2e10ac1d5ef70` 的 fact/entry ID 不同，不要求跨快照语义哈希相同。

| 阶段 | A wall ms / read MB | B wall ms / read MB |
|---|---:|---:|
| snapshot/check | 1250.4 / 272.87 | 1216.5 / 272.87 |
| L1 build | 4010.4 / 99.27 | 3917.8 / 99.27 |
| metadata | 431.0 / 5.16 | 441.2 / 5.16 |
| index | 496.5 / 72.50 | 568.1 / 72.50 |
| off（含入口/绑定/裁决） | 502.0 / 117.95 | 456.6 / 117.95 |
| report | 146.7 / 34.84 | 158.0 / 34.84 |
| check | 347.4 / 72.84 | 348.6 / 72.84 |
| **顺序分段和** | **7184.3 / 675.43** | **7106.8 / 675.43** |

每轮写 121.78 MB，采样 RSS 峰值 398.54/398.45 MB（L1 build）；事实三段 5691.8/5575.5 ms，占分段和约 79.2/78.5%，完整 check 固定约 348 ms/72.84 MB。各 JSON 另有 CPU user/system、read/write calls；读写是 Node fs 包装统计，RSS 是采样峰值；未清 OS 缓存，A/B 只是连续独立进程，**不是物理冷盘/热盘**。单 code 的 off 时间不能外推为 17 入口边际或 R4 可持续吞吐。全量 R2 重建成本仍是主要部分；已有 R2 文件级增量实验对不变/单文件修改有收益，本轮没有实测出额外缓存或省略报告复算的净 wall 收益，保留源码哈希、范围/变体及 check 校验，不为这一单入口加缓存。

**CES 对照的失败边界。** 新 `sha256:ed62de813f07adf703537a6326c9e06b1f4dc571a8a57e959d46f415296afa3a` 的 `K/policies/autonomy-ces-icommonevent-scope-v3.json` 实测 `CHECK-OK`、288 目标文件、19,200 calls、19 IDL、索引 19,213 relations/无截断。未传知识/锚点的 `RUN:e9595a1eca11e7c1` 17 task/51 questions/76 tools，17 observation，report/check 0/0；`r3-ces17-e2e-*.json` 七段共 4791.5 ms、335.73 MB read、75.21 MB write、采样峰值 288.54 MB，**仅代表无知识扫描**。随后按旧 run 参数传已发布 `d820f377…` 知识与 CES 锚点时，`r3-ces17-e2e-off-a-fixed.json` exit 2 / `authorization-review-invalid-or-stale`：知识被旧快照固定，不能在新快照上冒充已授权双命题；未改知识归档或旧 run。§32 的 17 入口正式裁决成本仍只覆盖索引至 check，不与本轮新事实成本相加。

**身份与下一动作。** PrivacyManager code 9 的 GN `idl_gen_interface`→proxy/stub、SA 3505 的 standard+`ability_base_enable` 声明及服务早退形状可定位；但 `BinderInvoker::GetCallerTokenID:1379-1386` 在 token=0 时回退 UID，`IPCSkeleton::GetCallingTokenID:148-157` 在非 local 时返回 0、无 active invoker 时返回 self token。离线重新生成不证明产品目标二进制等价，也不能无条件推出 ArkTS 进程 token 到服务端的原始身份；`on` 仍为证据不足，不新建裁决。下一步先以明确变体/发送边和 callback 对象建立可复算 proof；若不能闭合，保留该失败，尝试独立 Rust Asset 或其它非 C/C++ 真实入口。同步补 R4 表的新增 ArkTS/TokenSync 状态、同形态 1/4/16 入口边际和可持续吞吐；75 待定、未支持语言/依赖不转 0。R3 五项出口未齐，路线图状态不变；未做 live、产品源码/out 修改、旧归档修改、提交或推送。

### 35. R3 第二十三轮：同快照任务边际与 R4 移交表修订（2026-10-27）

**任务边际，仅扫描。** 固定 CES v3 `ed62de81…` 快照、同一 scope/预算、17 个已发现 IDL 入口，分别限制 1/4/16 task，另以 §34 的完整 17 task 作端点；`RUN:99f9b2f0cb8e8205`、`RUN:7700481bc1d21ed4`、`RUN:97a0860b21109a90`、`RUN:e9595a1eca11e7c1` 均 off→report→check 0 error/0 warning、0 模型。原始 `out/autonomy/bench/r3-ces17-e2e-{off,report,check}-{1,4,16}.json` 和 §34 的 `-a.json`：off wall 383.8/416.9/571.9/584.1 ms，三段合计 714.9/768.4/928.1/951.6 ms，check 166.0/178.7/171.0/175.0 ms；off read 74.22/74.80/77.18/77.40 MB。1→4 增 33.2 ms、4→16 增 155.0 ms（off），这些批内差分不是独立任务真实边际或安全 verdict 吞吐；各 run 仅 1/4/16/17 observation，受 `max-tasks` 排除的入口仍未分析。知识套件不接受新快照，故**不**以这些数替代 §32 有知识的 17 入口裁决成本。新 scope 与旧 scope 的结构对比仅在 policy/scope/snapshot ID 和说明文字不同，绑定/门禁字段相同；JSON、`git diff --check`、UTF-8 BOM/U+FFFD 检查通过。无代码逻辑改动，本轮沿用 §33 的 309/309 全量测试结果。

**R4 移交修订（取代 §28 对后续新样本的旧状态，不改原表）。** IDL CES 17 入口 1 限定 excluded/16 observation，SA 3299 方法 1 限定 excluded；NAPI privacyManager 10 literal exports 仍 10 observation、其他模块导出分母未知。TokenSync 3504 的三条真实 enum code：Delete 1 scoped excluded（`RUN:7c583a5d5d336026`、`RUN:1f5d9a05407a821c` 复算）；Get 与 Update 各 1 未分析，另 10 个同 shard `OnRemoteRequest` 为 `build-proof-not-selected`，不从全域 1,116 候选扣减成已审计。DBinder 两对象三条边仍 3 observation，其余五个动态/条件派发对象未闭合。CES ArkTS 14 导出中两个重载证据不足、12 未分析；access_token privacy ArkTS 15 导出中 `on` 1 证据不足、14 未分析，另外三个 ArkTS 生产文件未获形态支持。上述数是不同入口宇宙，不能相加成全域唯一入口分母。

`asset` 102 个生产文件中 54 Rust 文件、七个服务 code：`Query` 的局部源码链为证据不足，另外六 code 未分析；仍无正式 Rust 事实/入口/run。Windows `rust-analyzer` 仅是 rustup shim，当前 stable toolchain 报 unknown binary；经批准只读检查 Debian WSL 未发现 `rustc`/`cargo`/`rust-analyzer`/`tree-sitter-rust`，已有 Node/Cargo 缓存亦无 Rust 语法包。`access_token/frameworks/common/permission_check.py` 虽被 R1 归入生产代码，但 GN 是构建期 `action("permission_definition_check")`，且 `ohos_indep_compiler_enable` 变体可不依赖它；不能用构建期输入校验冒充设备运行时非 C/C++ 入口。全域非 C/C++ 3,407 个生产文件、75 个 `production-pending` 本轮无分类改变，未知语言入口数和构建/必要依赖闭包仍为 unknown。§28 的十组件顺序与 5,076 文件/283 非 C/C++ 仅是计划，未变；R4 可持续 rate 仍 unknown，单 code 完整重建约 7.1 秒/轮不是跨组件吞吐率。

**下一动作与出口。** 最小补证是：在不改产品源码/out 的条件下固定 Rust 结构化语法来源并把 Asset `Query` 的 caller/object/FFI/操作和门禁接到新版本 proof，或固定 ANI 同步发送身份/对象变体并做 ArkTS 双命题；两者不能闭合时逐项记录失败并调查另一独立运行时形态。补非 C/C++ 正/反/未知正式 run、抽样入口/变体账本和可持续吞吐后再复核五项出口；目前出口 1 和 5 未齐，路线图 R3 不更新。没有新 live、提交、推送或旧归档修改。

### 36. R3 第二十四轮：仓内 `syn` 的 Asset Rust AST 派发探针（2026-10-27）

**离线工具来源与修正。** §32/§35 的“无 Rust 解析器”只针对已装 Node/Cargo 缓存：`OpenHarmony/third_party/rust/crates/syn` v2.0.48、`proc-macro2` v1.0.92、`unicode-ident` v1.0.14 实际在仓内。`tools/rust-ast-probe/` 以这三项 path/patch 依赖和 Windows rustc 1.96.0 `cargo --offline` 编译，target 仅在 `out/autonomy/rust-ast-probe-target/`。初版误在禁用 `printing` feature 时引入 `syn::spanned::Spanned`，编译失败；改用标识符自身 span 后通过。随后一项正例夹具误写裸 `query()`，按“只接受 `stub.query()`”的规则失败，修正夹具后 4/4 测试通过（含真实 Asset 7 边、无/多调用未知、坏语法拒绝）。这两次均为工具失败迭代，不是产品 finding；旧产品源码和旧归档未动。

**可回查语法产物。** `node tools/rust-ast-probe/record.js` 从 R1 刷新清单 `sha256:7e38162b3ceaad59f0174ce15963c8c15590f1f6841a717d6f5e6572373c4f82` 取 `@ohos/asset` 的 54/54 Rust 生产文件，全部经 `syn::parse_file`，产出 `out/autonomy/rust-probe/asset-ast-inventory.json`（sha256 `36a28a70de829011d6ecae5ee5e599599534ddaecbf3e163a36c7b8231ce27c3`、UTF-8 无 BOM/U+FFFD）。文件逐项源码哈希、工具源码/二进制/Cargo.lock 哈希与 551 条带行号语法行都在产物中。`frameworks/ipc/src/lib.rs:41-53` 的宏输入有 7 个 `IpcCode` 成员；`services/core_service/src/stub.rs:128-149` 有 7 个同名 match arm，各恰有一个直接 `stub.<method>` 调用，`Query:141→stub.query:141`。其他文件的 `impl_enum_trait!` 行不当作 IPC 分母；551 行还包含 `#[cfg(test)]` 等未解析变体，**不是** 551 个生产函数。宏展开、IPC 数值、唯一目标服务实现、GN/SA/FFI 与实际安全门禁尚未作为机器证明入账。

**Query 的局部路径与不足。** 真实 `AssetService::query` 在 `lib.rs:277-279` 用 `execute!(operations::query, calling_info, query)`，宏定义 `:237-254` 在创建用户目录后调用 `$func`；`operation_query.rs:174-195` 在数据库查询前以 `?` 调 `check_arguments`，后者 `:161-172` 最后调用 `check_system_permission`。`permission_check.rs:30-53` 仅当请求含 `Tag::UserId` 时拒绝非 system HAP、缺 `INTERACT_ACROSS_LOCAL_ACCOUNTS` 权限或 UID 用户范围不符；C++ `access_token_wrapper.cpp:32-64` 从 IPC calling token/full token 判 system HAP 和权限。`CallingInfo::build:58-85` 把请求 UserId 用作目标用户，而 `ProcessInfo` 由 IPC caller 与 C FFI 构造。上述只是源码定位，尚未由 AST 证明 `?` 的早退、宏语义、跨 FFI caller/object 与目标变体/外部依赖；`Query` 仍**证据不足**，其他六 code 仍**未分析**，没有 Asset off→report→check 或双命题。下一动作在版本化 Rust 事实/入口里固定这些边与失败反例，接入正式 proof/check；若变体或身份不能闭合，继续保持不足而不降低命题。全域 Rust 370、非 C/C++ 3,407 和 75 待定不因解析 54 文件而扣为已审计；R3 路线图不变。无新 live、产品源码/out 修改、提交或推送。

### 37. R3 转交勘误：Asset AST 最新产物与门禁失败（2026-10-27）

§36 是初版 551 行产物；随后探针加入 `execute!`、`?`、尾调用语法边和 `asset_gate` 判形。本轮离线 `cargo test --offline` **5/5**、`cargo build --offline` 与 `node tools/rust-ast-probe/record.js` 均通过。当前 `out/autonomy/rust-probe/asset-ast-inventory.json` 为 **830** 条语法行、54/54 Asset Rust 生产文件、7 条真实 enum→stub 派发边，sha256 `ce9aadeb590eec37ba0ba404b2608d65e4486037e31e77220073925a41f99dfe`，无 BOM/U+FFFD。§36 的哈希不再代表现行工具；830 行含未解析 `#[cfg(test)]`，不是生产函数分母。

**实际失败。** `permission_check.rs:30` 的唯一门禁记录是 `asset-gate-unresolved`，不是 `asset-gate`。源码 `:36` 的初始化为 `CString::new("ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS").unwrap()`，当前 `asset_gate` 的 `permission` 局部值只接受直接 `Expr::Call`；新增的字面量、`Skeleton::calling_uid()`、`get_user_id(uid)?` 校验尚无真实成功形状与变异反例测试。下一步先修 AST 判形并补拒绝早退/非调用方/对象反例，再核宏、GN/SA 8100、FFI 身份和目标变体，接版本化正式事实→入口→裁决 off→report→check。没有新正式 run；Query 仍证据不足，其他六 code 未分析，R3 五项出口与路线图状态不变。新对话顺序与其他形态/分母见 `R3-EXECUTION-GUIDE.md` §0.1；不以探针测试通过宣布非 C/C++ 支持。转交时只读 `check` 复算 `RUN:7c583a5d5d336026`、`RUN:1f5d9a05407a821c`、`RUN:46ae635ab3a15b53` 均 0 error/0 warning；ArkTS run 仍有 3 个缺失问题结果，不能算双命题裁决。

### 38. R3 第二十五轮：`asset_gate` 修复、反例测试与产物重录（2026-10-27）

**接手项完成，仅探针层。** `tools/rust-ast-probe/src/main.rs` 的 `asset_gate` 经新增 `cstring_init` 接受 `permission` 局部值为 `CString::new(lit)` 直接调用或单一 `.unwrap()` 包装（真实 `permission_check.rs:36` 形状）；`.expect(..)` 等其他包装保持不识别。测试从 5 增至 **8/8**：真实成功形状与两种正例（`.unwrap()`/直接调用）；11 条变异反例覆盖拒绝早退消失（三处 `return log_throw_error!` 各去 `return`）、门禁极性反转（`!CheckSystemHapPermission()` 去非）、条件漂移（`>` 改 `>=`）、非调用方身份（`Skeleton::calling_uid()` 换 `self_uid()`、`CheckPermission` 参数换其他对象、helper 加参）、对象错位（权限串换 `ohos.permission.OTHER`、`Tag::UserId` 换 `Tag::Secret`）、`get_user_id(uid)?` 去 `?`，全部保持 `asset-gate-unresolved`；另以真实 `permission_check.rs` 断言 `asset-gate` 恰 1 条、无 unresolved。`record.js` 增加门禁自校验（`asset-gate` 唯一且名 `UserId->system-app,permission,uid`，否则 `asset-gate-unresolved` 报错不产出），limits 注明门禁形状已查、dominance/FFI/裁决仍未证。

**产物。** `cargo test --offline` 8/8、`cargo build --offline` 与 `node tools/rust-ast-probe/record.js` 均通过；新 `out/autonomy/rust-probe/asset-ast-inventory.json` sha256 `6007bed9fa1a59f67fcde69351c49a35d21833ed96c8072384b5f5f61d8bfc7e`（§37 的 `ce9aadeb…` 仅作历史），54/54 文件、830 条语法行、7 条 enum→stub 派发边不变，`asset-gate` 行定位 `permission_check.rs:30`；工具源/记录器/二进制/Cargo.lock 哈希随产物固定。830 行仍含 `#[cfg(test)]` 等未解析变体，不是生产函数分母。

**边界。** 本修复只证明探针能识别该门禁形状；`Query` 仍**证据不足**（宏 `execute!` 展开、`?` 早退语义、GN/SA 8100、C++ FFI IPC calling token、请求 `Tag::UserId` 对象与替代门、版本化双命题 off→report→check 均未做），另六 code 仍**未分析**，无新正式 run；不以探针测试通过宣布非 C/C++ 支持，R3 五项出口与路线图状态不变。下一动作按 §0.1：核 `execute!`、`?`、GN/SA 8100、FFI 身份、对象与替代门的源码/构建证据，登记新架构版本后接正式双命题。

### 39. R3 第二十六轮：Rust 非 C/C++ 双命题纵向贯通、同输入成本与出口复核（2026-10-27）

**固定输入与事实。** asset 仓 HEAD `b3f4c98a3e6ebcd4a1b75aa4fe765eebb35d559e`（§32 的 GN/Cargo 等原有 dirty 未动，无产品源码/out 修改）。新事实快照 `sha256:e3284b8879ffcd644db5fb0b7783169e6bae4d29897ea091a42132958f0ec280`（`scope-asset-r3`：base/security/asset，155 目标文件/C 与 C++ 头/.rs 全含，规则版本 `K-1.2.0-rust-ast-probe`，`toolVersions.rustProbe=652feee2cf0c5d693284ec296ef00982730725334a489435d5b89db639cebc05`）；`fact-snapshot --check` 通过，L1 995 函数/2,057 调用（Rust 函数 654、探针边调用 427，`AssetService::query`/`query`/`check_arguments`/`check_system_permission`/`on_remote_request`/`start_service` 均唯一，`check_arguments`×7 为各操作文件同名函数不混淆）、unsupported 31；metadata SA 8100 行 `M:e3284b8879ff:sa:b4e49f0af091f97a`（asset_service/libasset_service.dylib.so）、NAPI 1（`security.asset`，metadata-only）、CES 8、外部 permission_definitions 726、IDL 0（asset 无 .idl，R1 的 IPC 候选即 `impl_enum_trait!` 派发）。探针产物 `asset-ast-inventory.json` sha256 `e5f3fd4a1593c2d5931be85f9ffc268a3de19210b7e51827285808c1ed7d365a`（966 行：method 233/function 246/try-call 242/tail-call 165/execute-call 7/ipc-enum 58/ipc-arm 7/ipc-call 7/asset-gate 1，无重复键；58 条 enum 行含其他 `impl_enum_trait!` 用途，不当 IPC 分母）。

**探针判形与格式扩展（§38 后三处，9/9 测试）。** ①`asset_gate_state` 三态：全部拒绝带早退 `return`→`asset-gate`、任一缺 `return`→`asset-gate-noblock`、结构不符→`asset-gate-unresolved`；首跑发现 syn 2 把无 `return` 宏语句解析为 `Stmt::Macro` 而非 `Stmt::Expr(Expr::Macro)`，`gate_macro` 补该分支后通过——`asset-gate-noblock` 是候选（不阻断）判定的前提，不得与 unresolved 混淆。②行格式扩为 `file/kind/name/line/endLine/ctx/argc` 七列 TSV：`method` 的 ctx=impl 类型（`AssetService::query`），调用行 ctx=所在函数限定名，ipc-arm/ipc-call ctx=派发函数（`on_remote_request`）；函数行携 owner/argc/endLine。③测试：真实成功形状、`.unwrap()`/直接调用正例、`.expect` 拒绝、3 条拒绝早退丢失→noblock、8 条结构/极性/调用方/对象变异→unresolved、混合变异→unresolved、真实 `permission_check.rs` 断言 `asset-gate` 恰 1、ctx/argc 列断言、真实 7 派发边、malformed 拒绝。`record.js` 自校验 `asset-gate` 唯一且无 unresolved/noblock、`Query->query` 行 ctx=`on_remote_request`/argc=2。

**版本登记与接线。** 按纪律先在架构指南登记 §1.0.41（run 语义 `1.0.23-rust-ipc-code-verdict`，与 1.0.22 同的问题/状态/契约 `not-applicable`/check 边界，独立证明器与 `cross-user-system-hap-permission` 门禁族，限定 Asset 8100 `Query` 单 code）。实现：`lib/facts/rust.js` 经探针二进制产 files/functions/calls（`edgeKind`/`calleePath` 附加字段，重复行按 occurrence 入 locator）/quality/unsupported，`parse.js` `languageOf` 增 rust、`manifest.js` `K-1.2.0-rust-ast-probe`、`fact-snapshot` 记 `toolVersions.rustProbe` 与 parseRulesVersion；`ipc-dispatch.js` 增 `shape='rust-enum'`（固定七项顺序 enum + 同 `stub` 参数唯一调用 + Rust match 无 fallthrough + probeSha256 校验）；`index.js` 增 `entryFilter.onRemoteRequestNames` 与指纹 `r3-ipc-code-rust-v1`；`lib/autonomy/rust-verdict.js` 以探针重跑（按二进制哈希固定）+ 紧凑源码形状 + 固定哈希依赖复算 12 组证据（派发、`execute!` 宏双臂含 `create_user_de_dir(...)?`、`check_arguments?→common::check_system_permission` 链、`asset-gate` 判形、descriptor/`IpcCode::try_from`/`CallingInfo::build(map.get(&Tag::UserId)...)`、`CallingInfo::build` 覆盖、`ProcessInfo::build` 主体来源、`access_token_wrapper.cpp` 三 FFI 形状 + `extern "C"` 头、SA profile/GN/`.init_array`→`build_system_ability(SA_ID,true)`→`register`/`publish`、ipc_skeleton/binder_invoker 身份机制哈希），经 `ipc-verdict.analyze` 按 shape 分发；`bin/autonomy.js` 线程化 `RUST_IPC_CODE_VERSION`（`IPC_VERDICT_VERSIONS` 扩宽 ipcRun、门禁族/判词按版本分支、`not-applicable` 守卫扩宽），`report.js`/`autonomy-run-v1` 枚举扩宽，`state.js` 注册 19 个 `rust-*` reasonCode。schema 三处最小调整：`facts-v1` language enum+rust、run-v1 枚举+1.0.23、report-model gates kind+`cross-user-system-hap-permission` 与 `site` 字段。

**正式 run（1.0.23 双命题）。** 同输入 A/B：`RUN:43a2da003add8905`、`RUN:8ac19cd48f0b0265` 均 off→report→check 1 task/5 questions/5 tools/0 模型请求、**1 scoped excluded / 0 candidate / 0 observation / 0 finding**、report/check **0 error / 0 warning**、语义哈希同 `sha256:a595cf3dc738216ca951e83f6b698993c29c45498af6c0a908f33b074a693a4b`；B 重建 L1 后 A 只读复算仍 0/0。限定命题：主体=非 system HAP 的本地 IPC HAP 调用方、对象=请求 `Tag::UserId` 指定用户的资产记录（`CallingInfo::build` 覆盖链闭合）、操作=`operations::query`（operationRef `F:e3284b8879ff:function:2bdd09c1da6f76e3`，operationCallRef=execute! 边 `F:e3284b8879ff:call:045181f86efeabf6`）；三门禁（`system-hap-or-app`@33、`interact-across-local-accounts`@38、`caller-user-range`@45，均 `cross-user-system-hap-permission` 且 blocksOperation）在任何 DB 读取前拒绝早退，securityDecision 反驳为 scoped excluded，契约 `not-applicable`；limitation 明记 C++ IPC 身份回退（token 0→UID、无 active invoker→self）、插件 `on_app_request`/`redirect_request` 未证、宏数值展开未证、仅 standard dylib 声明变体。全 code 扫描 run `RUN:91df24e0c7a05277`（entryFilter 不限 method）：7 task = 1 excluded（Query）+ 6 observation（`rust-code-binding-unresolved`，登记语义仅限 Query 单 code），report/check 0/0，语义哈希 `sha256:4600f36a1ff97f1c7dc2bf5813ac6361ca8bb4c391894018956116916f12f4f4`。

**同输入端到端成本（bench 原件 `out/autonomy/bench/r3-asset-e2e-{fact-check,fact-build,fact-metadata,index,off,report,check}-{a,b}.json` 与 `-allcodes.json`）。** 各段 wall ms / read MB（A|B）：snapshot/check 828.9/258.03 | 783.7/258.03；L1 build 674.1/5.10 | 745.7/5.10；metadata 165.0/1.06 | 173.3/1.06；index 205.6/14.08 | 186.7/14.08；off（含入口/绑定/裁决）264.6/19.91 | 289.0/19.91；report 136.1/10.42 | 153.4/10.42；check 249.6/16.11 | 260.5/16.11。分段和 **A 2523.9 ms / B 2592.2 ms**，每轮读 324.71 MB、写 7.20 MB，maxRSS 峰值 237.2/237.8 MB（snapshot/check 段）。7-code 扫描 off 394.6 ms/23.88 MB read、report 139.3、check 243.2 ms；对 1-task off 的差按 6 任务摊分约 **21.7 ms / 0.66 MB 每 code（非隔离边际估计）**。未清 OS 缓存，A/B 为连续独立进程，非物理冷/热盘；事实三段（check+build+metadata）占约 65%，主要固定成本是全文件哈希核对，本组件量级下无可测出净收益的重复读取热点（§27 的 off 去重读保留），未加缓存、未省略任何证据/复算检查。R4 吞吐假设：102 生产文件级组件单 code 完整纵向约 2.5 s 一轮、每 code 边际 ~22 ms（扫描）；千文件级 shard 未实测，不外推。

**asset 逐入口互斥账（11 个索引入口，和=候选分母）。** `Query`（`ENT:5fea79d5b702c585`，stub.rs:141→`AssetService::query`）**已裁决（限定 scoped excluded，A/B run）**；`Add/Remove/Update/PreQuery/PostQuery/QuerySyncResult`（stub.rs:128-149，6 条已绑定 code 边）**未分析**（1.0.23 登记仅 Query 单 code，操作/门禁/主体双命题未建，扫描 run 记 `rust-code-binding-unresolved` observation）；`on_remote_request` free fn（`ENT:8c81d5f3e881dafe`，派发容器，7 边全 resolved-dispatch）与 `AssetService::on_remote_request` trait 方法（`ENT:ef11a65aeb3ff703`，委托 free 派发函数）**不适用**（对象级容器非 per-code 裁决对象，不把对象数当 code 边数）；SA 8100（`ENT:b95f8e4a5e11e0ce`）**不适用**（注册元数据）；NAPI `security.asset`（`ENT:51439358a2831f00`，asset_napi.cpp:242）**未分析**（metadata-only，导出/操作分母未知）。合计已裁决 1 / candidate 0 / 证据不足 0 / 未分析 7 / 不适用 3 = 11。§31 的 TokenSync 3 code（1 excluded/2 未分析）、§33 的 privacy ArkTS 15 导出（1 证据不足/14 未分析）、§35 的 CES ArkTS 14 导出（2 证据不足/12 未分析）、DBinder 10 项（3 边证据不足/其余未分析或证据不足）、§28 的 4 个 access_token SA（仅归属链）等既有逐入口账不变；全域 1,116 IPC 候选、3,407 非 C/C++ 文件、75 `production-pending`、Rust 370 文件的入口/变体/依赖闭包继续全留账（54 个 Asset Rust 文件有事实≠已审计；本轮 75→75 无变化）。

**失败与修正（全部保留原件）。** ①`state.js` 未注册 `rust-*` reasonCode 致首个 run `RUN:d8cf4357bb041abd` 中断（check 报 2 errors，作失败迭代留档）；②宏形状检查把 `macro_rules!execute{` 前缀误加在第二臂（只出现一次），修正后过；③FFI 紧凑片段两处笔误（`auto` 拼接、变量名实为 `tokenId` 而非 `accessTokenId`），`RUN:a604dcde3b1901d2`/`RUN:926c6d0d0da02db1` 为该失败迭代（存证 `rust-ffi-identity-unknown`，现只读 check 报 `static-proof-drift`——修复前后 prover 不同所致，恰是失败证据，不作出口）；④syn 2 `Stmt::Macro` 判形缺口（测试暴露）；⑤report-model schema 被 Node 整体重写破坏紧凑格式，已按 HEAD 风格重建为最小 diff（+24/-1，内容含前序 6 个安全字段与本轮 gates 扩展，`git diff --check`、BOM/U+FFFD 清洁）；⑥`sourceProof` 缺入口绑定前置检查（测试暴露，补 `rust-code-binding-unresolved`）。首个通过 run `RUN:bb3ce1b88bf95def` 与 `RUN:078774b186ab6817`（同语义哈希）留档，正式出口以 A/B 为准。

**回归。** 全量 `node --test` **313/313**（新增 `test/r3-rust-verdict.test.js` 4 项：真实 excluded、`asset-gate-noblock`→candidate（`policy-anchor-doc-only` 上限）、10 组绑定/派发/门禁/身份/对象/宏/操作链/SA/GN 漂移→具名 insufficient、隔离根 off→report→check + live 拒绝 + `not-applicable` 篡改→exit 3 `bad-enum`）。旧 run 只读复算 9 个全 0/0（`RUN:7ee2e10ac1d5ef70`、`RUN:7c583a5d5d336026`、`RUN:1f5d9a05407a821c`、`RUN:958a100c25039b96`、`RUN:01caf9305d77b70c`、`RUN:46ae635ab3a15b53`、`RUN:0483e20da5b8cf2b`、`RUN:8c5332b0cec8e1b0`、`RUN:d59f202e05a0ddf2`），1.0.22 及更早语义未漂移。

**R4 移交修订（叠加 §28/§35，不改旧表）。** 已支持形态新增：Rust `impl_enum_trait!` enum-code（Asset 8100 `Query`，standard dylib 声明变体，`1.0.23-rust-ipc-code-verdict`，探针 652feee2/K-1.2.0-rust-ast-probe）；未支持形状：其余 6 个 Asset code（未分析）、`on_extension_request`（code≥200 动态插件 redirect）、Rust `impl_enum_trait!` 其他用途（58 enum 行）、ipc 样本 5 个动态/条件派发对象仍无 per-code 分母（§28）、DBinder 3 边仍 observation、ArkTS/ANI 仍条件绑定 observation（`RUN:46ae635ab3a15b53` 3 个缺失问题结果未补）、NAPI 10 literal exports 仍 observation 且全域 497 注册候选导出分母未知、access_token 4 SA 仍仅归属链。必要外部依赖：rust-ast-probe 二进制（哈希入快照）、ipc/samgr/safwk Rust crate、`libsoftbus_client.z.so`（DBinder）、IDL 生成器、TaskPool/ANI runtime；75 待定文件不变。十组件顺序与 5,076/283 计划分母不变（asset 行更新为：Rust 形态已有单 code 纵向，其余 6 code+NAPI+FFI 变体待 R4）；吞吐假设见上（~2.5 s/单 code 纵向轮、~22 ms/code 边际，千文件级 unknown）。

**出口逐项复核（对照 §4 五项）。** ①形态纵向：IDL 回归（9 旧 run 复算）、SA（CES 3299）、IPC per-code（TokenSync Delete）、非 C/C++（Rust Query）各具固定源/变体、候选分母与入口→操作→门禁→限定裁决→report/check 链，各有正/反/未知测试；未选 NAPI 及未闭合形态保留未支持数量——**有证据**。②逐入口互斥账：本节 asset 11 项与既有各组件表逐项互斥、和对账、原因具名，未绑定/未知语言/变体/依赖具名保留，60,678/75/1,116/3,407 不冒充已审计——**有证据**。③受控正/反/未知各有预定来源与判定，真实 scoped excluded 逐项复核，无独立锚点、真实 precision/recall/independentAccuracy 保持 `null`——**有证据**。④新形态 off→report→check 0/0、语义/证据可回查、旧 run 无漂移、313/313、冷/热（连续进程口径）与逐入口边际/读写/RSS 实测、无已测收益的重复读取可消除（披露固定哈希成本）——**有证据**。⑤本节 R4 移交表更新齐（已支持形态、未支持形状、5 条 ipc 样本状态、非 C/C++/SA/NAPI 未闭合量、75 待定、依赖、吞吐假设、十组件顺序）——**有证据**。五项出口均有可回查产物；按 §4 更新路线图 R3 状态为已完成（限定口径：仅本节列明的已支持形态与样本，其余分母继续 R4+）。真实 finding 能力、全域覆盖与漏洞召回不在 R3 口径。本轮无 live、无产品源码/out/旧归档修改、无提交/推送。

### 40. R3 已验收后的文档交接校正（2026-10-27）

`R3-EXECUTION-GUIDE.md` 原 §0.1 的“部分完成”、830 行 `asset-gate-unresolved` 和 §1 可交给 `/goal` 的旧提示词是 §37 时点的历史快照，与 §39 验收后的现状冲突。本轮将其显式标为历史，在 §0.2 链接 §39 的五项完成证据和 `RUN:43a2da003add8905` / `RUN:8ac19cd48f0b0265` / `RUN:91df24e0c7a05277`；新增 `R4-EXECUTION-GUIDE.md` 作为新对话的 `/goal` 入口，路线图与 README 只加导航链接。**没有新审计 run、覆盖或安全裁决**；R3 仍为限定口径完成，R4 尚未开始验收。下一动作按 R4 指南复核首批组件及构建/依赖分母，逐组件扩审并量测可持续吞吐；原有未分析量不转零。未外发 live、未动产品源码/out、旧归档、未提交/推送。

### 41. R4 前置改进的文档交接（2026-10-27）

新增 `R4-AGENT-IMPROVEMENT-GUIDE.md` 的 `/goal` 目标与两项验收：先以真实入口建立不降低 §15.4 finding 门槛的可行动假设/候选分诊，再对 `IAccount` 成员调用和一条表/间接 IPC 派发做同输入语义边对照；未绑定操作留调查项，CodeQL/Joern/clangd 只在离线可用且实测获益时采纳。`R4-EXECUTION-GUIDE.md` §0.1 登记回写条件、§1 保留十组件扩面目标，README 指向先前置、后扩面的顺序。**本轮仅文档，没有新 run、测试、实现或性能收益**；R3 状态不变，R4 与两项前置优化均待验收。下一动作由新对话按前置指南固定输入、跑正/反/未知及成本对照，将成功、失败、run ID 和未覆盖分母继续追加到本账本，然后据实修订 R4 指南。未外发 live、未改产品源码/out/旧归档、未提交/推送。
