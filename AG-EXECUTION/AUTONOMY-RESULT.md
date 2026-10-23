# 自主审计 Agent MVP 交付结果（AUTONOMY-RESULT）

> 历史记录：2026-10-22 的 `1.0.0-mvp` 交付验收，原目标书已归档删除。此处的“无 runtime witness 不出 finding”、固定三问和测试数量仅描述该旧 run；现行静态 `finding` 出口与验收以 `AGENT-ARCHITECTURE-GUIDE.md` 为准，不用本记录推断当前能力。
> 交付日期：2026-10-22
> 事实快照：`sha256:2142c229d142bdacc472969fe96d73a36da4554f3775dee4f710b79878997a1e`（只读复用，未重建未改写）
> 试点 run：`RUN:9b1bdf44daebe542`（复跑 `RUN:ed75ea5cb9a0176e`）
> 工作区：`D:\oh6.0\OpenHarmony-v6.0-Release`；工具目录：`oh6-surface-audit`

## 0 结论

MVP 闭环跑通：`doctor → index → run(off) → check → report` 全绿，`verify` 只登记占位并返回 `blocked`。
试点 scope = `base/accesscontrol/sandbox_manager`（单组件），产出 24 个任务 / 72 个子问题，
报告为 **candidate 7 / observation 17 / excluded 0 / finding 0**。

`FINDINGS.md` 为空且注明原因：**没有 runtime witness**，MVP 的 `verify` 不执行设备/host 验证，
`Q-dominance` 恒为 `insufficient`（`dominance-unproven`）。

**candidate 不是漏洞。** 它只表示「入口绑定到唯一实现体，且实现体内**直接调用**中没看到词表内的校验调用」；
宏、包装、基类、上游调用、以及「校验是否支配敏感操作」在 MVP 中均未验证。

## 1 交付物

```text
bin/autonomy.js                              # CLI：doctor|index|run|tools|check|report|verify
lib/autonomy/ids.js                          # 自治 ID（复用 lib/facts/ids.js，不改既存事实层）
lib/autonomy/jsonl.js                        # StringDecoder 跨块安全 JSONL + 坏行计数
lib/autonomy/schema.js                        # JSON-Schema 受限子集校验器（无第三方依赖）
lib/autonomy/store.js                        # run 目录、append-only 事件、原子 checkpoint、证据归档、校验和
lib/autonomy/state.js                        # 记录封套 + Task/Question/Missing 状态机与 reason 注册表
lib/autonomy/facts.js                        # 既存 Facts 的只读适配（作用域索引、哈希校验、上限）
lib/autonomy/doctor.js                       # 只读环境/能力检查（零网络）
lib/autonomy/tools.js                        # dispatcher + 6 工具 + 5 unsupported
lib/autonomy/index.js                        # 事实 → 实体/关系索引 + 对账
lib/autonomy/discovery.js                    # 入口枚举、绑定、任务提案/接纳、20% 覆盖抽样
lib/autonomy/retrieval.js                    # ContextPacket（≤80 行窗口、guards、calls、token 估算）
lib/autonomy/model.js                        # 网关 off/live/mock + 预算预留/结算 + 台账
lib/autonomy/assessment.js                   # 确定性裁决 + live 程序证据门
lib/autonomy/report.js                       # report-model / C/O/F 渲染 / manifest / checksums
K/policies/autonomy-pilot-scope.json         # 试点 scope（sandbox_manager 单组件 + 词表 + 抽样）
K/policies/autonomy-pilot-budget.json        # 预算
K/schemas/autonomy-{run,task,question,missing,toolresult,assessment,report-model,context,event}-v1.json
test/autonomy-contract.test.js
test/autonomy-doctor-index.test.js
test/autonomy-tools.test.js
test/autonomy-pipeline.test.js
test/autonomy-check-failures.test.js
test/fixtures/autonomy/model/check-presence.json
eval/autonomy/pilot-summary.json
eval/autonomy/labels.json                    # 只建 schema + status=pending，无伪造标注
eval/autonomy/ag0-baseline.json              # 开工前事实层基线（22 个文件的 sha256）
tools/autonomy-pilot-summary.js              # 从 run 产物复算 pilot-summary（只读、不重裁决）
out/autonomy/index/sha256-2142.../           # entities/relations/index-manifest
out/autonomy/RUN-9b1bdf44daebe542/           # 试点 run 产物（含 evidence/、checkpoints/、verification/）
out/autonomy/RUN-ed75ea5cb9a0176e/           # 同参数复跑（确定性证据）
```

说明：`lib/autonomy/` 实际 14 个文件 —— 指南 §4 列的 13 个 + `schema.js`（JSON-Schema 子集校验器）。
schema 校验被 dispatcher、`check`、report 共用，单列比塞进某个模块更清楚；`lib/facts/*` 一行未改。

## 2 §7 验收 12 条（命令 + 输出）

### 1 doctor 可用

```powershell
node bin\autonomy.js doctor --scope=K/policies/autonomy-pilot-scope.json
```

```text
ok=true networkRequests=0 capabilities=9 hardFail=0        # exit 0
checks: node-version / scope-policy / budget-policy / facts-snapshot / facts-snapshot-pinned /
        facts-tables(13) / facts-metadata(7) / facts-manifest / facts-src-root /
        llm-gateway-config / llm-api-key(布尔) / wsl-installed(只报不调用)
```

无网络请求（`networkRequests: 0`，代码路径里没有 fetch）；密钥只报 `apiKeyPresent` 布尔值。

### 2 index 可建（与 facts 对账）

```powershell
node bin\autonomy.js index --snapshot=sha256:2142c229... --scope=K/policies/autonomy-pilot-scope.json
```

```text
ok=true entities=720 relations=4975 entries=19 recon=true   # exit 0
reconciliation.expected == actual:
  functions 566 / files 135 / calls 4958 / idl 17 / sa 2 / napi 0
relations: calls 4958 / registers 17
entryKinds: idl 17 / sa 2
indexTruncated: functions=false calls=false
```

`registers 17` = 17 个 IDL 方法都唯一绑定到 `SandboxManagerService::<Method>`。
索引不重解析源码（只读 `l1/*` 与 `metadata/*`）。

### 3 run(off) 可跑，0 次模型调用

```powershell
node bin\autonomy.js run --mode=off --scope=K/policies/autonomy-pilot-scope.json --budget=K/policies/autonomy-pilot-budget.json --max-tasks=0
```

```text
ok=true runId=RUN:9b1bdf44daebe542
planned: entries 19 (idl 17 / sa 2) + coverageAnchors 5 => tasks 24, questions 72
executed: tasks 24, toolCalls 92, modelRequests 0, modelCalls 0, wallMs 285
counts: tasks 24 / candidate 7 / observation 17 / excluded 0 / finding 0
missingByReason: binding-metadata-only 2, check-call-weak-only 1, dominance-unproven 24
```

`modelRequests=0` 且 run 目录内**不存在** `model-calls/`（off 模式零调用是结构性的，不是"没记"）。

### 4 check 通过

```powershell
node bin\autonomy.js check --run=RUN:9b1bdf44daebe542
```

```text
ok=true errors=0 warnings=0
counts: events 76 / tasks 24 / questions 72 / missing 27 / toolResults 92 / assessments 72 / contexts 24 / reportRows 24
```

（`events 76` = 建 run 1 + task-admitted 24 + task-started 24 + task-finished 24 + report-written 1 + run-finished 1
 + §7.9 的 `verify-placeholder` 1；不加 verify 时是 75。）

校验面：9 类记录 schema、事件 seq 连续、引用可回查（task↔question↔missing↔evidence）、
`snapshotId`/`inputManifestId` 一致、证据归档件存在、checksums 逐文件复核、
`report-model` 语义哈希可复算、task 记录状态与事件归约一致。

### 5 报告三件套（FINDINGS 为空且注明原因）

```powershell
node bin\autonomy.js report --run=RUN:9b1bdf44daebe542
```

```text
ok=true counts={"tasks":24,"candidate":7,"observation":17,"excluded":0,"finding":0}
semanticHash=sha256:6b9b126fcda86ff73f5690d7ee5d0c162fb9cc84d7a0dc4242756974a9410ef2
artifacts: report-model.jsonl / report-model.json / CANDIDATES.md / OBSERVATIONS.md / FINDINGS.md / report.md
```

`FINDINGS.md`（435 字节）：

```text
# FINDINGS

空。

原因：MVP 不产出 finding：没有 runtime witness，静态证据不足以支撑「已证漏洞」；
本文件的空不是「无问题」，而是「未证」。
- MVP 的 verify 只登记计划并返回 blocked，不执行设备/host 验证；
- 因此没有任何 runtime witness；没有 witness 就不出 finding（红线 §8.4）；
- Q-dominance 恒为 insufficient（dominance-unproven）。
```

`report` 幂等：同一 run 再跑一次 `report`，`CANDIDATES.md` 与 `report-model.jsonl` **逐字节不变**
（复用已提交记录的 `createdAt`；`test/autonomy-pipeline.test.js` 断言了这一点）。

### 6 工具边界（未实现工具不得冒充实现）

```powershell
node bin\autonomy.js tools --scope=K/policies/autonomy-pilot-scope.json
node -e "const t=require('./lib/autonomy/tools');t.run('inspectLifetime',{},{}).then(r=>console.log(r.payload.tool,r.payload.status,r.payload.errorCode,r.payload.answer.text))"
```

```text
available:   getEvidence getScopeOverview inspectAuthorization inspectEntry inspectRelation searchEntities
unsupported: checkSource collectEvidence getApplicableNorms inspectLifetime traceValue

inspectLifetime unsupported tool-unsupported unsupported: lifetime-model-not-implemented: MVP 不做生命周期分析
```

dispatcher：schema 校验 → 能力/作用域 → 预算预留 → 超时 30 s → 结果 ≤256 KiB → 归档 → 台账。

### 7 证据可回查（抽 10 条 EVID）

```powershell
node -e "…（抽 10 条 tool-results，核对 evidence/<EVID>.json 与全部 F: factRef 是否在 facts 表内）"
```

```text
EVID:b76ecb3be5ce3575 inspectEntry      evidence-ok frefs=1
EVID:d68f4ca8a4873f8b inspectAuthorization evidence-ok frefs=2
EVID:7e1f28e94c6e8a83 inspectEntry      evidence-ok frefs=1
EVID:c4d9cf424b7743b6 inspectAuthorization evidence-ok frefs=3
EVID:e27292a4bf96f617 inspectRelation   evidence-ok frefs=11
EVID:a481140081855390 getEvidence       evidence-ok frefs=1
EVID:e76133f5ee5a4fab inspectEntry      evidence-ok frefs=1
EVID:04cd38b66ce719d9 inspectAuthorization evidence-ok frefs=0
EVID:3c3b402f22c687d4 inspectRelation   evidence-ok frefs=18
EVID:8904a279ceff97f4 inspectAuthorization evidence-ok frefs=2
sample=10 evidenceOk=10 evidenceBad=0 distinctFactRefs=40 foundInFacts=40 missing=0
```

40 个不同的 `F:` 引用全部能在 `l1/{functions,files,calls,guards,sinks}.jsonl` 里按 `factId` 命中。
`check` 对**全部** 92 条 tool-result 做了同样的归档存在性校验，覆盖强于抽样。

### 8 裁决枚举（无 T1 / PROVEN-VULN）

```powershell
node -e "…（扫描 assessments 的 decision 枚举与 rationale/proposition/assumptions 的禁用词）"
```

```text
assessments=72 decisions=insufficient,refuted,supported PROVENVULN=false T1token=false safeWord=false
reportRows=24 reportability=candidate,observation anyFinding=false
```

禁用词按**词元**匹配（`/PROVEN[-_]VULN/i`、`/(?:^|[^A-Za-z0-9_-])T1(?:[^A-Za-z0-9_-]|$)/`），
避免把时间戳里的 `T17` 误判成 `T1`。`check` 内建同样的判定。

### 9 verify 占位

```powershell
node bin\autonomy.js verify --run=RUN:9b1bdf44daebe542 --plan=<plan.json>
```

```text
result=blocked  status=blocked  executedCommands=[]
missing: [{category: environment, reasonCode: verification-disabled, nextActions: []}]
artifact: out/autonomy/RUN-9b1bdf44daebe542/verification/placeholder.json
```

只读 plan、校验其为 JSON 对象、写 `verification/placeholder.json`；**不**调用 `hdc`、**不**编译、
**不** spawn 任何进程（`executedCommands` 恒为空数组）。

### 10 确定性

```powershell
node bin\autonomy.js run --mode=off … --max-tasks=0   # 两次
node tools\autonomy-pilot-summary.js --run=RUN:9b1bdf44daebe542 --replay=RUN:ed75ea5cb9a0176e
```

```text
RUN-9b1bdf44daebe542  sha256:6b9b126fcda86ff73f5690d7ee5d0c162fb9cc84d7a0dc4242756974a9410ef2  {tasks:24,candidate:7,observation:17,excluded:0,finding:0}
RUN-ed75ea5cb9a0176e  sha256:6b9b126fcda86ff73f5690d7ee5d0c162fb9cc84d7a0dc4242756974a9410ef2  {同上}
sameSemanticHash=true sameReportability=true sameCounts=true
```

确定性来源：所有 ID 都是内容哈希；JSONL 按 ID 排序；集合字段排序去重；语义哈希排除 `createdAt`；
`EVID` 只由语义字段派生（`usage.wallMs` 不入 ID）；`runId` 带唯一化非确定字段但**不进**任何语义哈希。

### 11 不回归

```powershell
node --test
node bin\agent.js gates --strict
```

```text
node --test : tests 280 / pass 280 / fail 0 / skipped 0   （基线 233 → +47，只增不减）
gates       : agent campaigns 20/20, 15/15, 13/13, 5/5, 8/8, 8/8；gates 70/70；consistency OK（exit 0）
```

新增 47 个测试分在 5 个文件里：

| 文件 | 覆盖 |
|---|---|
| `test/autonomy-contract.test.js` | 9 张 schema、校验器、ID/语义哈希、JSONL 跨块 UTF-8、状态机、reason 注册表、report-model 三分支、live 证据门四条 |
| `test/autonomy-doctor-index.test.js` | doctor 零网络/能力矩阵、facts 哈希与 stale、缺表、index 对账、两次构建同 ID、discovery 24 task/72 question、绑定与空入口 |
| `test/autonomy-tools.test.js` | 6 工具 + 5 unsupported、缺参/未知工具、超时、超限、预算、stale-input、EVID 稳定性、归档与台账 |
| `test/autonomy-pipeline.test.js` | run(off) 零模型调用、seq 连续、check、report 幂等、确定性、mock fixture、replay-miss、live 缺 key、预算停止、`--task`、verify、参数错误 |
| `test/autonomy-check-failures.test.js` | tail-partial、ledger-corrupt、evidence 丢失、dangling-ref、report-model-drift、forbidden-token、task-state-mismatch、run.json 坏/不可解析、verify 缺 plan |

### 12 既存事实层未被修改

```powershell
node -e "…（逐文件对比 eval/autonomy/ag0-baseline.json 的 sha256 与字节数）"
```

```text
files=22 changed=0 snapshotId=sha256:2142c229d142bdacc472969fe96d73a36da4554f3775dee4f710b79878997a1e
```

基线含 `snapshot.json`、`manifest.json`、13 张 `l1/*` 表、7 张 `metadata/*` 表（开工前采集）。
`lib/facts/*`、`bin/fact-*.js` 一行未改；所有新代码在 `lib/autonomy/`、`bin/autonomy.js`、`K/`、`test/`、
`eval/`、`tools/`，所有产物在 `out/autonomy/`。

## 3 试点数字（sandbox_manager）

| 项 | 值 |
|---|---|
| 入口候选 | 19（IDL 方法 17 / SA 2；无 NAPI、无 `OnRemoteRequest` 命名函数） |
| 覆盖抽样 | 5 个实现文件（35 个 production `.c/.cc/.cpp/.cxx` 的 20%，按 `sha256(path)` 升序） |
| 任务 / 子问题 | 24 / 72 |
| 工具调用 | 92（`inspectEntry` 24 + `inspectAuthorization` 24 + `inspectRelation` 22 + `getEvidence` 22） |
| 模型调用 | 0（off） |
| 耗时 | 285 ms（进程内；索引已建） |
| question 状态 | supported 36 / refuted 7 / insufficient 29 |
| 缺口 | `dominance-unproven` 24、`binding-metadata-only` 2、`check-call-weak-only` 1 |
| 报告 | candidate 7 / observation 17 / excluded 0 / finding 0 |

7 个 candidate：`ISandboxManager#SetPolicyAsync`、`ISandboxManager#UnSetPolicyAsync`（二者把校验委托给
`SetPolicy`/`UnSetPolicy`，函数体内没有直接校验调用），以及 5 个覆盖抽样函数（`PolicyInfoParcel::Marshalling`、
`PolicyTrie::Clear`、`MacAdapter::MacAdapter`、`GetPartitionRemainSize`、`sandbox_test_common` 的 `GetTokenId`）。

17 个 observation：15 个 IDL 方法体内命中 strong 校验调用（`CheckPermission` / `IsFileManagerCalling`）、
2 个 SA 入口（`saId=3508`，只有元数据、没有方法体 ⇒ `binding-metadata-only`），
以及 `StartAccessingByTokenId`（只有 `GetCallingUid` 这类 weak 身份获取 ⇒ `check-call-weak-only`）。

完整数字：`eval/autonomy/pilot-summary.json`（`tools/autonomy-pilot-summary.js` 只读复算，不重裁决）。

## 4 与指南的偏差（明确登记，不掩饰）

| 项 | 指南 | 实现 | 理由 |
|---|---|---|---|
| `lib/autonomy` 文件数 | 13 | 14（+`schema.js`） | schema 校验被 dispatcher / check / report 共用，单列更清楚 |
| schema 数 | 7 | 9（+`context`、`event`） | P5/P3 的记录也要被 `check` 校验，否则"校验了但没校验全" |
| 工具数 | 6 可用 + 6 unsupported（含 `getApplicableNorms` 等） | 6 可用 + 5 unsupported | 指南那张表列了 5 个未实现工具（`getApplicableNorms`/`collectEvidence`/`inspectLifetime`/`traceValue`/`checkSource`），§4 的"其余 6 个"是笔误 |
| `checkVocabulary` | §3.2 的 9 个名字 | 9 个 + `IsFileManagerCalling`（strong）+ `GetCallingTokenID`/`GetCallingUid`（weak） | `IsFileManagerCalling` 是该项目真实的授权门；`GetCalling*` 只是身份获取，命中时判 `insufficient` + `check-call-weak-only`，**不**算"有校验" |
| 预算 | `maxToolCalls=150` | `maxToolCalls=400` | 全量入口 + 20% 抽样需要 92 次工具调用；150 会人为制造 budget 停止。数字本身可改，口径不变（`--max-tasks=0` 仍以预算为上限） |
| `runId` 唯一化 | 未规定 | 含 `pid` + 序号 | 两个并发/同毫秒运行绝不能写进同一目录 |
| `bin/autonomy.js` 之外 | 只要 1 个 bin | 多了 `tools/autonomy-pilot-summary.js` | pilot-summary 必须可从 run 产物复算，不能只有一次性脚本 |
| mock 模式 | "仅测试用" | `run --mode=mock` 会真的走 assessment 的模型分支 | 否则 mock 只测到 CLI 参数，测不到网关/预算/证据门链路 |

## 5 已知缺口（如实列出）

1. **`Q-dominance` 恒 `insufficient`**：MVP 不做支配关系与对象一致性分析，24 个任务全部带 `dominance-unproven`；
2. **绑定只是名称 + owner 段匹配**，不是 canonical entry + 完整绑定：重载/同名不同 owner 会落到 `suspect`；
3. **`Q-check` 只看函数体内的直接调用名**：宏、包装、基类、上游、跨函数的校验都不在观察范围内；
4. **SA / NAPI 入口没有方法体**，只能产出 `binding-metadata-only` 的 observation；
5. **finding 关闭**：没有 runtime witness，`verify` 只返回 `blocked`；
6. **`labels.json` 没有标注**，因此不报 precision/recall（字段刻意保留 `null`）；
7. `index` 的作用域索引有上限（`maxIndexFunctions=5000` / `maxIndexCalls=20000`）；本轮 sandbox_manager
   是 566 / 4958，未触发；扩仓前必须先调上限或改成分页。

## 6 复算命令（一键序列）

```powershell
cd D:\oh6.0\OpenHarmony-v6.0-Release\oh6-surface-audit

node bin\autonomy.js doctor  --scope=K/policies/autonomy-pilot-scope.json
node bin\autonomy.js index   --snapshot=sha256:2142c229d142bdacc472969fe96d73a36da4554f3775dee4f710b79878997a1e --scope=K/policies/autonomy-pilot-scope.json
node bin\autonomy.js run     --mode=off --scope=K/policies/autonomy-pilot-scope.json --budget=K/policies/autonomy-pilot-budget.json --max-tasks=0
node bin\autonomy.js check   --run=<上面输出的 runId>
node bin\autonomy.js report  --run=<同上>
node bin\autonomy.js verify  --run=<同上> --plan=<plan.json>
node tools\autonomy-pilot-summary.js --run=<同上> [--replay=<第二次 runId>]

node --test
node bin\agent.js gates --strict
```
