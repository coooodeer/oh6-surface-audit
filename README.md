# oh6-surface-audit

> **唯一开发规范**：[OpenHarmony 6.0 自主审计 Agent 架构与实现规范](AG-EXECUTION/AGENT-ARCHITECTURE-GUIDE.md)。新 Agent 的架构、接口、开发顺序与验收以该自包含文档为准。
> 下文保留既有工具的命令和历史实验说明，不代表新架构已经实现；其他架构文档仅作历史资料，不再补充或覆盖上述规范。

对 OH6.0 的入口面、历史 patch、spec 泛化和义务证明做可验证实验；live 模型实验需要 `OH6_LLM_API_KEY`。

## 1 入口台账（dsoftbus / os_account）

入口枚举（当前实现）：

- `idl`：`.idl` 的 interface × method
- `dispatch`：`*_stub.cpp` 的 `OnRemoteRequest` + `switch(code)` case
- `dispatch-map`：`memberFuncMap_` / `memberPermissionMap_` 函数表分发
- `harness`：`ipc-harness-index.jsonl` 的 token + code
- `sa`：`sa_profile/*.json` 的 systemability
- `napi`：`napi_module_register` / `NAPI_MODULE` / `nm_register_func`
- `socket`：`accept/accept4/recvfrom/recvmsg/listen/bind` 调用点
- `hdi`：`HdfDeviceIoCommand` / `IDeviceIoService` / `ioctl(` 调用点
- `parser`：`Parse|Decode|Unmarshal|Unpack|Deserialize|ReadFrom` 且参数含字节缓冲的函数
- `broadcast`：`PublishCommonEvent` / `PublishEvent` 调用点

口径：

- `expected`：八路并集按 `entryKey` 去重
- `resolved`：有 file/line 与身份（token+code / interface+method / saId / module / symbol）
- `contracted`：resolved 且有 attackerPosition 与 requiredChecks
- `linked`：contracted 且找到实现侧证据（handler / stub / process / register func / 函数体）

`ECR = contracted / expected`，`ELR = linked / contracted`。
这是“表层契约率”，不是语义证明；`linked` 只表示找到实现侧，不表示控制流闭合。

## 2 补丁差分验证（20 条本地 patch）

输入：`oh6-vuln-agent/data/facts/history-invariants.jsonl` 的 20 条产品代码 patch（按仓轮转抽样）。

对每条：

1. `git show <sha>^:<file>` / `git show <sha>:<file>` 取前后版本；
2. 用 `git diff -U0` 找 hunk，取变更行所在函数体（大括号匹配；失败则 hunk ±30 行）；
3. 检查 `witness` 是否“前不存在、后存在”。

状态：`validated` / `pre-already` / `post-missing` / `pre-missing` / `extract-failed`。

这是 SpecAuditor 差分验证的**机器可检半边**：证明“修复确实引入了见证”。语义约束是否成立由 live 模型复核（见 §3）。

## 3 Live 模型差分（需 key）

用 `oh6-vuln-agent` 的 HTTP 运输层和 `config/llm.json` 的端点/模型；key 只从 `OH6_LLM_API_KEY` 读。

```powershell
$env:OH6_LLM_API_KEY = [Environment]::GetEnvironmentVariable('OH6_LLM_API_KEY','User')
node bin/specdiff-live.js --ids=INV-HIST-2c307697,INV-HIST-5af29df4,INV-HIST-99d126b9 --max-tokens=2048 --timeout-ms=300000
node bin/specdiff-live.js --all --missing --max-tokens=2048 --timeout-ms=300000
node bin/specdiff-live-report.js
node bin/specdiff-merge.js
```

- `out/specdiff/live/`：每次调用的原始结果、账本、summary。
- `out/specdiff/results.jsonl`：机械结果 + `live` 字段（由 merge 并回）。
- `out/report/specdiff-live.md`：模型判定与机械 witness 的并排对比。

## 4 Spec 泛化 dry run

从 18 条 confirmed seed 生成 behavior-level spec，检索本地函数实体，再判“约束是否适用”：

```powershell
$env:OH6_LLM_API_KEY = [Environment]::GetEnvironmentVariable('OH6_LLM_API_KEY','User')
node bin/specmine-dryrun.js --mode=induce --max-tokens=8192
node bin/specmine-dryrun.js --mode=retrieve
node bin/specmine-dryrun.js --mode=judge --max-tokens=8192
node bin/specmine-dryrun.js --mode=report
```

产物：`out/specmine/{seeds,candidates,judged,specs}.jsonl`、`out/specmine/summary.json`、`out/report/specmine.md`。
`constraintApplies=true` 只表示规范适用于该实体，不是漏洞；检索是词法匹配，不是 embedding。

## 5 义务化试点（3 条 spec）

```powershell
node bin/spec-prover.js
```

对 3 条 concrete spec 手工落义务，并在 `out/specprover/mutants/` 生成对应变异体；原函数应为 `SATISFIED`，变异体应为 `VIOLATION`。产物：`out/specprover/{results.jsonl,summary.json}`、`out/report/specprover.md`。

## 6 自动义务化与批量 prover（12 条 spec）

```powershell
$env:OH6_LLM_API_KEY = [Environment]::GetEnvironmentVariable('OH6_LLM_API_KEY','User')
node bin/spec-obligations.js --max-tokens=8192
node bin/spec-prover-batch.js
```

- `out/obligations/obligations.jsonl`：每条 spec 的模型生成义务（literal 片段 → 行匹配正则）；只有片段能匹配函数体的义务才有效。
- `out/obligations/verdicts.jsonl`：逐 spec 的 proven/disproven/unproven 与 `claimability`。
- `out/obligations/claims.jsonl`：只收 `VIOLATION` 且被反证义务 confidence 非 low 的 claim-candidate；没有 entry-reachability/dataflow 时不送 judge。
- 报告：`out/report/obligations.md`。

## 7 L1/L2 事实与 P3/P6 缺口探针

```powershell
node bin/l1-facts.js          # dsoftbus + os_account 的 body token/calls/guards/publishes
node bin/l2-ledger.js         # 入口台账 + P6 action 台账（evidence ↔ actions）
node bin/gap-probes.js        # P3 deref / P6 action 的确定性探针
node bin/p3-callgraph-probe.js# 直接调用图到 entry 的可达性
```

产物：`out/l1/`、`out/l2/`、`out/gaps/`；缺口台账见 [GAPS.md](GAPS.md)。

## 8 P3/P6 第一步缺口补齐

```powershell
node bin/l1-callgraph.js        # 74k 调用边 + entry 可达性
node bin/l1-producer-types.js   # producer 返回类型/指针
node bin/l2-p6-payload.js       # 源码级 payload grounding
node bin/l2-p6-index.js         # restricted/public/design 交叉索引
node bin/l4b-evidence.js        # P3/P6 L4b 证据包
node bin/l3-claim-seeds.js      # P3/P6 claim-seed
node bin/p3-prove.js            # P3 蕴含式判定 + 10 mutant 验证
node bin/p4-facts.js            # P4 11 条候选的类型提示/entry/UBSan oracle
node bin/p4-cve-fetch.js        # 30 条 P4 外部 CVE 元数据（NVD/CVE.org）
node bin/p4-cve-enrich.js       # 归一化 commit 并抓取 patch diff
node bin/bakeoff-p4-p5.js       # P4 vs P5 10+10 结构性义务闭合率
node bin/gt-build.js            # P3 mutants + P6 cases（写 eval/）
```

产物：`out/l1/call-edges.jsonl`、`out/gaps/p3-reachability.json`、`out/l1/producers.jsonl`、`out/l2/p6-payload.jsonl`、`out/l2/p6-index.jsonl`、`out/l4b/`、`out/l3/`、`eval/`。

## 9 L1–L4 闭环（P6 + P3 + P4）

目标与硬门见 [GOAL-PROMPT-L1-L4.md](GOAL-PROMPT-L1-L4.md)，实现状态见 [IMPLEMENTATION-STATUS.md](IMPLEMENTATION-STATUS.md)。L5 动态 oracle 与 L7 finding/report/delivery 的目标书见 [GOAL-PROMPT-L5-L7.md](GOAL-PROMPT-L5-L7.md)。

```powershell
$env:OH6_LLM_API_KEY = [Environment]::GetEnvironmentVariable('OH6_LLM_API_KEY','User')
node bin/build-claims.js        # L3：P3 25 / P6 115 / P4 24
node bin/run-p3p4p6.js          # L1->L2->L3->L4a->L4b->verdict->report/calibration
node bin/build-in-scope-verdicts.js  # R1 严格口径：只统计本仓新发现候选
node bin/l4b-judge.js --limit=10
node --test
```

- `lib/l1.js`：函数/调用边/producer/guard/payload/miner site/entity/gate/slice 查询。
- `lib/l2.js`：file→entry、action→site（95 os_account site）、函数级可达性、owner-aware producer。
- `lib/claims.js`：P3/P6/P4 claim + obligation；P6 判定单位是 site。
- `lib/prover-p3.js`、`lib/prover-p6.js`、`lib/prover-p4.js`：确定性 prover。
- `lib/l4b.js`：item 级 P6 / producer 可空性 P3 的有界语义判定；无 key 时 mock，live 标 blocked。
- `lib/calibration.js`：§7.7 抽样复核（3 轮 × 10 accepted + 10 rejected）。
- `lib/in-scope.js`：R1 严格口径统计；P3 按 owner 根因族、P4 按算术 site、P6 按 site；排除 miner findings / 外部 CVE / R2。

产物：`out/l3/`、`out/l4a/`、`out/l4b/`、`out/verdicts/`、`out/report/{implementation,calibration,in-scope-findings}.md`、`out/report/CALIBRATION-LOG.jsonl`、`out/report/run-summary.json`。

范围：本节只描述 L1–L4 的 P6/P3/P4 链路；P1/P2/P5 见各自目标书，L5/L7 见 [GOAL-PROMPT-L5-L7.md](GOAL-PROMPT-L5-L7.md)。P4 仍只读消费已有 native-harness UBSan oracle，不把 legacy 当新 L5。

P5（权限提升/访问控制绕过）的独立目标书见 [GOAL-PROMPT-P5.md](GOAL-PROMPT-P5.md)：R1 严格口径、method-level 拆分、IDL 方向/配对、服务端权限检查 path-scoped、dsoftbus CWE-862 + synthetic mutant 校准。

## 9.1 P5（R1）

```powershell
node bin/run-p5.js          # audit -> fixtures -> claims -> L4b -> calibration -> report -> gates
node --test
```

产物：`out/p5/{method-units,pairing,check-sites,paths,claims,verdicts}.jsonl`、`out/verdicts/p5-in-scope-verdicts.jsonl`、`out/report/p5-{implementation,gates}.md`、`IMPLEMENTATION-STATUS-P5.md`。当前门禁 13/13；L4b live 使用 DeepSeek 官方 API（`deepseek-flash`，9/10 schema）。

P1/P2/P7/P8 的静态发现目标书见 [GOAL-PROMPT-P1P2P7P8.md](GOAL-PROMPT-P1P2P7P8.md)：D4 五仓、P1/P2 候选扩展、P7 四类 DoS、P8 invariant、fixtures 与 T2/T3/T4 口径；静态目标书仍以 T2/T3/T4 为主，L5 动态验证见 [GOAL-PROMPT-L5-L7.md](GOAL-PROMPT-L5-L7.md)。外部 CVE 只放 `eval/external-cve/` 测试义务编排/裁决，不映射 target；候选 production 资格由 [lib/candidate-origin.js](lib/candidate-origin.js) 统一判定。

## 9.2 统一 Agent 入口

`bin/agent.js` 把六套既有 campaign 的 gate summary 与 `node --test` 聚合成统一状态；它不重写各类判定逻辑，但 `audit` 命令会把 P1–P8 的上游链和 global L4b 串起来。

```powershell
node bin/agent.js status                 # 只聚合，写 out/report/agent-state.json
node bin/agent.js gates --strict         # CI 用法；失败退出 3
node bin/agent.js audit --classes=all    # 统一全类链：上游 campaign + global L4b
node bin/agent.js audit --classes=all --reuse       # 只重跑 global L4b
node bin/agent.js audit --classes=all --reuse --with-l5 --with-report  # 追加 L5/L7
node bin/agent.js l5                     # L5 select -> target -> report
node bin/agent.js report                 # L7 findings + delivery
node bin/agent.js run --campaigns=p3p4p6,p1p2p7p8   # 确定性 campaign
node bin/agent.js run --campaigns=all --with-tests   # 含 P5、global L4b、L5、L7；可能需要 OH6_LLM_API_KEY
```

- 统一 gate 数固定为 **70** = P3/P4/P6 20 + P1/P2/P7/P8 15 + P5 13 + global L4b 5 + L5 8 + L7 8 + tests 1。
- **L5**：[lib/l5](lib/l5) + [bin/l5.js](bin/l5.js)；6 个 host fixtures（4 confirmed / 2 no-signal）、P4 `MallocStr` target 3/3 confirmed；O1 未闭合所以 T1=0。`out/l5/summary.json` 8/8。
- **L7**：[lib/l7](lib/l7) + [bin/report.js](bin/report.js)；59 张 T2 card、13 条 T3 observation、1 条 test-only 排除、0 T1、0 unresolved；`out/delivery/` 有 manifest/SHA256SUMS。`out/report/l7-summary.json` 8/8。
- **L4b 已全局化**：[lib/agent/l4b-global.js](lib/agent/l4b-global.js) 默认选取 P1–P8 的**全部 production T2/T3**（当前 78 条）：T2 做证据补强，T3 尝试补全 gap；P1/P2/P7/P8 的 T2 `refute` 可回写 O5/O6，P3/P4/P5/P6 只记录 observation，O10 不变。`--per-class=N` 仅用于限流；`audit --classes=...` 只控制上游重跑哪些类。
- gate 定义与 `evaluate(ctx)` 都在 [lib/agent/registry.js](lib/agent/registry.js) 自动加载的 `lib/agent/campaigns/*.js`；新增 campaign 只需增加一个定义文件，`status`/`gates`/`run` 自动发现；新增 gate 只改定义文件。
- 产物：[out/report/agent-state.json](out/report/agent-state.json)、[out/report/agent-gates.md](out/report/agent-gates.md)、[out/report/agent-node-test.txt](out/report/agent-node-test.txt)、[out/report/global-l4b-summary.json](out/report/global-l4b-summary.json)。
- 每个 gate 有全局唯一 `campaign/key` ID；`status`/`gates` 不跑 campaign，`audit`/`run` 才执行。
- 实现细节与完整架构见 [AGENT-IMPLEMENTATION-ARCHITECTURE.md](AGENT-IMPLEMENTATION-ARCHITECTURE.md)。
- 三篇参考（SpecAuditor / NEO / GitHub Security Lab Taskflow）的可落地设计综合见 [REFERENCE-DESIGN-SYNTHESIS.md](REFERENCE-DESIGN-SYNTHESIS.md)。
- P0 事实层（自建 L0/L1/L2、规则库、query/provenance）的执行方案见 [P0-FACT-LAYER-EXECUTION.md](P0-FACT-LAYER-EXECUTION.md)。
- P2 L6/L7（文档实体检索、reportability/severity/fix、条件扩面）的执行方案见 [P2-L6-L7-DELIVERY-EXECUTION.md](P2-L6-L7-DELIVERY-EXECUTION.md)。
- **唯一开发规范**：[AGENT-ARCHITECTURE-GUIDE.md](AG-EXECUTION/AGENT-ARCHITECTURE-GUIDE.md)，完整定义新 Agent 的目标与实现合同，不依赖历史架构材料。
- 历史分阶段记录保留在 [AG-EXECUTION/README.md](AG-EXECUTION/README.md)、[AG0](AG-EXECUTION/AG0.md)、[AG1](AG-EXECUTION/AG1.md)、[AG2](AG-EXECUTION/AG2.md)、[AG3](AG-EXECUTION/AG3.md)、[AG4](AG-EXECUTION/AG4.md)、[AG5](AG-EXECUTION/AG5.md)、[AG6](AG-EXECUTION/AG6.md)、[AG7](AG-EXECUTION/AG7.md)，不作为新开发的规范来源。

## 9.3 自主审计 Agent（MVP 闭环）

`doctor → index → run → check → report` 的最小闭环，只读消费 AG0 事实（`out/facts/<snapshotId>/`），
**不重建、不改写**事实层。方案见 [AG-EXECUTION/AUTONOMY-MVP-GOAL-GUIDE.md](AG-EXECUTION/AUTONOMY-MVP-GOAL-GUIDE.md)，
验收证据见 [AG-EXECUTION/AUTONOMY-RESULT.md](AG-EXECUTION/AUTONOMY-RESULT.md)。

```powershell
node bin/autonomy.js doctor  --scope=K/policies/autonomy-pilot-scope.json
node bin/autonomy.js index   --snapshot=sha256:2142c229... --scope=K/policies/autonomy-pilot-scope.json
node bin/autonomy.js tools   --scope=K/policies/autonomy-pilot-scope.json
node bin/autonomy.js run     --mode=off --scope=K/policies/autonomy-pilot-scope.json --budget=K/policies/autonomy-pilot-budget.json --max-tasks=0
node bin/autonomy.js check   --run=<runId>
node bin/autonomy.js report  --run=<runId>
node bin/autonomy.js verify  --run=<runId> --plan=<plan.json>   # 只登记占位，恒 blocked
node tools\autonomy-pilot-summary.js --run=<runId> [--replay=<第二次 runId>]
```

- 每个入口固定三个子问题：`Q-binding`（能否唯一绑定实现）/ `Q-check`（实现体内有无校验调用）/
  `Q-dominance`（校验是否支配敏感操作，**MVP 恒 insufficient**）。
- **candidate 不是漏洞**：只表示"绑定了唯一实现体，且函数体内直接调用中没看到词表内的校验调用"。
- **不出 finding**：没有 runtime witness（`verify` 只返回 `blocked`），`FINDINGS.md` 为空并注明原因。
- 工具 6 个可用（`getScopeOverview` / `searchEntities` / `inspectEntry` / `inspectRelation` /
  `getEvidence` / `inspectAuthorization`）+ 5 个 `unsupported`（具名 reason，不冒充实现）。
- 模式：`off`（零模型调用）/ `mock`（fixture）/ `live`（网关，需 `OH6_LLM_API_KEY`；缺 key 明确失败，不降级）。
- 产物：[out/autonomy/index/](out/autonomy/index/)、`out/autonomy/RUN-<hex>/`（records / evidence / checkpoints /
  C/O/F / checksums）、[eval/autonomy/pilot-summary.json](eval/autonomy/pilot-summary.json)（可从 run 产物复算）。
- 试点 scope = `base/accesscontrol/sandbox_manager`；`--max-tasks=0` 表示不限任务数，真实上限由预算文件决定。


## 运行

```powershell
cd oh6-surface-audit
node bin/audit.js snapshot
node bin/audit.js ledger
node bin/audit.js specdiff
node bin/audit.js all
```

结果在 `out/`。所有输入只读；不改 `OpenHarmony/`，不改 `oh6-vuln-agent/result/`。
