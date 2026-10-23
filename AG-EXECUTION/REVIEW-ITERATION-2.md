# 第二轮迭代评审：方向、可行性与后续建议

> 评审对象：`AG-EXECUTION/AGENT-ARCHITECTURE-GUIDE.md` v1.0.14（1494 行，131 KB，2026-10-22 18:28）
> 实现对象：`lib/autonomy/` 22 个模块、`bin/autonomy.js`、45 个 `out/autonomy/RUN-*`
> 评审日期：2026-10-22
> 方法：读 §24.4–§24.15 的迭代记录、§21–§23 的评估与验收合同，复跑测试与评估器，逐条统计 run 产物。
> 口径：只保留可复算的确定性事实与一版建议；不保留过程性选项。

---

## 0 结论

工程上，它已经是一个**可运行、可复算、额度诚实**的证据引擎（22 模块、322 测试、45 个版本化 run、确定性 replay、受限恢复）；科学上，它**还没有证明自己能判别**——任务级裁决被程序固定为 `insufficient`，而评估器只统计这个恒弃答的问题。

**当前最该做的不是再加机制，而是把评估对象改成系统能回答的问题，给 candidate 一个可证伪的出口，并让最小纵向流程覆盖设计中的多数 LLM 调用点。**

443 条 missing 的归因是：**46% 架构固定（dominance 205 条，补实现无效）、38% 实现缺口（补实现有效）、其余约 15% 为知识/范围/数据**。这个比例决定了修复顺序：先改出口与问题分解，再补 operation 绑定，最后才是知识与数据。

按去重问题计：**77 个问题里 45 个可判定（58.4%），32 个 insufficient（41.6%）**；判不动的集中在 `dominance` 与授权效果。

| 维度 | 评分 | 依据 |
|---|---|---|
| 方向合理性 | **8/10** | 全量架构 → MVP → 单入口 → 双入口 → 局部反证，收敛路径正确 |
| 工程质量 | **9/10** | 322 tests、70/70 gates、确定性 replay、恢复、内容寻址 |
| 科学有效性 | **3/10** | 任务级裁决 27/27 `insufficient`；0 finding；无标签 |
| 可评估性 | **4/10** | holdout 只统计恒弃答问题；能判定的局部问题被排除在分母外 |
| 可维护性 | **5/10** | 131 KB 规范内嵌 12 节实验日志；3 份架构文档并存；8 个实验版本 |
| 诚实度 | **10/10** | 每轮都写明"不证明效果"；不伪造标签；截断被记录 |

---

## 1 迭代记录与实现数据

### 1.1 一天的迭代轨迹

| 版本 | 实验 | 主要动作 | 结果 |
|---|---|---|---|
| 1.0.0-mvp | MVP | 三问模板、off 闭环 | 24 task / 7 candidate / 0 finding |
| 1.0.1/1.0.2-auth | 授权最小实验 | `origin` 分流、一跳委托、`operation-unbound` | 24 task 全 observation |
| 1.0.3–1.0.5-vertical | 纵向 v1 | 单入口 live、规范提案、跨视图分支、模型账本 | 2 task / 0 candidate，模型意见被门控压成 insufficient |
| 1.0.6-vertical | 纵向 v2 | 第二入口、第二规范提案 | 1 task / 0 candidate |
| 1.0.7-vertical | 权限参数反证 | `inspectPermissionArgument` | 3 supported / 4 refuted（局部），主裁决仍 insufficient |

- **45 个 run**，覆盖 8 个 `architectureVersion`、off/live/replay 三种模式；
- **22 个模块**（`branch/delegation/diagnostic/knowledge/permission-argument/recovery/summaries/vertical/verification` 等）；
- **322/322 tests**（复跑需临时 `GIT_CONFIG_*` 放行嵌套 git 所有权）；**70/70 gates**（其中 `150 tests` 是旧汇总）；
- 规范 **1.0.14**，§24.4–§24.15 共 12 节实验记录。

### 1.2 跨 45 个 run 的聚合数据

**Assessment 按命题统计**：

| 命题 | supported | refuted | insufficient |
|---|---|---|---|
| 入口能否绑定到唯一实现？ | 191 | 0 | 14 |
| 实现体内是否存在权限/身份校验调用？ | 98 | **84** | 23 |
| 校验是否支配敏感操作、且对象一致？ | 0 | 0 | **205** |
| **异步入口的调用主体是否在策略修改前得到有效授权？** | 0 | 0 | **27** |
| 策略数据解析是否拒绝越界/异常输入？ | 0 | 0 | 18 |
| 一跳 CheckPermission 权限实参是否与文档一致？ | 3 | 4 | 0 |

**Missing 原因分布**（443 行）：

| reasonCode | 次数 | 含义 |
|---|---|---|
| `dominance-unproven` | 205 | 不做支配/对象分析 |
| `operation-unbound` | 74 | 入口没有具体操作绑定 |
| `delegated-check-unproven` | 43 | 一跳委托的检查未被证明 |
| `norm-applicability-unapproved` | 27 | 规范未获批准 |
| `operation-target-unproven` | 27 | 操作目标是 name-only |
| `verification-disabled` | 27 | 无隔离 runner |
| `binding-metadata-only` | 14 | SA 入口只有元数据 |
| `check-call-weak-only` | 7 | 只有身份获取、不算校验 |
| `input-parser-unproven` | 18 | 解析目标未证明 |
| `model-output-invalid` | 1 | 模型输出未过证据门 |

**归因**（同一批 443 条，按成因分组）：

| 类别 | 条数 | 占比 | 典型 reasonCode | 补什么能降 |
|---|---|---|---|---|
| **架构固定** | 205 | **46%** | `dominance-unproven` 205 | 改裁决/出口规则，不是加实现 |
| **实现缺口** | 170 | **38%** | `operation-unbound` 74、`operation-target-unproven` 27、`delegated-check-unproven` 43、`input-parser-unproven` 18、`check-call-weak-only` 7、`model-output-invalid` 1 | 补 operation 绑定、调用目标解析、多跳委托、parser 分析 |
| 知识供给 | 27 | 6% | `norm-applicability-unapproved` | 生成并发布规范 |
| 范围外 | 27 | 6% | `verification-disabled` | 只产静态候选时不需要 |
| 数据缺口 | 14 | 3% | `binding-metadata-only` | 补 SA 元数据/操作 |

计数口径：443 是 `(run, task, question)` 的实例数，不是 443 个独立缺陷；`dominance-unproven` 每个任务贡献一条（205 = 205 个任务实例）。**补实现只能动 38%；46% 的架构固定项不会因实现变大而下降。**

另注：27 个 `authorization-effect` Assessment 也被门控固定为 `insufficient`，但其 missing 落在上表的知识/实现/范围类（`norm-applicability-unapproved`、`operation-target-unproven`、`verification-disabled`），不重复计入"架构固定"。

**知识/标注**：`K/norms/` 为空；`out/autonomy/knowledge/proposals/` 只有 1 个提案（`d75afb38…`，SetPolicy）；`eval/autonomy/labels.json` 仍 `pending`，独立评估器返回 `insufficient-sample`。

### 1.3 计数口径与指标（先定义分母）

同一批产物有四种计数单位，不能混用：

| 单位 | 当前值 | 用途 |
|---|---|---|
| missing 行 | **443** | 缺口清单；含跨 run 重复 |
| assessment 行 | **667** | 裁决记录；含跨 run 重复 |
| distinct question | **77** | **去重后的问题数；评估能力用它** |
| task | 24/run（MVP、auth） | **候选率用它** |

**去重后的 77 个问题**（同一 `questionId` 取最后一次裁决）：

| 命题 | supported | refuted | insufficient | decisive rate |
|---|---|---|---|---|
| 入口绑定 | 22 | 0 | 2 | 91.7% |
| 函数体内有无校验调用 | 14 | 7 | 3 | 87.5% |
| 校验是否支配敏感操作 | 0 | 0 | 24 | **0%** |
| 异步入口授权效果 | 0 | 0 | 2 | **0%** |
| 权限实参是否与文档一致 | 1 | 1 | 0 | 100% |
| 解析是否拒绝越界输入 | 0 | 0 | 1 | 0% |
| **合计** | **37** | **8** | **32** | **58.4%** |

**四个率（下一轮报告必须用这四个，不用总条数）**：

| 指标 | 分子 | 分母 | 当前 | 目标 |
|---|---|---|---|---|
| decisive rate（binding + check） | 43 | 48 | **89.6%** | ≥90% |
| insufficient per-question rate | 32 | 77 | **41.6%** | 逐轮下降 |
| candidate rate | candidate tasks | tasks | MVP 7/24 = 29.2%；auth 0/24 = 0% | 有可行动候选 |
| operation-unbound rate | 74（行） | 待去重 | 待补 | <30% |

口径纪律：

- 443 条 missing 是行数，不是缺陷数；`dominance` 每任务一条（205 = 205 个任务实例）；
- 能力评估用 distinct question（77），不用 667 行；
- 候选率用 task，不用 question；
- 扩入口会抬高绝对条数，必须同时报分母。

---

## 2 方向合理性：做对了什么

### 2.1 收敛路径正确

从"全量六职责架构"收缩到"单组件 → 单入口 → 双入口 → 局部反证"，每一步都配负例、失败用例和"不证明效果"的声明。这是**工程上正确的降风险顺序**。

### 2.2 把瓶颈定位在"候选精度"而不是"索引规模"

`origin` 分流、一跳委托、`operation-unbound`、`permission-argument-match` 都围绕"candidate 值不值得看"，而不是继续堆索引。

### 2.3 诚实机制是真实存在的

- `FINDINGS.md` 为空并写明"未证 ≠ 无问题"；
- `labels.json` 保持 `pending`，评估器拒绝测试标签冒充；
- 截断（`finishReason=length`）被记录，不悄悄改写历史 run；
- `replay` 只重放解析结果，不宣称重放供应商原始响应；
- 发布器有内容哈希与信任锚机制（当前尚无正式 norm 发布）。

### 2.4 恢复与信任边界做了真正的工作

任务边界恢复、首个工具 intent 恢复、实现指纹、单写者锁、`remote-outcome-unknown` 不重发——这些是很多同类系统会跳过的部分。

---

## 3 可行性评价

### 3.1 工程可行性：高（9/10）

- 全部在 Windows 原生跑通，无 WSL 依赖；
- off run 77–90 ms、live 单入口 2 次请求约 27–88 s；
- 确定性 replay 与语义哈希可复算；
- 322 个测试覆盖契约、工具、恢复、评估器、安全边界。

### 3.2 科学有效性：低（3/10）

**评估目标与门控自相矛盾。**

- M5 的 holdout 只统计 `authorization-effect`（§21.5）；
- 而 `vertical.gateInterpretation` 与控制器把 `authorization-effect` **固定写成 `insufficient`**（§24.12 自述，27/27 实测）；
- 因此即使有 20 正/20 反/10 缺信息的标签，系统输出也永远只有 `insufficient`：accuracy 无意义、false-certainty 恒 0、"弃答质量"成了唯一可测指标；
- 真正能出 `supported/refuted` 的 `permission-argument-match`（3/4）被排除在效果分母之外。

**这不是"效果差"，是"评估设计测不出能力"。** 继续跑 live/replay/off 只会增加同一条问题的重复记录。

**另有一层问题分解错误**："授权是否有效"需要主体、对象、支配关系与失败路径；当前证据只能回答"函数体内有没有出现某个校验名的直接调用"。这不是实现规模问题，而是**问题层级与证据层级不匹配**。应拆成：

- `authorization-presence`（可判定）：有无校验调用、实参是否与文档一致；
- `authorization-effectiveness`（当前不可判定）：是否支配、对象是否一致、失败是否处理。

任务级 decision 应由这两类**组合**得出，而不是把 effectiveness 当唯一门槛。

### 3.3 约束

| 约束 | 现状 | 影响 |
|---|---|---|
| 单入口过拟合 | v1 固定 `SetPolicyAsync`；8 条 v1 run 共享同一问题 `Q:95f6…` | 任何 precision/recall 都不可信 |
| 知识供给 | 0 条正式 norm，1 条 proposal | M2 未闭环 |
| 隔离能力 | Windows Sandbox/Hyper-V 均 Disabled | 只产静态候选时不构成阻塞；出 finding 才需要 |
| 模型可比性 | v1 用 `cn:glm-5.3-flash`，v2 用 `cn:step-5-preview` | 跨实验不可比 |
| 截断 | SetPolicy live 出现 `finishReason=length`（4096 tokens） | 模型意见不完整，不能当完成证据 |

---

## 4 主要风险

| # | 风险 | 证据 | 后果 |
|---|---|---|---|
| 1 | **评估测不出能力** | holdout 只统计恒弃答问题；可判定问题被排除 | M5 永远 `insufficient-sample` 或"全弃答" |
| 2 | **candidate 没有出口** | 84 次 `check-presence=refuted`，但 `operation-unbound` 74 次，candidate 0 | 证据采到了，决策出不来 |
| 3 | **单入口/同家族过拟合** | 8 条 v1 run 同一问题；v2 只多一个入口 | 无法证明泛化 |
| 4 | **规范生成的自证风险** | 规范由模型生成，无人工签名；与 Agent 可能同源 | 需要用模型分离 + 来源锚定 + 内容哈希缓解 |
| 5 | **文档/版本膨胀** | 131 KB 规范 + 12 节实验日志 + 3 份架构文档 + 8 个实验版本 | 契约被日志淹没 |
| 6 | **模型/参数漂移** | 两个模型混用；截断未统一处理 | 实验不可比，结论不可复算 |
| 7 | **gate 计数失真** | 322 tests 但 gate 显示 150 | 外部读者看到的"不回归"是旧数 |
| 8 | **兼容分支累积** | v1/v2/1.0.x 多套 schema 与 run 合同 | 后续每加一个机制都要维护多版本 |
| 9 | **问题层级与证据层级不匹配** | "授权是否有效"只能用"有无直接校验调用"回答；`dominance` 205/205、`authorization-effect` 27/27 恒 `insufficient` | 补实现无法降低；必须先拆分 presence/effectiveness 并定义组合规则 |

---

## 5 当前架构（agent 工程视角）

### 5.1 控制流：静态计划 + 任务循环

`bin/autonomy.js` 的主循环：

```
discovery 枚举入口 → plannedTasks（静态计划）
  → for (task of plannedTasks)
  → 每任务按 origin 固定工具序列
  → assessment → report
```

- 没有通用 action space；
- 没有动态 replanning（只有一个 type-hint 触发的 `analysis-branch`）；
- 没有多轮 think-act-observe。

### 5.2 决策点：设计 vs 实现

| 设计的 LLM 用途（§14.3） | 实现状态 | 代码位置 |
|---|---|---|
| `discover` | **未接**：入口枚举是确定性规则 | `discovery.js` |
| `plan` | 仅 vertical：只能选一个 `inspectDelegation` action | `vertical.js:122` |
| `interpret` | 仅 vertical：局部判断 | `vertical.js:176` |
| `summarize` | **未接**：条件摘要是确定性的 | `summaries.js` |
| `judge` | live 裁决路径，受程序证据门 | `assessment.js:310` |
| `extract-norm` | **未接**：规范提案由确定性抽取 | `knowledge.js` |
| `format-repair` | **未实现** | — |

> `diagnostic.js` 的 `diagnostic-*` 是开发诊断，不在生产链。

主 `run` 在 off 模式 **0 次模型调用**；vertical live 每次 2 次请求（plan + interpret）。

### 5.3 状态、工具、上下文、记忆、评估

- **状态**：append-only `events.jsonl` + 每任务 checkpoint + 单写者锁；
- **工具**：dispatcher（schema/权限/预算/超时/上限/归档/台账）；
- **上下文**：ContextPacket（入口、绑定、guards、calls、源码窗口、token 估算、`sufficiency`）；
- **记忆**：`summaries.js` 条件摘要 + 依赖失效；无向量库；
- **知识**：提案/发布机制，0 条正式 norm；
- **评估**：独立 holdout 评估器，标签 pending；
- **无多 Agent、无 MCP、无向量 DB**。

### 5.4 与业界模式对照

| 模式 | 业界代表 | 当前实现 | 评价 |
|---|---|---|---|
| **ReAct** | LangChain Agent、function calling | 无自由循环；仅 vertical 单 action | 对审计是对的：要可复算，不要自由发挥 |
| **Plan-and-Execute** | LangGraph plan node、AutoGPT | 静态计划 + 固定执行 | 有计划，无缺口驱动的重规划 |
| **Reflexion** | Reflexion、Self-Refine | 只有 no-progress 停止，无结构化 reflection | 可借：写 reflection 记录，不写隐藏 CoT |
| **Router** | LangGraph router、semantic router | views 当路由；无模型路由 | 视图路由够用；模型分层未做 |
| **LangGraph** | graph + checkpointer | 自研事件账本 + checkpoint | 图编排用不上；checkpoint 是重复造轮子 |
| **LangChain tools** | tool schema + executor | 自研 dispatcher + JSON schema 子集 | 工具协议重复；证据归档是差异化 |
| **Context engineering** | LlamaIndex、LangChain retrieval | 自研 ContextPacket + sufficiency | 比多数框架更严，不是轮子 |
| **Harness engineering** | sandbox + approvals + tracing | 自研 dispatcher/gateway/store | 分层对；缺标准 tracing |
| **Eval harness** | promptfoo、DeepEval | 自研 evaluator | 运行器是轮子；grader 是差异化 |

---

## 6 重复造轮子清单与建议

### 6.1 高重复度组件（建议优先处理）

| 组件 | 现成方案 | 重复度 | 建议 | 成本 |
|---|---|---|---|---|
| **JSON-Schema 校验**（`schema.js`） | ajv / zod | 高 | 引入 ajv（或 vendor），保留薄封装；不要再扩自研子集 | 0.5 天 |
| **持久化执行 / 恢复**（`recovery.js`） | Temporal、Restate、LangGraph checkpointer | 高 | 不整体迁移（Windows、无依赖、审计哈希难满足）；借"幂等键 + 状态机 + 补偿"模型，补属性测试 | 2–3 天（借模式，不换框架） |
| **观测 / tracing** | OpenTelemetry、Langfuse | 高 | 保留账本为权威，额外发 tool/model/task span；不要两套真相 | 1 天 |
| **评估运行器**（holdout-eval） | promptfoo、DeepEval | 中高 | 用现成 runner 管用例/报告，grader 仍用 `missing`/`evidenceRefs` 逻辑 | 1–2 天 |
| **token 计数** | js-tiktoken | 中 | 替换 `chars/4` 估算；预算敏感时误差会放大 | 0.5 天 |
| **重试/退避** | p-retry、Bottleneck | 中 | 复用，不要手写退避 | 0.5 天 |

### 6.2 中低重复度

| 组件 | 现成方案 | 建议 |
|---|---|---|
| BM25 / 检索 | lunr、flexsearch | 当前 scope 小，可不换 |
| CLI 解析 | commander / yargs | 可换可不换 |
| 函数调用协议 | 原生 tool_calls / MCP | 保持 JSON content 以支持 replay；可选支持原生 tool_calls，不强制 |

### 6.3 不应替换的自建部分

1. **证据账本 + 内容哈希 + 可回查引用**：框架的 trace 不是可复算证据；
2. **`missing` 作为一等输出**：框架的错误处理是 exception/None；
3. **`sufficiency` / `truncated` 上下文语义**：框架给截断，不给"够不够判"；
4. **确定性 replay（解析结果级）**：框架缓存按 prompt 哈希，不保证 run 级重放；
5. **来源锚定的规范/知识**：框架没有发布/失效模型；
6. **模型相对评估**：框架报分数，不报标签生成者与运行时模型是否同源。

---

## 7 后续迭代建议

### 7.0 前置必做：三件事（先于 P0）

以下三条为已确认口径，作为下一轮的前置门；不做，P0 的评估口径与出口规则改了也无法验收。

| # | 必做项 | 结论/做法 | 验收证据 | 影响的文件 |
|---|---|---|---|---|
| 1 | **范围锁定：只产静态候选，不做 finding** | finding 不在 v1 范围；`verify` 保持 `blocked`；§23 验收中与 finding 相关的条目移除；不投隔离 runner / 设备 | `FINDINGS.md` 为空且注明原因；`verify` 返回 `blocked` 且 `executedCommands=[]` | 规范 §15/§23、报告策略、`verification.js` |
| 2 | **规范生成：AI 生成 + 模型分离 + 来源锚定，不做人工签名** | 规范由完成实现的模型生成；`authority: llm-generated`；记录 `generator.model/promptVersion`；每条锚定 `file:line:sha256`；发布与运行时重抽取比对；`knowledgeVersion = sha256(canonical(norm))`；标注模型 ≠ 运行时模型 | 至少 2 条规范发布（SetPolicy / UnSetPolicy）；`sourceRefs` 可回查；篡改原文后发布/运行被拒 | `knowledge.js`、norm schema、`K/norms` |
| 3 | **评估标签：AI 生成、盲标、冻结、只报一致率** | 标注由实现模型完成且**看不到 Agent 裁决**；`annotator: model:<id>`；`generation` 块；冻结后内容哈希；指标叫 `agreementWithModelLabels`，不叫 accuracy；同源时标 `sameFamily=true` | 10/10/5 冒烟标签生成并冻结；评估器跑出一致率；报告写明标注模型 | labels schema、holdout evaluator、报告 |

**顺序**：1 → 2 → 3 → P0。第 1 条决定验收边界；第 2、3 条决定"证据从哪来"；三者完成后再改 P0 的评估口径和出口规则，否则改了也测不出。

### 7.1 P0

1. **重定义 M5 的评估对象**：
   - A 组（可判定局部命题）：binding、check-presence、`permission-argument-match`、operation-target —— 统计 accuracy、false-certainty、abstention-quality；
   - B 组（任务级 authorization-effect）：只统计"是否正确指出关键缺口"，**不统计 accuracy**；
   - 改 §21.5 口径：不再把恒弃答问题当 accuracy 分母。
2. **拆开问题**：`authorization-presence`（可判定）与 `authorization-effectiveness`（需支配/对象/运行时）分开，任务级 decision 用组合规则：
   ```
   presence refuted（无校验调用 / 实参不匹配）
       → candidate（missing=effectiveness-unproven）
   presence supported + effectiveness 缺
       → observation
   binding 不足
       → observation
   ```
   这是 46% 架构固定项的唯一解：不能再把 effectiveness 当 candidate 的门槛。
3. **给 candidate 一个可证伪的出口**：按第 2 条的组合规则输出；`dominance` 继续 `insufficient`，但**不阻断** candidate。验收：同一批入口能产出 ≥1 个 candidate，且每个都带 `missing`。
4. **把 operation 绑定列为 P0**：`operation-unbound` 74 次是当前最大的单点阻塞。做法：
   - 从 IDL 方法名/参数 + 调用点（`SetPolicyAsync → SetPolicy`）+ 规范里的操作名，生成 `operationRef`；
   - 绑定状态 `resolved/suspect/unbound`；`suspect` 也允许进入"具体疑点"；
   - 验收：10 个真实入口上 `operation-unbound` < 30%。
5. **扩入口到 5–10 个真实 IDL 方法、2–3 个组件**，每个配 source-backed norm；同家族改写不能当独立样本。
6. **冻结模型与请求参数**：一个评估系列固定一个 catalog id；`finishReason != stop` 一律记 `insufficient` 并版本化。
7. **规范/标签改为"AI 生成 + 模型分离 + 来源锚定"**：
   - 规范由完成实现的模型生成，记录 `generator.model/promptVersion`；
   - 每条规范锚定 README/头文件 `file:line:sha256`，发布与运行时重抽取比对；
   - `knowledgeVersion = sha256(canonical(norm))`，只增不改；
   - 标签同理，`annotator: model:<id>`，标注模型 ≠ Agent 运行时模型；
   - 指标改称"与模型标签的一致率"，不叫准确率。
8. **量化四个率，而不是总条数**：
   - binding / check-presence 的 **decisive rate**（目标 ≥90%）；
   - candidate 的 **actionability rate**（标注集上 ≥50%）；
   - `operation-unbound` 的 **rate**（目标 <30%）；
   - **insufficient per-question rate**（每问题，而非总数）。
   扩入口会抬高 `insufficient` 的绝对条数，必须看率。

### 7.2 先用对照实验分清架构 vs 实现

只改出口规则（presence refuted 即可 candidate，`dominance` 不阻断），跑同一批入口：

- **出现 candidate** → 瓶颈在出口/问题分解（架构）；
- **仍为 0** → 瓶颈在 operation 绑定/绑定质量（实现）。

成本：一条映射 + 一次 off run（<1 分钟），比继续争论"实现小不小"更有说服力。结果写回本节。

### 7.3 最小完整纵向流程应覆盖的 LLM 调用点

当前 vertical 只接了 `plan` + `interpret` 两个点；"最小完整纵向流程"应至少覆盖下表 5 个，另 2 个用独立测试覆盖：

| # | 调用点 | 在一条纵向流程里要证明什么 | 程序门 |
|---|---|---|---|
| 1 | `discover` | 模型从发现包提出 ≥3 个有锚点的问题，不发明实体 | 锚点存在、版本一致、去重 |
| 2 | `plan` | 模型在 ≥3 个允许 Action 中选一个，非法/过期 Action 被拒 | Action schema + task revision |
| 3 | `interpret` | 对局部语义问题给 supported/refuted/insufficient，附引用 | 引用可回查、枚举合法 |
| 4 | `summarize` | 产出条件摘要，带前提与依赖哈希；依赖变化后失效 | 依赖哈希校验 |
| 5 | `judge` | 综合支持/反证/缺口给 Assessment，不越权 | 证据门 + 禁止词 |
| 6 | `extract-norm` | 从 README/头文件提出规范提案（proposed，不发布） | 原文重抽取 + 来源锚定 |
| 7 | `format-repair` | 注入一次坏 JSON，模型修复且只计一次费用 | 只允许一次修复 |

**要求**：一条 run 里至少串起 1–5；6 放在 `knowledge propose`；7 用故障注入测试。每次调用都要计预算、写台账、可 replay——覆盖调用点不是"多调模型"，而是证明**每个设计节点都有受控的输入、输出和失败路径**。

### 7.4 P1

9. **拆分文档**：把 §24.4–§24.15 移到 `AG-EXECUTION/ITERATION-LOG.md`；规范只留契约与验收；`SINGLE-AGENT-IMPLEMENTATION-GUIDE.md` 与 `ARCHITECTURE-TARGET.md` 标为历史，只留一份权威。
10. **收敛实验分支**：v1/v2 的 run 保留只读，代码收敛到一条路径；删除 `--experiment` 兼容分叉或明确冻结日期。
11. **修正 gate 计数**：把 322 项纳入汇总，或拆成 `autonomy-suite` 与产品基线两个数。
12. **成本标定**：扩入口后测 30–60 次 live 的 P50/P95，再决定预算默认值（当前 30 次偏低）。
13. **采纳 6.1 的高重复度组件建议**（ajv / OTel / token 计数 / 重试），把自研精力留给差异化部分。

### 7.5 P2

14. 完整恢复、MCP、多 Agent、知识库全量建设——等 M5 有可测结果再说。
15. 隔离 runner/设备验证——不在"只产静态候选"的范围内。

### 7.6 停止做的事

- 停止在同一入口上做更多"局部正反"变体（同家族不能当独立样本）；
- 停止把"没发出 candidate"写成精度收益；
- 停止在规范正文里继续内嵌实验日志；
- 停止用测试密钥/合成标签冒充正式审核（改为 AI 生成 + 溯源 + 模型分离）。

---

## 8 一页纸

| 问题 | 回答 |
|---|---|
| 方向对不对？ | 对。收敛路径、诚实机制、把瓶颈放在候选精度上，都是正确的 |
| 工程能不能跑？ | 能。322 tests、70/70 gates、45 run、确定性 replay、恢复 |
| 有没有证明能发现？ | **没有**。任务级实质问题 27/27 `insufficient`，0 finding，0 标签 |
| 为什么证明不了？ | 评估只统计被程序固定为 `insufficient` 的问题；能判定的局部问题被排除 |
| **为什么 `insufficient` 多？** | **46% 架构固定**（`dominance` 恒弃答，205 条）、**38% 实现缺口**（operation 绑定/调用目标/委托/parser）、**约 15% 知识·范围·数据**；补实现只动 38% |
| **去重后多少能判？** | **45/77 = 58.4% decisive**；32/77 = 41.6% insufficient；`dominance` 与授权效果 0% |
| **补实现能解决多少？** | 最多 38%；candidate 仍可能为 0，除非先改出口规则（presence refuted 即可 candidate） |
| 当前像 agent 吗？ | 不像。是"静态计划 + 固定取证 + 窄模型节点"的流水线，不是自主循环 |
| 重复造轮子多吗？ | 编排没造（流程简单）；schema/恢复/观测/评估造了，见 §6.1 |
| 最该先做什么？ | 拆 presence/effectiveness + 改出口 + operation 绑定 + 四个率 + 覆盖 5 个 LLM 调用点 |
| 最该停什么？ | 同家族变体、把弃答当精度、规范内嵌日志 |
| 一句话 | **工程已就绪，科学待证；先分清 46% 架构固定与 38% 实现缺口，再改出口与问题分解。** |
