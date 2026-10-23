# 评审：《AGENT-ARCHITECTURE-GUIDE》在当前环境的可行性与有效性

> 评审对象：`AG-EXECUTION/AGENT-ARCHITECTURE-GUIDE.md`（v1.0.0，1120 行，2026-10-21）
> 评审日期：2026-10-22（**2026-10-22 晚增补 §11：MVP 构建完成后的实测校准，§0 评分已按实测更新**）
> 方法：文档全文通读 + 与当前代码/产物/环境逐项对照。凡标"实测"的，均来自本会话可复算的证据；标"代码核实"的，来自对现有实现的直接阅读；标"未验证"的，明确没有证据。
> MVP 交付物：`AG-EXECUTION/AUTONOMY-RESULT.md`、`out/autonomy/RUN-9b1bdf44daebe542/`、`eval/autonomy/pilot-summary.json`。

---

## 0 结论

**一句话**：这是一份纪律很强、边界清晰的上层规范。**最小闭环已被真实构建并跑通**（280 tests、70/70 gates、24 任务/72 子问题/7 candidate/0 finding，off 模式 287 ms、0 次模型调用），证明"骨架"完全可行；但**候选精度尚未证明**——本次试点的 7 个 candidate **没有一个是可直接行动的**（2 个是委托包装、5 个是非入口的覆盖抽样函数）。

| 维度 | 评分 | 依据（2026-10-22 实测后） |
|---|---|---|
| 设计严谨性 | **9/10** | 12 条不变量、来源分离、强否定门槛、内容≠指令、单写者账本；MVP 逐一落地且可检查 |
| 与现状契合 | **8/10** | AG0 零改动复用（22 个基线文件 0 changed）；新增代码全在 `lib/autonomy/`，边界干净 |
| 工程可行性 | **9/10** | 9 个阶段、14 个模块、47 个新测试，一个 agent 在约 12 分钟内完成并通过全部验收 |
| 当前有效性 | **5/10** | 机制有效（事实正确、可回查、可复算）；但 7/7 candidate 不可行动，精度问题未解 |
| 成本可控性 | **8/10** | off 模式 **0 次模型调用**、287 ms/run；live 只做 1 次冒烟；成本不再是瓶颈 |
| 诚实度 | **9/10** | FINDINGS 为空并写原因、labels 保持 pending、偏差与缺口逐条登记 |

**核心判断（更新）**：骨架不是问题，"发现"才是问题。MVP 已经证明"问题 → 证据 → 裁决 → 报告"的管道可以确定性运行；下一阶段的全部价值在**提高 candidate 的可行动性**（委托展开、入口/抽样分离、支配关系），而不是继续扩管道。

---

## 1 它主张的是一次路线切换

文档第 0 节声明"本文是新 Agent 架构、接口、实现顺序和验收要求的**唯一开发规范**，其他架构材料只保留历史价值"。这意味着：

| 现有 | 文档主张的替代 |
|---|---|
| L0–L7 分层 | 六项逻辑职责（事实/知识/派生/证据服务/发现调度/裁决） |
| claim + O1–O9 | task + question + evidence-needs 图 |
| S1/S2/S3/SX | decision `supported/refuted/insufficient/conflict` + assurance |
| V0–VX | verification result + `entryFaithfulness` |
| C/O/F（S×V 矩阵） | report policy 表（finding 需 runtime witness） |
| K/obligations | K/norms + concepts + views + recipes |

这不是"补充"，是**换一套状态语义**。若不明确取舍，实现者会同时面对 `S1` 与 `supported`、`O5` 与 `QUESTION:object` 两套词表。

---

## 2 与当前环境的逐项对照

| 文档假设 | 本机现状 | 判定 |
|---|---|---|
| Windows Node 控制器 | 已具备（Node 25、229 tests、70/70 gates） | ✅ 符合 |
| WSL 做**目标语义** Clang | 已装 Debian 12（`D:\wsl\debian`，524 MB）；Linux clang 15.0.4 可跑，单文件 **16.2 s** vs native 0.48 s（**33×**） | ✅ 可用，但只能点用、不能批量 |
| 不得用 Windows clang 作目标语义 | 同意；但 Windows clang 已实测可做**语法指纹**（100 抽样 78 通过），保留 |
| 模型走统一网关 | 本机 `127.0.0.1:7864` 已验证：52 个模型、`cn:step-5-preview`、smoke 通过；单次 7,493 token / 33 s | ✅ 可用，但吞吐与限流未知 |
| 事实层可直接消费 | AG0 已交付：4,476 文件、13 张表、789 MB | ✅ 可用 |
| 入口绑定可用 | AG1 **未实现**；当前只有 metadata + 命名匹配 | ❌ **缺** |
| 文档库可用 | `OpenHarmony/docs` 约 26,363 文件 / 2.6 GB（文档估算），L6 未建 | ❌ 未就绪 |
| 设备 runner 默认关闭 | 无设备 | ✅ 符合（但也意味着 finding 门槛达不到） |
| 一个组件纵向试点 | 合理 | ✅ 建议选 **sandbox_manager**（566 函数，最小；有 IPC/权限语义） |
| 预算默认 30 次模型请求 / 100 任务 | 100 任务 × 每任务 ≤6 次 = 600 次，**默认预算与任务规模自相矛盾** | ⚠️ 需重新标定 |

**环境结论**：Windows 侧完全可行；WSL 目标语义与模型网关吞吐是两个必须先验证的前置条件。

---

## 3 模块可行性评分

| 模块 | 可行性 | 理由 | 建议 |
|---|---|---|---|
| 事实适配（`lib/facts`） | **高** | 已有 FactsIndex、稳定 ID、manifest | 直接做薄适配 + 修 5 个已知缺陷（§5） |
| 知识库（norms/concepts） | **中** | 设计清楚，但文档→实体→规范需要人工审核；26k 文件规模大 | 先做 1 个组件 + 1 个视图（authorization） |
| 派生答案（summaries） | **中** | 设计合理；缓存键/失效/自证环处理复杂 | 首版只缓存"权限封装/分发器"两类 |
| 工具调度（dispatcher） | **高** | 与现有 query API 的 `wrap` 契约兼容 | 先 4 基础 + 1 问题级（`inspectAuthorization`） |
| 任务/子问题 | **高** | 纯数据模型 + 状态机 | 可直接实现 |
| 上下文编译（ContextPacket） | **高** | 关键是 tokenizer 校准与充分性记录 | 首版固定 8–12k 输入，实测校准 |
| 模型网关 | **高** | 复用 `oh6-vuln-agent/src/llm/http.js`，已验证 | 加预算/台账/取消 |
| 裁决（Assessment） | **中** | 语义判断依赖 LLM；程序只能查证据门 | 首版只放行 `candidate/insufficient` |
| 隔离验证（verification） | **低–中** | 无设备；IPC 服务的 entry-faithful harness 很难构造 | 首版只登记计划，不执行 |
| 账本/恢复 | **中** | 事件溯源 + checkpoint + orphan 处理工程量大 | 首版 append-only + 重跑，不做 exactly-once |
| CLI | **高** | 纯工程 | 先 `doctor/index/run/inspect/check/report` |

---

## 4 有效性：能不能真的发现问题

### 4.1 设计上的优势

1. **问题驱动而非模板驱动**：任务围绕行为命题（"能否未经对象授权执行修改"），不围绕漏洞类，避免了"命中危险函数即告警"的旧病。
2. **来源分离**：`observed / derived / llm / runtime` + `assurance` 分级，比 AG0 的 `quality.resolution` 更能表达"这条结论有多硬"。
3. **强否定纪律**：`may-reach` 不等于可达，`unreachable` 需要保守模型 + 完整未解析边 + 未截断；这直接堵死了当前 DFG（coverage 0.5153）被误用的可能。
4. **反证与例外是一等公民**：每个 judge 包必须带"最强反对解释"；负结果只关闭该启发式，不关闭实体。
5. **上下文充分性可审计**：`ContextPacket` 记录 `sufficiency / omittedRefs / truncated`，不允许"预算不够就删掉关键证据还称充分"。

### 4.2 四个有效性折扣

| 折扣 | 证据 | 后果 |
|---|---|---|
| **事实底座不足** | 宏未展开（11,328 个宏函数只识别形态）、类型全 syntax-only、DFG 0.5153、compdb 覆盖 47.4% | `inspectAuthorization` 经常"找到检查调用，但无法确认对象一致" → `insufficient` |
| **入口绑定缺失** | AG1 未实现，只有 metadata 220 个 IDL 方法 + 命名匹配 | `inspectEntry` 只能给候选；`ambiguous/unbound` 比例高 |
| **finding 门槛过高** | 默认要求 runtime witness；设备 runner 关闭；IPC harness 难构造 | 首版 FINDINGS ≈ 0，只能出 candidate/observation |
| **LLM 判断未评估** | 文档自己要求"独立评估"，但当前没有任何标注集 | 直接 live 的结论不可信；需先建 30–50 条标注 |

### 4.3 单组件试点的现实预期（预测 vs 2026-10-22 实测）

以 **sandbox_manager（566 函数、171 个宏函数）** 为试点：

| 指标 | 当时的预测 | MVP 实测 | 差异解释 |
|---|---|---|---|
| 入口候选 | 20–50 | **19**（IDL 17 + SA 2） | 该组件没有 NAPI / `OnRemoteRequest` 命名函数 |
| 成功绑定 | 30–60% | **17/19 唯一绑定**（2 个 SA 只有元数据、无方法体） | 名称 + owner 匹配在单组件上比预期准 |
| candidate | 5–20 | **7** | 数量落在区间，但质量见下 |
| finding | 0–2 | **0** | 与预测一致（无 runtime witness） |
| 运行耗时 | 未估 | **287 ms / 24 任务 / 92 次工具调用** | 骨架成本远低于预期 |
| 模型调用 | 未估 | **0（off）** | 成本不再是瓶颈 |

**质量比数量重要**：7 个 candidate 里，2 个是 `SetPolicyAsync`/`UnSetPolicyAsync` 的**委托包装**（真正的 `CheckPermission` 在 `SetPolicy`/`UnSetPolicy` 里，源码已核实），5 个是**覆盖抽样抽到的内部函数**（序列化、构造器、工具函数），不是攻击面。也就是说：**机制给出的"事实"是对的（函数体内确实没有直接校验调用），但"candidate"这个分类对读者没有行动价值**。

这个结果**低于文档读者的直觉预期**，但与当前事实底座一致。文档的价值在于**把"为什么不足"说清楚**，而不是"保证发现"。

### 4.4 与旧链路相比好在哪里

| 维度 | 旧链路（当前） | 本文 |
|---|---|---|
| 结论单位 | 候选 + 固定类别判定 | 命题 + 子问题 + 反证 |
| 未知的处理 | `needs-human` 兜底 | `insufficient` + 具名 reasonCode + nextAction |
| 跨版本 | snapshotId 绑定事实，但知识/索引/分析版本未绑定 | RunContext 固定 6 个版本 |
| 负结果 | 容易当成"没有" | 明确"未检索到 ≠ 不存在"，负查询还依赖枚举覆盖 |
| 恢复 | 无 | 事件账本 + checkpoint + orphan 识别 |
| 安全 | 无明确能力模型 | capability profile + 内容≠指令 + 数据外发策略 |

---

## 5 文档对现有代码的批评：核实结果

文档第 3 节列了 6 条"事实接入问题"。逐条核实：

| 批评 | 核实 | 影响 | 处置建议 |
|---|---|---|---|
| `getSource/Qast` 读当前内容却挂旧 `snapshotId` | **真**（`getSource` 直接读盘，无哈希核对；`Qast` 重新解析当前文件） | 快照漂移时证据与 ID 不符 | 加 `sha256` 校验，不符返回 `stale-input` |
| `Qcg` 按名字匹配，不是完整调用图 | **真**（`calleeName` 匹配，`resolution=name-only`） | 误当已消歧 | 保留歧义字段，接口改名/加 `ambiguity` |
| `Qflow` unsupported | **真** | 不能做数据流结论 | 维持 unsupported，禁止包装假结果 |
| JSONL 跨块 UTF-8 解码 + 坏行静默跳过 | **真**（`forEachRow` 每块独立 `buf.toString('utf8')`；`catch { continue }`） | 多字节字符被截断；损坏行无声丢失 | 用 `StringDecoder` 保留尾字节；坏行计数上报 |
| compdb 只取每文件首条命令 | **真**（`scanPart` 与 `loadEntries` 都是 first-wins；只记 `variants` 计数，其余命令被丢弃） | 丢失构建变体 | 按 `buildVariantId` 保留多份 |
| Windows clang 不能作目标语义 | **部分真**：compdb 命令自带 `--target=arm-linux-ohos -march=armv7-a`，实测 Windows clang 会按该 target 定义 `__OHOS__/__arm__/__linux__` 且指针 4 字节，**前端类型语义是目标 ABI**；但它是 Windows 宿主二进制、路径被改写、36/53 生成头缺失、`-fsyntax-only` 只到前端，不能当"目标构建等价证明" | 语义结论需 WSL 原生 clang 或设备侧编译 | 定位为**语法/宏指纹**，不用于 `checkSource` 级证明 |

这 6 条里前 5 条**应当修**，而且与 `AG0-COMPLETION-PLAN.md` 的 B0（compdb 变体）部分重叠。**这是文档最有价值的部分之一**：它不是空泛批评，而是能落到具体函数。

---

## 6 与 AG0–AG7 的关系：冲突与合并建议

### 6.1 能力对照

| 能力 | AG 文档 | 本文 | 更强的一方 |
|---|---|---|---|
| 事实层 | AG0（已实现，789 MB） | 只做适配 | **AG0** |
| 入口枚举/绑定 | AG1（8 源 + canonical + exact/suspect/unbound 算法） | `inspectEntry` 只给合同 | **AG1** |
| 义务/状态 | AG2/AG3（O1–O9、S1–SX、L4a/L4b） | task/question/decision | 各有优势：AG 更可机械复算，本文更通用 |
| 动态验证 | AG4（V0–VX、classMinimumVerification） | VerificationPlan + entryFaithfulness | **AG4** 更具体，本文的 `entryFaithfulness` 更好 |
| 报告 | AG5（S×V 矩阵，精确） | report policy 表（更宽） | **AG5** 的分类矩阵更可执行 |
| 知识/检索 | AG6（BM25 + entity linking） | norms/concepts/views + 派生答案 | **本文**（多了规范生命周期与派生缓存） |
| 账本/恢复/安全 | 只有 manifest | 事件溯源 + capability profile | **本文** |
| 扩面 gate | AG7 G0–G6 | 无（只说"试点"） | **AG7** |

### 6.2 建议的混合路线

```
AG0 事实层（已交付） + 本文的 stale-input/变体修复
        │
AG1 入口绑定（按 AG1 实现，补齐 exact/suspect/unbound）
        │
本文的任务/子问题/证据图/ContextPacket/账本/安全
        │
AG3 L4a 作为"确定性 answerer"：把 O1–O9 变成预置 question 模板
        │
AG4 验证（V0–VX）作为 verification runner 的一种
        │
AG5 的 S×V 矩阵作为 report policy 的一个实现
```

映射关系（若要合并两套词表）：

| AG 词表 | 本文词表 |
|---|---|
| O1–O9 | 预置 `QUESTION` 模板 |
| `proven/disproven/unproven/not-applicable` | `supported/refuted/insufficient/not-applicable` |
| S1/S2/S3/SX | `decision` + `assurance` 的组合（S1≈supported+model-assessment，S3≈insufficient） |
| V0–VX | `verification.result` + `entryFaithfulness` |
| C/O/F | `candidate/observation/finding` |

**注意**：S1 ≠ finding。AG5 里 S1+V 才是 finding；本文里 finding 还要 runtime witness。合并时必须以**更严**的为准。

### 6.3 不建议的做法

- 用本文替换 AG0 事实层（会丢掉已交付的 13 张表与 229 个测试）；
- 同时维护 O1–O9 与 question 模板两套义务（会双写、双份漂移）；
- 把 `K/obligations` 直接删掉（AG3 的机械证明仍是最便宜、最可复算的一层）。

---

## 7 成本与工期（预测 vs 实测）

| 范围 | 内容 | 当时预估 | **2026-10-22 实测** |
|---|---|---|---|
| **最小闭环** | doctor + facts 适配 + 6 工具 + run loop + 账本 + 网关 + assessment + report | 10–15 轮 / 3–4 周 | **9 阶段、约 12 分钟**（时间戳 01:42–01:54），+47 测试，280 pass |
| + 知识与检索 | docs 子集 + entity/link + norm 提案 + BM25 | +5–6 轮 / +2 周 | 未做 |
| + 验证与评估 | VerificationPlan + host runner + 30–50 条标注 | +5–6 轮 / +2 周 | 未做（本轮红线禁止） |
| **全量** | 含 knowledge publish、replay/mock、device runner、MCP、完整恢复 | 25–35 轮 / 3–4 个月 | 未做 |

**为什么差这么多**：当时的估算是按"完整规范全量实现"给的；MVP 只做了骨架，且大量依赖已经存在的 AG0 事实与查询接口。**骨架成本接近零，不代表完整系统成本低**——真正的成本在知识、绑定与验证，这三块一行未动。

模型成本（实测）：

- **off 模式：0 次模型调用、287 ms/run**，确定性可复算；
- live 只做过 1 次冒烟（`max-model-requests=2`，实际 1 次），单次约 33 s / 7.5k token；
- 若按文档默认 30 次/run，一个组件只能跑 30 次决策——**远不够**；实际需要把 `maxModelRequests` 提到 150–300，或按任务动态分配；
- 网关计费在外部（WorkBuddy 用量页），本仓不产 CNY 数字；预算只能以 token/次数/墙钟硬门控制。

---

## 8 建议

### 8.1 立即采纳（回填到 AG0/AG1，与本文无关也应做）

1. `getSource/Qast` 加 `sha256` 校验，返回 `stale-input`；
2. `forEachRow` 用 `StringDecoder` 处理跨块 UTF-8，坏行计数并上报；
3. compdb 保留多构建变体（`buildVariantId`）；
4. 负查询缓存依赖"枚举覆盖 + 索引版本"失效（当前无缓存，但设计要预留）；
5. 结论记录 `basis` 与 `assurance`（哪怕只加两个字段）。

> **2026-10-22 更新**：第 1、2 条在 MVP 里以"适配层"方式实现了（`lib/autonomy/facts.js` 的哈希校验、`lib/autonomy/jsonl.js` 的 `StringDecoder`），但**没有回填 AG0**；AG0 的 `forEachRow` 跨块问题仍在，属于已知缺口。

### 8.2 首版采纳（最小闭环）——已交付

- `doctor`（只读环境检查）；
- facts 适配层（`execute(args, ctx, signal)` 统一入口 + 证据归档）；
- 6 个基础工具 + `inspectAuthorization`（其余 5 个注册为 unsupported）；
- RunContext + task/question + append-only 事件账本；
- 模型网关（复用 L4b 运输层）+ 预算 + 调用台账；
- assessment + report（只出 candidate/observation，finding 关闭）；
- 单组件试点（**sandbox_manager**）+ 30–50 条标注评估（**标注仍是 pending**）。

### 8.3 后置

- `knowledge publish` 完整流程（先人工批准单一 JSON）；
- `replay` / `mock` 双模式（先 live + off）；
- device runner；
- MCP adapter；
- 多 worker / 并行模型；
- 完整崩溃恢复与 exactly-once（先 append-only + 重跑）。

### 8.4 不建议

- 按本文全量重写 AG1–AG7；
- 删除 K/obligations；
- 把 finding 门槛降到"模型说 supported"；
- 在没有标注集的情况下直接 live 出报告。

---

## 9 风险登记

| # | 风险 | 证据 | 缓解 |
|---|---|---|---|
| 1 | WSL 目标语义：可用但极慢 | 已装 Debian 12；同一 TU 16.2 s vs native 0.48 s（33×），瓶颈是 9p 跨 VM 读头文件 | 只在 `auto` 模式对 native 判 `compile-error` 的少数文件复核（默认 ≤2）；批量仍走 native |
| 2 | 模型网关限流/不稳定 | 只跑过 1 次 smoke（33 s / 7.5k token） | 先 50 次压测；记录失败率与 P95 |
| 3 | 事实缺口导致大面积 `insufficient` | 宏 11,328、类型 syntax-only、compdb 47.4%、DFG 0.5153 | 先做 AG0 补全 B0/B1 |
| 4 | 入口绑定缺失 | AG1 未实现 | 先实现 AG1 的 canonical + binding，或明确 `unbound` 比例 |
| 5 | finding 门槛 vs 无设备 | 文档要求 runtime witness；设备 runner 关闭 | 首版只承诺 candidate，报告写明 "no finding ≠ safe" |
| 6 | 路线冲突 | 文档自称唯一规范，与 AG0–AG7 并存 | 用 §6.2 的混合路线，明确废弃项 |
| 7 | 预算与任务规模不匹配 | 默认 30 次 vs 100 任务 × 6 | 按试点重新标定；先小样本 |
| 8 | 文档规模 | 26k 文件 / 2.6 GB | 只取 sandbox_manager 相关子集 |
| 9 | **compdb 与设备镜像 ABI 可能不一致** | 四个 compdb part 共 11,038 条命令，**全部**是 `--target=arm-linux-ohos -march=armv7-a`（32 位 ARM）；若开发板跑 aarch64 镜像，静态事实与设备验证不是同一 ABI | 先确认镜像位宽；不一致则 device runner 只对同 ABI 组件开放，或改 build variant |
| 10 | **候选精度未证明**（新增，实测） | 7 个 candidate：2 个委托包装（`SetPolicyAsync`/`UnSetPolicyAsync` → `SetPolicy`/`UnSetPolicy` 内有 `CheckPermission`，源码已核实），5 个覆盖抽样内部函数（序列化/构造器/工具函数） | 报告增加 `origin` 字段；`Q-check` 增加 1 跳委托展开；覆盖抽样单独归类，不进 CANDIDATES |
| 11 | **覆盖抽样污染候选**（新增，实测） | 5 个抽样锚点 100% 变成 candidate；`report-model` 无 `origin` 字段，读者无法区分攻击面与内部函数 | 抽样任务用不同问题模板；报告分节或加列 |
| 12 | **live 证据不可复算**（新增） | 台账记录 1 次 live 成功（`finishReason=stop`），但 `out/autonomy/RUN-*` 下无 `model-calls/`，评估记录也无 `modelCallRef` | 保留 live run 目录；或在 `eval/` 存调用台账摘要 |
| 13 | **标注未做**（新增，已知） | `eval/autonomy/labels.json` 只有 schema + `pending` | 30–50 条人工标注后才有 precision/recall；在那之前不报准确率 |

---

## 10 一页纸（2026-10-22 更新）

| 问题 | 回答 |
|---|---|
| 方案好不好？ | 好，纪律与边界明显优于现有 AG 文档的上层设计 |
| 能不能做？ | **骨架已经做出来了**：9 阶段、14 模块、280 tests、70/70 gates、24 任务/72 问题/7 candidate |
| 跑得动吗？ | off 模式 **287 ms、0 次模型调用、语义哈希可复算**；live 冒烟 1 次通过 |
| 当前能不能产出 finding？ | 不能，也不应该：无 runtime witness，FINDINGS 为空并写明原因 |
| candidate 可信吗？ | **不可行动**：7/7 在本次试点里都不是可行动项（2 委托 + 5 非入口） |
| 最该先做什么？ | ① 报告加 `origin` 并分离抽样；② `Q-check` 加 1 跳委托展开；③ 人工标注 30–50 条 |
| 最该先验证什么？ | 候选精度（不是管道）；标注集是唯一硬指标 |
| 最该砍什么？ | 完整恢复、knowledge publish、replay/mock、device runner、MCP（与 MVP 结论一致） |
| 验收怎么定？ | 不看"发现数"，看"每条 candidate 能否回查 + 每条 insufficient 是否具名 + 每条 candidate 是否可行动" |

---

## 11 MVP 实测校准（2026-10-22）

### 11.1 构建与验收

| 项 | 结果 | 证据 |
|---|---|---|
| 代码量 | `bin/autonomy.js` 40 KB + `lib/autonomy/` 14 个模块 | `AG-EXECUTION/AUTONOMY-RESULT.md` §1 |
| 阶段 | P0–P8 全部完成 | `AUTONOMY-PROGRESS.md` |
| 测试 | **280 pass / 0 fail**（基线 233，新增 47） | 本次复跑 |
| gates | **70/70**，consistency OK | 本次复跑 |
| AG0 | 22 个基线文件 **0 changed**，`snapshotId` 不变 | 本次复跑 `eval/autonomy/ag0-baseline.json` |
| 验收 12 条 | 12/12 | `AUTONOMY-RESULT.md` §2 |

### 11.2 试点数字（sandbox_manager）

| 项 | 值 |
|---|---|
| 入口候选 | 19（IDL 17 / SA 2；无 NAPI、无 `OnRemoteRequest`） |
| 任务 / 子问题 | 24 / 72 |
| 工具调用 | 92（0 模型调用） |
| 运行耗时 | **287 ms**（进程内；含索引进程 768 ms） |
| question 状态 | supported 36 / refuted 7 / insufficient 29 |
| 报告 | candidate 7 / observation 17 / excluded 0 / **finding 0** |
| 确定性 | 两次运行的语义哈希同为 `sha256:6b9b126f...`（本次第三次复跑仍同） |

### 11.3 这次实测**证明**了什么

1. **规范可落地**：12 条不变量、来源分离、单写者账本、finding 门槛，都能变成可运行的代码与测试；
2. **AG0 可零改动复用**：`lib/facts/*` 一行未改，事实层与自治层边界干净；
3. **确定性可做到**：内容哈希 ID、排序去重、语义哈希排除时间戳，三次运行同一哈希；
4. **成本可控**：off 模式零模型调用，287 ms/组件；live 只在需要时点用；
5. **诚实可执行**：FINDINGS 空并写原因、labels 保持 pending、偏差逐条登记，没有"假验收"。

### 11.4 这次实测**否证**了什么

1. **"骨架难做"是错的**：一个 agent 约 12 分钟完成 9 个阶段；真正的成本在知识、绑定、验证；
2. **"有 candidate 就有价值"是错的**：7/7 不可行动。事实正确 ≠ 结论有用；
3. **"覆盖抽样能扩大发现面"暂不成立**：5 个抽样锚点全部变成噪声 candidate；抽样需要独立的问题模板与报告分区；
4. **"模型是瓶颈"暂不成立**：off 模式已经能跑完整闭环；模型只在语义裁决处才需要，且当前精度问题不是模型能修的（是委托/作用域问题）。

### 11.5 下一步的最小改动（按性价比排序）

| # | 改动 | 预期效果 | 成本 |
|---|---|---|---|
| 1 | `report-model` 加 `origin`（entry-scan / coverage-sample），CANDIDATES 只收 entry 来源 | 候选从 7 → 2，噪声归入 OBSERVATIONS | 半天 |
| 2 | `Q-check` 加 **1 跳委托展开**（callee 在 functions 表里且唯一 → 读其 body 再判） | 2 个委托假阳性会被消掉 | 1 天 |
| 3 | 覆盖抽样改用独立问题（"该函数是否处理不可信输入"），不再复用入口模板 | 抽样产出变成 observation，不污染 candidate | 半天 |
| 4 | 人工标注 30–50 条（绑定/校验/候选） | 才有 precision/recall；否则不报 | 1–2 天（人工） |
| 5 | 保留 live run 目录 + 调用台账 | live 证据可复算 | 半天 |

### 11.6 结论（给决策者）

- **可行性**：从 6/10 上调到 **9/10**——骨架已被真实构建，不是纸面设计；
- **有效性**：从 4/10 上调到 **5/10**——机制有效、事实正确，但候选精度未证明；
- **投入建议**：不要再扩管道；先做 §11.5 的 1–4，把"candidate 可行动率"作为下一个 gate（例如 ≥50% 人工复核为"值得看"），再谈知识库与验证。

> 一句话：**这套方案的骨架已经证明能跑；它现在缺的不是代码量，而是"候选值不值得看"的证据。**
