# R4 前置：候选召回与语义边改进执行指南

> 状态：待执行的离线实验，不是 R4 已验收能力，也不新增路线图阶段。本文件处理 R4 扩面前的两项风险：真实疑点难进入可行动候选、组件局部 `operationRecipe` 对新派发/调用形态泛化不足。正式裁决合同仍以 [AGENT-ARCHITECTURE-GUIDE.md](AGENT-ARCHITECTURE-GUIDE.md) §0、§15.4 为准；`IAccount`/dsoftbus 基线与 R3 移交见 [EXPANSION-RESULT.md](EXPANSION-RESULT.md) §3-4、§28、§35、§39；R4 十组件出口见 [FULL-SCOPE-ROADMAP.md](FULL-SCOPE-ROADMAP.md) §3 与 [R4-EXECUTION-GUIDE.md](R4-EXECUTION-GUIDE.md)。本实验不改变 R3 的限定验收，也不预先宣称真实 finding 召回。

## 0. 固定起点与范围

共享工作区 `D:\oh6.0\OpenHarmony-v6.0-Release`，工具目录 `oh6-surface-audit/`。先读上级 `AGENTS.md`、本文件、架构指南 §0/§3/§15.4、R4 指南、结果账本 §3-4/§39，再核源版本、工作树、既有快照与 run。`IAccountIAM` 15 条 scoped excluded 见架构指南 1.0.33；1.0.38 的 `IAccount` v2 为 1 excluded/15 observation。账本 §3 的首轮 `IAccount` 16 入口 14/16 resolved、0/16 唯一操作、0/16 可判门禁，是语义边实验基线；后续单入口改善不能冒充 16/16。真实正向策略锚点/独立真值尚缺，precision/recall/independentAccuracy 保持 `null`，不能由 0 finding 推导真实召回为零。

现行 §15.4 已允许有具体违规信号、1–2 个受限假设和下一动作的 `candidate`；`lib/autonomy/report.js` 的双命题出口要求候选绑定 `operationRef`。不要用“证据达到 70%–80%”放宽门槛：调用方、对象、可达性或替代门禁等任何关键前提缺失都可能决定命题真假。`High-Risk Candidate` 仅是**调查优先级**，不是 finding、漏洞严重性或数值置信度。`verify`/M6 仍是 blocked 的可选能力，本目标不实现 runner、harness 或设备测试。

既有 run、R1-R3 清单/快照、产品源码和 `OpenHarmony/out/` 只读；保留共享工作树未跟踪/dirty 内容，不 `reset`、`stash`、`checkout`，不清理共享输出、不提交/推送。仅离线；不外发新 live、不联网安装依赖。当前 Windows `PATH` 未发现 `codeql`/`joern`/`clangd` CLI，下一轮须核实 WSL/仓内现成工具与构建适用性；不可用即登记失败并试另一独立路径，不以工具名称充当语义能力。

## 1. 可交给 `/goal` 的目标文本

> 在当前共享工作区按 `oh6-surface-audit/AG-EXECUTION/R4-AGENT-IMPROVEMENT-GUIDE.md` 持续执行 R4 前置两项改进，并在取得实测结果后更新 `AG-EXECUTION/R4-EXECUTION-GUIDE.md` 的接手状态、采用范围和下一步；不提前改变 R4 出口或声称十组件已审计。先固定 R3 §39 与 `IAccount` 16 入口、一个真实表驱动/动态 IPC 入口的源码、变体、分母、既有 run 和同输入基线。第一项建立可追踪的假设调查队列和有具体操作/对象的候选分诊：只把满足现行 §15.4 与 `operationRef` 门槛的真实入口疑点报为 candidate；操作目标仍不定的高优先级记录留作 observation/调查项，不用百分比打分、虚构策略锚点或降低 finding 门槛。第二项针对 `IAccount` 成员调用/重载及 dsoftbus 或 DBinder 的表/间接派发，先核现有 CFG/DFG 与离线可用的 CodeQL/Joern/clangd 等选项，再做有版本、源码哈希、变体和 `proven/possible/unknown` 边界的最小语义边对照；不建全仓 CPG、不以可能边证明可达。两项均以真实正/反/未知案例、同输入旧/新覆盖与误连边、候选可行动性/复核成本、端到端 wall/读写/RSS/磁盘、off→report→check 及旧 run 只读复算验收。工具不可用或无净收益时留实际失败、成本和替代形态，不伪称完成。任何裁决/schema/报告合同变更先登记架构版本，再实现和测试；受控变异体与真实效果分开，真实指标无独立真值继续 `null`。每轮将已验证项、run ID、失败、剩余分母和下一动作追加到 `EXPANSION-RESULT.md`；两项的采用/拒绝有可回查证据后才据实修订 R4 指南，再以其 §1 的 `/goal` 继续十组件扩面。只离线，不外发新 live、不修改产品源码/旧归档/`OpenHarmony/out/`、不提交/推送，不因日期、测试通过或零 finding 宣告完成。

## 2. 第一项：假设调查与候选分诊

1. **冻结基线。** 选 `IAccount` 全 16 入口及一个跨组件真实 IPC 样本，保留入口/操作/主体/对象/变体/缺口的原状态与 run；并保留随机或按风险分层抽样的入口作为对照，不只挑已知容易成功的路径。受控变异体标签、历史 finding 和真实未知入口分开记账。先复核 `assessment.js`、`report.js`、`state.js`、report-model/schema 和 `check` 的现有 candidate 路径，确认候选稀少发生在发现、绑定、策略材料还是最终出口。
2. **调查项与报告分离。** 每个假设列具体入口或可信触发、候选操作/对象、主体与信任边界、异常信号、策略来源及适用性、替代门/反证、具名未知、最小下一动作和可观察结果。按影响与触发可行性、独立信号、缺证成本做定性优先级，缺影响依据时不标 high severity。`operationRef` 已唯一且有可回查违规信号时，才按现行 §15.4 尝试条件化 candidate；仍多目标/无操作的高优先级项保留 observation + 调查队列，不计 candidate/finding。ACL/provision、未知调用方身份或异步时序不当作已证无门禁。
3. **最小接线。** 优先复用现有 task/missing/report 字段；只有真实需求跨 run 追踪假设优先级时才新增版本化调查记录或报告字段。改变裁决、schema 或 `check` 前先按架构指南登记新版本，旧 run 保持旧语义。正例验证可行动 candidate，反例验证无操作/无策略/替代门不误报，未知例验证主体或时序不明时不升 finding；真实样本 off→report→check 0/0，关联 `operationRef`、缺口与下一动作可复算。
4. **效果口径。** 报每 100 个实际入口的可行动调查项/candidate、独立复核样本中的 precision@k、复核时间与新增有效疑点、候选重复/误连边、未分析/证据不足变化；同一假设生成器不能给自己标真实正确性，未复核项不进 precision 分母，独立真值不足时相应指标仍为 `null`。受控语料只计给定样本灵敏度，不能冒充无种子真实 recall。若新通道只增无操作告警或把 excluded 偷换成 candidate，保留基线并记录失败。

## 3. 第二项：语义边对照实验

1. **固定两种难例。** `IAccount` 的 `innerManager_.X`/`InnerQuery...`/重载与 `HasAccountRequestPermission` 形状；另选真实 `dsoftbus` 的 `memberPermissionMap_`/`memberFuncMap_` 或 DBinder 的动态/间接派发。分别固定源哈希、目标变体、入口/code 分母、操作候选及源码反例。遇到 `dlsym`、虚派发、FFRT/PostTask 或跨语言 FFI 时明确目标集合和未知依赖，不以同名/顺序相邻当可达证明。
2. **先核可用性再选择引擎。** 检查 `lib/facts/{cfg,dfg,flow,query}.js`、既有 compdb/生成器以及 WSL/仓内现成 CodeQL、Joern、clangd；记录版本、运行许可、可重建的 C/C++ 目标配置、磁盘与资源成本。LSP 仅作为定义/引用候选，不能当跨过程控制/数据流证明；图查询输出也只是候选边。若外部引擎不可离线使用，先用现有事实层做这两种形态的受限语义边试验，记录工具不可用，不绕过网络/安装限制。
3. **按 shard 对账。** 边最少带 `snapshotId`、源码 file:line/哈希、调用点与可能目标集、边形态（直接/成员/表/回调/虚/FFI/异步）、变体、引擎/规则版本及 `proven/possible/unknown`。多目标不得取第一个充当唯一实现；缺宏展开、生成代码、动态库或线程身份的边留 unknown。接线先供候选调查，不取代门禁 dominance、策略锚点和 `check`；每个宣称 resolved 的新边要有正、反、歧义测试及旧样本回归。
4. **同输入比较。** 逐入口比较旧 recipe 与新边的绑定、唯一操作、证据不足/未分析、误连边和下游可行动候选；量测事实/建图/索引/查询/off/report/check 的 wall、CPU、read/write、maxRSS、磁盘、受影响文件增量成本及规则维护量。未清 OS 缓存的连续进程不能称物理冷/热；不能以缩小入口或变体分母换提升。只采纳能使至少一个真实难例更可定位、保留反/未知边界且成本可持续的最小方案；否则具名拒绝并继续另一独立形态，不部署全仓万能索引。

## 4. 验收、失败与 R4 更新

本前置目标完成需要：第一项有真实入口的可行动假设记录与 candidate/observation 分界、正/反/未知测试及同输入人工复核结果；第二项两个互补难例均有可回查的旧/新边、变体/缺口、收益与成本对照，至少一个真实形态得到经反例验证的可定位改善，另一形态失败也须明确留账。所有宣称支持的新增路径正式 off→report→check 0 error/0 warning；影响共享语义时全量 `node --test`、受影响旧 run 只读 check 与哈希/语义对照无未解释漂移。不能闭合则记实际失败、仍缺的前提及下一独立动作，保持目标未完成；零 finding 或测试通过不是验收。

新对话每轮只追加 [EXPANSION-RESULT.md](EXPANSION-RESULT.md) 的输入、分母、原始测量路径、run ID、失败及下一动作。**实验结论出来后**才更新 [R4-EXECUTION-GUIDE.md](R4-EXECUTION-GUIDE.md)：写清采用/拒绝的具体引擎与语义边、候选队列合同、已支持与未知形态、效果和成本分母、十组件顺序/预算需否调整，以及旧 run 兼容证据。若任何改进未验收，仍标待定并保留旧 R4 出口；不得把前置实验或候选数量写成 R4 十组件已完成。M6 runner、设备 PoC、全仓 CPG 与无独立锚点的真实 finding 均不在本目标内。
