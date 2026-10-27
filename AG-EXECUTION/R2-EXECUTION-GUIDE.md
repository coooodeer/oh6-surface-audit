# R2：可扩展事实层执行指南

> 状态：供新 chat 在 goal 模式下持续执行 R2 的实施指南，不是新的安全裁决规范。总目标、阶段出口和参考窗口见 [FULL-SCOPE-ROADMAP.md](FULL-SCOPE-ROADMAP.md) §1-3；安全命题和证据等级以 [AGENT-ARCHITECTURE-GUIDE.md](AGENT-ARCHITECTURE-GUIDE.md) 为准。实测、失败和阶段状态只追加到 [EXPANSION-RESULT.md](EXPANSION-RESULT.md)，不在本指南另建成绩账本。

## 0. 背景与接手

工作区为 `D:\oh6.0\OpenHarmony-v6.0-Release`，审计工具仓为 `oh6-surface-audit/`，产品源码在 `OpenHarmony/`。总目标是对固定 OH6.0 版本的 `base/`、`foundation/` 全部生产代码和必要依赖建立可对账的静态审计覆盖。R1 只建立了范围地图，**没有**完成全部代码抽取、入口绑定或审计。R2 让事实层能以组件/子系统为单位有效扩展并正确更新，使 R3 能在其上补审计形态；本阶段不以 finding 数量验收。

R1 §12 的 v1.2.1 基线已验收：147,561 个被遍历文件、60,678 个已确认生产代码文件、116 个 `production-pending`、16 个登记目标的符号链接；`.p7b` 296 个归 config 后 config=15,122、other=11,721。R1 入口数字是**候选**，不是已绑定或已裁决的分母。新 chat 先阅读上级 `AGENTS.md`、本文件、总路线图 §1-4、架构指南 §0/§15.4 和 `EXPANSION-RESULT.md` §11-12；以实际工作区及产物复核这些历史值，不复制为新基线。

优先检查 `out/autonomy/inventory/` 下的 `r1-scope-baseline.json`、`r1-files.jsonl`、`r1-source-version.json`、`r1-verify-result.json`、`layered-sample-bench.json`、`incremental-bench.json`、`access-token-binding.json`、`ipc-dispatch.json`；代码 `lib/facts/{scope,parse,parse-worker,io}.js`、`bin/fact-{snapshot,build}.js`、`lib/autonomy/{facts,discovery}.js`、`tools/{autonomy-incremental-shard,autonomy-entry-inventory,autonomy-bench}.js`；三个样本 scope 为 `K/policies/scope-{access-token,init,ipc}-r1.json`。忽略目录中的输出仍是实验原件，不可当临时文件批量清理。工作区含未提交改动，不 reset/stash/checkout，不改产品源码、旧 run、旧事实快照或 R1 产物，不提交/推送。变更场景使用**明确命名的受控副本与新输出路径**；不递归删除共享的 `out/autonomy`、`out/facts` 或历史归档。

```powershell
cd D:\oh6.0\OpenHarmony-v6.0-Release\oh6-surface-audit
$safe = 'safe.directory=D:/oh6.0/OpenHarmony-v6.0-Release/oh6-surface-audit'
git -c $safe status --short
node --version
```

## 1. 可交给 goal 模式的目标文本

> 在当前共享工作区，按 `AG-EXECUTION/R2-EXECUTION-GUIDE.md` 持续推进，直到 `FULL-SCOPE-ROADMAP.md` 的 R2 出口逐项具有可核验产物。先核对 R1 v1.2.1、§11 的同组件单文件增量实验和现有三个样本，不重做 R0/R1。实现按组件、必要时按子系统的可复用事实分片与文件增量更新，使未变、修改、新增、删除、头文件和跨组件依赖变更的结果与相同输入的干净全量构建一致；无法判明影响面时明确扩大重建范围，不沿用旧事实。三个样本没有静默截断，解析不足具名；对 access_token 重载、SA 和 IPC 派发做有界绑定/入口实验，逐项报告改善与剩余歧义。测量冷/热、读写字节、峰值内存和净收益，消除无收益的重复读取/校验而保留覆盖与证据边界。默认 Windows 原生、只做离线实验；不做新的 live 外发、不修改产品源码或旧归档、不自行提交/推送。结果分阶段记入 `AG-EXECUTION/EXPANSION-RESULT.md`，最后如实更新路线图 R2 状态。未达到某项时保持部分完成，记录原因并继续其他独立工作，不以时间窗口或测试通过代替验收。

路线图给 R2 的**参考**窗口为 2026-11-09 至 11-29；R1 已提前验收，可以现在启动，不能以参考日期作为等待理由或自动完工日期。每轮恢复先读最新账本与工作区状态，再处理尚未验收的一项，不反复重扫 147,561 文件。

## 2. 目标、边界与分母

R2 交付的是**事实可复用与失效正确**，不是全仓一次性快照，更不是按源码名猜测安全结论。按 shard/组件分别记录：R1 生产文件数、进入当前事实层的目标文件数与语言、函数/calls 等 L1 行数、`unsupported`、失败与截断、IDL/SA/NAPI/IPC 入口候选及绑定状态。当前 `lib/facts/parse.js` 只解析 C/C++ 范围，其他语言和 R1 待定角色继续单列，不因分片成功而从总分母消失。scope 排除的文件不属于该 shard 的抽取分母，但仍在 R1 总范围账本中。

区分源文件版本与构建/元数据输入、L1 的 13 张表和 `unsupported.jsonl`、用于发现/绑定的派生索引、审计 run 的结论。只比较 L1 不足以声称元数据、索引或结论一致。旧事实快照及其 ID 不写入升级结果；新产物有明确 scope、源版本和输入边界。`completeExtraction` 至少区分**未截断**与**解析全部成功**：上限未触发但存在 unsupported、未建模语言或未知生成头时，只能报告对应层的完整性，不能称组件代码已完整抽取。`maxIndexCalls=50,000` 是现有样本上限，不是所有 shard 的普适常数。

R2 针对 access_token、init、ipc 三种形态和一条真实跨组件头文件依赖验证方法；其余组件的推广策略与预计成本据实测提出，不要求本阶段构建全部 190 组件。R3 承接全面的 IPC per-code 派发、非 C/C++ 入口、操作/门禁/主体/对象和策略锚点；R2 可做最小真实探针，但不得把探针推广为“该形态已支持”。真实正向 finding、更多 live、全范围审计、完整构建变体与依赖闭包都不是 R2 出口。

## 3. 执行顺序

### R2-A 固定基线与瓶颈

1. 只读核对 R1 v1.2.1 的产物、源仓版本与 dirty 口径，以及三个 scope/事实快照、已有增量副本和 §11 账本。记录当前函数/calls/unsupported、入口绑定分布、索引上限和实测成本。现存相关 run 存在时选代表性 run 做只读 `check`；不存在就记缺失，不补造历史归档。
2. 定向判明 116 个 `production-pending` 中可能影响样本/依赖边界的文件，优先 SELinux 策略、hiview 配置与无扩展名的链接/构建输入；仅对用途明确的家族修分类、测试和派生分母。其余保持逐文件待定，不在 R2 重做全目录人工分类。需要更新 R1 基线时另存新版本及差额，不覆盖已验收原件。
3. 使用现有 `autonomy-bench.js` 测每样本的 snapshot/check、build、index/入口清点和必要复算，分开统计重复枚举、源文件读、L1 重扫、merge/写入与验证的 wall/CPU/readBytes/writeBytes/maxRSS。性能建议先有改前测量；不因单次小于 5 秒就忽略随 shard 数增长的固定读放大。

### R2-B 分片与上限可见性

1. 复用 scope 和现有 parse-worker/L1 表格式，先让三个既有样本成为可独立处理、可按固定输入定位的 shard；只有某组件的资源指标或调用表确有压力时才拆子系统，不预造万能调度器。保持按文件定位的来源、确定排序与重复行处理；必要时让索引只读选定 shard，不对每个入口重扫所有组件的 JSONL。
2. 针对三个 20k 曾截断的样本，以实际调用数选择本 shard 上限并记录 `callsSeen/callsRetained/callsTruncated`；函数等其他限制分别记录。调高上限后重算事实、索引、入口/绑定与 `unsupported`，给出每 shard 的完整性状态、遗漏原因和所属分母。大 shard 若超过可承受内存，先缩 shard 或有界流式合并，不静默截断或读入 GB 级 JSON 后直接 `JSON.parse`。
3. 用同输入、同 scope 和固定版本的干净全量构建作对照：13 张 L1 表、`unsupported`、元数据/派生索引的有效内容以及入口/缺口账本一致。若 snapshot ID 或时间字段按合同变化，只对这些身份字段做明确归一化，不能因此跳过事实比较。抽样核对实际源码与未支持形态，尤其 ipc 的 0 IDL/SA 不等于 0 入口。

### R2-C 多文件增量与依赖失效

1. 把 `tools/autonomy-incremental-shard.js` 的**实验结果**作为起点，不把当前单文件、单组件整表重写工具直接宣称为完成的增量引擎。只在有跨 run 实测收益时实现最小复用单位：按文件记录输入版本与所属 shard，未变文件跳过重解析；改变/新增/删除的文件替换对应 L1 行，更新受影响索引和缺口。不要每次额外全树哈希抵消收益；文件元数据仅可作变化筛选，若来源无法保证同大小、同 mtime 内容不变，就用可靠变更清单或在受影响 scope 回退重建，不能仅凭 mtime/size 复用旧事实。最终产物须绑定正确源码/构建输入；元数据、scope、工具规则或构建变体变化不得沿用旧事实。
2. 在隔离的可写副本上覆盖未变、源码修改、新增、删除、同大小且保留 mtime 的内容修改、同组件头文件改变、跨组件头文件改变、include 删除/改指向。用真实 `#include`、可见编译命令和生成头关系界定可证明的反向依赖；宏 include、不可解析 include、未知构建配置标 `dependency-unknown` 并对受影响 scope 回退全量重建，不能推断“无依赖”。跨组件样本需真实文件与实际 include 路径，不能仅靠伪造路径 fixture 声称闭合。
3. 每场景在**相同最终文件集合和输入版本**上独立做干净全量构建，与增量结果比对 13 表、`unsupported`、元数据及派生入口/索引/缺口；记录重新解析的文件、失效的 shard、回退及原因。某层暂不支持增量时主动全量重建该层并计入成本；不把旧索引接在新 L1 后报告一致。失败对照保留具名证据，修复后重测，不以空表或仅比总数蒙混通过。

### R2-D 入口绑定与派发的最小改进

1. 对 access_token 的 2 条同 argc `VerifyAccessToken` 重载，用 IDL 参数与实现签名的类型、限定符和别名信息有界消歧；仅唯一且证据可定位才把 suspect 改为 resolved。补相反类型、别名未解、多候选、同名测试函数的正反未知测试，不再靠参数个数或名称猜测。记录 85 个入口前后的 `resolved/suspect/unbound` 与每条变动证据。
2. 对 4 个未绑定 SA，从 profile、libpath、构建目标到注册/实现尝试一条可验证归属链；链条缺口保持 unbound，不能把含同名函数当服务实现。至少一条可检验真实案例与一条缺失/歧义案例，登记四条各自状态及推广限制。
3. 对 ipc 的 7 个生产 `OnRemoteRequest` 清点对象、code 来源和 handler/虚派发形状，选择一个**真实可绑定**的对象/code 关系做最小证明探针；若该组件无可闭合关系，改取已清点的 ability_runtime 样本并记录转移及剩余七条。验收的是有分母的入口模型与可定位的改善/不足，不要求遍历全域 1,116 处或完成 R3 的权限裁决。`resolved/suspect/unbound` 均须注明对象、变体、分派边与源码行；无法闭合不得报 resolved。

### R2-E 性能、回归与移交

对同一机器、Node 版本、固定语料和等价输出，分别测冷全量、未变增量、单源变化、跨组件头文件变化、回退全量的 wall/CPU、readBytes/writeBytes、maxRSS、解析文件数和最终可用输出。至少各重复一次以揭示波动；报告净收益和因依赖扩大带来的最坏成本，不用省掉重解析的局部耗时冒充端到端提速。优先减少重扫、整表重写及重复源码读取，若实际净收益不成立就保留原实现并登记实测。不增加防篡改签名、攻击隔离、冗余哈希链、多级锁或为研究场景无收益的恢复框架；保留避免漏计、陈旧事实与错误结论的必要校验。

开发时跑定向单测与一个受影响 shard 的对照；修改共享 facts/index/绑定代码时，阶段验收跑 `node --test` 全量、三个样本的事实/入口回归和受影响既有 run 的 `check`，只读核对语义及原归档哈希。无关旧 run 不因独立测量脚本改动反复重跑。结果写入 `EXPANSION-RESULT.md` 新节：输入版本、shard 与分母、before/after 产物哈希和对照、失败案例、性能、残余未知及下一步；路线图 R2 只更新状态与出口证据链接，不复制原始表。保留 R3 的 IPC/语言/安全策略缺口，不改写架构指南的裁决定义。

## 4. 阶段验收

R2 只有以下各项**均有可复核产物**才标为完成：

1. access_token、init、ipc 三个样本按 scope/shard 列出生产目标、L1 各表、入口候选及未支持量；索引上限与解析失败具名，三个样本无**未标记**截断；不能把“50k 未截断”写成“所有生产代码已抽取”。
2. 受控副本中的未变、修改（含同大小/同 mtime）、新增、删除、同组件头文件、跨组件头文件及未知依赖回退场景，对**相同最终输入**的干净全量结果逐表与入口/缺口对照一致；不一致的身份字段有明确合同依据，其他漂移为失败。跨组件失效不闭合时扩大重建且有测试，不沿用陈旧事实。
3. 两条类型重载、四个 SA 和 ipc 派发样本有前后状态、证据与正反未知例；至少一类真实入口/绑定形态的可判结果有所改善，仍 suspect/unbound 的每条有定位原因。全域 IPC per-code 能力不在本阶段冒充完成。
4. 冷/热、单文件和跨组件场景有端到端成本与净收益；不实施没有净收益的缓存或分片复杂化。变更只进入新产物，旧 run、快照及 R1 原件仍可读；相关 `check` 和全量测试有实际结果。
5. R1 总范围分母保持可对账，116 个待定项和未支持语言/构建变体/依赖明确归属或保留具名待办；R3 接手清单附样本路径、当前状态、失败/未知原因与下一实验。不宣称 base/foundation 已审计或真实 finding 能力已验证。

任何一项未闭合，就保留 R2 部分完成，先报告实际分母和下一可执行实验，继续不受阻的工作。R2 完成后进入 R3 审计形态扩展；R2 的性能与事实复用成果不改变 finding 的独立证据门槛。
