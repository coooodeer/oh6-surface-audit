# R4：首批规模审计接手指南

> 状态：待执行，不是 R4 已完成声明。R3 已于 2026-10-27 按限定口径验收；原始产物、失败与 R4 移交见 [EXPANSION-RESULT.md](EXPANSION-RESULT.md) §28、§35、§39。新对话**先执行** [R4-AGENT-IMPROVEMENT-GUIDE.md](R4-AGENT-IMPROVEMENT-GUIDE.md) 的前置 `/goal`，取得两项实测结论并回写本指南后，再用下文 §1 的十组件扩面目标。总目标与 R4 出口以 [FULL-SCOPE-ROADMAP.md](FULL-SCOPE-ROADMAP.md) §1-3 为准，裁决与证据等级只以 [AGENT-ARCHITECTURE-GUIDE.md](AGENT-ARCHITECTURE-GUIDE.md) §0、§15.4 为准；不另设成绩账本。

## 0. 接手事实与边界

共享工作区：`D:\oh6.0\OpenHarmony-v6.0-Release`；工具在 `oh6-surface-audit/`，产品源码在 `OpenHarmony/`。先读上级 `AGENTS.md`、本文件、路线图 R4 行、架构指南相关裁决约束、结果账本 §28/§35/§39，再核固定 run、范围清单和当前工作树。R3 的 Rust Asset `Query` 正式 `RUN:43a2da003add8905` / `RUN:8ac19cd48f0b0265` 是**单 code、standard dylib 声明变体、限定非 system HAP 主体与请求 `Tag::UserId` 对象**的 scoped excluded；`RUN:91df24e0c7a05277` 的其他六 code 仍未分析。既有 IDL、CES SA、TokenSync per-code 样本也只在各自限定范围内成立。不要重做 R1-R3 或把已验收样本外推到整个组件。

R3 移交仍有 75 个 `production-pending`、1,116 个全域 IPC 候选、3,407 个非 C/C++ 生产文件；Asset NAPI、privacy NAPI/ArkTS、CES ArkTS、DBinder 和五个动态/条件 IPC 对象未闭合，构建变体与必要依赖闭包未知。真实正向 finding 无独立合格策略锚点，效果指标为 `null`。R3 的约 2.5 s 单 code 完整轮和约 22 ms/code 非隔离边际不是 R4 的跨组件可持续吞吐率。

工作树含大量既有修改与未跟踪工具、文档和产物。既有 run、R1-R3 清单/快照、`OpenHarmony/` 产品源码及 `OpenHarmony/out/` 只读；不 `reset`、`stash`、`checkout` 或清理共享输出，不提交/推送。本轮仅离线，既有 live 授权不扩展到新组件或预算；新增 scope、快照、run、评测产物使用独立版本化路径。

### 0.1 前置改进的回写位

当前候选分诊与语义边对照**尚未执行**，不能把计划中的 `High-Risk Candidate`、CodeQL/Joern/clangd 或统一 CPG 写成已支持能力。前置 `/goal` 按其指南 §4 验收后，在此处填入固定输入与 run、采用或拒绝的实现范围、正/反/未知及旧 run 复算、可行动候选和误连边的分母、端到端成本、残留语言/变体/依赖，再据实调整 §2 的十组件顺序和预算。失败保持待定与具名原因，不降低路线图 R4 的十组件出口或 finding 证据门槛。此时不预填实验结论。

## 1. 前置实验完成后可交给 `/goal` 的 R4 目标文本

> 在当前共享工作区按 `oh6-surface-audit/AG-EXECUTION/R4-EXECUTION-GUIDE.md` 持续执行，直到 `FULL-SCOPE-ROADMAP.md` 的 R4 首批规模审计出口逐项有可核验产物。以 `EXPANSION-RESULT.md` §39 的 R3 限定验收与 R1 刷新范围清单为起点，不重复 R1-R3、不把单入口 scoped excluded 推成组件安全。按该账本 §28 的首批顺序选至少十个不同 `base/`/`foundation/` 组件，逐组件固定源码、构建适用性、生产文件、函数、实际入口与 per-code 边及必要依赖分母；对批内每个生产文件、入口和变体登记互斥状态、来源与原因。逐入口追踪绑定、敏感操作、实际门禁、主体/对象和双命题；证据不足可以具名保留，入口未分析数为零才关闭该批，不把未知、未绑定、解析失败或截断写成零或安全。对代表性真实入口做离线 off→report→check 与正/反/未知验证，受影响旧 run 只读复算；无独立策略锚点不产真实正向 finding。测量每组件/每入口同输入端到端成本及真实可持续吞吐，区分固定开销、批内边际、连续进程与物理冷/热盘；仅对有实测收益的重复读取优化，不删证据检查。每轮把完成范围、run ID、失败、未分析/不足及下一动作追加到 `EXPANSION-RESULT.md`，只有十组件批次逐项达到 R4 出口后才更新路线图 R4 状态。只做离线实验，不外发新 live，不修改产品源码、旧归档或 `OpenHarmony/out/`，不提交/推送。难例记录实际失败后推进其他独立组件，不因日期、测试通过或零 finding 宣告完成。

## 2. 首批顺序与执行口径

结果账本 §28 的选择顺序是 `common_event_service` → `access_token` → `os_account` → `init` → `asset` → `ipc` → `samgr` → `data_share` → `bundle_framework` → `ability_runtime`；§39 更新了 Asset 的单 code 能力。十组件合计 5,076 个词法生产文件、283 个非 C/C++ 文件只是计划分母，须按当前固定源码、变体和范围清单逐组件复核。可据实测调整顺序，但记录理由；不能以挑选十条已闭合入口替代十个组件的生产入口账。路线图的 2026-12-28 至 2027-01-24 仅是参考窗口，R3 已验收后可现在启动 R4，不因日期等待或据日期宣布完成。

从 CES/`access_token` 的既有 shard 和报告校准逐入口状态，再处理 `os_account`/`init` 的构建与依赖，随后扩 Asset Rust 其余 code/NAPI 与 ipc 动态派发，最后测大 shard 的入口密度和吞吐。每组件先对账生产文件/语言/入口候选与本轮实际枚举，构建未启用分支也登记变体；再做事实→索引→入口→操作→门禁→裁决→report/check。无法闭合的入口保持证据不足并写明缺失的具体边；不能关闭时保留未分析量并继续下一独立组件。必要外部依赖按决定安全边界的程度取证或审计，避免只凭声明依赖推断已覆盖。

R4 验收以路线图原文为准：至少十个不同组件，批内每个生产文件、入口和构建适用性均有状态，**入口未分析数为零**；证据不足可保留但逐项公开，无静默截断或“未知门禁=无门禁”；代表性报告 `check` 通过，给出每组件/每入口端到端成本与真实可持续吞吐率。R4 不等于全范围审计完成；R5 的剩余批次/日期只能在 R4 实测速率后滚动预测。

## 3. 复核与记录

新对话先用 `git -c safe.directory=D:/oh6.0/OpenHarmony-v6.0-Release/oh6-surface-audit status --short` 记工作树，再只读 `node bin/autonomy.js check --run=RUN:43a2da003add8905` 与相应旧样本核 R3 起点。开发时先跑受影响单测与小 scope；触及共享 facts、入口、裁决或 schema 时再跑全量 `node --test`、所有受影响正式 run 的 `check` 和语义/原件哈希对照。每轮结果只追加 [EXPANSION-RESULT.md](EXPANSION-RESULT.md)，保留失败原件和真实分母；五项 R3 出口已完成，不再以旧 [R3 目标文本](R3-EXECUTION-GUIDE.md) 启动工作。
