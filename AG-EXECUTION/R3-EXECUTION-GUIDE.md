# R3：审计形态扩展执行指南

> 状态：R3 已于 2026-10-27 按限定口径验收，五项出口及原始证据见 [EXPANSION-RESULT.md](EXPANSION-RESULT.md) §39 与 [FULL-SCOPE-ROADMAP.md](FULL-SCOPE-ROADMAP.md) §3。本文件保留 R3 执行过程和历史目标，**不再作为新对话的 `/goal` 提示词**；下一阶段接手见 [R4-EXECUTION-GUIDE.md](R4-EXECUTION-GUIDE.md)。双命题、证据等级及报告准入仍以 [AGENT-ARCHITECTURE-GUIDE.md](AGENT-ARCHITECTURE-GUIDE.md) §0、§15.4 为准。

## 0. 背景与接手

工作区为 `D:\oh6.0\OpenHarmony-v6.0-Release`，Agent 工具在 `oh6-surface-audit/`，产品源码在 `OpenHarmony/`。总目标是对固定版本的 `base/`、`foundation/` **全部生产代码及必要依赖**建立可对账的静态审计覆盖，不是仅审计几个服务。R1 建了范围地图（60,678 个已确认生产代码文件；R2 定向刷新后仍有 75 个 `production-pending`），R2 在 access_token、init、ipc 三样本验证了 shard、增量、派生快照和有界绑定探针；这些不是全域入口绑定或安全裁决。R3 的任务是让不同生产入口形态能进入可信的“入口→实现/派发→操作→实际门禁→限定主体/对象→双命题裁决→report/check”路径，为 R4 的规模审计提供可复用的能力与诚实的分母。本阶段不以 finding 数量验收。

先读上级 `AGENTS.md`、本文件、总路线图 §1-4、架构指南 §0/§3/§15.4、`EXPANSION-RESULT.md` §11-13（尤其 §13 的四轮修正），再看实际代码和产物。优先检查 `out/autonomy/inventory/r1-refresh/` 的范围清单、`r2-shard-manifest.json`、`r2-binding-overloads.json`、`r2-sa-chain.json`、`r2-ipc-dispatch-probe.json`、`r2-promote-validation.json`；`lib/facts/{scope,parse,parse-worker,incremental}.js`、`lib/autonomy/{facts,index,discovery,vertical,gates,static-proof,policy,report}.js`、`bin/autonomy.js` 与相关 `K/policies/`、已发布 `K/norms/`。以当前文件/固定 run 核实历史数字，不照抄为新基线。

已知交接：access_token 85 个入口的 IDL 类型消歧结果为 81 resolved / 0 suspect，另 4 个 SA **只有 profile→注册归属链，仍无方法绑定**；ipc 样本 7 个生产 `OnRemoteRequest` 仅 2 个有同对象的 code→handler 派发证明，其余 5 个具名 unbound。`IAccount` 16 入口 v2 与 CES `ICommonEvent` 17 入口 v2 已各有一条 scoped excluded，其余入口不能因同接口另一方法已闭合而视为已审计。R2 派生快照 `sha256:337554b3…` 经 `RUN:09104ee71a49cd28` 的正式 off/check 消费；该受限 run 没有适用知识套件，不能充当 R3 双命题安全裁决证据。真实正向 finding 的入口/对象专属策略锚点仍未建立，真实效果指标目前为 `null`。

使用共享工作区，不重做 R0-R2；既有 run、R1 清单与快照、产品源码和 `OpenHarmony/out/` 均只读。工作区可能有大量未跟踪改动，先记状态，不 `reset`、`stash`、`checkout`，不清理共享 `out/autonomy`、`out/facts`，不自行提交/推送。新增实验按 scope 和版本写入新路径，运行和评测产物留作复核。默认 Windows 原生离线执行；已有 IAM/IAccount/CES 的历史 live 授权不扩展到新组件、新入口或新增预算，R3 不以 live 为前置条件。

```powershell
cd D:\oh6.0\OpenHarmony-v6.0-Release\oh6-surface-audit
$safe = 'safe.directory=D:/oh6.0/OpenHarmony-v6.0-Release/oh6-surface-audit'
git -c $safe status --short
node --version
```

### 0.1 历史接手快照：R3 验收前

以下仅记录 §37 时点的部分完成状态，**已被 §38-39 的新产物与下节验收快照取代**。当时的 Rust 门禁失败、830 行探针哈希和待办均为历史事实，不是当前缺口或当前探针版本；保留供失败迭代追溯。共享工作树的既有改动与 run 仍应原样保留。

| 出口（§37 时点） | 当时已有证据 | 当时尚缺的验收 |
|---|---|---|
| 1 真实纵向形态 | 既有 IDL、CES SA 3299 scoped excluded；TokenSync 3504 `DELETE_REMOTE_HAP_TOKEN_INFO` 的 IPC per-code 双命题 `RUN:7c583a5d5d336026`、`RUN:1f5d9a05407a821c` 均 check 0/0。 | NAPI privacy 10 literal exports、DBinder 3 code 边仍 observation；ArkTS `privacyManager.on` `RUN:46ae635ab3a15b53` 只有条件 ANI 绑定/observation；Rust Asset 无正式事实→入口→裁决 run。**非 C/C++ 完整纵向路径未闭合。** |
| 2 入口账 | §28/§33/§35 草表：TokenSync 3 code 为 1 excluded/2 未分析；privacy ArkTS 15 导出为 1 证据不足/14 未分析；Asset 7 code 为 Query 证据不足/6 未分析。 | 样本逐入口、变体和依赖的互斥对账尚未全齐；全域 60,678 生产文件、75 待定、1,116 IPC 候选、3,407 非 C/C++ 文件和未知入口/构建闭包不得写成已审计或零。 |
| 3 判定案例 | TokenSync 原件 excluded、去拒绝早退 candidate、错误绑定/身份/门禁 insufficient 的受控正/反/未知及真实限定排除见 §31。 | 非 C/C++ 尚无正式双命题案例；无独立正向策略锚点，真实 precision/recall/independentAccuracy 为 `null`。 |
| 4 复算/成本 | §34 同输入完整事实→索引→off→report→check 两轮 7.184/7.107 s、675.43 MB 逻辑读、121.78 MB 写、约 398.5 MB RSS，同语义哈希 `sha256:402de4b9…`；§33 Node 309/309。§27 去重复读使 SA off 少读 13.25 MB，未证 wall 净收益。 | A/B 未清 OS 缓存，不是物理冷/热盘；§35 CES 1/4/16/17 task 仅无知识扫描，旧知识套件在新快照上失败 `authorization-review-invalid-or-stale`。新形态正式 run、回归与可持续吞吐未齐。 |
| 5 R4 移交 | §28 十组件选择/顺序及 §35 新样本状态有草表。 | 五个动态/条件 IPC 对象、SA/NAPI 未闭合量、非 C/C++ 变体/必要依赖和实际吞吐仍需落实。 |

**立即接手。** 仓内 `OpenHarmony/third_party/rust/crates/syn` 2.0.48 等依赖可离线编译 `tools/rust-ast-probe/`。当前 `out/autonomy/rust-probe/asset-ast-inventory.json` sha256 `ce9aadeb590eec37ba0ba404b2608d65e4486037e31e77220073925a41f99dfe`：54/54 Asset Rust 文件、830 条含 `#[cfg(test)]` 的语法行（不是生产函数数）、7 条 `IpcCode`→`stub` 派发边、`Query→stub.query:141`。`cargo test --offline` 5/5、构建和重录通过，**但门禁记录为 `asset-gate-unresolved`**：真实 `permission_check.rs:36` 是 `CString::new(...).unwrap()`，当前 `asset_gate` 仅接受直接 `Expr::Call`。先补这个形状及拒绝早退/调用方/对象反例；再核 `execute!`、`?`、GN/SA 8100、C++ FFI IPC calling token、请求 `Tag::UserId` 对象及替代门，接版本化正式双命题 off→report→check。仅修 AST 不改变 Query 证据不足、另六 code 未分析的状态。

```powershell
cd D:\oh6.0\OpenHarmony-v6.0-Release\oh6-surface-audit
$env:CARGO_TARGET_DIR='D:\oh6.0\OpenHarmony-v6.0-Release\oh6-surface-audit\out\autonomy\rust-ast-probe-target'
$env:RUSTFLAGS='-Awarnings'
cargo test --offline --manifest-path tools/rust-ast-probe/Cargo.toml --quiet
cargo build --offline --manifest-path tools/rust-ast-probe/Cargo.toml --quiet
node tools/rust-ast-probe/record.js
```

若 Rust 身份/对象或变体不能闭合，记录实际失败后继续独立运行时非 C/C++ 形态。`privacyManager.on` 另需目标产品、生成 IPC 发送边、caller token/callback 归属及策略适用性证明；本地参数校验不是授权门禁。补样本分母、同输入成本与 R4 吞吐/依赖表后按 §4 逐项复核；五项均有证据才更新路线图。每轮追加 `EXPANSION-RESULT.md` 的 run ID、失败、已验收项和下一动作；只离线，不新 live、不改产品源码/`OpenHarmony/out/`或旧归档、不提交/推送。测试通过、零 finding、check 0/0 或日期到期都不能单独关闭 R3。

### 0.2 R3 验收快照与 R4 交接

`EXPANSION-RESULT.md` §39 已逐项复核 §4 的五项出口，并据此更新路线图 R3 为**已完成（限定口径）**：IDL/CES SA 既有限定路径、TokenSync IPC per-code、Rust Asset SA 8100 `Query` 非 C/C++ 路径均有真实入口、正/反/未知测试和可复算 off→report→check。Rust 正式 A/B `RUN:43a2da003add8905`、`RUN:8ac19cd48f0b0265` 均 1 scoped excluded、0 error/0 warning、同语义哈希；7-code 扫描 `RUN:91df24e0c7a05277` 为 1 excluded/6 observation（六条仍**未分析**）。Asset 11 个索引入口账为已裁决 1 / candidate 0 / 证据不足 0 / 未分析 7 / 不适用 3；全量 Node 313/313、Rust 探针 9/9，9 个旧 run 只读复算 0/0。当前探针为 `K-1.2.0-rust-ast-probe`，§39 登记的 966 行产物；§0.1 的 `asset-gate-unresolved` 及 830 行产物不是当前状态。

完成仅对固定样本、声明的 standard dylib 变体和限定主体/对象成立，不代表全 Asset、Rust、NAPI/ArkTS/DBinder 或全范围审计。Asset 其余六 code 未分析，NAPI/ArkTS/DBinder 仍未闭合；1,116 个 IPC 候选、3,407 个非 C/C++ 生产文件、75 个待定文件和构建/依赖未知量继续留账。没有独立真实正向策略锚点，效果指标仍为 `null`；约 22 ms/code 是非隔离边际估计，不能外推可持续吞吐。R4 的十组件顺序、未支持形状及必要依赖见结果账本 §28/§35/§39；**新对话应使用 [R4-EXECUTION-GUIDE.md](R4-EXECUTION-GUIDE.md) 的目标文本，不再执行下述 R3 原目标**。

## 1. R3 原目标文本（已验收，仅供追溯）

以下是当时提交给 `/goal` 的原文，不应在新对话再次提交：

> 在当前共享工作区按 `AG-EXECUTION/R3-EXECUTION-GUIDE.md` 持续执行，直到 `FULL-SCOPE-ROADMAP.md` 的 R3 出口逐项有可核验产物。先核对 R2 修正后的代码、账本和事实快照，不重复 R1/R2。选取真实且互补的 IDL、SA/NAPI、IPC per-code 派发和非 C/C++ 生产入口样本，逐形态建立可定位的绑定、操作、实际门禁、主体/对象、策略锚点与双命题有界裁决；每种宣称支持的形态须有真实入口贯通 off→report→check 和正/反/未知测试。对抽样组件的入口逐项登记裁决、candidate、证据不足、未分析或不适用及其原因；未支持语言、构建变体和依赖留在全范围账本，不用 0 代替未知。用同输入测量事实/索引/入口/裁决/check 的端到端成本，消除有实测收益的重复读取和过度防御，但不得省略影响结论的证据和覆盖边界。只做离线实验；不外发新 live，不修改产品源码或旧归档，不提交/推送。每轮把已验收项、run ID、失败和下一动作写入 `EXPANSION-RESULT.md`；五项出口均有证据后才更新路线图 R3 状态。遇到某形态无法闭合，记录实际失败并继续其他独立形态，不以时间到期、测试通过或零 finding 宣告完成。

路线图的 2026-11-30 至 12-27 是原参考窗口；实际 R3 已于 2026-10-27 提前按证据验收。下文 §2-4 为当时的执行与验收规则，不能据此重启 R3 或扩大已支持范围。

## 2. 范围、分母与裁决边界

R3 是**形态扩展与真实纵向验证**，不是全域 1,116 处 IPC 实现的逐 code 审计，也不是 R4 的至少十组件规模审计。样本须同时覆盖 `base/` 与 `foundation/`，包含已有真实路径作对照和至少一条尚未闭合的新形态。优先从 R2 的 7 条 ipc、4 个 SA 与现存 NAPI/非 C/C++ 生产文件中挑选可检验的样本；若某个样本不能形成可定位的入口或操作，用源码说明理由并选下一个，不能靠构造简化的伪生产入口凑出口。支持范围精确到语言、入口形状、构建变体和可识别的门禁家族，不用组件名称宣布整类支持。

每个抽样组件保留两个分母：R1/R2 总范围中的文件、语言、入口**候选**；本轮固定 scope/snapshot 实际枚举的入口、绑定/操作/门禁及裁决状态。按入口或 per-code 边去重并标记 `已裁决 / candidate / 证据不足 / 未分析 / 不适用`；一个 IPC `OnRemoteRequest` 可有多个 code，不把对象数当 code 边数。覆盖抽样函数、仅有 SA profile/NAPI 注册而无 handler、缺编译变体、调用链不唯一或未知语言均分别登记，不混入已裁决分母。R1 剩余 75 个待定文件及未纳入样本的其他语言仍保持在总账；R3 只需定向判明与本轮入口或依赖有关的部分。

`contractDeviation` 是声明与实现的比较，最多提供候选线索；`securityDecision` 必须说明具体主体、对象、敏感操作、预期约束、实际入口到操作的路径、替代门禁和拒绝分支。有界静态证明充分时可报 `static-only` finding；有真实门禁阻断指定主体时只作 **scoped excluded**，不推成整入口安全。无入口/对象专属预期策略材料、ACL 可获得性不明、未绑定操作或未知门禁时保留 candidate/observation 与具名缺口；候选须绑定 `operationRef`。Builder 标注、文档权限差异、伪造的 `--security-anchors` 受控桩均不得当真实 finding 真值。无适用且已审核的知识/策略材料时，普通 off run 只可验证入口和工具路径，**不计作双命题安全纵向完成**。

## 3. 执行顺序与实现规范

### R3-A 固定样本和真实分母

1. 在 R1 刷新清单、R2 shard 与实际产品源码上选样本：一条已有 IDL 完整路径作回归；一个 SA 注册服务方法链或 NAPI 模块/导出到 handler；一个包含对象、code、handler 的 IPC 入口（R2 DBinder 两条边作正对照，再选至少一条未绑定形状）；一个真实非 C/C++ 生产入口及其源码/注册证据。可将 SA 与 NAPI 二选一作为本轮完整纵向代表，但另一类至少给出独立候选分母与具名不足；若要宣称两类均支持，分别完成纵向路径。
2. 为每项登记 scope、源码 HEAD/dirty、shard snapshot/manifest、适用 build 条件、源文件与跨组件依赖、候选入口数、已解析数和未知数。复查 R2 的 `OnRemoteRequest` 精确入口 7 与名字相似的 6 个邻接函数、SA profile 的 4 条归属链，避免生产/测试误计及“注册即方法绑定”。从 `r1-refresh` 对账组件样本，不重写 R1 原件。
3. 先做基线 off/index/check 和同机性能剖面；若 source、metadata、编译输入或解析限额不闭合，先具名停止或缩窄可判命题。选择具有不同绑定/门禁形态的真实样本，而不是只挑词表已经覆盖的路径。

### R3-B 入口与派发

1. 在 `lib/facts`/`lib/autonomy/index`/`discovery` 既有边界扩展必要形态，不另起平行扫描器作为正式裁决来源。IDL 保持接口、ipcCode、重载类型和唯一实现的证据；SA 需由 profile→构建目标→注册对象→可调用方法/IDL 关联闭合，NAPI 需由注册表/导出名→回调→实现闭合。SA 归属链闭合仅证明服务身份，不自动等于某方法可调用。若某链不唯一，保留 suspect/unbound 和候选集合。
2. IPC 按 **具体对象 + code 定义 + 可见派发分支 + 同对象/可证转发 handler** 建边，核查默认分支、表驱动、宏/条件编译、重载、虚函数目标；代码不可定位或同名跨类时返回具名 unknown，不用同名全域回退。至少对 R2 已知未绑定形状之一做真实改善或留下可复核的失败证据，不将两条已知边复制为新成果；全部 1,116 候选逐 code 绑定属后续规模阶段。
3. 非 C/C++ 选择一个在构建/发布证据下属于生产代码的实际语言族，用仓库已安装的解析/注册能力构造**该族有限形态**的文件→入口→调用/操作事实。必须有源路径、版本、位置、绑定和不支持语法的记录；不以文件扩展名或跨语言同名调用证明可达。无法可靠抽取时保持未支持并继续别的形态，但 R3 不能据此声称该语言入口已支持或该项已验收。

### R3-C 操作、门禁、策略和裁决

1. 对每个拟宣称完整的入口，从唯一 handler 追到具体敏感操作与对象，记录调用边及委托/异步/跨组件跳转；路径超出证据窗口、虚派发未定或操作不唯一就列缺口。操作 recipe 与门禁词表须按明确 scope 启用，有真实源码反例证明不会把同名调用误绑。新门禁形状核查受检者是否为调用方、拒绝分支是否**确实阻断**该路径、组合条件和其他可行门；未识别身份条件不等于无门禁。
2. 策略材料分离：文档/Builder 审核材料用于 contractDeviation；安全预期需独立说明主体、对象、操作及适用变体。权限定义、SA 配置、调用方枚举、对象归属和 ACL/provision 条件各记录来源、hash 与推理链；只靠等级或文档不升为真实 finding。若经定向调查无合格锚点，如实报 `null` 的真实正例指标并保持 candidate 上限，**不以此阻塞负例/未知机制的 R3 验收**。
3. 现有 `discovery.js` 把 SA/NAPI 作为无方法体元数据入口，`static-proof.js` 的 `analyzeSecurity` 还要求 `anchor.kind === 'idl'`、绑定已解析和已接受的 Builder 规范。新增绑定本身不会接通双命题：须在既有任务/证明边界按新形态与证据条件有界接线；安全预期不能仅为通过 IDL/规范前置条件而伪造文档规范，contractDeviation 无适用声明时明确不适用或不足，securityDecision 单独由独立策略证据决定。保留旧版分支的输入、出口和 `check` 复算，不以删除条件的全局放宽代替逐形态证明。
4. 将新形态接入既有任务、证据引用、report-model 和 `check` 复算；必要时只做最小 schema/报告调整。测试对每个**宣称支持的形态**各含成立、不成立、歧义/未知；对门禁再覆盖同主体/非调用方、阻断/不阻断及替代门。每条真实样本运行 off→report→check，审查 `operationRef`、主体/对象、反证与可达路径，不能只看 `check=0` 或 `finding=0`。受控变异体可检验判定机制，但单列 Builder 标签，不冒充独立真实效果。

### R3-D 性能、回归与移交

选定同一源码/变体和任务集合，分别测冷/热事实读取、索引、入口/派发、取证、裁决、report/check 的 wall/CPU、readBytes/writeBytes、maxRSS、截断量与任务边际成本；需要比较优化时用等价输出和语义哈希，不能以缩小入口分母换加速。优先复用 R2 shard、在一个 run 内共享已读表/源码窗口，针对实测重扫或重复验证优化；不要预建全仓万能索引、假设恶意输入而加签名/隔离/复杂锁、重复多层缓存。保留源和构建边界、适用范围、未知门禁及报告复算这些防止错误结论的最小检查。若净收益不成立，记录成本并保留简单实现；随样本放大重测，而非只据单入口毫秒数推断 R4 吞吐。

开发时只跑受影响形态的单测和小 scope off/check；改了共享 facts/入口/门禁/裁决/schema 路径，阶段验收跑 `node --test` 全量、每个新样本的正式 run `check`、受影响旧 run 的只读复算与语义/原件哈希对照。版本化修订不得追溯改写旧 run 合同；若新功能需要新架构或 schema 版本，先按架构指南登记再接线，不把旧语义默默迁移。记录新功能的每任务成本和 R4 批量扩展时的限制。只清理本轮可明确识别的临时副本，不删除未归属的忽略目录产物。

## 4. 阶段验收与 R4 移交

只有下列各项**同时有可回查产物**才标 R3 完成；阶段记录写入 `EXPANSION-RESULT.md` 新节，路线图只更新状态和证据链接。

1. 至少一条已有 IDL 路径作为回归，及来自 SA 或 NAPI、IPC per-code、非 C/C++ 的真实生产入口样本，各有固定源码/变体、独立候选分母与入口→操作→门禁/具名未知→限定裁决→report/check 链。每种**宣称支持**的形态至少有一条操作和调用方/对象均可定位的完整纵向路径，并有成立、不成立、歧义/未知测试。SA 与 NAPI 未选的一类及任何无法闭合的形态明确保留未支持数量，不将 profile/注册/文件候选数算为已裁决。若非 C/C++ 真实路径仍未贯通，R3 保持部分完成。
2. 抽样组件的每个实际枚举生产入口或 per-code 边都有互斥状态：已裁决、candidate、证据不足、未分析、不适用；总和与候选分母对账，未绑定、未知语言、解析/截断、预算、构建变体及跨组件依赖均有来源与原因。样本外 60,678 个生产文件、剩余 75 个待定文件和全域 1,116 个 IPC 候选不得被悄悄写成已审计。
3. 新增受控正/反/未知案例有预先固定的来源和各自判定；至少一条真实有限范围 scoped excluded 或有实际缺口的 candidate/observation 经逐项证据复核。finding 只在 §15.4 独立策略锚点合格时准入；无真实正向锚点时真实 precision/recall/independentAccuracy 为 `null`，不为了指标降低门槛，也不因此阻塞本阶段。
4. 新形态 off→report→check 全部 0 error / 0 warning，语义及证据引用可回查；受影响旧 run 不漂移或具名解释，全量测试通过。冷/热、逐入口边际、主要读写与峰值内存均有实测；收益和未消除的固定成本分别披露，不以局部处理时间冒充端到端收益。
5. R4 移交表列明每种已支持形态的真实组件/入口、构建适用性、未支持形状、剩余 5 条 ipc 样本状态、非 C/C++ 未覆盖量、SA/NAPI 未闭合量、75 个待定文件的本轮变化、必要外部依赖和可持续吞吐假设；给首批十组件的**选择依据和实验顺序**，不预先声称十组件已审计。R3 不要求全域 per-code、所有语言、完整依赖/变体闭包或真实漏洞发现召回，它们留给 R4-R6。

验收有缺项则保持“部分完成”，列出最小可执行补充与受影响分母，继续其他独立形态；不得用延长参考窗口或隐去难例换“完成”。R3 通过后进入 R4 首批规模审计，阶段结论仅对本轮真实样本与明确支持的形态成立。
