# R1：base/foundation 全范围基线执行指南

> 状态：供新 chat 在 goal 模式下持续执行 R1 的实施指南，不是新的安全裁决规范。总目标和阶段出口见 [FULL-SCOPE-ROADMAP.md](FULL-SCOPE-ROADMAP.md) §1-3；裁决语义以 [AGENT-ARCHITECTURE-GUIDE.md](AGENT-ARCHITECTURE-GUIDE.md) 为准。第一阶段已做的跨组件实验与实测缺口见 [EXPANSION-PLAN.md](EXPANSION-PLAN.md) 和 [EXPANSION-RESULT.md](EXPANSION-RESULT.md) §10-11。R1 只验收**范围基线**，不声称完成安全审计。

## 0. 项目背景与交接

工作区为 `D:\oh6.0\OpenHarmony-v6.0-Release`，审计工具仓为其下的 `oh6-surface-audit/`，产品源码在 `OpenHarmony/`。目标是最终对固定 OpenHarmony 6.0 版本的 `base/`、`foundation/` 全部生产代码及必要的跨目录依赖建立可对账的静态审计覆盖；当前 Agent 已在 sandbox_manager、os_account 和 common_event_service 完成局部双命题纵向实验，但不具备全范围审计或真实正向 finding 效果的验收证据。R0 的受限完成允许直接进入 R1，不能以“还没有真实 finding”为由停留在 R0，也不能把 R1 清点当成 finding 能力证明。

以 `EXPANSION-RESULT.md` §11 和本地文件为准核对接手状态，不把下列历史数字当成本轮固定真值：首层文件系统清点约 190 个 bundle 组件、60,268 个生产代码文件、3,018 个现有事实层不支持的非 C/C++ 文件、201 个无 bundle 文件（其中 134 个生产代码）、245 个 IDL 文件 / 3,234 个轻量解析的方法、155 个 SA profile。access_token 的 85 个入口目前是 79 resolved / 2 同参数个数但不同类型的重载 suspect / 4 个 SA 未绑定；IPC 已见 7 个生产 `OnRemoteRequest`，虚函数和 code 派发尚未绑定；跨组件头文件变更对增量 shard 的失效范围尚未闭合。上述问题在 R1 **入账和分流**，而非要求本阶段全部实现解决。

新 chat 先阅读上级 `AGENTS.md`、本文件、总路线图 §1-4、扩面指南 §0/§4/§5、实验账本 §10-11，以及架构指南 §0、§15.4、§24.32-24.34。核对工具 `tools/oh6-full-scope-inventory.js`、`tools/autonomy-entry-inventory.js`、`tools/autonomy-incremental-shard.js` 与 `out/autonomy/inventory/full-scope-baseline.json` 的实际状态。首层工具目前只输出组件汇总及无归属文件样本；IDL 用轻量正则清点，compdb 只按 subsystem 名称映射 part 存在性，这两者都不能冒充精确入口分母或已验证构建变体。其他历史章节和结果属于记录，不替代当前代码与产物。

工作区可能含大量未提交改动及未跟踪文件。使用当前共享工作区，不从旧 GitHub 提交或新 worktree 推定已具备当前实现；不 `reset`、`checkout`、`stash`，不覆盖现存 run、快照和第一层清点产物，不修改 `OpenHarmony/out/` 或产品源码。开始时只做只读检查：

```powershell
cd D:\oh6.0\OpenHarmony-v6.0-Release\oh6-surface-audit
$safe = 'safe.directory=D:/oh6.0/OpenHarmony-v6.0-Release/oh6-surface-audit'
git -c $safe status --short
node --version
```

## 1. 可交给 goal 模式的目标文本

> 在当前共享工作区，按 `AG-EXECUTION/R1-EXECUTION-GUIDE.md` 持续推进，直到 `FULL-SCOPE-ROADMAP.md` 的 R1 范围基线验收逐项具有可核验产物。先核对现有代码、首层清点和 `EXPANSION-RESULT.md` §11，不重复已完成的 R0 实验。为 `OpenHarmony/base/`、`OpenHarmony/foundation/` 生产文件建立逐项可对账的归属/角色/语言清单，列出入口形态、构建变体与必要依赖的已知和未知分母，验证首层计数及误分类样本；把重载、SA、IPC、跨组件增量缺口作为 R2/R3 待办，不把未知伪装成零或已解决。复用现有清点工具，测量全扫描与增量成本，消除实测重复开销而不引入研究态无用的签名、隔离或多层恢复。只用 Windows 原生工具；R1 不做新的 live 外发，不修改产品源码或旧 run，不自行提交/推送。相关原始结果和阶段状态记入现有 `AG-EXECUTION/EXPANSION-RESULT.md`，最后如实更新总路线图的 R1 状态。不要停在计划、部分清点或单组件抽样；达不到验收项时公开实际分母、原因和仍可执行的下一动作，继续完成不受阻部分。

目标模式每轮从账本最新的 R1 进度和工作区状态恢复；完成一项立即登记产物及下一动作，不反复从首层清点重新开始。参考时间窗是 2026-10-26 至 11-08，不以到期日替代验收证据，也不因为未到 R2 日历周就禁止必要的小规模识别探针。

## 2. R1 目标、分母和非目标

R1 交付一份能让 R2-R5 按组件/形态分批工作的**范围地图**：固定本次源码状态与被考察的构建配置；让主范围内每个生产文件有路径、角色、语言、组件归属或具名待归属理由；按组件列出可见的生产入口类型和计数的可靠程度、构建特性/变体的已知与未知、声明依赖与尚未解析的 include/链接/运行时依赖。生产文件、函数、入口、敏感操作、构建变体属于不同层的分母；R1 无法提取的函数/操作不得用文件数代替。保留测试、生成、文档和配置的排除/证据角色，生产生成源码与其生成器输入分别记账，避免双计。

入口 `discovered`、`bound`、`operation-resolved`、`security-assessed` 是不同状态。IDL 轻量方法候选数、SA profile 数、NAPI 注册或 IPC 派发函数名只表示对应的清点层；无法确认生产角色、目标或分支时标 `unknown`/`suspect`，不标 `resolved` 或 `no-entry`。对于尚无解析器的语言，明确记录文件数量和“入口分母未知”，不是声称该语言入口为 0。必要依赖先分“声明已知”“源码引用待解析”“范围外待纳入/仅作解释”几类，不能以 bundle 依赖闭包代替实际调用和构建依赖审计。

**R1 不要求**解决两个 `VerifyAccessToken` 类型重载、4 个 SA 的绑定、IPC 的对象与 code 映射、跨组件头文件增量失效，也不要求新增策略锚点、更多 live、真实 finding 或全量 off 扫描。这些属于 R2/R3 及以后的能力；本阶段只需给每项具体组件、源位置、当前状态、验证它所需的下一步和进入后续阶段的归属。可以做有界探针帮助判定数量或成本，不能把探针结果推广成整个形态已支持。

## 3. 执行顺序

### R1-A 固定起点与最小测量

记录日期、Windows/Node 版本、两棵源码目录及相关子仓的版本标识、未提交改动对样本的影响、现有第一层 JSON 的路径和哈希。多仓库或无单一提交时分别记版本和 dirty/unknown 状态，不编造一个整树 Git commit；仅在需要绑定证据的文件上固定内容哈希，不为每次迭代反复哈希 60,268 个文件。选择一条现存代表性 run 做只读 `check`（存在才做；归档缺失如实记录）；若只改独立清点脚本，不必每天重跑旧 run 或全仓测试。

读取首层 JSON 的 `totals`、`components`、`unbundled`、`unscopedFiles`、`notRun`。首层工具输出路径固定为 `out/autonomy/inventory/full-scope-baseline.*`，不要仅为测量而重复运行并覆盖旧产物；R1 新产物使用不同名字。先测一次实际的目录遍历、读取字节、耗时和内存，作为后续优化比较基准；无需构造全仓源码 AST 或预建通用缓存。

### R1-B 建立逐文件可对账清单

优先扩展现有只读清点工具或添加一个很小的归属导出入口，复用现有 role、lang、bundle 识别规则；为每个被遍历文件保留规范化相对路径、字节数、文件角色、语言、所属 bundle/待归属理由和分类依据。大量文件的明细宜流式写到 `out/autonomy/inventory/r1-files.jsonl`，汇总写 `r1-scope-baseline.json`；不要将 GB 级 compdb `readFileSync` 后一次性 `JSON.parse`，也不必将全部源文件内容常驻内存。稳定排序或同等的确定性汇总便于同输入复算；仅在实测有收益时增加跨 run 缓存。

对账必须以当前扫描的实际结果为准：生产代码 = 各组件生产代码 + 无归属生产代码；C/C++/头文件/其他语言之和 = 生产代码；各角色文件互斥，同一路径只计一次；bundle 路径唯一或给出待归属原因。针对路径词法分类的局限，至少复核每种角色/语言、一个无 bundle 文件、生成生产文件、测试目录嵌套、IDL 和 SA profile 的真实样例；错分就修分类并重新计算分母，不把粗略目录正则当构建真值。无法读取的文件、符号链接或无法判断的生产角色列入单独未知量，不静默跳过。

### R1-C 入口、构建与依赖的第二层清点

按组件汇总 IDL 文件/接口/方法候选、SA profile、可见 NAPI 注册、`OnRemoteRequest`/表派发及其他已观察到的入口形态。已有 scope 和快照可复用 `tools/autonomy-entry-inventory.js` 做抽样，但它仅处理 scope roots，不代表整个 `base/foundation`；若需要全域候选分母，使用只读扫描或在逐文件清单上做轻量派生，不为 R1 改写通用裁决器。针对 IDL 正则、生产/测试同名和间接注册抽样核对，给每类计数标明 `observed`/`candidate`/`unknown`；同时登记 2 个重载、4 个 SA、7 个 IPC OnRemoteRequest 的已知难例及更多同族样本数量。

从 bundle、`BUILD.gn`/`.gni`、SA profile 和已有 compdb part 登记发布角色、feature/系统类型声明及可见构建条件；part 存在不等于该组件或所有宏变体已编译。列出已识别的配置宇宙与“未解析的实际组合”分母，不只选 rk3568 单一配置冒充全版本覆盖。对主范围外的 bundle 声明依赖给出候选集合与去重数量；include/链接/注册/运行时依赖未解析时逐项标缺口，R1 不要求完成其安全分析或解析完整调用闭包。

### R1-D 核对、性能和移交

独立用文件清单按组件/角色/语言重算汇总，抽样对照源码与 bundle/build 元数据；核对首层与 R1 的差额，解释源码变更、规则修正或误分类，不直接复制历史 190/60,268 等数字充当实测。若改了清点逻辑，加直接测试覆盖生产/测试/生成/无 bundle 和至少一个解析失败或未知状态；只跑相关测试，阶段验收再跑项目全量 `node --test`。如果触及共享事实或审计路径，额外复算相关旧 run；否则不因文档或独立清点脚本改动重跑所有 live/replay。

给出一次完整冷扫描和一次无变更重跑的端到端耗时、读写字节、峰值内存及重复成本。优先消除确实重复的目录/元数据读取；若优化，比较同输入的新旧分母与未知量，不为几毫秒引入复杂缓存。开发中仅处理改变的组件和定向样本；阶段验收才做一次完整清点、汇总核对和必要回归。所有工具默认 Windows 原生；Linux/WSL 仅作为用户批准的逐次特例。不要为本地研究增加签名、攻击隔离、多重校验账本或复杂恢复状态机；保留能阻止漏计和错误安全结论的源/变体边界。

## 4. 验收清单与 R2 移交

R1 仅当以下各项都有产物时标为完成；`EXPANSION-RESULT.md` 追加一节记录实际数、源版本、工具与输出路径、测量、失败及结论，`FULL-SCOPE-ROADMAP.md` 只更新 R1 状态，不复制完整实验日志。

1. `base/`、`foundation/` 的逐文件清单与组件汇总可复算；生产/测试/生成等角色、语言、bundle 归属/待归属及扫描失败量互斥对账，首层基线差异逐项解释。
2. IDL、SA、NAPI、IPC 等已识别形态按组件列出入口候选数及 `observed`/`candidate`/`unknown` 口径；未支持语言、间接派发、绑定歧义、解析/截断失败和无 bundle 的未覆盖量有可定位条目。函数、操作或实际构建变体无法清点时明确标未知，不用零填充。
3. 发布系统类型/feature 与已观察构建配置的清单、未解析组合；必要跨目录依赖的声明候选及尚未解析的 include/链接/运行时类别，依赖不与主范围重复计数。
4. 分类样本的源码复核、汇总重算、相关测试和必要旧 run `check` 有实际结果；完整扫描和无变更重复扫描的成本有同机数据。任何仍截断的 shard 标 `completeExtraction=false`，不进入“完整提取”分母。
5. R2/R3 待办分别登记：两条 IDL 类型重载与 4 个 SA；IPC 对象/code 表绑定；跨组件头文件失效边界；非 C/C++ 提取与变体/依赖闭包。各项注明数量、来源及下一次可执行实验。真实正向 finding 效果仍未验收不阻塞 R1，但不能声称 Agent 已有效审计全部主范围。

如果某项无法完成，保持 R1 部分完成，记录阻塞输入及替代统计，并继续其它可做的清点；不要仅凭测试通过或时间窗口结束宣布 R1 完成。R1 完成后的下一步是 R2 可扩展事实层，不是直接全仓审计。无需新供应商配置或 live 请求，不提交、不推送。
