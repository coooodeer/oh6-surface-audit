# OpenHarmony 6.0 自主审计 Agent 架构与实现规范

> 规范版本：1.0.24。
> 生效日期：2026-10-23。
> 适用环境：Windows 原生工具调用与 OpenHarmony 6.0 源码；Linux/WSL 仅用于逐次批准、不可由 Windows 满足的例外验证。
> 权威范围：本文是 `oh6-surface-audit` 新 Agent 架构、接口、实现顺序和验收要求的唯一开发规范。其他架构材料只保留历史价值，不补充或覆盖本文。
> 实现状态：本文规定静态审计目标，不宣称目标模块已交付。第 3 节单独列出现有实现；未列为现有的接口、命令和 schema 均为待开发合同。

## 0. 使用方式与规范效力

本文自包含。实现者不需要查阅其他架构设计文件来决定数据格式、模块责任、控制流程、失败语义或验收条件。可以读取产品源码、正式 API 文档、配置和现有工具代码作为事实来源，但不能把旧工具的行为自动视为新系统要求。

**2026-10-23 目标修订优先级：** 主流程只验收静态审计完整闭环，最高等级为有界的 `Static Finding`；离线 Builder-LLM 负责规范审批、样本与基准标注，显式打标来源，不以人工签名或动态 runner 为前置条件。第 24 节是按当时目标写入的历史实验日志；其旧验收判断与本段及第 7、15、16、21-23 节冲突时，以本次修订为准。Runtime-LLM 仍不能审批自己的证据或规范。

本文中的“必须”“禁止”是验收要求；“建议”是可调整的默认选择，调整时需要记录理由和实验结果。示例中的 `example` ID、虚构函数和占位哈希仅用于说明数据形状，不是生产证据。代码片段为接口或伪代码，除明确标注现有命令外，不代表现在可以执行。

本文不覆盖平台安全约束、用户授权或仓库操作规则。它也不授权产品源码修改、实际设备操作、安装依赖、网络访问或外发代码。架构规范决定程序应怎样工作；程序运行证据决定它实际做到了什么，两者不能混淆。

开发时维护三个独立版本：本文的 `architectureVersion`、记录格式的 `schemaVersion`、领域知识的 `knowledgeVersion`。修改接口、状态或裁决门槛，先更新本文，再修改实现和测试。同一条要求不能同时在另一份设计正文中独立维护。

阅读导航：第 1-4 节说明目标、现状与本机环境；第 5-11 节定义输入、知识、任务和取证合同；第 12-18 节规定发现、编排、裁决、验证、恢复和安全；第 19-24 节给出代码布局、命令、样例、测试、实施顺序和完成标准。

## 1. 目标、边界与基本原则

### 1.1 系统目标

只给定审计范围、输入版本、允许能力和预算，Agent 能够：

1. 从源码行为、入口、操作和规范中发现有实体锚点的问题，不依赖预置漏洞清单。
2. 把问题分解为可检索、可分析和可反驳的子问题。
3. 取得与判断直接相关的事实、规范、局部分析及反证，避免反复理解相同代码。
4. 根据现有证据给出有范围的判断，或指出具体缺口和下一步。
5. 在授权范围内继续静态取证、分支探索，直至得到判断或合理停止；隔离验证是可选扩展。
6. 留下可回查、可恢复、可评估的记录，包括未覆盖区域和失败原因。

核心目标是“为具体问题建立足够的证据”，而不是“最大化检索数量”或“让所有问题得到确定答案”。LLM 在充分上下文下具有合理判断能力是设计假设，必须通过独立评估验证，不能被当成正确性定理。

### 1.2 非目标

- 不承诺发现全系统全部问题，也不承诺完整求解任意 C/C++ 程序。
- 不要求全仓 AST、数据流、全部规范或全部类别完成后才能运行。
- 不把一次模型调用、两个相同模型的一致意见或有效引用当成语义证明。
- 不以创建多个 Agent、图数据库、向量数据库或 MCP 服务作为首版前置条件。
- 不自动修复产品代码，不自动生成和执行攻击性载荷，不把实验结果直接发布到外部。
- 不要求问题必须属于预设类别；类别只是标签和分析视图选择依据。

### 1.3 强制不变量

| ID | 要求 |
|---|---|
| INV-01 | 一次运行固定源码、构建、文档、知识与分析器版本；不得静默跨版本混用。 |
| INV-02 | 观察事实、规范、工具推导和模型判断保持不同来源类型。 |
| INV-03 | 空结果、失败、不支持、截断和完整枚举后的未命中不得合并为一种状态。 |
| INV-04 | 名称匹配不等于实体绑定；图上有路径不等于存在可执行路径。 |
| INV-05 | 关键证据不足时不得给出无条件肯定或否定，尤其不得用未检索到证明不存在。 |
| INV-06 | 每项裁决必须有命题、适用范围、依据、反证处理和未决条件。 |
| INV-07 | Runtime-LLM 不得改写观察事实、批准自身提出的规范或扩大运行权限；离线 Builder-LLM 可以审查并批准规范、构造样本与标注基准，必须显式记录 AI 来源。 |
| INV-08 | 依赖变更使相关缓存失效；缓存命中不提高证据等级。 |
| INV-09 | 所有模型调用、重试、摘要与知识抽取都计入预算并登记。 |
| INV-10 | 只有一个任务状态写入者；并行 worker 只返回结果，不自行裁决或改账本。 |
| INV-11 | 模拟、回放、历史案例、受控变异体和真实目标结果不能混算。 |
| INV-12 | 运行停止必须保留未完成任务、覆盖边界、成本与终止原因。 |

## 2. 总体架构

### 2.1 六项逻辑职责

```text
源码 / 构建 / 配置 ---> 事实与关系库 -----------+
正式文档 / API -----> 领域知识库 -------------+
工具分析 / LLM -----> 有条件的派生答案库 -----+
                                              |
范围 + 预算 ---> 候选发现 ---> 任务队列         |
                               |              v
                         单 Agent 控制器 <--> 问题级证据服务
                               |              |
                               |       检索 / 补算 / 组装上下文
                               v
                     裁决 / 补证 / 关联任务 / 隔离验证
                               |
                        报告 + 覆盖 + 可复用结果
```

| 模块 | 负责 | 不负责 |
|---|---|---|
| 事实与关系库 | 固定输入，抽取实体和有来源的结构关系 | 判断漏洞、从名称猜语义 |
| 领域知识库 | 领域概念、条件规范、分析方法与例外 | 把实现现状当正确规范 |
| 派生答案库 | 保存带前提、范围和依赖的局部答案 | 保存脱离依据的“安全/不安全”标签 |
| 问题级证据服务 | 按问题检索、连接、计算、呈现证据 | 用相关性分数替代充分性 |
| 候选发现与调度 | 提出可执行问题，安排探索与补证 | 把未命中模板视为整个实体安全 |
| 裁决与验证 | 综合支持、反证和缺口，执行受控验证 | 伪造环境、影响或证明等级 |

这些是逻辑边界，不是六个进程。首版是一个 Node.js 应用，使用本地函数调用。解析和独立只读计算可以并行；同一运行的模型决策请求默认串行。

### 2.2 离线与在线

离线阶段全量完成便宜、稳定的结构抽取，整理选定范围的文档和正式规范，预计算高复用包装函数的局部分析。禁止先让 LLM 逐文件概括整个源码树。

在线阶段围绕任务按需取证和分析，将有复用价值的局部答案写入派生库。在线产生的新规范只能是提案，不改变本次运行固定的知识版本。正式发布后启动新运行或显式重新评估，不能中途替换规则。

每次取证返回局部答案、可执行缺口或终止原因。无法预知下一步时允许 LLM 规划，但不允许只返回“需要更多上下文”而没有目标和原因。

### 2.3 单 Agent 的含义

一个控制器负责选择问题、解释证据和决定下一步，可以多次调用同一模型执行发现、解释、计划、摘要与裁决。这些是调用目的，不是多个角色对话。

任务分支共享证据引用，不共享未经校验的确定结论。未来若增加并行任务执行，必须先证明单写者状态提交、预算预留和上下文版本校验正确；首版不实现多 Agent 协商。

## 3. 当前实现与可复用边界

以下为编写本文时对代码的观察，不是新架构的完成证明。开发前运行环境检查，不能把历史测试数量当作当前结果。

| 位置 | 现有能力 | 接入要求 |
|---|---|---|
| `bin/fact-snapshot.js`、`lib/facts/scope.js` | 源码枚举、哈希、快照和范围 | 快照记录不是源码副本；补实时读取一致性检查 |
| `lib/facts/compdb.js` | 流式扫描编译数据库及生成目录可见性 | 保留构建变体；不能只取每文件首条命令 |
| `bin/fact-build.js`、`lib/facts/parse*.js` | tree-sitter 抽取、分片和稳定事实引用 | 保留语法错误、宏和归属缺口 |
| `lib/facts/query.js` | 名称、语法、调用记录、源码、类型和检查点查询 | 不是完整语义查询服务，必须经过适配器 |
| `lib/facts/cfg.js`、`dfg.js` | 局部结构和粗粒度 def-use | 可作线索，不能宣称完整路径和别名分析 |
| `lib/facts/ids.js`、`manifest.js`、`schema.js` | 标识、清单和事实格式校验 | 新记录使用独立 schema，不覆写已有事实 |
| `lib/l4b.js` | 配置加载、运输适配、证据引用校验经验 | 仅复用通用能力，不继承固定类别提示词和判断规则 |
| 相邻工具的 `src/llm/http.js` | HTTP 运输、usage、错误和请求描述 | 通过薄网关接入，验证取消、超时和脱敏 |
| `lib/agent/pipeline.js`、`state.js` | 既有 campaign 编排和状态聚合 | 不是本规范的任务闭环，保留原行为直到明确切换 |
| `lib/l5/`、`lib/l7/` | 部分验证和报告基础 | 通过显式适配器复用，不继承旧结论等级 |

2026-10-22 已有 `lib/autonomy/`、`bin/autonomy.js` 的试点闭环：固定 binding/check-presence/dominance 三问，off 模式在 sandbox_manager 上运行 24 个任务、产出 7 个 candidate 和 0 个 finding。它不是第 12-14 节规定的自主提案、跨视图 Action 闭环；正式规范、派生答案、精确入口绑定与运行验证仍待实现。现有 7 个 candidate 中 5 个来自非入口覆盖抽样；评审指出另 2 个为委托检查包装，这一试点尚无人工标注指标。具体产物见 `AG-EXECUTION/AUTONOMY-RESULT.md`、`REVIEW-AGENT-ARCHITECTURE-GUIDE.md` 和 `eval/autonomy/pilot-summary.json`，不能将机械流程通过测试等同于审计有效性。

同日的授权小实验（`24.4）在原 MVP 上增加 opt-in 的入口候选准入和一跳委托取证，保留旧 run。最终实验版 `1.0.2-auth-experiment` 的 24 个任务均为 observation，0 candidate / 0 finding；19 个入口均缺具体操作绑定。这证明了有界取证和缺口显式登记的工程可行性，**不证明发现精度、召回或自主控制器有效**。

后续 `vertical-v1` 的真实 live、跨视图分支、模型账本和验证计划实验见第 24.5 节。实验版本号 `1.0.5-vertical-experiment` 是 run 标识，不代表本文规范版本，也不代表 M0-M6 已全部验收。

2026-10-23 新增 Builder 来源两条已发布规范和 `1.0.14-static-experiment`：精确异步委托、权限实参、限定操作目标和早退语法可产生限定于“文档权限契约错配”的静态 finding；`check` 重抽取规范与源码复算。见 §24.20。当前仍是两入口试点，非 19 入口全量自主调查；授权效果大命题及未知解析分支未被此局部结论证明。

必须先处理的事实接入问题：

1. `getSource/Qast` 读取工作区当前内容，不能在未校验文件哈希时附上旧快照 ID。
2. `Qcg` 按名字匹配调用记录，必须保留歧义，不能称作已消歧的完整调用图。
3. `Qflow` 当前返回不支持；不得增加伪造的安全或不可达结果。
4. JSONL 查询存在跨块 UTF-8 解码和损坏行静默跳过问题；新接口必须修复并报告数据不完整。
5. 精确类型分支、编译命令重建及大文件处理需要重新核验，不能把现有 Windows 校核路径当作目标语义证明。
6. 编译参数清理不得不加区分地复用现有删除规则；目标、宏、ABI 和异常模式都可能影响语义。

只修复新闭环实际依赖的共用缺陷，并增加直接测试。不要为了接入重写整个事实层。

## 4. Windows 原生执行与 Linux 例外

### 4.1 路径、范围与默认组件

本文以下相对路径均以工具目录为基准，产品路径明确以 `OpenHarmony/` 开头。

| 对象 | Windows 路径或约定 |
|---|---|
| 工作区 | `D:\oh6.0\OpenHarmony-v6.0-Release` |
| 产品源码 | `D:\oh6.0\OpenHarmony-v6.0-Release\OpenHarmony` |
| 工具 | `D:\oh6.0\OpenHarmony-v6.0-Release\oh6-surface-audit` |
| Linux 例外 | 默认关闭；启用时发现实际发行版并校验工具链与挂载，不写死发行版名称 |
| WSL 工作区映射 | 仅在已批准例外中检查实际挂载，不作为默认运行依赖 |
| 已有 Node 依赖候选 | 相邻 `oh6-framework-want-leak-miner/node_modules`，先验证模块可加载 |
| 产品生成目录 | `OpenHarmony/out/` 只读；工具不得清理、重写或以此作缓存 |

既有范围策略包含五个组件：`base/account/os_account`、`foundation/communication/dsoftbus`、`foundation/communication/ipc`、`base/notification/eventhandler`、`base/accesscontrol/sandbox_manager`。首版选择其中一个组件做完整纵向试点，不把五个组件全部闭合列为启动条件。

权限定义、公共事件实现、共享头文件和生成文件可能位于组件之外。区分 `auditRoots` 与 `dependencyReadRoots`：前者限定问题发现和统计，后者仅允许读取明确登记的依赖。新增依赖超出授权范围时返回缺口，不能自主扩权。

### 4.2 执行分工与强制边界

- 所有常规工具调用在 Windows 原生进程执行，包括 Node.js 控制器、tree-sitter、索引、查询、模型网关、报告、测试和按需 Windows Clang 校核。tree-sitter 不展开宏、不完成 C++ 重载解析，也不证明运行路径。
- Windows Clang 配合固定的 target/sysroot/宏/头文件可作目标配置下的有界前端查询；现有路径改写及生成头缺失时只给语法/宏指纹，不宣称构建等价或设备行为。宿主为 Windows 不自动否定前端结果，`--target` 存在也不自动升级其保证等级。
- Linux/WSL 分析或 harness 仅在具体命题确需、Windows 原生能力无法提供所需证据等级时逐次批准。首版不依赖 Linux；缺失或拒绝例外时工具返回具名 `unsupported`，任务登记 Missing，不自动迁移。
- 设备 runner 是另一项独立授权能力，默认关闭；无设备时明确不可验证，不模拟设备结果。

任何宿主上的精确结论都必须核对实际编译器、target triple、sysroot、架构、宏、生成头和构建变体；不能把一次 `-fsyntax-only` 成功当成完整构建证明。现有旧工具 `fact-clang --mode=auto` 的 WSL 回退不是新架构允许的默认行为。

### 4.3 命令与编译参数

工具使用 Windows 原生固定 executable 和 argv，不执行模型生成的 shell，也不通过 WSL、容器或远端主机隐式转发。例外计划须事先登记命题、Windows 不足之处、批准记录、发行版、精确可执行文件与 argv、文件/构建变体、次数、时间和输出上限；dispatcher 验证后才可执行单次指定动作，不允许 `auto` 回退、批量默认切换或由模型扩大范围。确需 WSL 时使用 `wsl.exe -d <已校验发行版> --exec <approved-executable> <args>`，不拼接 `bash -c` 或 `cmd /c`。后台进程隐藏窗口，超时清理仅限本工具创建的进程树；清理无法确认时阻断后续例外调用。

编译数据库优先读取 `arguments` 数组；只有 `command` 时使用经过测试的受限分词器。保留 `\$`、`\*`、转义空格、引号、`-D` 内容和 response file 的语义，不用 Python/GNU shlex 或简单空格切分替代。遇到无法确定的命令形态返回 `unsupported-command-syntax`。

从编译命令派生分析命令时：

1. 保留 target、sysroot、语言标准、include、强制包含文件、宏、ABI、异常和影响语义的选项。
2. 输出目标、依赖文件路径等写入参数重定向到本运行目录；只删除已证明与分析无关的参数并登记原因。
3. 禁止任意编译器插件、外部脚本、未批准 wrapper 和越界 response file；递归 response file 限深并校验哈希。
4. 记录原命令、规范化 argv、转换日志、工具链指纹和全部已知依赖。
5. 一个源文件有多个命令时生成多个 `buildVariantId`；不得无提示取第一条。

Windows 路径通过真实路径检查目录归属；仅启用 Linux 例外时由单一适配器转换路径，区分源路径、执行路径和稳定实体路径，保留 Linux 大小写。拒绝 `..`、junction、符号链接、UNC 和 response file 的未授权越界，不用字符串前缀直接判断目录包含关系。

### 4.4 文件与依赖纪律

已有文本用文件编辑工具或 `apply_patch` 修改。禁止用 PowerShell `Set-Content`、`Out-File`、重定向或读入后替换写回的方式修改 UTF-8 源码和文档。生成数据使用 Node 显式 UTF-8 无 BOM；新 shell 脚本使用 UTF-8 无 BOM、LF 和 `/` 路径分隔符。

本机不依赖 pip，不重复尝试 `pip` 或 `python -m pip`。Python 仅使用标准库；新增格式解析优先复用已安装 Node 依赖，无法获得依赖时实现明确受限子集并测试，不能静默错误解析。

GB 级编译数据库、JSONL 和日志必须流式读取，UTF-8 跨块解码使用保留尾字节的 decoder。索引分片构建，不把全部调用边和源码塞进一个对象。大函数、大文件和大工具输出都有显式上限，超过上限返回分页或缺口。

临时文件写入 `out/autonomy/<runId>/runtime/` 或明确归属的工具子目录。结束时删除本次产生且不再需要的临时文件，保留证据、事件与必要复现输入。递归删除前验证绝对路径位于本次运行目录，禁止跨 shell 拼接删除命令。

### 4.5 环境检查合同

`doctor` 只读检查 Node、模块加载、Windows 原生工具链、范围文件、编译数据库和生成头可见性；默认不启动或要求 WSL。只有选定并批准 Linux 例外时才检查发行版、路径映射及目标工具链。模型检查默认只检查配置字段与密钥是否存在，不打印值、不发请求。

每项返回 `available | missing | incompatible | not-checked`、证据和影响能力。缺 Clang 不阻断结构检索；缺模型不阻断离线索引；缺正式规范不伪造规范。只有请求的能力缺失时才阻断对应动作。

### 4.6 性能复测与适用范围（2026-10-22）

使用现有 `lib/facts/clang.js` 的 `checkOneAsync`，从 `d4-r1` 编译数据库读取同一条命令，分别以 Windows `native` 和明确指定 `debian` 的 WSL 模式运行 `-fsyntax-only`；每次超时 90 秒、串行、无 response file，不修改产品源码或 `OpenHarmony/out/`。首次在受限沙箱中出现 Windows 进程初始化错误和 WSL 访问拒绝，这些值不是性能结果；下表是获准在本机执行后的记录。

| sandbox_manager TU | Windows native | Debian/WSL | 可比状态 |
|---|---:|---:|---|
| `sandbox_manager_client.cpp` | 371 ms | 12,185 ms | 均缺 `isandbox_manager.h` |
| `sandbox_manager_kit.cpp` | 330 ms | 7,977 ms | 均缺 `isandbox_manager.h` |
| `stopaccessingpolicy_fuzzer.cpp` | 362 ms | 4,892 ms | 均 `ok` |

三组耗时比约为 32.8、24.2、13.5；只有最后一组成功编译语法，前两组仅说明换宿主没有补齐生成头。样本小、顺序固定、含 WSL 启动和跨文件系统读取成本，不能外推为所有 TU 的固定加速比，也不能据 `ok` 推断 ABI/构建完全等价。它足以支持 Windows 默认、Linux 不自动回退的成本决策；未来若迁移源码、工具链或构建目录，重新对同命令、同状态的样本计时并登记预处理成本。

## 5. 运行输入、版本与存储

### 5.1 RunContext

每次运行固定以下形状，真实 ID 在初始化时计算。示例预算是首版试点默认值，不是成本、吞吐或最优性的承诺。

```json
{
  "runId": "RUN:example",
  "architectureVersion": "1.0.1",
  "schemaVersion": "1",
  "inputManifestId": "MAN:example",
  "snapshotId": "sha256:example",
  "buildVariantIds": ["BUILD:example"],
  "docSetId": "DOCSET:example",
  "knowledgeVersion": "K:example",
  "indexVersion": "IDX:example",
  "analysisVersion": "AN:example",
  "scopeId": "SCOPE:example",
  "mode": "off",
  "capabilityProfile": "readonly-local",
  "budget": {
    "maxModelRequests": 30,
    "maxToolCalls": 150,
    "maxInputTokens": 300000,
    "maxOutputTokens": 60000,
    "maxWallSeconds": 1800,
    "maxTasks": 100,
    "maxTaskModelRequests": 6,
    "maxTaskToolCalls": 20,
    "maxConcurrentTools": 4,
    "maxConcurrentModels": 1
  }
}
```

范围配置另含 `auditRoots / dependencyReadRoots / documentRoots / allowedWriteRoots / dataPolicyId`。运行解析配置后保存完整有效值，不能只存 CLI 参数。run 总预算由 host 强制执行，任务预算只能在总预算内经登记调整。

`maxModelRequests` 是运行总上限，`maxTaskModelRequests` 是单任务上限，不表示每项任务都会用满；不能用两上限相乘推断实际花费，也不能因 off 模式零调用就给 live 任意增额。按冻结样本记录每项任务实际请求、token、耗时及停止原因后再调整总预算；未校准前保持保守上限，预算不足如实停止。

### 5.2 输入清单

`InputManifest` 必须登记源文件与元数据的路径、哈希和角色，构建命令与生成头，文档集合，正式知识版本，分析器和 schema 版本，目标平台及允许读取的依赖范围。未知依赖单列，不用空数组表示依赖完整。

输入一致性分两级：

- 结构查询读取已登记文件的同一份字节，先验证哈希再解析或呈现；内容变化返回 `stale-input`。
- 编译和语义分析还验证头文件、宏、sysroot、生成文件及命令；不能完整固定时保留 `dependency-closure-incomplete`，禁止强否定。

需要编译器稳定读入的一组依赖应制作已授权的只读输入副本，或使用能够证明读取内容一致的机制。仅在分析前后各比较一次主文件哈希，不能证明编译器读取的所有依赖稳定。

### 5.3 目录与所有权

```text
K/
  norms/                              # accepted 规范，发布流程写
  concepts/                           # accepted 领域语义及来源
  views/                              # 问题提示、反例和退出条件
  recipes/                            # 有界取证配方
  policies/                           # 范围、能力、预算、报告策略
  schemas/autonomy-*.json              # 新记录 schema
out/
  facts/<snapshotId>/                 # 已有事实，只读消费
  knowledge/<docSetId>/               # 文档实体、提案与发布记录
  derived/<inputKey>/                 # 关系索引、局部答案、依赖清单
  autonomy/<runId>/
    manifest.json
    run.json
    events.jsonl
    checkpoints/state.json
    tasks.jsonl
    evidence/
    contexts/
    model-calls/
    assessments.jsonl
    verification/
    runtime/
    coverage.json
    cost.json
    report-model.json
    report.md
    checksums.json
```

事实、知识、派生记录逻辑分离，允许共用同一种存储技术。JSONL 是首版账本和交换格式；高频读取用可重建倒排、邻接或分片索引。引入数据库前，先给出扫描瓶颈、查询负载和迁移收益的测量。

上面的目录占位符表示 store 解析后的安全目录名，不是把原始逻辑 ID 直接拼入路径。Windows 文件名不能使用逻辑 ID 中的冒号：既有 `sha256:<hex>` 快照目录使用 `<hex>`；新 `PREFIX:<hex>` 内容 ID 使用登记的 `<prefix>-<hex>` 文件名，保留完整哈希。版本与 run ID 必须通过登记表映射到唯一安全名称，拒绝 Windows 保留名、路径分隔符、尾部空格和点。不要用任意字符替换造成不同 ID 的文件名碰撞；manifest 保留逻辑 ID 与物理位置的对应关系。

`inputKey` 来自固定输入清单。`tasks.jsonl` 是事件归约得到的导出视图，不是第二个权威账本。运行恢复以完整事件和对应不可变证据为准。

### 5.4 公共记录与引用

新持久化记录具有 `recordId / recordType / schemaVersion / manifestId / createdAt / producer / dependencyRefs / payload`。既有 F: 事实不强制重写；适配器为其提供同等元数据和引用解析。

除显式包含公共封套的示例外，本文 JSON 展示配置对象或业务 payload。落盘时由 store 添加封套；模型不负责生成时间戳、内容哈希或存储路径。业务 ID 与 recordId 的对应关系由 schema 固定，禁止出现指向不同对象的重复身份字段。

| 前缀 | 对象 | 身份规则 |
|---|---|---|
| `F:` | 既有事实 | 保留既有稳定标识，不冒充新结论 |
| `ENT:`、`REL:` | 实体、关系 | 清单版本、限定身份和关系位置的哈希 |
| `DOC:`、`NORM:` | 文档片段、规范 | 文档内容与范围，或规范语义版本 |
| `SUM:` | 派生答案 | 命题、参数、依赖和分析版本 |
| `TASK:`、`QUESTION:` | 任务、子问题 | run 内分配，不用自由文本作为唯一键 |
| `EVID:`、`CTX:` | 工具结果、上下文包 | 规范化完整内容的哈希 |
| `ASSESS:`、`VERIFY:` | 裁决、验证 | 命题、输入和评估或执行记录 |

内容哈希使用规范化 JSON：对象键排序、禁止非有限数，保留有语义的数组顺序；只有声明为集合的字段排序去重。完整 SHA-256 作为存储身份，短 ID 仅展示。时间戳不参与需要稳定的语义缓存键。

源码引用至少含 `snapshotId / repo / file / sha256 / startLine / endLine`。行号从 1 开始；可选列号必须声明 `columnUnit`，禁止混用字节与 UTF-16 偏移。实体身份包含仓、文件、限定名称、签名和构建变体，名字仅用于召回。

## 6. 事实与关系建设

### 6.1 基础抽取

按范围枚举源码、IDL、SA 配置、NAPI 注册、权限声明、公共事件和必要构建信息。生产、测试、样例、生成代码分别标记，测试代码可以帮助理解和评估，但不能自动进入生产发现统计。

每个文件一次 tree-sitter 解析，抽取函数、类型声明、调用、参数、语法分支、读写、锁及注册位置。保留 ERROR 节点、未归属调用、未知语法和预处理限制。宏定义体识别不等于宏展开；文本 guard 不等于有效权限检查。

独立记录 `parseStatus / resolution / modelId / coverage / unresolved`，不用一个 `confidence=high` 隐藏不同维度。计数和比例必须给分母、枚举方法和失败数量。

### 6.2 实体与关系模型

实体首批类型：`component | file | function | type | field | entry | operation | object | permission | event | document`。入口和对象可能只有候选身份，必须允许 `unbound / ambiguous / resolved`。

首批关系为 `defines / declares / calls / registers / dispatches / reads / writes / documents / requires / derived-from`。`checks / owns / captures / releases / transfers-identity` 等语义关系只能由具名分析器或模型评估产生，不能与直接声明关系混用。

关系示例：

```json
{
  "recordId": "REL:example",
  "recordType": "relation",
  "schemaVersion": "1",
  "manifestId": "MAN:example",
  "createdAt": "2026-10-21T00:00:00Z",
  "producer": {"kind": "analyzer", "name": "entry-binding", "version": "1"},
  "dependencyRefs": ["F:example:registration"],
  "payload": {
    "relation": "dispatches",
    "from": "ENT:example-entry",
    "to": "ENT:example-handler",
    "basis": "derived",
    "resolution": "candidate",
    "buildVariantIds": ["BUILD:example"],
    "evidenceRefs": ["F:example:registration"],
    "unresolved": ["overload-target-ambiguous"]
  }
}
```

精确绑定优先使用接口描述符、分发码、注册项、签名、owner、构建归属。名称相同只提供候选；同名多仓、重载、虚调用、函数指针、异步回调保持歧义，不能为了连通关系图而补猜边。

### 6.3 宏、包装函数与复杂语义

优先处理高频、会改变控制流或身份语义的宏和包装函数。登记定义位置、参数映射、适用构建条件、副作用、返回行为、分析来源和未解析部分。

模型可以辅助理解宏或包装函数，但模型输出不直接变成 observed fact。经确定性代码套用一个模型生成的规则，结果仍依赖该模型解释；必要时用真实预处理展开、目标匹配分析和正反例校验。未验证宏不能用于证明“没有检查”或“所有路径受保护”。

### 6.4 有界分析与强否定

允许使用便宜的有界调用扩展、局部 def-use 和启发式操作检测来发现问题，但返回值必须暴露步数、节点上限、截断边界和未解析目标。

`may-reach` 只表示抽象结构存在候选路径。`unreachable` 仅在明确模型保守覆盖目标行为、全部相关未解析边已处理、搜索未截断且前提适用时允许输出。不能仅设置 `complete=true` 就获得证明资格。

每个能输出 `proof-within-model` 的分析器必须有模型说明、适用性检查、支持语义清单和可检查的证据产物。命题限定于具体版本、入口、目标和构建变体；证明调用不可达不能替代证明数据不可达或泄露不可能。

### 6.5 质量输出

每次索引构建同时产生文件、入口、关系和分析覆盖账本，记录读取失败、语法错误、缺生成头、宏未建模、未绑定入口、模糊调用和索引截断。事实数量增加不等于审计覆盖增加；输入枚举器的覆盖也不能由自身输出数量自证。

## 7. 领域知识库

### 7.1 三种知识不能混淆

| 类型 | 内容 | 使用方式 |
|---|---|---|
| 领域概念 | 调用主体、代理身份、权限、对象归属、异步生命周期等术语及其实现关联 | 帮助解释事实，保留来源和适用版本 |
| 条件规范 | 在何种条件下必须维持何种性质，以及明确例外 | 约束推论和裁决 |
| 分析方法 | 应查哪些子问题、用哪些工具、常见反证与停止条件 | 指导调查，不自行规定产品行为 |

知识按“通用安全原则、平台语义、组件契约”组织，共用实体和来源。不为权限、生命周期、边界检查各复制一个独立知识岛。缺项目特定规范时仍可根据已接纳的通用原则调查，但必须说明适用依据。

### 7.2 来源与权威

| 来源 | 可以支持 | 不能直接推出 |
|---|---|---|
| 正式接口契约、权限声明 | 接口要求、参数约束和例外 | 某个具体内部函数必须完成全部检查 |
| 平台安全设计 | 带前提的通用要求 | 所有接口套用同一权限策略 |
| 部署配置、权限定义 | 指定配置下的声明与授予条件 | 未观察到的设备运行状态 |
| 源码、测试 | 实际行为、意图线索和样例 | 现有实现必然符合要求 |
| 历史修复、示例 | 候选模式和类比 | 当前版本必然存在同一问题 |

不同版本、语言和组件契约分别登记。更具体的规则并不自动覆盖一般规则；只有明确适用关系或已批准的优先策略才允许覆盖。无明确优先关系时形成 conflict，不能让模型静默选一个。

### 7.3 规范记录

```json
{
  "normId": "NORM:example",
  "state": "proposed",
  "kind": "authorization",
  "statement": "在接口声明的主体与对象范围内，修改操作必须满足授权条件",
  "appliesTo": {"entityRefs": ["DOC:example-api"], "versions": ["6.0"]},
  "preconditions": ["object-mutation", "interface-binding-resolved"],
  "requirements": [{"id": "R1", "property": "caller-object-authorization"}],
  "exceptions": [],
  "requiredEvidence": ["caller-identity", "object-identity", "authorization-effect"],
  "sourceRefs": ["DOC:example-paragraph"],
  "authority": "interface-contract",
  "interpretation": {"basis": "llm", "modelCallRef": "CALL:example"},
  "knowledgeVersion": null
}
```

该示例不声明 OpenHarmony 的真实规范。每个语义映射都需要原文支持或显式项目策略，不能由“存在读操作”自动推出“读取了敏感信息”。

要求写成行为性质，而非某个函数名必须出现。规范适用性使用 `applicable | not-applicable | unknown | conflict`，逐项记录前提求值；未知前提不能当成不适用。

### 7.4 建设与发布算法

1. 固定文档集合，按标题、接口、参数、返回值、权限和例外切分，保留源位置、原文和哈希。
2. 提取文档实体，依次用完整符号、签名、模块、接口描述符及有来源的别名链接代码实体。
3. 结构化声明由确定性提取器记录；自然语言解释由 LLM 生成 proposed 规范。
4. 校验原文、实体绑定、版本、前提可观察性、例外和冲突，准备适用、不适用、例外和缺信息样例。
5. 离线 Builder-LLM 可以审核新语义规则与适用性，按原文、代码、前提和例外记录审查理由，以 `authority=builder-llm-review`、`generatedBy=builder-llm`、`needsHumanTuning=true` 发布；不需要人工审核或外部签名。其权威是项目内的静态分析前提，不声称独立人工确认。Runtime-LLM 不得自行审批正在调查的规范。
6. 发布不可变知识版本及来源记录；状态为 `accepted | rejected | superseded`，不能原地覆盖旧版本。签名可作为可选完整性机制，不能成为静态主流程的审批前置门。

未发布提案可以触发探索，但不能作为 finding 的唯一规范。Builder-LLM 审核可以批量完成；发布流程独立于 Runtime-Agent。运行时须重核来源哈希、入口适用性及冲突，不能把 Builder 标签当成源码事实。

试点 `UnSetPolicy` 的 README “其余接口”规则可由 Builder-LLM 明确批准对 `UnSetPolicy` 及其精确委托的异步入口适用，但必须同时核对 IDL、实现、公开接口例外和调用主体；适用性不是仅凭名称推断。若 README 与更具体契约冲突，标注 conflict 并限制结论。历史独立人工签名试验仅供兼容，不再作为 M2 主流程门槛。

### 7.5 视图与取证配方

首批视图为 `general / authorization / lifetime / input-boundary`。视图包含 `suggestedQuestions / normSelectors / commonCounterexamples / preferredRecipes / exitCriteria`，不复制规范正文，不限制读取证据，不改变工具权限。

配方是有界、可检查的工具 DAG，每一步有输入来源、失败分支、输出与停止条件。参数来自已验证实体或前一步结果，禁止模型提交任意脚本。配方不能隐藏模型调用；遇到语义解释需求时返回控制器安排分析。

同一任务可以组合多个视图。没有匹配视图时使用 general；不得因为未分类就丢弃问题。

## 8. 派生答案：可复用的局部分析

### 8.1 保存什么

派生答案不是一般性函数描述，而是对一个具体问题的条件化回答。优先缓存身份包装函数、权限封装、入口分发器、对象所有权、异步捕获、错误传播和常见校验宏。

每条记录包含以下字段：

| 字段 | 合同 |
|---|---|
| `summaryId / subjectRefs / proposition` | 稳定身份、被分析实体、明确待判命题 |
| `parameters / appliesWhen` | 形参语义、实参绑定要求和适用条件 |
| `answer / effects` | 局部答案、返回行为、相关读写与副作用 |
| `quantifier / scope` | 单个样例、某条路径、指定模型内全部路径等，不默认全称 |
| `basis / assurance` | 来源与保证类型，不自动排序升级 |
| `evidenceRefs / counterEvidenceRefs` | 支持依据与已取得反证 |
| `dependencyRefs / dependencyHashes` | 源码、规范、构建条件及被引用答案 |
| `unresolved / invalidationConditions` | 未解条件与失效条件 |
| `analyzerVersion / modelCallRef` | 实际产生答案的分析器或模型调用 |

可用答案示例：“在构建变体 B 中，该函数对传入主体 t 和对象 o 调用授权逻辑，失败返回错误；是否阻止实际写入取决于调用者是否处理该错误。”不可用答案示例：“该函数做了安全检查，所以安全。”

### 8.2 生成与接纳

1. 由当前任务或预热计划提出局部命题，取得函数、必要调用和规范。
2. 能机械回答的结构问题直接分析；需要语义解释时由统一网关调用 LLM。
3. 验证引用、前提、对象对应和依赖；有独立 checker 的子结论由 checker 核验。
4. 将局部结论写入派生库，不回写观察事实；未解决部分保留 unknown。
5. 只有存在明确复用价值才生成摘要，不把每次聊天自动压成长期知识。

模型结论经 schema 校验后可以成为 `model-assessment`，不要求全部先形式证明才允许使用，但必须保持该保证类型。缓存重放和温度设置不能把它升级为证明。

### 8.3 复用算法

先用实体、命题类型和参数索引召回答案，再验证输入依赖、构建条件、规范版本及实参映射。逐个求值 `appliesWhen`，未知时只返回条件结论或补证动作。

匹配成功时返回答案、最小关键证据窗口和未解条件，不再让模型从头解释完整函数。关键裁决依赖模型摘要时仍可按需展开原文；“复用”不意味着隐藏来源。

依赖图禁止自证环。递归函数或相互依赖规范不能用循环引用获得证明；可以做有模型说明的迭代分析，否则保留未闭合依赖。一个结论及其多次转述算同一来源。

## 9. 任务、子问题与证据需求图

### 9.1 审计任务

任务围绕行为命题，不围绕漏洞类别。下面展示任务 payload；落盘仍使用第 5 节公共记录封套。

```json
{
  "taskId": "TASK:example",
  "parentTaskId": null,
  "origin": "entry-scan",
  "anchorRefs": ["ENT:example-entry", "ENT:example-operation"],
  "question": "在指定入口与调用者条件下，能否未经对象授权执行修改？",
  "hypothesis": null,
  "labels": [],
  "views": ["general", "authorization"],
  "state": "queued",
  "terminalReason": null,
  "questionRefs": ["QUESTION:identity", "QUESTION:object", "QUESTION:coverage"],
  "missingRefs": [],
  "relatedTaskRefs": [],
  "revision": 1
}
```

任务接纳要求：锚点可回查，问题具有可观察对象或行为，至少有一个首步动作或具名阻塞条件。纯概念提案先做实体搜索，找不到实体时登记未解析提案，不编造锚点。

去重键由锚点、对象、操作、命题类型、规范和构建范围组成。不能仅按自由文本或类别去重；无法确定是否相同则标 `possiblySameAs`。不同入口、主体或执行路径不能未经证明合并。

### 9.2 子问题合同

每个 Question 必须有 `questionId / proposition / polarity / scope / dependsOn / requiredEvidenceKinds / counterexampleQueries / status / basis / assurance / evidenceRefs / missingRefs`。

`polarity` 明确“存在违规路径”或“所有相关路径满足要求”等量词方向。状态为 `unknown | supported | refuted | conflict | not-applicable`。`not-applicable` 必须有前提不成立的依据，不能用于隐藏工具不支持。

对象授权问题的初始需求图：

```text
入口身份 -> 实现绑定 -> 可执行操作
调用/部署条件 -> 实际主体 -> 检查使用的主体
输入来源 -> 目标对象 -> 检查对象与实际修改对象是否一致
正式规范 + 主体/对象条件 -> 授权要求及例外
检查结果 + 失败处理 + 操作顺序 -> 检查是否有效约束该操作
上述结果 + 绕过候选 + 反证 -> 对原命题的评估
```

模板只提供初始问题，不固定九项义务或八种类别。LLM 可以新增、重组或细化子问题，但删除关键问题或标为不适用必须有依据和事件。依赖成环时先拆问题，无法拆解则登记 conflict，不无限循环。

### 9.3 可执行缺口

```json
{
  "missingId": "MISS:example",
  "questionId": "QUESTION:coverage",
  "category": "precision",
  "reasonCode": "callback-target-unresolved",
  "targetRefs": ["F:example:registration"],
  "whyNeeded": "回调目标决定对象是否在修改前重新授权",
  "blocking": true,
  "nextActions": [
    {
      "tool": "inspectRelation",
      "arguments": {"ref": "F:example:registration", "relation": "registers"},
      "successCriteria": "定位回调候选并说明候选集合的覆盖边界"
    }
  ],
  "attemptedMethods": [],
  "terminalReason": null
}
```

category 固定为 `data | tool | precision | environment | conflict | model-capability | budget | authorization`。reasonCode 至少支持 `stale-input / ambiguous-symbol / binding-unbound / policy-missing / unsupported-analysis / generated-header-missing / path-limit / result-truncated / malformed-record / source-out-of-scope / dependency-closure-incomplete / no-progress`。

无可执行下一步时，`nextActions=[]` 且 `terminalReason` 必填。未知字段不能用 null 或空数组冒充已知为空，例如“未知道是否要求权限”不等于“没有权限要求”。

### 9.4 执行状态与结果分离

| 维度 | 状态 | 含义 |
|---|---|---|
| 工具执行 | `ok / error / unsupported / cancelled` | 工具是否执行，不表示命题成立 |
| 任务执行 | `queued / active / waiting / closed` | 调度状态 |
| 关闭原因 | `assessed / inconclusive / blocked / cancelled / budget-exhausted` | 结束原因，不能被当成安全标签 |
| 证据充分性 | `sufficient-for-claim / insufficient / conflict` | 仅相对于当前命题、前提和结论强度 |
| 裁决 | `supported / refuted / insufficient / conflict` | 对具名命题的评估 |
| 对外分类 | `candidate / observation / finding / excluded` | 报告策略计算结果 |

waiting 只用于本次运行已有可完成依赖的情况。等待设备或授权等外部变化时关闭为 blocked 并保留恢复条件；没有可运行任务时结束 run，不空转。

## 10. 问题驱动的 RAG 与上下文编译

### 10.1 检索单位

代码以函数、完整语法块、类型、字段、注册项和配置项为单位；文档以带标题与实体归属的段落为单位；派生答案以命题和前提为单位。大函数切分必须保留控制条件、作用域与错误出口，不采用固定行数切片作为唯一上下文。

首版索引包括实体精确索引、符号/文档倒排索引、带来源关系的前向/反向邻接索引、规范适用范围索引、摘要命题索引和依赖反向索引。

### 10.2 取证流程

1. 输入 task、当前子问题、已固定版本和预算，列出本轮目标与决定结论的缺口。
2. 精确解析锚点和实体身份；不能消歧则先补绑定，禁止把多个候选合成一个函数。
3. 检索适用规范及已有派生答案，验证前提和依赖，保留不适用原因。
4. 按需求图选择有界配方，沿调用者、被调用者、注册、控制和数据关系取得材料。
5. 对别名、同义概念和未知行为使用词法召回；确有召回缺口后才增加语义检索。
6. 单独执行反证与例外查询，不能只沿支持初始假设的方向扩展。
7. 按证据槽合并、去重并保留语义完整窗口，生成 ContextPacket。
8. 若关键缺口仍可解决，返回下一步；若需要局部语义分析，交控制器调用 LLM。

检索排序优先命题匹配、实体准确性、前提一致性、依赖距离和新信息贡献，文本相似度只是召回信号。相关性分数不得进入最终证明等级。

分页、top-k、hop 上限、超时和 token 裁剪必须显式记录。索引无命中只证明本次查询没有取得材料，不证明不存在对应代码或反例。

### 10.3 两种上下文包

发现包包含组件职责、入口与操作概览、对象关系、规范候选、差异信号和覆盖缺口。目的是产生可调查问题，不需要预先建立全部证明义务。

裁决包包含原问题与命题方向、当前子问题图、适用规范及例外、主体和对象对应、决定性源码、有效局部答案、最强已知反证、未解析依赖及验证记录。发现包中的粗摘要不能未经检查直接成为最终依据。

两种包都包含以下字段：

```json
{
  "contextId": "CTX:example",
  "taskId": "TASK:example",
  "taskRevision": 3,
  "purpose": "interpret",
  "inputManifestId": "MAN:example",
  "focusQuestionIds": ["QUESTION:coverage"],
  "normRefs": ["NORM:example"],
  "evidenceRefs": ["EVID:example"],
  "summaryRefs": [],
  "counterEvidenceRefs": [],
  "missingRefs": ["MISS:example"],
  "attemptHistoryRefs": [],
  "renderedBlocks": [],
  "omittedRefs": [],
  "truncated": false,
  "estimatedInputTokens": 0,
  "sufficiency": "insufficient"
}
```

这是字段示例，不是可直接发送的空包。模型实际收到的 `renderedBlocks` 必须含可理解的原文与局部答案，不能只有 ID。上下文包保存最终发送内容及哈希，模型只能引用当前可见或已明确取回的证据。

### 10.4 预算与增量上下文

初始建议单次输入包上限约 12k token，输出预留约 4k，必须以实际模型能力和 tokenizer 校准。不把估算字符数宣称为精确 token 数。超大问题拆成有连接关系的子问题，局部结论仍保留依赖。

每轮重发简短问题状态、仍关键的证据和新增内容。旧内容只有在重新渲染摘要或原文后才算当前可见；不能假设一次无历史的模型请求会记得前一轮。裁决依赖已压缩的关键分支时，重新展开该分支。

压缩必须保留身份、对象、比较方向、错误处理、操作顺序、构建条件和例外。关键内容无法放入包时标 insufficient，不得为了预算把它删除后仍称充分。

### 10.5 充分性与停止判断

充分性是针对当前命题的可审计工程判断，不是一个通用完备性算法。程序检查来源、版本、证据槽、分析能力和已知缺口；LLM 检查可能遗漏的前提、替代解释和例外。后者仍是模型判断。

进入裁决需要：关键子问题已得到与结论强度匹配的依据，或已明确无法取得；反证搜索是否完成及覆盖已登记；当前假设与规范适用性已说明。证据不足也可以进入裁决，但输出只能保留不足或冲突，不能强行完成命题。

“已有许多引用”“模型确信”“所有字段非空”“再搜索没有结果”均不是充分性判据。

## 11. 工具接口与证据服务

### 11.1 统一入口

所有查询工具实现 `execute(args, runContext, signal)`。dispatcher 统一处理参数、权限、路径、版本、缓存、预算、超时、结果大小和证据归档。第一版直接进程内调用。

注册项必须声明 `name / version / inputSchema / outputSchema / capabilities / determinism / timeoutMs / maxResultBytes / costBound`。默认只读工具超时 30 秒、单次返回正文上限 256 KiB；编译分析可单独登记 120 秒。上限是可配置默认值，截断时必须给出分页或 missing。

### 11.2 首批工具合同

| 工具 | 必需参数 | 局部输出 | 边界 |
|---|---|---|---|
| `getScopeOverview` | `scopeId`，可选 cursor | 入口、操作、规范覆盖和未探索区域 | 不宣称完整攻击面 |
| `searchEntities` | query；可选 kind/repo/cursor | 候选、匹配依据、消歧字段 | 名称命中不自动绑定 |
| `inspectEntry` | entryRef | 绑定候选、主体条件、边界和缺口 | 接受部分入口，不要求完整契约 |
| `getApplicableNorms` | entityRefs、contextFacts | 正式规范、提案、适用性与例外 | 未知前提不判不适用 |
| `inspectRelation` | ref、relation；可选 direction/cursor | 带来源和精度的邻接关系 | 不支持的关系明确返回 unsupported |
| `collectEvidence` | taskId、questionId、recipeId | 有界配方结果和需求槽覆盖 | 只执行注册配方 |
| `inspectAuthorization` | entryRef、operationRef | 主体、对象、检查和失败路径 | 找到检查调用不等于授权有效 |
| `inspectLifetime` | objectRef、operationRef | 创建、捕获、移交、释放、取消与顺序 | 目标或别名未解时保持未知 |
| `traceValue` | fromRef、toRef、modelId | 分析模型支持的路径与条件 | 初期允许 unsupported，不包装假数据流 |
| `getEvidence` | resultRef；可选 range | 已登记证据的原文及哈希检查 | 不接受任意 URL 或越界路径 |
| `checkSource` | fileRef、buildVariantId | Windows 原生有界分析及保证等级；必要时请求单次 Linux 例外 | 缺生成头/变体或未批准例外返回缺口；语法通过不等于目标构建或程序安全 |

`inspectAuthorization` 是首个必须实现的问题级工具；其他问题级工具可先注册为 unsupported，不能用空结果冒充实现完成。底层源码、AST 和精确实体查询保留为后备，允许 Agent 在既定范围内探索未被配方覆盖的问题。

### 11.3 ToolResult

```json
{
  "resultId": "EVID:example",
  "tool": "inspectAuthorization",
  "toolVersion": "1",
  "status": "ok",
  "questionId": "QUESTION:coverage",
  "inputManifestId": "MAN:example",
  "answer": {
    "status": "unknown",
    "text": "已找到检查调用，但尚不能确认检查对象与修改对象一致",
    "basis": "derived",
    "assurance": "bounded-analysis"
  },
  "assumptions": [],
  "evidenceRefs": ["F:example:check"],
  "counterEvidenceRefs": [],
  "sourceWindows": [],
  "completeness": {
    "scope": "指定入口的已解析调用区域",
    "enumeration": "partial",
    "unresolvedRefs": ["F:example:callback"],
    "truncated": false,
    "nextCursor": null
  },
  "missingRefs": ["MISS:example"],
  "nextActions": [],
  "requiresInterpretation": false,
  "usage": {"wallMs": 0, "bytesRead": 0, "cacheHit": false}
}
```

结果引用的 missing 可以包含下一步；只有不存在可行下一步时才需要终止原因。`counterEvidenceRefs=[]` 只表示当前未取得反证，另登记反证搜索是否执行及覆盖。`sourceWindows` 可以为空，但发送给模型前必须展开足够材料。

answer.status 使用子问题状态枚举。status=error/unsupported 时 answer 保持 unknown，附具名错误，不得返回 refuted。局部确定答案需要明确范围，不能从“当前函数内完整枚举无检查”扩展为“全调用路径无授权”。

### 11.4 问题级工具如何减少重复分析

工具先复用条件匹配的局部答案，再执行确定性取证，最后返回待解释的最小语义问题。它不能内部偷偷调用模型。需要模型分析时设置 `requiresInterpretation=true`，由控制器通过统一网关完成、计费和存档，再生成可复用答案。

授权查询若当前实现体只委托给包装函数，可按需沿唯一且有实体依据的 callee 展开一跳；记录边的解析精度、调用条件、返回值处理及完整性。看到 callee 内有检查调用只能把“当前体未见直接校验”改为“委托校验存在、有效性待判”，不能自动判定对象一致、支配敏感操作或排除候选。歧义、宏、虚调用、上游检查及截断保持具名未知；不得仅凭词表阴性作整条入口路径的强否定。

不要求每个工具直接输出整个漏洞结论；要求每个工具推进一个具体子问题。一次工具调用可以完成一个有界配方，但不能隐藏无界循环。

### 11.5 MCP 的位置

MCP 是可选的工具暴露协议，不是推理层。只有需要外部客户端时增加 adapter，调用同一个 dispatcher，不复制业务逻辑。SDK 和协议版本届时固定并测试；首版不以其为依赖。

本地与 MCP 路径对相同输入必须产生等价业务结果、引用和权限判断。工具 annotations 只是元数据，不能替代 host 权限检查。大结果先归档并分页，协议错误与业务 unknown 分开；远端描述、URL 和返回文本不得授予新权限。

## 12. 自主发现与候选调度

### 12.1 五条发现路径

| 路径 | 便宜的初始动作 | LLM 的任务 |
|---|---|---|
| 入口驱动 | 枚举 IDL、分发、注册、网络接收等入口候选 | 理解主体、输入与边界，提出待判问题 |
| 操作驱动 | 枚举修改、复制、分配、发布、异步注册等操作 | 判断对象、输入和操作组合是否值得追踪 |
| 规范驱动 | 找出正式规范或提案的候选实现 | 检查适用条件、可能违反方式及例外 |
| 差异驱动 | 比较同职责入口、修复前后或相邻实现的行为差异 | 判断差异是否有合理业务解释，不能把不一致直接判错 |
| 覆盖驱动 | 固定随机种子分层抽样低覆盖区域 | 找到未被既有模板表达的行为和问题 |

每次 scope-only 运行至少执行入口枚举和覆盖抽样，不能把已有 claim 列表作为唯一输入。历史修复只是线索；修复前版本不得混入当前生产快照。任务和报告保留 `origin`；覆盖抽样的函数不是入口，使用独立的行为探索问题，不直接套用入口授权模板，也不因“函数体内未见检查调用”进入 CANDIDATES。若抽样发现具体操作，再以可回查入口、主体和操作新建关联任务；原抽样仍计入覆盖观察。

初次发现包尽量围绕一个行为单元：入口、操作、对象或生命周期片段。模型不逐行扫描整个系统，也不只看危险函数名。对复杂跨组件问题，允许从当前单元向已授权依赖扩展，保留边界。

### 12.2 提案接纳

候选提案字段为 `anchorRefs / proposition / whyInteresting / initialEvidenceRefs / firstAction / possibleCounterexample / suggestedViews`。模型提出问题不是发现漏洞，报告不能在此阶段使用确定漏洞措辞。

接纳器验证锚点和版本、可反驳性、首个动作、重复性及授权范围。首步工具不支持时可以接纳为缺口任务；不能因暂时无验证器就删掉新类型问题。

发现器的负结果只关闭该条启发式，不关闭实体的其他发现路径。低覆盖、高不确定区域保留探索机会，不能永远排在最后。

### 12.3 排序与公平性

采用可解释排序元组：用户优先级、具证据的暴露和影响信号、可解决的关键缺口、未覆盖程度、预计成本、创建顺序。禁止将模型自报置信度作为唯一优先级。

初始建议预留 20% 的发现预算给覆盖抽样和 general 探索，其余用于有锚点候选与补证。记录实际分配和被预算截断的区域；20% 不是实验得出的最优比例。

排序与停止依据本次信息收益：新增决定性证据、解决关键缺口、排除一种解释或发现独立问题。重复读取同一材料、增加无关引用不算进展。

### 12.4 保持任务与分支

为同一命题补身份、对象、路径、类型或环境条件，保留当前任务。权限问题涉及异步身份变化时增加 lifetime 视图，不重新开始。

发现可独立判断的对象释放问题时创建关联任务，传入共同 evidenceRefs 与 parentTaskId。相同根因不同路径先关联，证据足够后才合并，避免去重丢失影响范围。

## 13. 控制器、动作与停止

### 13.1 运行循环

```text
检查输入 -> 固定 RunContext -> 建立发现任务 -> 选择可运行任务
                                                |
                                      组装当前问题上下文
                                                |
                           +--------------------+------------------+
                           |                                       |
                   已有明确合法下一步                      需要语义选择或解释
                           |                                       |
                       调用工具                              调用模型网关
                           +--------------------+------------------+
                                                |
                                   验证动作/结果 -> 写事件
                                                |
                                   更新证据图、预算与检查点
                                                |
                             继续 / 分支 / 裁决 / 验证 / 结束
```

不为凑齐阶段强制每步调用模型。对齐已知参数、查询分页、校验 hash、执行明确 nextAction、处理普通错误均由程序完成。

### 13.2 Action 合同

```json
{
  "taskId": "TASK:example",
  "taskRevision": 3,
  "contextId": "CTX:example",
  "purpose": "plan",
  "actions": [
    {
      "type": "callTool",
      "tool": "inspectRelation",
      "arguments": {"ref": "F:example:registration", "relation": "registers"},
      "addressesMissing": ["MISS:example"],
      "expectedEvidence": "带注册依据的回调目标候选及覆盖边界"
    }
  ],
  "reason": "回调目标决定实际修改前是否仍有授权检查",
  "evidenceRefs": ["EVID:example"]
}
```

Action 类型固定为 `callTool / reviseQuestions / changeView / proposeTask / proposeNorm / recordSummary / recordAssessment / requestVerification / closeTask`。每种类型在 schema 中声明 required、枚举、长度和引用约束，拒绝未声明字段。`record*` 是待校验的提议，不是让模型直接写文件。

批量最多四个互不依赖的只读查询；有依赖时等待前一步结果，不能预猜 resultId。模型请求串行，结果返回时再次校验任务 revision 与 contextId，过期动作拒绝执行。

### 13.3 动作校验顺序

1. 解析 JSON 和 schema，拒绝任意代码、路径或动态工具名。
2. 验证任务 active、context 未过期、引用属于本次输入且已被取回。
3. 验证权限、作用域、规范状态和工具能力。
4. 检查重复动作、已失败方法、依赖是否变化。
5. 预留预算并记录 action intent，再执行动作。
6. 校验结果 schema、引用、语义范围和来源类型，归档后提交完成事件。

格式错误允许一次修复请求并计费。非法引用、越权或缺少依据不能通过不断重试直到模型“填对”来解决。

### 13.4 核心伪代码

```javascript
async function runAudit(run) {
  const state = await restoreOrInitialize(run);
  await validatePinnedInputs(state);
  await ensureScopeDiscoveryTasks(state);
  while (withinRunBudget(state)) {
    const task = selectRunnableTask(state);
    if (!task) break;
    const context = await prepareContext(task, state);
    const known = selectDeterministicAction(task, context, state);
    const proposal = known || await modelGateway.decide({ task, context, state });
    const actions = validateActions(proposal, task, context, state);
    for (const action of actions) {
      const intent = await reserveAndRecordIntent(action, state);
      const result = await executeBoundedAction(intent, state);
      await persistResultAndCompletion(intent, result, state);
      reduceState(state, intent, result);
    }
    await enforceProgressAndStopPolicy(task, state);
    await checkpoint(state);
  }
  return finalizeWithCoverageAndCosts(state);
}
```

伪代码不省略工程义务：每个外部 await 必须有取消、超时和错误归类；初始化和发现也计入总预算；超时不得留下未跟踪子进程；有结果但未提交事件时不能直接修改内存状态并宣称持久完成。

### 13.5 停止与恢复条件

- 相同参数、版本和依赖的查询直接读缓存；失败方法在依赖未变时不重复。
- 连续两轮决策没有新证据、有效假设变化或可执行新动作，进行一次 stop-check；仍无进展则 inconclusive。
- 关键问题已有足够范围内的证据且反证检查已登记，进入裁决；裁决仍可提出新缺口。
- 没有可用工具、缺设备或授权且不能在本 run 内解决，关闭为 blocked。
- 总预算耗尽或用户取消，停止新动作，取消受控在途任务，保存结果和未完状态。
- 输入漂移或知识版本不一致，阻断相关任务；不得无提示重建快照继续。

运行结束只表示当前调度已停止，不表示 scope 已审计完全。关闭任务在新增证据或新输入版本下可以重新评估，必须创建新的评估记录，不能覆盖旧结论。

受限纵向实验的多轮补证必须把每轮允许动作、上一轮已提交工具结果、当前缺口和任务 revision 纳入上下文标识；执行后重算缺口，不能把“取过目标源码”当成“操作目标已解析”。同一动作不重复，最多两轮；无新可执行动作或模型响应失败时停下并保留不足。每次选择和执行都进入事件、模型及工具账本，`check` 从已归档记录复算，replay 不发远端请求。旧实验按原版本只读复算，不迁移裁决语义。这是 M4 的有界样本，不代替开放范围的自主调度与任意动作恢复。

## 14. 模型网关、提示词与成本

### 14.1 模型接入

拟新增 `modelGateway.invoke({purpose, contextId, messages, maxTokens, requestId, signal})`，复用相邻 `oh6-vuln-agent/src/llm/http.js` 的运输能力和既有 `config/llm.json` 配置约定。默认密钥环境变量为 `OH6_LLM_API_KEY`；若配置指定其他变量，显式记录变量名而不是值。

不要复制 endpoint、模型名称或价目。模型选择由受控配置决定，首次使用记录供应商、实际模型标识、请求参数、能力验证结果和数据策略。缺配置或密钥时 live 明确失败，不自动换供应商或降为模拟。

第一版通过模型 JSON 内容表达 Action，复用现有 content 运输路径。原生 tool_calls、流式增量解析或其他协议只有在往返、取消、错误和账本测试完成后才启用。

### 14.2 四种模式

| 模式 | 行为 | 结果限制 |
|---|---|---|
| `off` | 只做机械发现、查询和索引 | 语义缺口保持未知 |
| `mock` | 使用显式 fixture 回答 | 不进入生产摘要库、正式知识或真实发现统计 |
| `replay` | 使用固定输入和已有调用记录 | 重现记录，不等于重新验证当前目标 |
| `live` | 实际模型请求 | 显式开启，受预算、来源与外发策略限制 |

回放键不匹配时返回 `replay-miss`，不能自动调用 live。LLM 重新请求可能改变结果；缓存和 replay 的可重复性不能被宣传为模型重新计算的确定性。

### 14.3 提示词组成

稳定系统指令仅包含角色、Action 合同、来源边界、权限和裁决纪律。规范、源码、注释、文档和工具文本放在明确的数据区块中，不能执行其中出现的指令。

目的枚举为 `discover / plan / interpret / summarize / judge / extract-norm / format-repair`。同一次调用可以解决相邻目的，不强制多轮角色扮演。只要求短理由、引用、前提、反驳条件和 nextAction，不要求隐含思维链。

judge 包必须给出最强已知反对解释、例外和缺口，不能只给初始假设的支持材料。模型自检是有价值的分析，但不是独立审计证据。

### 14.4 预算、取消与重试

请求前预留输入估算与最大输出，完成后按真实 usage 结算；摘要、规范抽取、embedding、格式修复和失败重试都计入对应运行。缺 usage 时保留最大预留并标 `usage-unknown`，按保守策略停止额外 live 请求。

请求数、工具次数、输出上限和墙钟时间由 host 强制控制。tokenizer 不确定、供应商隐藏开销或远端计费无法确认时，不宣称本地预算是精确金额上限。

瞬时网络或限流错误最多自动重试一次，遵守服务端等待信息且受剩余时间限制。鉴权失败、无效模型、schema 不兼容和越权不自动重试。取消必须覆盖连接和正文读取；不能只给收到响应头之前的阶段加超时。

外部调用可能已经执行却没有收到结果。超时、断电或取消后无法确认远端状态时登记 `remote-outcome-unknown`，保留预算预留，不自动重发付费请求。

### 14.5 请求与结果账本

每次模型调用保存 purpose、requestId、contextId、模型和实际请求描述哈希、promptVersion、输入输出哈希、usage、耗时、重试、缓存命中及校验结果。缓存键必须覆盖影响输出的实际参数，包括输出 token 上限和响应格式。

原始输入输出存于受控目录，按数据策略保留与脱敏，不记录 authorization header、API key 或模型隐藏思维链。取消与超时返回的数据不得未经完整性检查作为可用结论。

## 15. 裁决与报告准入

### 15.1 Assessment 合同

```json
{
  "assessmentId": "ASSESS:example",
  "taskId": "TASK:example",
  "proposition": "指定入口存在未经对象授权的修改路径",
  "scope": {"entryRefs": ["ENT:example-entry"], "buildVariantIds": ["BUILD:example"]},
  "decision": "insufficient",
  "basis": "llm",
  "assurance": "model-assessment",
  "normRefs": ["NORM:example"],
  "evidenceRefs": ["EVID:example"],
  "counterEvidenceRefs": [],
  "assumptions": [],
  "missingRefs": ["MISS:example"],
  "contextId": "CTX:example",
  "modelCallRef": "CALL:example",
  "inputManifestId": "MAN:example",
  "rationale": "检查与操作已定位，但尚未确认二者作用于同一对象"
}
```

basis 为 `observed | derived | llm | runtime | mixed`；mixed 必须逐子问题记录实际来源。assurance 为 `none | observation | bounded-analysis | model-assessment | proof-within-model | runtime-witness`。

assurance 不是可自动取最大值的线性等级。运行见证支持某次行为，不自动证明所有路径；模型解释可以合理且有用，但不能自己设置 proof-within-model。最终结论必须保留关键依赖中尚未解决的限制。

### 15.2 肯定、否定与不适用

对存在性问题的支持需要路径与前提成立的依据，抽象调用链本身不够。对不存在性的强否定需要覆盖相关行为的模型或足够范围内的反证，不能依据有界搜索未命中。

“某条候选路径被有效检查阻断”只能反驳该路径；若原命题包含其他路径，任务不能据此整体 excluded。规范不适用只排除相应规范命题，不证明对象不存在其他问题。

### 15.3 程序证据门

程序校验引用存在、输入与版本一致、适用范围、已知前提、分析器能力、反证记录、缺口与结论强度。可以用 checker 验证结构性结论，不能仅凭引用有效就断言自然语言结论被证据蕴含。

缺关键前提却给出强结论时拒绝该评估，保留任务的未知状态和拒绝原因；不能通过改写措辞掩盖缺口。语义结论可靠性通过独立样本与必要验证衡量，不靠 schema 通过率替代。

### 15.4 唯一报告策略

| 条件 | 分类 |
|---|---|
| 有具体疑点，但仍缺决定性前提 | candidate，附缺口与验证计划 |
| 仅有覆盖、工具、规则或环境缺口 | observation |
| 入口、适用规范、主体/对象、敏感操作和缺陷机制构成可回查的完整静态证据链，关键反证已处理 | finding，`verificationStatus=static-only`，`assurance=bounded-analysis` 或 `model-assessment` |
| 已在命题范围内被反驳或规范明确不适用 | excluded，保留命题、前提和反证 |
| 有 1–2 个受限静态假设（如目标消歧未定），但有明确违规信号及下一步 | candidate，列出假设，不得写成确诊 |

candidate 至少说明可回查的入口或可信触发条件、具体操作/对象、疑似违反的约束以及尚缺的证据；“直接调用名未命中词表”本身只是局部观察。报告携带 `origin`，覆盖抽样函数和只缺工具的记录留在 observation；经独立绑定得到真实入口和操作后才创建关联 candidate。委托检查可见但有效性未知时保留条件化疑点或 observation，不因一跳命中就宣称 refuted/excluded。

静态审计最高等级是 `Static Finding`，不要求运行见证；必须标 `verificationStatus=static-only`，不得称作设备复现或可利用性确认。`bounded-analysis` 只授予工具实际覆盖的语法/控制流子集；其余可用 `model-assessment` 并清楚列出前提。函数级变异体即使成立也不能冒充真实入口。单纯权限字符串不符、同名唯一或检查调用在操作之前都不单独构成 finding；要核对适用性、精确委托、失败早退、主体/对象和操作影响。

严重性依据可证的主体能力、资产和影响，缺少影响证据时写 `unrated` 或有明确依据的暂定等级，不把静态模式名称直接映射为 high/critical。

报告从同一 report-model 渲染，包含问题卡、证据、规范、假设、反证、验证、缺口、建议修复位置、覆盖和成本。报告层不重新检测或改变裁决。没有发现必须写“本次未取得满足门槛的发现”，禁止写“系统安全”。

## 16. 隔离验证服务（可选扩展）

本节不在静态审计主流程及其完成门内。`verify=blocked` 不降低有完整静态证据链的 finding，也不能升级静态证据；启用本节时才适用下述授权与隔离要求。

### 16.1 验证既可确认，也可补证

验证可以在静态结论尚不充分时执行，例如确定某返回值是否实际阻断操作、回调是否运行在预期身份下、特定配置是否允许入口到达。它不必等待整个任务静态 confirmed。

验证始终是独立授权能力。控制器可以提出计划，但不能从只读审计权限推导设备、网络、代码执行或真实服务操作权限。

### 16.2 VerificationPlan

计划字段为 `planId / taskId / questionIds / hypothesis / runnerId / targetEnvironment / buildVariantId / sourceRefs / harnessRef / inputRefs / controls / expectedSignals / successCriteria / resourceLimits / requiredCapabilities / approvalRef`。

每份计划必须说明实验能回答哪个子问题、不能回答什么、失败时如何解释。无 signal 的含义必须预先定义，不能实验后按期望重解释。

首批 runner 分三种：

- `host-isolated`：默认在 Windows 原生隔离环境运行限定 harness，记录与目标平台的差异；若 Windows 无法提供计划要求的隔离，返回 blocked。Linux harness 只可按第 4.3 节单次例外计划执行。
- `target-build`：默认在 Windows 原生目标配置工具链中做编译或运行条件校核；匹配程度单独登记，不自动代表设备行为。仅当所需目标证据无法在 Windows 获得且已批准例外时使用 Linux 工具链。
- `device-isolated`：明确授权的测试设备，记录系统版本、账号、权限和配置。

生成的 harness 先成为不可变候选产物，经过范围、命令、资源和能力校验后才可由登记 runner 执行。不得把模型生成的命令直接传给 shell；不能以现有 runner 能执行任意命令为默认权限。

### 16.3 验证记录

记录 `verificationId / planId / runId / commandArgv / sourceHash / harnessHash / inputHash / environmentHash / repeats / controls / observations / result / evidenceRefs / limitations`。

result 为 `observed | no-signal | blocked | error | unsupported`。observed 只说明记录了目标信号，另行判断其是否支持问题命题。默认试点重复三次并包含负对照；并发、概率性或时序问题需要额外计划，不能以三次替代充分测量。

入口真实性单独记录 `entryFaithfulness=faithful | partial | function-only | unknown`。构造出本来不可达的参数或身份，最多证明局部危险行为，不能支持现实攻击条件。

### 16.4 执行保护

runner 在独立目录和隔离环境中执行，产品源码只读，默认禁网络和设备访问。内存、CPU、输出量、进程数与超时必须由可验证的环境能力限制；不能提供相应隔离时返回 blocked，不把 Windows 上一个子进程等同于完整沙箱，也不因 Windows 隔离不足自动转到 Linux。

只清理该 runner 创建的工作目录和进程树。保留失败输出及环境信息；超时、缺设备、no-signal 均不能作为问题不存在的反证。

## 17. 共享记忆、缓存与恢复

### 17.1 四种共享状态

| 状态 | 生命周期 | 写入者 |
|---|---|---|
| 固定事实与正式知识 | 跨任务、不可变版本 | 构建器和受控发布流程 |
| 派生答案与证据缓存 | 跨任务，可按依赖失效 | 校验通过的分析结果提交器 |
| 任务工作记忆 | 当前命题的假设、子问题和失败历史 | 单一状态归约器 |
| 运行事件与预算账本 | append-only，可恢复 | 控制器提交器 |

层间共享 ID 和可展开内容，不传未经管理的长对话作为权威状态。工具返回后由控制器提交事件；worker 不直接修改任务、规范或其他任务的结论。

### 17.2 缓存键与失效

工具缓存键包含工具版本、规范化参数、实际输入哈希、依赖集、构建变体、分析模型和能力范围。模型缓存再包含实际请求描述、promptVersion、上下文内容和模型标识。

否定查询还依赖枚举集合、索引版本、查询范围和覆盖。新增文件、注册点或规则会改变旧的未命中结论，不能只检查命中过的文件是否变化。

依赖反向索引支持传递失效：源码、头文件、编译参数、生成文件、规范或局部答案变化，所有依赖结果进入 stale。无变化的内容可以重用，但跨 snapshot 复用必须重新验证依赖并生成当前版本的引用映射，记录 reusedFrom；不得把旧 F: 直接贴入新快照裁决。

仅因本次没用到某个依赖不能删除其失效约束。模型提案、mock 和评估答案不得进入生产可检索缓存。缓存存储满时优先回收可重建索引和未引用临时文件，不自动删除仍被报告引用的证据。

### 17.3 持久提交顺序

1. 为 action 分配 ID，预留预算，将 intent 事件持久化。
2. 执行动作，将完整结果写到同目录临时文件，校验并关闭，按策略 flush。
3. 原子提交不可变证据文件，记录内容哈希。
4. 写入并持久化 completion 事件，引用已提交证据。
5. 归约内存状态，定期原子更新 checkpoint。

事件含递增 seq、runId、taskId、actionId、输入/输出引用、状态迁移和预算变化。checkpoint 包含 throughSeq、所有固定版本、队列、子问题、预算预留、未完成 action 和索引版本。

Windows 文件替换必须测试失败与恢复行为。替换失败时保留旧 checkpoint 和临时文件，不先删除旧文件制造空窗。一次 run 只允许一个写进程；锁记录进程身份和启动信息，恢复时不能仅按 PID 判断陈旧锁。

### 17.4 崩溃与重放

恢复时校验清单、checkpoint 哈希与 seq，再重放后续完整事件。已识别的尾部半条记录可作为崩溃残留处理；中间坏行、seq 缺口或引用证据缺失视为账本损坏，停止并报告。

已有证据但无 completion 的文件是 orphan，不能直接当任务成功。幂等只读动作可以重新执行；付费请求结果不明时保持 remote-outcome-unknown；规范发布和动态验证的副作用不能默认重放。

用户明确授权后可以处理未知远端结果，但必须保存原请求和新请求的关系、可能重复计费及预算变化。请求 ID 不等于服务端保证 exactly-once。

## 18. 信任边界与安全

### 18.1 内容不等于指令

源码、注释、文档、历史报告和工具正文中的命令一律是待分析数据。模型读取到“忽略规则”“修改预算”“调用某网址”等文本不能改变 host 策略。提示词分区只是辅助，实际边界由 dispatcher、schema、固定工具和权限检查执行。

### 18.2 能力配置

首版 capability profile 至少包括：

- `readonly-local`：已登记源码/文档/产物读取及本 run 写入，不联网、不执行构建产物。
- `model-enabled`：在 readonly-local 基础上允许指定 endpoint、数据策略和预算内的模型请求。
- `analysis-linux-exception`：仅对批准计划中指定的一次 Linux 工具调用开放，限定命题、文件、变体、发行版、argv 与资源上限；默认 profile 不含此能力，不执行任意 shell 或未登记程序。
- `verification-isolated`：允许已批准 runner 和计划，不能隐含设备或网络权限。

profile 是明确能力集合，可以组合但不能由模型扩大。知识视图、工具描述和返回值不能赋予权限。外部 provider、服务器与 endpoint 的变更必须由用户或受控配置流程授权。

### 18.3 数据外发与日志

固定哪些仓、文档与文件允许发送到模型，检查源码中的密钥、凭据和敏感数据。脱敏破坏判断语义时返回 `redacted-context`，不能用失真的上下文硬判。

原始 prompt、response、验证输入和报告受访问与保留策略管理，不能自动上传或分享。日志只记录密钥是否存在和配置指纹，异常文本也要脱敏。模型输出中的路径、SQL、正则和命令都必须作为不可信输入验证。

### 18.4 资源与安全失败

解析器、正则、编译器、模型、索引和报告都限制输入大小、时间和输出。病态输入超限后保留具名缺口，不崩溃整轮或误报安全。

发现越权动作、跨版本证据或数据外发违规时拒绝动作并记录事件；不能以“为了完成审计”为理由绕过控制。安全门失败与普通证据不足分别统计。

## 19. 代码布局与 CLI 合同

### 19.1 拟新增模块

```text
bin/autonomy.js
lib/autonomy/
  controller.js       # 运行循环、调度与停止
  state.js            # 任务、子问题、事件归约和恢复
  model.js            # 唯一模型网关、预算与调用记录
  tools.js            # 工具注册和 dispatcher
  facts.js            # 现有 FactsIndex 适配与一致性修补
  platform.js         # Windows 原生 argv/工具链；批准 Linux 例外时转换路径和校验能力
  knowledge.js        # 文档、概念、规范和发布
  retrieval.js        # 实体/关系检索、证据需求与 ContextPacket
  summaries.js        # 条件化答案、参数匹配与依赖复用
  discovery.js        # 候选发现、去重与覆盖抽样
  assessment.js       # 裁决校验与报告策略
  verification.js     # 隔离验证计划与 runner 接入
  store.js            # 内容寻址、原子提交、缓存和依赖索引
  report.js           # 单一 report-model 与渲染
  mcp.js              # 可选 adapter，最后实现
test/autonomy-*.test.js
test/fixtures/autonomy/
eval/autonomy/
```

模块按责任拆分，不为每个 record 或 tool 建空类。首版保留 CommonJS、Node 内置测试和现有运输层；不复制 AST 解析器。schema 校验优先复用已验证依赖，缺依赖时实现明确合同子集并验证，不能使用“字段存在”替代完整类型和状态检查。

公共事实修复仍放在现有拥有该逻辑的模块；新状态和语义放在新目录。不要把产品源码改动与工具实现混在同一提交。

### 19.2 命令集合

以下是完整目标 CLI 的规范；现有 `bin/autonomy.js` 仅实现其中部分命令及 MVP 语义（`verify` 仍为 blocked 占位），不能把表中未实现的合同视为当前可用。全部命令从工具目录执行，参数验证失败时不产生部分生产产物。

| 命令 | 必需输入 | 输出或行为 |
|---|---|---|
| `doctor` | `--scope` | 环境与能力报告，默认不联网 |
| `index` | `--snapshot --scope` | 新实体/关系/文档索引，保留已有事实 |
| `knowledge propose` | `--doc-set --scope --mode` | 规范提案与验证材料，不发布 |
| `knowledge publish` | `--proposal-set --approval-file` | 校验审批后发布不可变版本 |
| `run` | `--snapshot --scope --knowledge --budget --mode` | scope-only 发现、取证与报告 |
| `resume` | `--run --mode` | 校验固定输入后恢复；模式转换须显式策略允许 |
| `inspect` | `--run`，可选 `--task` | 只读查看问题、缺口和来源 |
| `verify` | `--run --plan --approval-file` | 经 capability 和隔离校验执行验证 |
| `report` | `--run` | 从已提交记录重建报告，不重新裁决 |
| `eval` | `--suite --mode --budget` | 冻结评估，不污染生产知识与缓存 |
| `check` | `--run` | schema、引用、版本、事件与报告完整性检查 |

配置文件采用 JSON。`--scope`、`--budget`、`--knowledge` 是文件路径或由配置明确解析的版本 ID，不接受模糊 latest 自动跨快照选择。CLI 保存解析后的绝对路径与内容哈希。

ID 解析只能通过受控 manifest/版本登记表进行，或解析为对应允许目录内的完整哈希位置；不得将用户传入的 ID 当路径。`--snapshot` 必须指向完整快照而非当前工作区别名，`--run` 必须对应唯一已登记运行。找不到或存在多个候选时返回配置错误，不猜最新记录。

### 19.3 开发完成后的调用示例

示例中的 `SNAPSHOT_ID`、文档集、审批文件和配置必须实际创建；命令实现前不能据此声称运行成功。

```powershell
node bin/autonomy.js doctor --scope=K/policies/autonomy-pilot-scope.json
node bin/autonomy.js index --snapshot=SNAPSHOT_ID --scope=K/policies/autonomy-pilot-scope.json
node bin/autonomy.js knowledge propose --doc-set=DOCSET_ID --scope=K/policies/autonomy-pilot-scope.json --mode=off
node bin/autonomy.js knowledge publish --proposal-set=PROPOSAL_SET --approval-file=APPROVAL_FILE
node bin/autonomy.js run --snapshot=SNAPSHOT_ID --scope=K/policies/autonomy-pilot-scope.json --knowledge=KNOWLEDGE_ID --budget=K/policies/autonomy-pilot-budget.json --mode=off
node bin/autonomy.js inspect --run=RUN_ID
node bin/autonomy.js check --run=RUN_ID
node bin/autonomy.js report --run=RUN_ID
```

`knowledge propose --mode=off` 仅提取结构声明和无需模型的提案，语义解释保持缺口。live 必须显式选择，并通过 data-policy、endpoint、密钥和预算检查；不提供 auto 模式。

退出码：0 表示请求的命令按合同完成；2 为参数或配置错误；3 为 check/eval 验收失败；4 为输入或能力前置条件不满足；5 为内部执行错误；6 为已保存检查点的预算停止；130 为已保存状态的用户取消。个别任务证据不足而 run 正常完成可以返回 0，但结果必须列出不足，不能用退出码表示“审计通过”。

## 20. 端到端执行样例

### 20.1 对象授权问题

以下使用虚构的 `UpdateObject` 接口和 `AuthorizeObject` 包装函数，不声称产品源码存在对应漏洞。目标是验证闭环，不是提供预置答案。

| 步骤 | 输入和执行者 | 必须产出的结果 | 后续动作 |
|---|---|---|---|
| 1 | 控制器只接收 scope、固定输入和预算 | 入口与操作概览、覆盖账本 | 创建发现任务，不预填漏洞 |
| 2 | LLM 读发现包 | 对象修改是否可能越权的提案、首步动作和反证方向 | 接纳具名任务 |
| 3 | inspectEntry、getApplicableNorms | 入口绑定、主体条件、授权要求、例外和未知字段 | 建身份、对象、检查效果子问题 |
| 4 | collectEvidence | 修改操作、调用关系和 AuthorizeObject 调用点 | 查询已有局部答案 |
| 5 | 派生答案匹配 | 该包装函数检查实参主体与对象，失败返回错误；调用者处理尚未知 | 不重复解释函数，检查调用者 |
| 6 | 工具分析错误路径与对象传递 | 失败分支和检查对象已定位，但实际修改经回调发生 | 生成 callback-target-unresolved |
| 7 | 控制器执行明确 nextAction | 注册点和候选回调；无法确定时列候选集合边界 | 消歧或请求语义分析 |
| 8 | LLM 解释新增证据 | 对象一致性局部答案，或发现异步身份/生命周期问题 | 继续当前命题或创建关联任务 |
| 9 | 反证配方 | 检索调用者检查、公开接口例外、代理授权和失败退出 | 保留支持与反对材料 |
| 10 | judge 与证据门 | 有范围的 supported/refuted，或具体 insufficient | 保存 Assessment，不直接发布 finding |
| 11 | 可选隔离验证 | 对关键未知或影响取得运行见证 | 更新证据并产生新的评估 |
| 12 | report | 问题卡、依据、限制、覆盖、成本与下一步 | 运行结束或调度关联任务 |

替代分支必须测试：权限检查针对服务自身而非调用者；检查后忽略错误；检查和修改针对不同对象；授权在调用者而非当前函数完成；接口具有明确公开例外；回调目标不可解析；文档版本冲突。

若已证明所有相关路径在当前模型内受到有效检查，可以反驳该越权命题。若只找到一个检查调用或单次实验正常，不能作同样结论。

### 20.2 跨问题方向与早期验证

调查授权时发现异步回调捕获裸指针，控制器保持授权任务不丢失，另建生命周期任务并共享对象、回调和注册证据。生命周期任务不要求先有权限结论，也不被固定类别入口阻止。

如果回调执行身份无法从静态材料确定，可以提前提出隔离观测计划；批准后将观察结果作为 runtime-witness，仅用于该环境和执行条件。若没有隔离能力，两个任务分别记录其未解条件，不能互相“借用”结论填空。

### 20.3 依赖变化与恢复

当 AuthorizeObject 定义、生成头、编译宏或适用规范改变：依赖索引标记相关摘要、工具结果与评估过期；已有报告保留原版本说明；新运行必须重新验证依赖或重算。不能因为函数名字没变继续使用旧答案。

崩溃发生在工具结果落盘后、completion 之前时，恢复先识别 orphan 和未完成 intent。普通只读查询可重做；若是远端模型请求，不能据没有 completion 直接假定没有计费。

## 21. 测试与效果评估

### 21.1 三套互相隔离的材料

| 材料 | 用途 | 初始规模与隔离 |
|---|---|---|
| 开发 fixtures | 合同、工具与控制器回归 | 至少 12 个小例：4 正、4 反、4 缺信息；不作效果证明 |
| 冻结 holdout | 检索、裁决与不足识别 | 试点至少 20 正、20 反、10 缺信息；不足则报告样本不足 |
| 无种子发现集 | 测候选提出而非已知问题复判 | 只给 scope、输入和预算，不给 claim、答案或漏洞函数清单 |

规模是扩面目标，不是最小静态闭环的配额，也不是统计充分性保证。Builder-LLM 可以构造、冻结并标注命题、适用规范、必要证据和关键反证；每条标 `labelSource=builder-llm-oracle`、模型/版本、输入哈希和样本类型。真实历史问题、修复前后、受控变异体及合成案例分别计数，不把 Builder 来源基准称为独立人工真值。

按修复家族、组件或时间划分开发与 holdout，不能将同一问题的轻微改写放在两边。评估标签和 oracle 上下文存放在 Agent 不可读取的评估器范围；清除专门提示答案的测试标签，不破坏真实代码语义。生产摘要、知识提案和缓存不得吸收 holdout 答案。

### 21.2 模块测试矩阵

| 测试文件 | 主要验收点 |
|---|---|
| `autonomy-contract.test.js` | schema、枚举、范围、引用、null/空/unknown 区别 |
| `autonomy-platform.test.js` | Windows 原生默认、无 WSL 时仍可运行、拒绝自动回退；Linux 例外的批准/argv/路径/超时/进程清理、空格、中文、junction 和 response file |
| `autonomy-facts.test.js` | 源文件漂移、同名符号、构建变体、坏 JSONL、UTF-8 跨块解码 |
| `autonomy-knowledge.test.js` | 规范原文、实体链接、例外、冲突、提案与发布权限 |
| `autonomy-summaries.test.js` | 实参对齐、前提未知、依赖失效、自证环、来源不升级 |
| `autonomy-retrieval.test.js` | 关键证据、低相似度反证、外围分支、分页与截断 |
| `autonomy-tools.test.js` | 局部答案、可执行缺口、配方限界、工具不隐藏模型调用 |
| `autonomy-discovery.test.js` | 无预置 claim、多个发现入口、去重不丢路径、探索预算 |
| `autonomy-controller.test.js` | 状态迁移、过期 Action、跨视图、分支、无进展和停止 |
| `autonomy-model.test.js` | off/mock/replay/live、缺密钥、取消、正文超时、usage 缺失、预算 |
| `autonomy-recovery.test.js` | intent/completion 崩溃点、尾记录、坏账本、orphan、锁和未知计费 |
| `autonomy-assessment.test.js` | 强否定门、模型判断不冒充证明、报告一致性 |
| `autonomy-holdout-eval.test.js` | Builder 来源标签隔离、按家族统计、重复样本与恒弃答排除；不宣称人工审核 |
| `autonomy-verification.test.js` | 早期补证、入口真实性、负对照、no-signal、runner 隔离 |
| `autonomy-security.test.js` | 文档注入、越界路径、compdb 插件、外发和日志脱敏 |
| `autonomy-mcp.test.js` | 可选阶段：本地与协议路径的业务和权限等价 |

修改公共 query 时运行其直接测试及受影响事实测试，不为了文档变化运行全仓或 live 审计。没有修改的逻辑不重复扩大测试；新失败和未决疑点除外。

### 21.3 必测扰动

1. 删除决定结论的授权文档、调用者检查或对象传递证据，系统应转为具体缺口，而非复述旧答案。
2. 将反证放在低词法相似度的调用者或文档例外中，检查能否召回并呈现。
3. 让调用链超过 hop 上限或存在未知虚调用、函数指针、回调，结果必须 unknown 而非 unreachable。
4. 修改源码、头文件、宏、规范或枚举集合，检查肯定和否定缓存的传递失效。
5. 在结果上限处截断、损坏中间 JSONL 行、切断中文 UTF-8 字节，检查不能静默少读。
6. 提供“检查存在但失败不退出”“主体错误”“对象错误”“检查后发生状态变化”的反例。
7. 注入要求扩权的文档文本、伪造 factRef 或旧 contextId，确认动作被拒绝。
8. 在付费请求发出后断开、在证据提交与事件提交间终止，确认恢复不重复计费或伪造完成。
9. 从权限问题转向生命周期，再返回原任务，确认共享证据但不混淆结论。
10. 验证 no-signal、超时、缺设备、function-only 与真实入口复现严格分开。
11. 抽样内部函数未见直接检查时不得成为入口 candidate；一跳唯一 callee 中有检查但对象/顺序未知时不得自动排除；歧义 callee 保持未知。

### 21.4 四组对照

| 组 | 输入机制 | 用于定位什么 |
|---|---|---|
| A | 原始源码/文档检索与相同模型 | 基础能力和成本基线 |
| B | A 加实体关系、问题级工具和反证检索 | 结构化上下文的收益 |
| C | B 加正式规范和条件化派生答案 | 领域知识与复用分析的增量收益 |
| D | 评估者提供经核实的充分上下文 | 将模型裁决问题与检索不足分开 |

A/B/C 使用相同任务、模型、输入版本和总预算，分别统计冷缓存与热缓存，并计入预处理摊销成本。D 是诊断上限，不参加自动发现成绩，也不能把人工整理成本隐藏为产品收益。

添加语义检索、第二模型、复杂摘要或新分析器前，都应解释哪个已观测失败会因此改善。不以索引规模、模型调用数量或找到单个问题作为架构有效的证据。

### 21.5 指标口径

| 指标 | 分母与含义 |
|---|---|
| discovery recall | 隐藏标注中可在授权范围内调查的问题，实际提出且匹配具体命题的比例 |
| candidate precision | 经核实的候选中具有真实问题依据的比例，缺信息与未核实单列 |
| candidate actionability | Builder 来源基准中具有入口/触发条件、具体操作和明确下一步的候选比例；分 `entry-scan` 与 `coverage-sample` 报告 |
| decisive evidence recall | 每个案例所需决定性证据进入有效上下文的比例，按子问题统计 |
| counterevidence recall | 标注反证/例外中被取得并呈现的比例 |
| judgment agreement with sufficient context | Builder 来源基准认定上下文足够案例的判断一致率；不等同独立人工正确率 |
| false certainty rate | 信息不足案例中输出不被证据支持的确定判断的比例，强否定单列 |
| abstention quality | insufficient 是否指出正确关键缺口及可执行动作或终止原因 |
| cost and latency | 每个问题、每个有效结论的请求、token、时间、重复读取与预处理成本 |
| traceability and consistency | 可回查引用、正确版本、事件/报告一致性的比例 |
| coverage | 组件、入口类型、操作、规范、未知边与未探索任务的实际覆盖 |

评估对象按命题分层：`binding`、`check-presence`、权限实参和操作目标等局部问题分别报去重 questionId 的 decisive/insufficient/unstable 数及分母。Builder 来源标签的效果只称 `agreementWithBuilderLabels`，记录生成者、模型家族、输入版本与冻结哈希，不声称独立人工正确率。`authorization-effect` 是任务级问题，缺入口、对象或规范适用时评价具名缺口；不得仅因无运行证据而恒弃答。Builder 与 Runtime 视野隔离降低直接答案泄漏，不能证明标签无误。

报告样本数、分模块结果和错误案例，不用总体平均掩盖某一方向失效。信息不足的正确弃答不能算安全反例；只复核已产出候选不能估计漏报。历史 `eval/autonomy/labels.json` 仍为 pending，不报告精度或召回。Builder 基准从小样本起步，先对 run 做 `check`，按家族区分开发/盲测并标明生产、变异或合成来源；不足时显示实际分母和 `insufficient-sample`，不造 20/20/10 标签。四组对照未做时标 `not-run`。

### 21.6 发布门槛

硬门在冻结验收集上要求：越权执行 0、跨版本引用 0、缺关键证据仍强否定 0、无引用的确定裁决 0、模拟输出混入生产 0；全部 unknown 有 reasonCode 和 nextAction 或 terminalReason；事件与证据一致性检查通过。观察到 0 不代表全程序无错误，必须同时记录样本量。

试点效果目标为 Builder 来源基准上的候选精度不低于 0.80、无种子发现召回不低于 0.50，且错误确定率不劣于 A 组。这些是待验证的诊断目标，不是对生产真实漏洞率的估计；改变阈值须记录理由。

只有在硬门通过且效果/成本存在可解释收益时扩大组件或问题方向。若充分上下文下仍主要判错，优先调整模型使用或判断方法，不继续堆索引掩盖瓶颈。

## 22. 分阶段实施与切换

### 22.1 实施顺序

M0-M5 是静态主流程的验收阶段，M6 为可选扩展，不等同于已有 MVP 的 P0-P8；已有固定三问闭环不能自动视为 M4 自主闭环通过。顺序用于开发，不要求真实任务照阶段重复运行。先做一个组件、一个授权问题的完整纵向流程，再扩大覆盖。

| 阶段 | 最小交付 | 依赖 | 退出条件 |
|---|---|---|---|
| M0 输入与合同 | doctor、RunContext、公共 schema、facts adapter、Windows 原生执行门、稳定引用和错误语义 | 现有事实和小 fixture | 漂移、坏输入、同名、跨块 UTF-8、越界和无 WSL 测试通过 |
| M1 取证底座 | 精确实体、关系索引、inspectEntry、getEvidence、覆盖账本 | M0 | 不混实体与版本，分页/歧义/不支持均显式 |
| M2 领域知识 | 小文档集、实体链接、Builder-LLM 来源审批与发布、general/authorization 视图 | M1 | 适用/例外/冲突样例通过，Runtime-LLM 不自批准 |
| M3 问题级答案 | inspectAuthorization、需求图、ContextPacket、条件摘要和反证配方 | M1、M2 | 一次调用能回答局部问题或给明确下一步；错误主体/对象不误判 |
| M4 自主闭环 | discovery、队列、控制器、off/mock/replay、事件与报告 | M3 | 不给 claim 可起步，覆盖抽样不污染入口 candidate，跨方向继续、分支共享和正确停止 |
| M5 小规模 live | 开源非 pro 模型能力确认、预算/外发门、Builder 来源冻结评估与四组对照 | M4、冻结评估集 | 静态发现、误报/漏报与成本实测，失败原因可归因 |
| M6 可选验证与扩展 | 隔离 runner、第二问题视图、按需精确分析、可选 MCP | M5 | 启用时有正反例、权限和回归证据；未启用不阻断静态闭环 |

M0-M4 只做完成纵向流程所需的最小覆盖，不建设全量规则库或全部高级分析器。第一条闭环用 mock/replay 验证协议，但不能据此声称真实模型审计有效。M5 不承诺必须发现新的生产漏洞。

### 22.2 每阶段的交付记录

每阶段提交实现文件、schema 与工具注册、最小正反和缺信息样例、可执行检查命令、实际测试结果、输入指纹、已知限制和剩余工作。未运行的命令标 not-run；环境失败标 blocked，不写 PASS。

若代码偏离本文，先明确偏离属于实现缺陷、规范缺口还是合理变更，不能在注释或其他文档中悄悄建立第二套合同。

### 22.3 与既有实现共存

首版通过独立 `bin/autonomy.js` 和新产物目录运行，不改变 `bin/agent.js` 的既有默认行为。已有事实只读复用；旧候选、tier、prover 结果和 live 调用只能作为显式标记的对照输入，不能直接成为新事实或缺口填充值。

确需兼容旧报告时增加命名 adapter，声明它支持的命题、前提和字段映射。旧 S/T/O 编号不是新系统的内部状态；无明确映射的情况保留 unknown 或独立结果，不能把自由文本“支持”直接映射为旧 confirmed。

### 22.4 切换条件与回退

切换默认入口前必须同时具备：M5 的 Builder 来源评估及局限记录、真实 off/replay/live 模式隔离、scope-only 轨迹、缓存失效和恢复轨迹、旧接口必要回归、报告可回查，以及明确的回退配置。两例同家族一致不能满足这一条件。

切换通过受控配置和用户决定完成，不因新增命令而自动迁移。回退只改变入口路由，保留两套不可变运行产物，不删除旧文件、不逆写产品源码。旧架构说明作为历史记录保留，但不得重新成为新开发的规范来源。

## 23. 完成定义与验收清单

系统开发完成必须展示以下真实记录，文档齐全或 schema 校验通过本身不算完成：

- [ ] 只给 scope、版本、能力和预算，创建至少一条可审查问题；最终允许被反驳。
- [ ] 一条问题级工具直接返回有依据局部答案，并实际避免重复分析的轨迹。
- [ ] 一条不能回答的问题返回具体 missing、下一步或终止原因。
- [ ] 一条跨视图继续调查并创建关联任务、复用证据而不混淆结论的轨迹。
- [ ] 一条主动发现反证或规范例外，从而改变初始判断的轨迹。
- [ ] 一次源码、编译条件或规范变化导致依赖摘要和否定缓存失效的记录。
- [ ] 一次崩溃恢复以及远端结果不明时未自动重复付费请求的记录。
- [ ] 固定验收集上强否定、权限、版本、模拟隔离和日志安全门通过。
- [ ] 四组对照、冷/热缓存和必要预处理成本报告，含失败案例和覆盖限制。
- [ ] 至少一个真实或明确标记的受控变异体产生可复算 Static Finding；真实目标不按预设答案强行升级；所有发现标 `static-only`，不伪装为动态验证。
- [ ] Builder-LLM 审批规范、样本及标签显式打标来源；评估报告给出实际分母、样本类型及未做的对照，不宣称独立人工准确率。
- [ ] 若启用 WSL、runner 或 MCP，提供其专属能力与边界测试；未启用则明确标记。
- [ ] 所有常规工具调用有 Windows 原生执行记录；Linux 例外均有逐次批准、必要性、工具链匹配和资源界限，不存在自动回退。

最终交付包包含本文版本、源代码与测试版本、固定配置、输入清单、正式知识版本、运行事件、证据、上下文、调用账本、评估记录、报告和校验和。密钥、未授权源码和临时探针不得进入交付包。

## 24. 术语与首轮开发清单

### 24.1 术语

| 术语 | 本文含义 |
|---|---|
| fact | 特定输入中观察到的事实，不自动包含安全语义 |
| norm | 有出处、适用前提和例外的要求 |
| derived answer | 对具体局部命题的条件化答案，保留分析来源和依赖 |
| evidence demand graph | 为当前问题组织的子问题及其证据依赖 |
| ContextPacket | 本轮模型实际可见的任务、规则、证据、反证和缺口 |
| recipe | 预登记、有界、可检查的取证步骤 DAG |
| model-assessment | 模型对证据的解释，不是机械证明 |
| proof-within-model | 在明确模型和前提内可检查的证明，不是全系统保证 |
| runtime-witness | 特定环境和输入下观察到的运行行为 |
| missing | 阻碍当前问题判断的具体缺口及其解决或终止方式 |
| sufficient-for-claim | 对当前命题和结论强度足够的工程判断，不是普遍完备性 |
| finding | 满足发布策略的正式发现，不等同任意静态可疑点 |

### 24.2 实现者第一轮工作

1. 核对工作区、Node 依赖、Windows 原生工具链和实际权限；只读记录可用能力。WSL 仅在拟申请具体例外时检查。
2. 选择一个组件，以少量源码、IDL 和文档建立固定 fixture，不先运行全仓 live。
3. 完成 RunContext、Task、Question、Missing、ToolResult、ContextPacket 和 Assessment 的 schema。
4. 修复新闭环依赖的快照、解码、实体身份和错误语义，跑最小直接测试。
5. 实现一条 inspectEntry -> getApplicableNorms -> collectEvidence -> interpret/judge 流程。
6. 加入条件摘要复用、反证检索、自主问题提出、任务分支和停止策略。
7. 用独立样本决定下一步补检索、规范、分析器还是模型使用方法，不按模块数量判断进度。

### 24.3 已有 MVP 的下一轮优先级

1. `origin` 分离、一跳委托和显式 `operation-unbound` 缺口已在 opt-in 实验中实现；保留真实入口的主体、具体操作、规范适用性和受保护操作证据绑定为下一步，不把缺口压制当发现成功。
2. 为一个真实 IDL 方法建立经校核的入口到操作绑定及主体/对象约束，再用冻结的反例和受控正例验证 candidate 门是否既能拒错又能放行；不要根据词表或单个调用宣布安全。
3. 人工标注入口与非入口、已发出与未发出候选、委托正反例，分别评估可行动性、误报与漏报；无标注不宣称 precision/recall。正式 holdout 仍按 `21 的至少 20 正、20 反、10 缺信息执行，不拿小实验替代。
4. 在 Windows 原生路径测量真实工具和 live 请求的分布，再调整预算或引入新分析器。Linux 只按第 4.3 节的个别例外流程执行；已有旧 CLI 的 `auto` 模式不进入新架构默认链。

### 24.4 现有 MVP 的授权最小实验（2026-10-22）

范围固定为 `sandbox_manager-pilot`、事实快照 `sha256:2142c229d142bdacc472969fe96d73a36da4554f3775dee4f710b79878997a1e`、Windows Node 25.2.1、`mode=off`。运行 `node bin/autonomy.js run --experiment=authorization-v1 --mode=off --scope=K/policies/autonomy-pilot-scope.json --budget=K/policies/autonomy-pilot-budget.json --max-tasks=0`，再按返回的 runId 执行 `check --run=<id>` 与 `report --run=<id>`。实验不能用于 `live` 或 `mock`，没有自动 Linux 回退。旧 `RUN:9b1bdf44daebe542` 仍按 `1.0.0-mvp` 规则复算通过，不重新裁决或覆盖。

最终 run `RUN:29898a9ac486f1f4`：19 入口（17 IDL、2 SA）加 5 个覆盖抽样，24 任务、72 问题、94 工具结果（比旧版多 2 次一跳工具）、0 模型请求、运行器计时 415 ms；`check` 为 0 errors / 0 warnings。报告 0 candidate、24 observation、0 finding；19 个 `operation-unbound`、2 个 `delegated-check-unproven`、24 个 `dominance-unproven`，语义哈希 `sha256:3aa83ee447556d9ba725f640174f7eca22838c0b01aaecdfd5afcc1a692ad6cc`。这些缺口按任务计数，不能相加当任务数。全量 `node --test` 为 285/285 通过（本机沙箱 Git ownership 需仅对测试进程设置 `GIT_CONFIG_COUNT=1`、`GIT_CONFIG_KEY_0=safe.directory`、`GIT_CONFIG_VALUE_0=*`）；`node bin/agent.js gates --strict` 为 70/70。普通运行不改变全局 Git 配置。

旧 7 条 candidate 的可行动性复核：`PolicyInfoParcel::Marshalling`、`GetTokenId`、`PolicyTrie::Clear`、`MacAdapter::MacAdapter`、`GetPartitionRemainSize` 五项都是 `coverage-sample` 函数，而非入口操作；`SetPolicyAsync` 和 `UnSetPolicyAsync` 两项为真实 IDL 入口，但精确一跳调用分别到 `SandboxManagerService::SetPolicy`（源码 382 行）和 `UnSetPolicy`（417 行），两者源码内均出现以调用方 token 为参数的 `CheckPermission`。工具只观察调用边与检查调用，不证明入口到服务端的完整路径、检查支配关系、对象一致性或失败处理。旧候选缺少可行动命题，不可据此计算 precision；新 run 的 7→0 更不能叫精度提升。

本实验只验证 `origin` 分流、一跳反证、缺口与报告复算的**局部工程机制**。在该次运行时，Task schema 尚无 `operationRef`，所有入口都缺具体操作；有操作的 candidate 分支只有受控单测覆盖，没有真实正例、冻结人工标签、独立反例/缺信息集或 live 请求。该次运行既不能计算召回，也不能验证 M2 知识发布、M3 条件答案复用、M4 自主 Action 分支/恢复和 M5 独立效果评估。后续增量实验见第 24.5 节；正式验收仍遵守第 21-23 节的规模与门槛。

### 24.5 Windows 原生纵向增量实验与阶段判定（2026-10-22）

在第 24.4 节的 MVP 上，以 opt-in `vertical-v1` 固定 `SetPolicyAsync` 一条 IDL 入口和同一 AG0 快照，接入源码/README 原文锚定的授权规范**提案**、精确一跳委托、问题级条件摘要、模型提出的受限 `inspectDelegation` Action、局部裁决，以及从 `Unmarshalling` 名称线索提出的 `input-boundary` 子任务。子任务对解析目标只取得 type hint，保持 `insufficient`。提案不能由模型发布；`SetPolicy` README 规则也不自动适用于 `SetPolicyAsync`。程序的证据门不会因模型意见把 name-only 操作边升级为确定目标。

固定 live run 为 `RUN:4792cd3d41b052b3`，`snapshotId=sha256:2142c229d142bdacc472969fe96d73a36da4554f3775dee4f710b79878997a1e`，模型 `cn:glm-5.3-flash`，Windows Node 25.2.1。2 task、5 question、8 tool、2 次模型请求（输入 1375、输出 294 token），约 11.2 秒；1 observation、1 excluded、0 candidate、0 finding。`report` 的语义哈希为 `sha256:fddb0be7a90bc439901abc5736f01a1f34466d670eecbe333a252a7a9fa15eb1`；`check` 为 0 error / 0 warning。7 个缺口类别包含规范适用性未批准、操作目标未证明、解析调用目标未证明和验证不可用，不能把“没发出 candidate”计为精度或召回收益。产物在 `out/autonomy/RUN-4792cd3d41b052b3/`，包含上下文、Assessment、摘要、Action、事件、调用账本、报告及校验和。工具调用只在 Windows 原生执行，未使用 Linux/WSL；模型 HTTP 网关是已配置的外部服务，不是 Linux 工具执行。

开发诊断 `out/autonomy/diagnostic/1792652540274-90982f41.json` 的 A/B/C/D 在同模型、同 maxTokens 下，对“局部源码中 calling-token 检查与提前返回是否出现在设置调用点之前”均返回有引用的 `supported`。B/C 未观察到相对 A 的判断增益；D 是程序整理的上下文，**不是独立 oracle**。该命题不涵盖完整 IPC 可达性、操作对象一致性、规范适用性或漏洞结论；单一正向局部命题不能代替第 21 节冻结 holdout 和无种子发现评估。

发送前的付费请求 intent 已入账；Windows 子进程崩溃测试在 intent 后终止，`recover` 返回 `remote-outcome-unknown`、`autoResend=false`。live run 的 `recover` 显示 2 组 `reserved → ok`、无 pending，且自身发起 0 次模型请求。这里的 `recover` 是**只读对账**，不是恢复队列继续运行。`verify` 对匹配 run 的计划 `K/verification/sandbox-setpolicy-input-plan.json` 返回 `blocked`、`entryFaithfulness=unknown`、`executedCommands=[]`；不绑定的计划返回参数错误 2、无事件写入。计划仅检查形状与 task/question 归属，不证明 sourceRefs 语义、审批或隔离能力；无批准的 Windows 隔离 runner/harness 时不得用普通子进程冒充沙箱，也不得自动改用 Linux。

受限 `replay` 从上述 live run 的已归档解析结果重建 `RUN:220aedf4208f1c68`：2 task、5 question、8 tool、2 次重放模型结果、**0 次远端请求**，约 75 ms；报告语义哈希与 live 完全一致，`check` 为 0 error / 0 warning。新 run 在 manifest/事件和模型调用中绑定源 run、校验和及源 callId；请求正文哈希、task、context 或知识/快照/scope 不匹配时拒绝重放，源产物漂移也拒绝。原始模型文本未归档，因此这只是**解析结果重放**，不验证供应商原始响应、不同模型的可重复性或崩溃后的继续执行；不能把它写成完整的 `resume`。

| 阶段 | 本次实际证据 | 尚未满足的退出条件 |
|---|---|---|
| M0-M1 | doctor、快照哈希检查、实体绑定/关系、取证与记录复算的正反单测 | 完整构建变体、精确路径和所有公共错误边界仍非全域验证 |
| M2 | README/头文件提案、适用性未知、测试签名的不可变发布与消费见 24.7 | 没有实际独立审核签署、正式知识版本或冲突集验收 |
| M3 | 局部工具回答、摘要依赖指纹命中/失效、反证一跳；错误目标仍不足 | 没有对象一致性和跨入口/操作链的确定证明 |
| M4 | off/mock/live、解析结果 replay、受限模型 Action、跨视图子任务、事件与报告；任务边界 off/replay 原 run 续跑见 24.6 | 任意中途 action、live 远端结果不明的安全恢复，以及多方向无进展停止轨迹尚未完整实测 |
| M5 | 两次真实 live 请求、A/B/C/D 开发诊断、成本与失败账本 | 20 正/20 反/10 缺信息的独立人工 holdout、无种子发现集与正式效果门未具备 |
| M6 | 计划绑定/拒绝和阻断记录；Windows 原生隔离能力实测见 24.7，无命令执行 | 隔离 runner、正反与负对照、三次重复、入口真实性及设备见证均未具备 |

定向 replay、崩溃恢复和验证测试通过；全量 `node --test` 的 303/303 项通过。首次全量运行被测试自动发现误启动的常驻崩溃探针卡住，已将探针移到 `tools/fixtures/`，保留由父测试启动/终止的崩溃轨迹，复跑全量通过。`node bin/agent.js gates --strict` 为 70/70；其显示的 `tests: 150/150` 来自既存汇总，**不是**本次 303 项全量测试。测试进程仅临时设置 `GIT_CONFIG_*` 绕过沙箱目录所有权检查，不更改全局 Git 配置。以上结果证明了一个从 scope 到具名 `blocked` 验证和报告的**可运行纵向样本**，不证明 M0-M6 的总体效果验收或完成定义第 23 节的全部清单。

评审建议中已采纳入口/抽样分流、一跳委托反证、具名不足与人工标签前不报精度；进一步保留小文档集和按需模型语义判读，而非扩建全量知识库。评审提出“先砍 knowledge publish、完整恢复、验证”只适用于早期 MVP 裁剪：本规范最终验收仍需要受控发布、恢复和隔离验证，不能把它们永久取消。下一轮应由独立审核者签署规范与冻结正反/缺信息样本，并提供可核验的 Windows 隔离能力；然后运行正式 A/B/C/D、负对照和正反验证，扩展中途 action 恢复与跨视图停止轨迹，再决定是否扩大范围或切换入口。没有这些外部条件，不应为追求“全绿”而放宽 finding 或平台隔离门槛。

### 24.6 Windows 任务边界恢复增量实验（2026-10-22）

`resume --run --scope --budget --mode=off|replay` 是当前 `vertical-v1` 的**受限**续跑入口；不是第 19 节完整目标 `resume` 合同。新 run 的 manifest 固定 scope、预算、快照、知识、模型和模式指纹；checkpoint 记录 `throughSeq`、累计活动 wall time、任务进度及预算。提交顺序改为先持久化 `task-finished` 事件、后原子更新 checkpoint。续跑必须位于一个已完成任务之后、下一任务尚未启动的边界，并验证连续事件、任务归约、已归档证据哈希和预算计数。单写者锁包含 runId、PID、随机 nonce 和启动时间；原进程仍存在时拒绝接管，原进程终止后把旧锁保留为审计痕迹再独占新锁。锁文件不参与产物校验和。

Windows 子进程在首任务 checkpoint 后受控退出 71。off run `RUN:a49563e90d8de937` 在**同一 run**继续排队的 `input-boundary` 任务：2 task、5 question、8 tool、0 模型请求，报告语义哈希仍为 `sha256:fddb0be7a90bc439901abc5736f01a1f34466d670eecbe333a252a7a9fa15eb1`，`check` 为 0 error / 0 warning。replay run `RUN:2c6cc3fe30425cb6` 从相同 live 源恢复：2 个已归档模型结果、0 远端请求、8 tool，同一哈希，`check` 也是 0 error / 0 warning。错误预算、仍在运行的原写者、被篡改的 evidence 分别在追加事件前拒绝；崩溃测试与两项负例见 `test/autonomy-resume.test.js`。累计活动 wall time 在续跑前后不倒退。全量 Windows Node 测试 305/305、旧系统 gate 70/70；gate 的 `tests: 150/150` 仍是旧汇总，不是本次全量数。

这只能证明**已提交任务边界**的 off/replay 续跑及拒绝条件；任务中途工具 intent、尾部半条事件、旧 run 无指纹 checkpoint、付费请求结果不明、规范发布和验证副作用都不能自动续跑。live `recover` 仍是只读对账，`remote-outcome-unknown` 不重发。当前没有经独立评估的候选精度/召回，也没有 Windows 隔离 runner；M5、M6 不能因恢复轨迹变绿。

### 24.7 受控知识发布与 Windows 隔离能力核查（2026-10-22）

最小 `knowledge propose/publish` 现只支持 `sandbox-manager-pilot` 的 `SetPolicy` 授权声明。真实源码/README 提案为 `NORM:298088535ea57095`、`sha256:d75afb38c14221f293d38d3fd164119452842c7719b445883af78b79e6a3abd2`，保留在 `out/autonomy/knowledge/proposals/`，状态仍为 `proposed`。`publish` 必须重新提取当前快照并与提案逐字段比对，核验 Ed25519 签名、公钥指纹、审核范围和适用实体，按知识版本在 `K/norms/` 只写一次。CLI 拒绝把工作区内公钥当作发布信任锚；私钥不能交给 Agent。运行时若显式指定正式知识版本，也重新验签和核对源码；`SetPolicy` 被接纳后，`SetPolicyAsync` 依旧 `unknown`，不能凭一跳委托自动扩面。

`test/autonomy-knowledge-publish.test.js` 使用临时测试密钥验证发布幂等、伪造审核、提案漂移、信任锚位置拒绝以及 off 纵向 run 消费已发布版本，随后清理测试审核和版本。**这是发布机制的模拟正例，不是独立人工审核。** 本工作区当前没有真实审核签名，也没有正式 `K/norms/` 版本；因此生产纵向 run 仍使用提案，不将其升级为正式裁决规范。M2 的效果门尚缺适用、例外、冲突和缺信息的独立样例。

只读 Windows 功能查询（未启用或安装功能）确认 `Containers-DisposableClientVM=Disabled`、`Containers=Disabled`、`Microsoft-Hyper-V-All=Disabled`、`VirtualMachinePlatform=Enabled`。`WindowsSandbox.exe` 不存在；SDK 提供 `hdc.exe`，但没有据此认定测试设备已授权或可用。单有虚拟机平台不等于存在受控 Windows 隔离镜像、资源/网络限制和登记 runner。当前 `verify` 保持 `blocked` 与 `executedCommands=[]`，没有自动 Linux 回退。若将来配置 Windows 原生隔离 runner，必须先按第 16 节验证其能力和批准，再运行三次重复、负对照、无 signal 判据及入口真实性测试；不能仅把子进程命名为 `host-isolated`。

全量 `node --test` 为 306/306；`node bin/agent.js gates --strict` 为 70/70（其 150 tests 是旧汇总）。M5 的至少 20 正、20 反、10 缺信息独立人工 holdout 与无种子发现集仍不存在；因此这轮只加强了 M2 发布协议和 M6 阻断归因，不改变总体有效性结论。

### 24.8 独立评估入口的实际阻断（2026-10-22）

新增 `tools/autonomy-holdout-eval.js`，只在评估进程读取 `eval/autonomy/labels.json` 和已通过 `check` 的运行记录；支持多个 run，拒绝重复 run、重复问题、引用不匹配和用 `binding/check-presence/dominance` 简单题凑数。标签不传给 Agent、不写入 run。冻结标签必须带审核人与时间、案例家族/来源、实质命题和具体 question/entry/run 标识；这些是可检查的输入约束，**不是独立人工审核的证明**。即使 20 正、20 反、10 缺信息齐备，脚本也只给有标签子问题的 judgmentAccuracy 和 falseCertaintyRate 计数，候选精度、发现召回、四组对照及发布门保持未评估，避免以局部准确率替代完整效果。

Windows 原生复算命令：在工具目录运行 `node tools/autonomy-holdout-eval.js --run=RUN:4792cd3d41b052b3 --run=RUN:220aedf4208f1c68`。这两条既有 live/replay run 经逐一 `check` 后，真实标签数为 supported/refuted/insufficient = 0/0/0，最低缺口为 20/20/10；输出 `status=insufficient-sample`，全部效果指标为 null，`releaseGate=not-evaluated`。live/replay 是同一问题，不能重复充当独立样本。针对测试构造的 20/20/10 只验证评估程序统计和拒绝逻辑，不是 OpenHarmony 审计成绩。全量 Windows Node 测试 310/310；旧系统 gate 70/70（其 150 tests 是旧汇总）。未运行新的付费请求，也没有 Linux 工具调用。

因此本轮增加了可复算的 M5 样本不足判据，但不改变最终验收：M2 缺独立知识审核及适用/例外样例，M4 缺任意中途 action 恢复和充分跨方向停止记录，M5 缺冻结独立 holdout、无种子发现集和正式 A/B/C/D，M6 缺获批 Windows 隔离 runner 的真实正反验证。下一步先由**独立于 Agent 的审核者**固定样本与规范并登记来源/划分，再扩大真实运行；同时提供经核验的 Windows 原生隔离能力。不能用测试密钥、合成标签或未隔离子进程宣称完成。

### 24.9 正式规范消费边界复核（2026-10-22）

复核发现旧实现的 `run --knowledge-review` 可从签名审核文件直接生成运行时 `accepted` 知识，绕过 `knowledge publish` 的不可变版本落地；这违反第 10 节的发布/消费分离。现已拒绝该参数，运行时只接受显式 `--knowledge=<K/norms/版本/knowledge.json>`，且仍逐次核验签名、原文和快照。外部审核本身仍需真实人员和受控私钥，测试签名不得当成正式审核。公钥的“工作区外”判断改为检查真实路径，防止工作区内文件借 Windows 链接路径伪装为外部信任锚。直接旁路、链接路径、正常发布与已发布版本消费有定向回归；这只修复 M2 信任边界，不补足独立审核、适用/例外/冲突样本或最终效果门。

### 24.10 Windows 工具动作中断识别（2026-10-22）

新 run 在 manifest 标记 `toolTraceVersion=1`，每次工具调用前记录不含原始参数的 `tool-intent`（工具名、子问题、参数哈希），归档结果后记录引用 intent 与结果 ID 的 `tool-completed`。`check` 对新 run 核对完成事件和工具结果，任务边界 `resume` 再核对完成事件与工具账本；伪造结果引用在追加新事件前被拒绝。旧 run 不追认原本没有的工具意图：`recover` 将其标为 `toolTraceStatus=not-recorded`、`pendingTools=null`，不是“已确认无挂起工具”。

Windows 子进程在首个工具 intent 提交后、执行前受控退出 71。只读 `recover` 返回一个 pending tool、一个 running task、`autoRerunTools=false`，退出码 3；在**本节当时的实现**中 `resume` 拒绝，事件数不变，后续受限续跑见第 24.11 节。完整 off run `RUN:2ec90e5d8e7952ae` 为 2 task、5 question、8 tool、0 模型请求、8 对工具事件、77 ms；`check` 为 0 error / 0 warning，`recover` 为无挂起，报告语义哈希仍为 `sha256:fddb0be7a90bc439901abc5736f01a1f34466d670eecbe333a252a7a9fa15eb1`。既有 live run `RUN:4792cd3d41b052b3` 复查仍通过，工具轨迹明确标为 not-recorded。全量 Windows Node 测试 314/314、旧 gate 70/70（其 150 tests 是旧汇总）；未执行 Linux 或新的付费请求。

这证明工具动作意图的持久登记、已提交完成的对账与**中途不盲目重放**，不证明任意中途 action 的继续执行。当前恢复仍只支持已提交任务边界的 off/replay；工具已执行但结果尚未提交、半条事件和 live 远端结果不明仍需人工对账或专门的安全恢复协议。M4 与第 23 节的完整恢复条件保持未通过，M5/M6 的独立效果与隔离验证也不受本实验影响。

### 24.11 原 run 首个只读工具意图的受限续跑（2026-10-22）

在第 24.10 节的“只识别中断”上，增加严格的 `vertical-v1 / off` 首个 `inspectEntry` intent 恢复：必须尚无 checkpoint、模型请求、工具结果/账本、证据和纵向分析产物；事件恰为 run 创建、任务入队、任务启动、首个工具 intent，序号和 actionId 连续；scope、快照、预算、知识与模式指纹不变；初始 task/question 必须与当前固定输入重新生成的计划逐字段相同。续跑独占旧锁，在同一 run 记录 `run-resumed(resumeKind=first-tool-intent)`，复用已提交 intent 后执行只读工具，不重复写入 intent 或 task-started。已执行但结果未提交的工具、第二个或后续 action、回放模型调用、live 未知远端结果及验证副作用均不在此恢复范围；遇到这些状态继续阻断。

Windows 受控中断后，`RUN:9085788a8af58d20` 的 `recover` 先记录一个挂起只读工具、一个 running task、无 checkpoint；显式 `resume --mode=off` 后为 2 task、5 question、8 tool、0 模型请求，首任务只启动一次，8 对 intent/completion，无重复 intent。`check` 0 error / 0 warning，语义哈希 `sha256:fddb0be7a90bc439901abc5736f01a1f34466d670eecbe333a252a7a9fa15eb1` 与干净 off run 一致。intent 参数、未提交账本和初始 task 篡改均在追加事件前拒绝。全量 Windows Node 测试 315/315，旧 gate 70/70（其 150 tests 为旧汇总）；没有 Linux 或新付费请求。

这验证了一个真实任务中途点的**受限续跑可行性**，但不是第 17 节对任意 action、orphan、尾部半条事件和付费结果未知的完整恢复协议。M4 退出条件仍未满足；独立 M5 效果、真实 M2 审核和 Windows 隔离 M6 也保持未通过。

### 24.12 M5 样本供给与判断能力的内部阻断（2026-10-22）

上一轮只把 M5 归因为缺少独立标注和正式四组对照，**不完整**。代码核实显示 `vertical-v1` 固定一条 `SetPolicyAsync` 入口；`vertical.gateInterpretation` 对正常模型判断最后只给 `insufficient`，反向冲突给 `conflict`；控制器又将 `authorization-effect` 的 Assessment 固定写成 `insufficient`。因此这版纵向流程即使拿到人工 20 正/20 反/10 缺信息，也不能产生足以评价正反判断的多样化实质问题，更不可能凭当前结果达到第 21.6 节的效果目标。重复 live/replay/off 不是独立案例。

对现存 8 条 `1.0.5-vertical-experiment` run 逐条读取 question 与 Assessment：它们共享同一个 `Q:95f6769b1b7cc81f`，8/8 为 `insufficient`。独立评估器对四条经 `check` 的 run（`RUN:4792cd3d41b052b3`、`RUN:220aedf4208f1c68`、`RUN:2ec90e5d8e7952ae`、`RUN:9085788a8af58d20`）返回 `substantiveRecords=4`、`distinctQuestions=1`、四次 `insufficient`、标签 0/0/0、`insufficient-sample`，所有效果指标 null。全量 Windows Node 测试 316/316、旧 gate 70/70；此诊断无新模型请求或 Linux 工具调用。

下一步先扩展**实现能力**：从固定单入口切换到有来源的多入口/操作命题，保留入口真实性和规范适用范围；为独立正、反、缺信息案例提供能区分证据充分性的裁决，不放宽强否定、主体/对象和验证门。然后由独立审核者冻结按家族隔离的 holdout 与无种子发现集，运行正式 A/B/C/D 与冷/热成本；Windows 原生隔离 runner 仍需单独获批并实测。没有这些实现与外部条件，M5/M6 都不能验收，不能靠增加重复请求或伪造标签凑数。

### 24.13 Windows live 复测、恢复指纹与验证附注回归（2026-10-22）

用户级环境变量在本次执行进程中为空，但供应商手册约定的用户目录密钥文件存在。仅在 Windows Node 子进程内注入密钥，不记录或复制密钥；本机 `http://127.0.0.1:7864/v1` 返回 200，配置模型 `cn:step-5-preview` 存在，chat probe 返回 200。`check-provider.js` 仍因模型目录缺 `supported-endpoints` 元数据返回 1（`supported-endpoints-absent`），不能写成供应商体检全绿，也不是鉴权失败。新 live `RUN:976611974f27852e` 实际发送 2 次请求，模型账本均为 `reserved -> ok`，消耗 1453 input / 1054 output tokens，活动 wall time 26468 ms；8 次 Windows 原生只读取证工具，2 task、5 question、0 finding，`check` 无错误。模型对局部调用顺序给出 `supported` 意见，但受控门因异步规范适用性未知、操作目标仅 name-only 而保持 `authorization-effect=insufficient`。新 off `RUN:ca5c441b1208376d` 0 模型请求、78 ms，报告语义哈希与 live 一致。此处没有运行 Linux/WSL 工具。

恢复预检增加 `bin/autonomy.js`、`lib/autonomy/*.js` 和自治 schema 的实现指纹，新 run 写入 manifest 与 `resumeFingerprint`；任务边界和首个工具 intent 的模拟指纹漂移都在写入新事件前被拒绝，正常续跑仍由既有正例覆盖。旧 run 没有实现指纹时仅按旧合同读取，不得追认这一保证；指纹也不覆盖全部跨目录依赖，不能宣称任意代码变更都可识别。

跨阶段实测暴露 replay 缺陷：先生成的 `RUN:14d245a81fc9187c` 在 live 源 run 执行 `verify` 后，因源 manifest、events、verification 附注改写完整 `checksums.json`，`check` 报 `replay-source-invalid`。已对**新 replay** 固定源文件摘要（排除这三种可追加验证附注；其余归档仍逐文件校验）；从已 verify 的源 run 新建 `RUN:27970c4274c7ebca` 后，`check` 0 error / 0 warning，报告语义哈希仍为 `sha256:fddb0be7a90bc439901abc5736f01a1f34466d670eecbe333a252a7a9fa15eb1`，远端请求 0。旧 replay 保持原完整校验和合同，不迁移、不静默放宽；其失效记录保留作为回归证据。`verify` 仍只登记 `blocked`、`executedCommands=[]`，不构成隔离验证。

独立评估器检查新 off/live/修复后的 replay，得到 3 条实质记录但只有 1 个不同问题、3 次 `insufficient`；冻结标签 0/0/0，`releaseGate=not-evaluated`。这再次确认内部固定单入口和恒不足的授权效果裁决是 M5 的**实现阻断**，不是多付费调用可弥补。全量 Windows Node 测试在测试子进程临时配置 Git `safe.directory` 后为 317/317，旧 gate 70/70（其 150 tests 是旧汇总）；不配置时历史 patch fixture 因沙箱 Git 所有权而失败，不是这次代码回归。

本轮对总体验收的判定不变：M0/M1/M3 的局部协议可运行；M2 仅测试密钥模拟发布而无独立规范审核；M4 仅两种受限中断点；M5 缺多入口/可区分的实质裁决、冻结的独立 20/20/10 holdout、无种子发现集和正式 A/B/C/D；M6 缺获批的 Windows 隔离 runner 与正反见证。下一步先扩展有来源的多入口/操作命题与可区分裁决，并补完整安全恢复；再由独立审核者冻结规范和样本，提供具能力界限的 Windows runner 后执行正式对照与验证。不能由 Agent 自己签署审核、制造 holdout 标签或以普通 Windows 子进程冒充隔离验证，也不因这些前置条件缺失而自动回退 Linux。

### 24.14 第二入口的最小纵向扩展与效果判定（2026-10-22）

新增 opt-in `vertical-v2`，在保持 `vertical-v1` 历史 run 合同的同时，允许分别选择真实 IDL `SetPolicyAsync` 和 `UnSetPolicyAsync`。后者的授权规范提案来自同组件 `README_zh.md:23` 对“除 SetPolicy、CheckPersistPolicy 外其余接口”的 `ohos.permission.FILE_ACCESS_PERSIST` 原文，并核对 `sandbox_manager_const.h` 中的权限常量；`UnSetPolicyAsync -> UnSetPolicy` 的一跳调用目标为 exact，`CheckPermission` 调用可定位，但下游策略变更调用目标仍为 name-only，异步入口上的规范适用性仍需独立审核。该提案**没有**获得发布签名；运行时拒绝对该第二规范使用现有仅限 SetPolicy 的 `--knowledge` 发布通道，不能把“原文涉及其余接口”直接升为已批准的异步规则。run schema、工具观察、模型上下文、回放、复算和受限恢复接受新的 `1.0.6-vertical-experiment` 版本；没有扩大为任意入口或完整语义证明。

Windows 原生新 off `RUN:79887e02bb6425d6`：1 task、4 question、7 tool、0 模型请求、90 ms，`check` 0 error / 0 warning；第二入口的效果问题 `Q:b1753db52e17ebc1` 不等于原入口 `Q:95f6769b1b7cc81f`。真实 live `RUN:ce49f02d7cf21a00` 使用 `cn:step-5-preview` 两次请求，模型账本完整，1254 input / 1069 output tokens，活动 wall time 29921 ms，`check` 无错误；模型意见 `supported` 仅限局部检查先于调用的观察，程序仍给 `authorization-effect=insufficient`、0 finding。replay `RUN:d66c08144c91d554` 为 0 次远端请求、76 ms，报告语义哈希与新 off/live 均为 `sha256:07c502c6b5c36bb07697628aa1d6b35f99ebe9cb18a64ca2f62ce2a3bcefdb0b`。新 live 源 run 后续登记验证占位时，replay 再次 `check` 仍无错误。
Windows 子进程退出码 71 分别中断 v2 首个工具 intent 和任务已提交边界；同一 run 续跑后只有一次 task-started、7 对工具事件且语义哈希与干净 off run 相同。这仅覆盖这两个受限恢复点。

将旧 SetPolicy 输入计划绑定到第二 run 被 `verification-plan-task-or-question-unbound` 拒绝；新计划 `K/verification/sandbox-unsetpolicy-plan.json` 绑定真实第二问题，但因没有获批 Windows 隔离 runner/harness，只返回 `blocked`、`executedCommands=[]`，入口真实性未知。独立评估器读取两条不同入口的已校验 live run，仅得到 `substantiveRecords=2`、`distinctQuestions=2`、两次 `insufficient`、独立标签 0/0/0，所有效果指标仍为 null，`releaseGate=not-evaluated`。另修正零操作调用点被 `every()` 误算成已解析的边界，并用缺调用点样例验证为 false。全量 Windows Node 测试 321/321，既有 gate 70/70（其中展示的 150 tests 为旧汇总）；没有 Linux/WSL 工具调用。

这轮证明**多入口规范来源、独立问题身份和保守门控**可行，不证明第 21.6 节精度/召回目标。内部能力仍需扩展到有来源的更多操作、精确操作目标及对象/失败路径分析，并能在证据足够的正反案例上输出可区分裁决；不能通过增加同家族改写或放松 `gateInterpretation` 来凑 20/20/10。M2 仍缺第二规范的独立受控审核，M4 任意动作恢复未通过，M5 独立冻结 holdout 与正式四组对照未通过，M6 隔离执行未通过。进入正式评估前必须由 Agent 外部审核者固定适用/例外/反例与隔离样本，并提供获批且可核验的 Windows 原生隔离执行能力。

### 24.15 权限参数局部反证与纵向复验（2026-10-22）

工具还检查知识的 appliesTo 覆盖实际委托方法；跨方法误传规范必须返回 insufficient，而非制造 refuted。该边界有交叉知识测试。

在双入口 vertical-v2 上新增 permission-argument-match 子问题和只读 inspectPermissionArgument 工具。它要求 IDL 入口、唯一精确一跳委托、已校验源码/头文件、唯一权限检查调用与可解析的常量声明；条件不满足返回 insufficient。该工具只比较有来源的文档权限名和 CheckPermission 实参，不判定异步规范适用、授权效果、对象、失败路径或漏洞。新 run 的架构版本为 1.0.7-vertical-experiment；报告模型仅从已提交 Assessment 取局部裁决，主裁决独立保持 insufficient。check 复算问题、Assessment、工具观察、分析 sidecar 和报告行；篡改 sidecar 的权限值被拒绝。正、反、不足、源码漂移和受限中断续跑定向测试通过，旧 1.0.5/1.0.6 run 不回填新子问题。

Windows 原生实验：SetPolicyAsync 的 off/live/replay 分别为 RUN:a8ece1856027e2a9、RUN:95597561fb3f51f6、RUN:194cd41343aa8d4c；局部比较 supported（实参和文档均为 ohos.permission.SET_SANDBOX_POLICY），主裁决 insufficient、0 finding，三模式报告语义哈希均为 sha256:cb4a34a61f9f6e7d6fe37ea6e83f3e8cd7aecff73de795a7e2aafda98bc78e9a。UnSetPolicyAsync 的 off/live/replay 分别为 RUN:d5191d85daa9b3e1、RUN:02d76907f6dcae81、RUN:fa1708ba968d1934；局部比较 refuted：sandbox_manager_service.cpp:421 使用 SET_POLICY_PERMISSION_NAME（ohos.permission.SET_SANDBOX_POLICY），README_zh.md:23 所引权限为 ohos.permission.FILE_ACCESS_PERSIST；主裁决仍 insufficient、0 finding，三模式哈希均为 sha256:cac1e4c089f407e7e0099adae9f8f396641f4e50052843f8181280472e7d6284。每条 live 各两次真实请求（活动 wall time 88441/27522 ms），replay 各零次远端请求；六条 run 的 check 均为零错误、零警告。

live 密钥只从 Windows 宿主 User 环境临时注入子进程，未写入产物；两条验证计划均返回 blocked、executedCommands=[]，没有 Linux/WSL 调用。SetPolicy 的 vertical-interpret 响应 finishReason=length、4096 completion tokens，虽解析出局部意见，不能视为完整的模型完成证据；后续应把截断当模型意见不足并作版本化复算，不悄悄改写历史 run。全量 Windows Node 测试在测试子进程临时放行嵌套 Git 所有权后 322/322，旧 gate 70/70；未放行时历史 patch fixtures 的 pre-missing 是环境失败。新局部子问题不在仅统计 authorization-effect 的独立评估器效果分母；两个新 live run 只有两个不同实质问题、两次 insufficient、冻结标签 0/0/0，准确率、候选精度、发现召回和 A/B/C/D 均为 null，releaseGate=not-evaluated。

这验证了 Windows 原生的任务、局部正反取证、裁决、报告复算、live/replay 协议；**未完成 M0-M6 的完整验收**。M0/M1/M3 只有局部覆盖；M2 缺外部独立规范审核及适用/例外/冲突样例；M4 仅有受限恢复点；M5 缺独立冻结的 20/20/10、无种子发现集、实质可区分裁决和正式四组对照；M6 缺获批可核验的 Windows 隔离 runner 与真实正反见证。下一步必须由外部审核者先固定规范、标签和样本划分，并补精确操作/对象/失败路径分析、安全恢复和具隔离能力的 Windows runner；不可用同家族改写、自签标签或普通子进程凑验收，也不得自动回退 Linux。

### 24.16 第二轮评审核查与 1.0.8 复验（2026-10-22）

`REVIEW-ITERATION-2.md` §7.0 三项前置已逐项核查，取舍及原始统计见 `ITERATION-2-PREFLIGHT.md`。采纳静态 candidate 与 finding 分离；将带来源锚定的模型规范提案、盲标模型一致性诊断列为后续开发实验，**目前并未实现**。不采纳删除 M6/正式 finding 验收，也不以模型自签规范或同源模型标签取代外部审核。理由是前者直接缩小用户要求的 M0–M6 完整目标，后两者只能检验模型彼此一致，不能核实适用/例外或发现漏报。`verify` 仍为 `blocked`、`executedCommands=[]`；这不是 M6 已通过。将来模型生成的规范提案也只能保持 `proposed`，正式知识发布仍要求独立签名审核。未取得足够独立正反/缺信息案例时，不生成虚假的 10/10/5 或 20/20/10 验收集。

出口规则消融在旧 `RUN:29898a9ac486f1f4` 上只读复算：24 task 原为 0 candidate；仅按入口绑定且 `check-presence=refuted` 得到 2 个候选，但均为已观察到一跳委托检查的异步包装，且均缺 `operationRef`。保留操作绑定条件仍为 0。故不把增加 candidate 数作为效果提升，不以未知支配关系直接否定候选，也不在委托/操作缺口尚存时放松出口。后续应先提出可回查的具体操作和完整反证，再由独立样本检验 actionability。

`vertical-v2` 的新运行版本 `1.0.8-vertical-experiment` 将 `finishReason != stop` 的 live 响应记为 `model-response-incomplete`：保留用量与内容哈希，解析意见不可用于裁决或新版 replay；旧版本产物按原规则只读复算，不改写历史。Windows 原生 SetPolicyAsync 的 off/live/replay 为 `RUN:d8f1b4ea089a95e1` / `RUN:ec1d97bbbad4357f` / `RUN:68faefb84998e48b`；UnSetPolicyAsync 为 `RUN:d47e5ff3483e172f` / `RUN:2ae3c4b987b761fe` / `RUN:fa2f430c24d7cd07`。两条 live 各 2 次真实请求，四次均 `stop`；两条 replay 均 0 次远端请求、语义哈希分别与对应 off/live 一致，新版六条 `check` 无错误。旧 SetPolicy live `RUN:95597561fb3f51f6` 的截断响应已实测不能作新版 replay 源。模型使用同一 catalog ID `cn:glm-5.3-flash`，未以改模型掩盖对照；live 活动请求用时约 14.7/10.9 秒，不外推 P95 成本。

Windows 原生执行门现由 CLI、doctor、工具 dispatcher 共同拒绝非 `win32`，模拟 WSL 测试验证在读取事实或耗用预算前失败；未调用 Linux 工具，也没有自动回退。全量 Windows `node --test` 为 326/326，通过测试进程局部 `GIT_CONFIG_*` 放行嵌套 Git fixture 所有权；旧 `gates --strict` 为 70/70，其内置 150 项是旧产品基线，不能称新测试总数。两个新版 live 的只读评估：`permission-argument-match` 去重 2 问（一 supported、一 refuted），`binding` 2/2 supported，`check-presence` 2/2 refuted；`authorization-effect` 2/2 insufficient、`dominance` 2/2 insufficient。正式标签 0/0/0，效果指标全为 null，`releaseGate=not-evaluated`。局部 decisive rate 是覆盖诊断，不是准确率或漏洞发现能力证明。

评审建议的五个模型节点不能用强制增加调用数来验收“自主”：当前发现和摘要是确定性，单一 Action 的 plan 还不足以证明缺口驱动的多轮重规划；`extract-norm` 与坏 JSON 修复应在有独立门控及预算账本后作单独负面测试。M0/M1/M3 已有局部工程证据，但未覆盖全部扰动；M2 缺第二条正式规范及适用/例外独立审核；M4 缺无预置 claim 的受控多分支行动和任意动作安全恢复；M5 缺冻结独立 holdout、无种子发现和正式 A/B/C/D；M6 缺获批 Windows 隔离 runner 与真实正反见证。因此本轮仍**不是 M0–M6 的完整有效性验收**。下一次进入效果评估前，先提供独立审核的多家族案例和具有精确目标/对象/失败路径证据的操作绑定；隔离执行仍须单独批准，不借用普通子进程或 WSL 冒充。

### 24.17 有来源的操作候选与版本隔离（2026-10-22）

在 `vertical-v2` 的 `1.0.9-vertical-experiment` 中，限定为经 AG0 哈希校验的 `SandboxManagerService::{SetPolicy,UnSetPolicy}` 源码行、唯一同命名空间 `PolicyInfoManager` 生产函数且参数个数一致时，生成 `status=suspect` 的操作候选。候选记录调用 factRef、目标函数 factRef、源码行与两侧文件哈希；歧义目标或漂移文件不给候选。AG0 调用边仍为 `name-only`/partial parse，因此候选**不是** `operationRef`，`operationTargetResolved=false`、`operation-target-unproven` 与 `operation-unbound` 缺口保留，不能提升 candidate 或授权效果裁决。问题级条件摘要将候选纳入依赖指纹；报告显示候选及其 suspect 等级；新版本 `check` 交叉检查分析 sidecar、纵向上下文源码文本、归档函数/文件/调用事实和仍未解析的调用边。旧版本 `check` 不重算该字段。

Windows 原生 SetPolicyAsync 新版 off `RUN:94755e7b7546e61e`、基于已校验 1.0.8 live 的 replay `RUN:198750ed0b232051`；UnSetPolicyAsync 新版 off `RUN:db9ce5dd45350421`、replay `RUN:a977cf79f8e2dc45`。四条 run 的 `check` 均为 0 error / 0 warning，两个 replay 均为 0 远端请求；各入口 off/replay 与旧版报告语义哈希相同，均 0 candidate、0 finding。SetPolicy 操作候选指向 `policy_info_manager.cpp:516`，UnSetPolicy 指向该文件 561 行；这只是源码限定的可审查下一跳。歧义、目标源码漂移和候选篡改定向测试通过；全量 `node --test` 327/327，旧 gate 70/70。未再次请求 live，不能把旧 replay 当成本轮新模型能力实验。

操作候选让下一步精确解析有了目标，但未证明接收者绑定、重载、构建变体、入口可达路径、对象和失败路径；正式 `operation-unbound` 率尚未下降。M2/M4/M5/M6 的独立审核、动态规划、冻结评估与 Windows 隔离验证仍按第 22-23 节待完成，不以这次局部补证替代完整纵向验收。

### 24.18 缺口驱动的受限第二 Action 与失败复算（2026-10-22）

`vertical-v2` 从 `1.0.10-vertical-experiment` 起在一跳委托和源码窗口取得后，由模型从程序按当前上下文生成的 `inspectPermissionArgument(entryRef)` 与 `getEvidence(唯一 suspect 目标文件/行, 12 行)` 中选**一个**；同时校验 taskId、revision、contextId 和完整工具参数。off 确定性选择前者。目标补证不会顺带执行权限核对，未选择的权限子问题保持 `insufficient`，操作目标也仍是 `suspect`。计划、工具 intent/completion、模型调用及选择结果进入账本；`check` 对侧记录、归档模型响应、工具和问题状态复算。模型的选择只影响下一步取证，不能发布规范、提高来源等级或给出任务级漏洞结论。它仍不是开放任务空间中的多轮自主控制器。

Windows 原生的 1.0.10 UnSetPolicyAsync live `RUN:8bff1bd0ada1123f` 实际选择 `getEvidence(policy_info_manager.cpp:561)`，3 次模型请求均 `stop`，未调用 `inspectPermissionArgument`，该局部问题为 insufficient；replay `RUN:d77eb1c15c1fcef2` 为 0 远端请求且报告语义哈希一致。同期 SetPolicyAsync live `RUN:4d4eae5bd933b2b2` 首次模型请求 `transport-error` 暴露旧后备分支仍执行了未选择的权限工具；此 run **无效**，保留作失败证据。修复后 `check` 对它输出 `vertical-early-stop-mismatch` 和 `permission-argument-mismatch`，不再崩溃，也不把它算入效果集。注入传输错误的完整 CLI 回归验证：新 run 早停、未执行权限工具、`check` 可复算。修正后的新 run 使用 `1.0.11-vertical-experiment`，历史产物不重写。

1.0.11 的 SetPolicyAsync live/replay 为 `RUN:9387d4a906229765` / `RUN:e33f895a18a55e59`，UnSetPolicyAsync 为 `RUN:18e805c979bea9a2` / `RUN:2f038cc1dc9bb790`。两条 live 均选择权限实参工具，各 3 次真实 `stop` 响应，活动 wall time 约 15.7/20.9 秒；两条 replay 各 0 远端请求，四条 run 的 `check` 均为零错误、零警告，报告哈希各自与原 off 结果一致。局部权限比较仍一 supported、一 refuted；两个 `authorization-effect` 均 insufficient、0 candidate、0 finding。独立评估入口给出 `insufficient-sample`、正式标签 0/0/0、`releaseGate=not-evaluated`，准确率、候选精度、发现召回和正式四组对照仍为 null。模型选择分支的变化不代表判断正确性或行动收益；两入口和三次请求不是成本 P95。所有常规工具在 Windows 原生执行，密钥仅临时注入子进程。

本轮推进了 M4 的一个可审查动态选择和失败路径，但还缺基于新缺口的多轮重规划、任意动作安全恢复及无种子发现；M2 的独立规范审核、M5 的多家族冻结评估与 M6 的隔离 runner 仍未通过。下一轮要以独立案例检验行动选择是否减少关键缺口，而非按模型请求数或候选条数宣布有效。

### 24.19 第二轮评审前置建议的再验证与第二规范发布链（2026-10-22）

重新核查 `REVIEW-ITERATION-2.md` §7.0 三件事并保持第 22-23 节的完整目标。第一项采纳为**当前静态试验边界**：`FINDINGS.md` 仍为空且说明原因，`verify` 返回 `blocked`、`executedCommands=[]`；不删除正式 finding/M6 验收。理由是用户要求的 M0-M6 完整纵向流程包含隔离验证，删除 M6 只能改变目标，不能证明目标可行。普通 Windows 子进程和 WSL 都不能冒充获批隔离 runner。

第二项采纳来源锚定、不同规范分离、发布与运行时重抽取；不采纳“AI 生成即可免人工审核发布”。字面权限句可确定性提取，增加生成模型调用不提高适用性可靠性；模型即使与运行模型不同，仍不能自行决定例外和异步适用性。现在 `knowledge propose --norm=UnSetPolicy --doc-set=sandbox-manager-pilot` 在 Windows 原生产出 `NORM:aa1295d063607f4d`、提案版本 `sha256:7b3da1d13142fa1ff4a34bba99d6cf5a463d798fd885b3cce52bb825f50615ff`，来源为 README 第 23 行及头文件哈希；`SetPolicy` 旧提案不变。第二规范已接通外部 Ed25519 签名审核、不可变发布、运行时重抽取与入口/规范匹配；测试用临时密钥证明错误签名、错误适用目标、源文漂移和错误入口均被拒。测试签名随后清理，**没有正式外部审核或第二条 accepted 知识版本**，`UnSetPolicyAsync` 仍为 `unknown`，M2 不能据此通过。模型提出新语义规范仍只能处于 `proposed`。

第三项的盲标、标注模型与运行模型分离、生成参数和冻结哈希可用于将来的**模型一致性诊断**，但拒绝用它代替正式人工 holdout。既有两条 1.0.11 live run 的只读评估显示 `binding`、`check-presence` 和 `permission-argument-match` 各 2/2 局部可判定，`dominance` 与 `authorization-effect` 各 0/2；正式标签仍 0/0/0，`judgmentAccuracy`、`candidatePrecision`、`discoveryRecall` 均为 null，`releaseGate=not-evaluated`。这是同一组件两个委托入口，不足以构成独立的 10 正/10 反/5 缺信息样本；为凑配额重复 run、同家族改写或让模型编造标签会污染效果测量。因此未生成虚假的冻结集，也不把这些局部决定率称为准确率。评审的“presence refuted 直接成为 candidate”仍受真实入口、具体 `operationRef` 和委托反证约束；旧 run 的只读消融见 §24.16，放宽后出现的两个无操作绑定委托包装不是可行动候选。

验证：定向知识/纵向测试 18/18；全量 Windows 原生 `node --test` 330/330（仅测试进程设置嵌套 Git 的 `safe.directory`）；最后增加错误入口与发布时原文漂移断言后，发布链定向测试 2/2。没有修改产品源码或调用 Linux。供应商宿主探针确认用户级密钥存在、网关鉴权和 chat probe HTTP 200，但因 catalog 缺 endpoint 元数据返回非零；本轮未把探针当作新 live 审计或模型盲标证据。M4 多轮重规划、M5 独立多家族效果集及 A/B/C/D、M6 获批 Windows 隔离与正反见证仍未完成，故本轮不是完整有效性验收。

### 24.20 Builder 来源静态权限契约试点（2026-10-23）

本节按 §0 的新目标记录，不回写旧 run。`K/reviews/sandbox-*-builder.json` 明示 Builder-LLM 来源、异步适用性理由和需后续调优；`knowledge publish` 产出两条不可变 accepted 规范，运行时对 README/头文件、提案版本和审核记录重新核对。旧 Ed25519 人工签名版本仍可读，但不是本轮门槛。Builder 审批不是独立人工确认，文档“其余接口”对 `UnSetPolicy` 的适用解释仍是明确的项目静态前提。

`lib/autonomy/static-proof.js` 只处理两条 IDL 异步委托入口：要求唯一精确委托、已发布适用规范、带限定符的单一操作候选、已核实的权限常量、`GetCallingTokenID` 主体与 `if (!CheckPermission(...)) return PERMISSION_DENIED` 的直线局部早退。它不把一般 name-only 调用当全局精确边，不证明编译变体、任意别名/虚调用、设备可利用性或整体授权安全。早退不符、提案规范、错误委托或权限参数未取到时返回具名 insufficient。运行版 `1.0.14-static-experiment` 把限定命题的裁决放进 `report-model`，`check` 从固定快照与发布知识重新计算证明；`verificationStatus=static-only`，动态 `verify` 继续可选。

Windows 原生 off 试验：`SetPolicyAsync` 为 `RUN:c8f7bcf459912b89`，1 个权限契约 `excluded`、1 个输入解析 observation；`UnSetPolicyAsync` 为 `RUN:a4112fde24b81541`，1 个 **Static Finding**：README 的 `FILE_ACCESS_PERSIST` 与委托后服务端 `SET_SANDBOX_POLICY` 检查不一致。两条 `check` 都是 0 errors / 0 warnings；全量 `node --test` 337/337 通过（嵌套 Git fixture 仅在测试进程设置 `safe.directory`）。两例同属于一组件/家族，不应把 `excluded` 解读成函数整体安全，也不把 finding 解读成权限提升已复现。

`tools/autonomy-static-eval.js` 读取显式 `builder-llm-oracle` 标注并先做 `check`：2/2 标签一致、1/1 Builder 标签下的 finding precision；只有 1 个家族，`independentAccuracy` 与 `discoveryRecall=null`，A/B/C/D=`not-run`。这仅是开发诊断，不是独立效果验收。Command Code Windows 原生供应商探针：catalog HTTP 200、默认 `deepseek/deepseek-v4.1-flash` 存在、无源码的 chat probe HTTP 200；密钥从本机文件临时注入子进程，未写入仓库。此前因外发范围未获许可而停止真实 live 请求；获得本次仅限 `sandbox_manager` 单入口源码上下文、最多 4 次请求的明确许可后，运行 `UnSetPolicyAsync` live `RUN:aee4f309acaa80e7`：4 次模型请求均归档为 `ok` / `finishReason=stop`，9 次 Windows 原生工具调用，1 个有界 Static Finding。`check` 复算 1 task、5 question、9 tool result、5 assessment、1 report row，0 error / 0 warning。模型请求数和响应成功只证明调用链执行，不证明 finding 正确；静态证明仍由固定快照、已发布 Builder 规范与源码复算约束。

从该 live run 重放 `RUN:6f5c3205df8b544e`：4 个归档解析结果、**0 次远端请求**、9 次 Windows 原生工具调用，93 ms，1 个同一 Static Finding；`check` 同样为 0 error / 0 warning。live、replay 与 off `RUN:a4112fde24b81541` 的报告语义哈希均为 `sha256:810c5af4b1dd129204a3b774b318440c9fbf1fa0bd12c8bb42d1500a7258f112`。这是相同输入的确定性重放，不是独立样本、原始供应商响应重演、模型可靠性或发现能力评估。19 入口覆盖、更多独立家族与变异体盲测、四组对照及完整 Runtime-LLM 调查闭环仍未完成；不能据此宣称 M0-M5 全部有效性验收。

### 24.21 范围发现与规范驱动的静态证明连接（2026-10-23）

不提供 `--task` / claim 的通用 off 范围扫描 `RUN:4256644d08100e4b`，从同一固定快照发现 19 个入口（17 IDL、2 SA）与 5 个覆盖抽样锚点，完成 24 task、72 question、92 次 Windows 原生工具调用、0 模型请求；报告为 7 candidate、17 observation、0 finding，`check` 为 0 error / 0 warning。两个异步入口在这条旧通用路径里仍只是直接校验词表下的 candidate；其中 5/7 candidate 来自覆盖抽样或非 IDL 函数，不能作为入口漏洞计数。旧报告的“没有 runtime witness 就不产 finding”措辞仅反映通用历史出口，**不适用于**本规范已批准的有界静态 finding。需要继续把正式静态出口接到多入口调度，不能以这条范围扫描宣称 M4/M5 已完成。

`vertical-v2` 现在允许省略 `--task`，但必须提供已发布的 `--knowledge`；只在 scope 的真实 IDL 锚点中选择与规范 `appliesTo` 匹配的唯一受支持异步入口。无匹配或多匹配拒绝，不猜测或扩充规范适用性；显式任务路径保持不变，筛选先于 `--max-tasks` 截断。Windows 原生无任务 off `RUN:a8723ed00e663fab` 经 UnSetPolicy 已发布规范选中 `TASK:ce534608cd00a85c`，9 tool、0 模型请求、1 Static Finding；无任务 replay `RUN:a839400fdec5008e` 复用既有 live 的 4 个归档模型结果，9 tool、**0 远端请求**、1 Static Finding。两者与显式任务 live/off 的语义哈希均为 `sha256:810c5af4b1dd129204a3b774b318440c9fbf1fa0bd12c8bb42d1500a7258f112`。另一条已发布 SetPolicy 规范的无任务 off `RUN:f447a56966cfb24e` 选择 `SetPolicyAsync`，9 tool、0 模型请求，限定契约命题为 1 excluded、0 finding；不代表函数整体安全。三条新 run 逐一 `check` 均 0 error / 0 warning；定向纵向与静态测试 18/18，全量 Windows 原生测试 338/338（仅对测试进程设置嵌套 Git 的 `safe.directory=*`，未写全局配置）。这验证规范驱动的**单入口**选择，不是 Runtime-LLM 无种子提出多个问题、开放任务调度、跨家族盲测或四组对照；两入口仍属同一权限契约家族。M4/M5 仍未验收。

新通用范围扫描使用独立版本 `1.0.15-static-scan`：仅对真实 `entry-scan` 且唯一绑定、直接校验未命中的入口做精确一跳补证；被调函数中观察到校验或枚举不完整时，入口仅保留 observation 和具名缺口。`coverage-sample` 内部函数不升级为入口 candidate。扫描没有适用的已发布规范时不产 Static Finding，报告须说明这一点，而不能再以“没有 runtime witness”为拒绝静态结论的理由。旧版本运行按原报告语义只读复算，不回写历史。

实测新通用 off `RUN:66910fec73000320`：同样 19 入口、5 个覆盖抽样、24 task、72 question，94 次 Windows 原生工具调用（较旧 run 多 2 次一跳补证）、0 模型请求；0 candidate、24 observation、0 finding。两个异步委托的直接检查未命中被 `delegated-check-unproven` 反证，非入口的覆盖抽样不再占 candidate；19 个入口仍有 `operation-unbound`，因此 0 candidate 不能解释为没有风险。新旧 run 各自的 `check` 均 0 error / 0 warning，定向测试 29/29；更新旧出口断言后全量 Windows 原生测试 339/339（测试进程临时设置嵌套 Git 的 `safe.directory=*`）。通用扫描尚未按多条已发布规范自主构造和完成任务级静态命题，必须继续连接知识、调度与效果评估。

下一轮通用扫描版本 `1.0.16-static-scan` 对唯一绑定的 IDL 入口增设只读操作候选查询：仅在固定快照的服务函数行出现同命名空间 `PolicyInfoManager::GetInstance().Method(...)`、参数数目一致、唯一生产定义且源/目标文件均经哈希核对时，返回 `suspect` 与调用点、目标、文件哈希。精确一跳异步委托可复用同一限定查询。此结果使 `operation-unbound` 转为 `operation-target-unproven`，**不生成 resolved `operationRef`**、不单独产生 candidate/finding；入口源码截断/漂移给具名不足，目标歧义或目标文件漂移当前合并为未绑定，尚不能区分其具体原因。工具结果进入 Windows 原生账本及 `check` 复算，旧版本不迁移。

Windows 原生 off `RUN:6c978126744791ee`：19 个入口、5 个抽样锚点、24 task、72 question、111 tool、0 模型请求；17 个 IDL 入口收到局部操作查询，其中 16 个返回单一 `suspect` 目标（含两条精确委托后的操作），余下一条未绑定。报告为 0 candidate / 24 observation / 0 finding，缺口中 `operation-target-unproven=16`、`operation-unbound=3`（含两条 SA 元数据入口）；不能将 16/17 当作精确调用目标解析率或漏洞发现率。新 run 与上一版 `RUN:66910fec73000320` 均 `check` 0 error / 0 warning；定向测试 50/50，全量 Windows 原生测试 341/341（仅测试进程临时设置嵌套 Git 的 `safe.directory=*`）。多规范任务级裁决、独立样本和四组对照仍未实现。

本文的最终约束是：每个确定判断有可审查依据，每个未知都有具体含义，每次工具或模型调用都推进问题或合理停止；任何层都不能把缺少证据转写成证据。
