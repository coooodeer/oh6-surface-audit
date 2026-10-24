# oh6-surface-audit

OpenHarmony 6.0 静态自主审计实验。**唯一开发规范**是 [AGENT-ARCHITECTURE-GUIDE.md](AG-EXECUTION/AGENT-ARCHITECTURE-GUIDE.md)；实现状态和未验收项以该文档第 3、24 节及实际 run、测试为准。本文只提供当前命令入口，既存扫描链路的设计不构成新 Agent 的开发合同。

当前目标是静态审计完整闭环：有界证据充分时最高出口为 `finding`，`verificationStatus: "static-only"`；`verify` 是可选占位。Builder-LLM 规范、变异体和标签可以支撑实验，但须明确其来源，Builder 标签不等于独立人工真值。常规工具在 Windows 原生环境运行；Linux/WSL 仅用于逐次批准的必要例外。既存事实快照由新 Agent **只读消费**，无需读取其他设计文档。

## 当前入口

在本目录的 Windows PowerShell 中运行：

```powershell
node bin/autonomy.js doctor --scope=K/policies/autonomy-pilot-scope.json
node bin/autonomy.js index --snapshot=latest --scope=K/policies/autonomy-pilot-scope.json
node bin/autonomy.js run --mode=off --scope=K/policies/autonomy-pilot-scope.json --budget=K/policies/autonomy-pilot-budget.json --max-tasks=0 --knowledge=K/norms/050e10d78c6e93541813beb477a3c1000cbfd46817a5bf8fbf7bc5dc21b7572c/knowledge.json,K/norms/7b1ad465ab401111ad3bfa060d31e4e790e390ad3c6f68d7b30b74ee09fd215f/knowledge.json
node bin/autonomy.js check --run=<runId>
node bin/autonomy.js report --run=<runId>
node tools/autonomy-static-eval.js --suite-run=<runId>
node --test
```

`run` 输出实际 run ID；`--knowledge` 的两条已发布规范用于 `sandbox_manager-pilot` 的多入口静态扫描。`off` 不发模型请求；需要真实 live 时使用下方供应商入口，`replay` 只读取已归档的有效模型响应。运行结果保存在 `out/autonomy/RUN-*`，受控变异体及 Builder 标签在 `test/fixtures/autonomy/mutants/` 和 `eval/autonomy/static-builder-mutants.json`，不混入生产统计。历史 MVP 的原始运行数据见 [AUTONOMY-RESULT.md](AG-EXECUTION/AUTONOMY-RESULT.md)，不能用其旧出口规则覆盖现行规则。

默认 `node --test` 运行当前自治 Agent 与通用事实层测试（§24.26 本轮 207/207）；旧独立实验流程的测试已退役，其历史门禁结果仍保存在原 `out/` 归档中，不计入当前 Agent 的测试成绩。

## 模型供应商设置（Windows）

自治 Agent 的默认配置和 HTTP 传输均位于本项目：`config/autonomy-llm.json` 与 `lib/autonomy/http.js`。首次 profile 从本项目默认配置创建；选择 profile 后，直接运行 `bin/autonomy.js` 与 doctor 都读取 `runtime/autonomy-model/active.json`，可用 `OH6_AUTONOMY_LLM_CONFIG` 显式覆盖。以下为本轮完成全范围 live 的 Command Code 模型示例：

```powershell
pwsh -NoProfile -File tools/autonomy-model.ps1 configure `
  --name=commandcode `
  --base-url=https://api.commandcode.ai/provider/v1 `
  --model=xiaomi/mimo-v2.6-pro `
  --response-format=json_schema `
  --timeout-ms=120000 `
  --max-tokens=32768 `
  --headers-json='{"x-cmd-zdr":"1"}'

pwsh -NoProfile -File tools/autonomy-model.ps1 set-key
pwsh -NoProfile -File tools/autonomy-model.ps1 show
pwsh -NoProfile -File tools/autonomy-model.ps1 validate-key
pwsh -NoProfile -File tools/autonomy-model.ps1 probe
pwsh -NoProfile -File tools/autonomy-model.ps1 run --max-tasks=3 --max-model-requests=3
pwsh -NoProfile -File tools/autonomy-model.ps1 eval
```

`set-key` 交互输入一次密钥；`probe` 发一条真实短请求，`run` 先探针再审计。默认 3 个任务，`--max-tasks=0` 扫全量；单次审计 run 最多 30 次模型请求，前置探针另计。新增供应商用 `configure --name=<name> --base-url=<url> --model=<模型ID>` 后单独 `set-key`，用 `use --name=<name>` 切换；不限制开源或 Pro，但每次比较必须记录实际型号。可选 `--response-format=json_schema|json_object|none`、`--timeout-ms`、`--max-tokens`、`--headers-json`、`--request-extra-json`；`remove-key` 删除当前供应商密钥。

`eval` 是后续效果评估，不阻塞本阶段最小静态闭环；它对五个隔离的 Builder 标注变异体运行同一模型的 A/B/C/D 输入对照，最多 20 次请求，另有一次探针。逐次请求意图和结果写入 `out/autonomy/eval/model-abcd-*.jsonl`，完整批次汇总写入同名 JSON；失败和无效 verdict 在 `runtime/autonomy-model/history.jsonl` 留痕，不以部分成功或确定性消融结果代替模型对照。全组件离线评测使用 `node tools/autonomy-static-eval.js --suite-run=<runId> --write`；其中 `givenMutantFindingRecall` 是已给定受控样本的命中率，`discoveryRecall` 未评估。本轮真实 live `RUN:b4421b4481c6c171` 和零请求 replay `RUN:d3e0fe758fefca62` 均通过 `check` 且语义哈希相同；模型对照因传输超时延期，详见指南 §24.27。

密钥明文保存在 Git 忽略的 `runtime/autonomy-model/keys/<provider>.key`，仅适用于本地测试，不要将密钥放到命令行或提交工作区。`show` 显示端点、模型和 `keyFilePresent`；`validate-key` 只检查本地密钥，不能证明远端鉴权成功。状态、run ID 与具名失败原因见 `runtime/autonomy-model/history.jsonl`。若探针失败，先看该台账；离线检查不能替代真实 live 验收。

## 文档边界

[AGENT-ARCHITECTURE-GUIDE.md](AG-EXECUTION/AGENT-ARCHITECTURE-GUIDE.md) 是唯一规范，§24 保留版本化实验与评价记录；[AUTONOMY-RESULT.md](AG-EXECUTION/AUTONOMY-RESULT.md) 仅保存 2026-10-22 当前 Agent 的首次 MVP 原始验收。旧 Agent 的设计、状态和评测说明文档均不参与当前架构，也不作为运行前置条件；具体数据结构以 `K/schemas/`、代码和固定 run 产物为准。
