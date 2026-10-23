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

## 模型供应商设置（Windows）

自治 Agent 使用独立 profile，不修改旧链路 `oh6-vuln-agent/config/llm.json`；首次默认复制其非密钥字段。以下为 Command Code 的开源非 Pro 模型示例，可按供应商实际兼容接口调整：

```powershell
pwsh -NoProfile -File tools/autonomy-model.ps1 configure `
  --name=commandcode `
  --base-url=https://api.commandcode.ai/provider/v1 `
  --model=deepseek/deepseek-v4.1-flash `
  --response-format=json_schema `
  --timeout-ms=120000 `
  --max-tokens=32768 `
  --headers-json='{"x-cmd-zdr":"1"}'

pwsh -NoProfile -File tools/autonomy-model.ps1 set-key
pwsh -NoProfile -File tools/autonomy-model.ps1 show
pwsh -NoProfile -File tools/autonomy-model.ps1 validate-key
pwsh -NoProfile -File tools/autonomy-model.ps1 probe
pwsh -NoProfile -File tools/autonomy-model.ps1 run --max-tasks=3 --max-model-requests=3
```

`set-key` 交互输入一次密钥；`probe` 发一条真实短请求，`run` 先探针再审计。默认 3 个任务，`--max-tasks=0` 扫全量；单次审计 run 最多 30 次模型请求，前置探针另计。新增供应商用 `configure --name=<name> --base-url=<url> --model=<开源非Pro模型>` 后单独 `set-key`，用 `use --name=<name>` 切换。可选 `--response-format=json_schema|json_object|none`、`--timeout-ms`、`--max-tokens`、`--headers-json`、`--request-extra-json`；`remove-key` 删除当前供应商密钥。

密钥明文保存在 Git 忽略的 `runtime/autonomy-model/keys/<provider>.key`，仅适用于本地测试，不要将密钥放到命令行或提交工作区。`show` 显示端点、模型和 `keyFilePresent`；`validate-key` 只检查本地密钥，不能证明远端鉴权成功。状态、run ID 与具名失败原因见 `runtime/autonomy-model/history.jsonl`。若探针失败，先看该台账；离线检查不能替代真实 live 验收。

## 文档边界

[AGENT-ARCHITECTURE-GUIDE.md](AG-EXECUTION/AGENT-ARCHITECTURE-GUIDE.md) 是唯一规范，§24 保留版本化实验与评价记录；[AUTONOMY-RESULT.md](AG-EXECUTION/AUTONOMY-RESULT.md) 仅保存 2026-10-22 当前 Agent 的首次 MVP 原始验收。旧 Agent 的设计、状态和评测说明文档均不参与当前架构，也不作为运行前置条件；具体数据结构以 `K/schemas/`、代码和固定 run 产物为准。
