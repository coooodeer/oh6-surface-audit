# Ground truth v0（P3/P6）

## P3

- `p3/cases.jsonl`：10 个函数级 mutant。
  - 每个 case 记录 repo/file/function/guardLineInBody/variable/mutantFile；
  - `expected.original=SATISFIED`、`expected.mutant=VIOLATION`；
  - `p3/mutants/*.cpp`：从原文件复制后删除 `if (!var)` / `if (var == nullptr)` 块；
  - 已逐个校验：mutant 中目标 guard 消失。
- `p3/historical.jsonl`：5 条 `history-invariants` 的 `null-check-added` seed，作为历史样本。

## P6

- `p6/cases.jsonl`：25 个 case。
  - `original`：10 个第三方可达 + 有 payload 的 action；
  - `control-subscriber-permission`：同 action 加上假的 `ohos.permission.TEST_ONLY`，期望 `receiverThirdParty=false`；
  - `negative-restricted`：5 个 `restricted` action，期望 `receiverThirdParty=false`。

## 口径

- 这是 **P3/P6 的判据一致性 ground truth**，不是“当前 OH6 漏洞标注集”。
- P3 mutant 只验证 `guard-before-deref` 这一条义务，不证明真实可利用性。
- P6 case 只验证 `payload-present / receiver-third-party` 这类事实级义务；`payload-sensitive` 仍需要 L4b 语义判定。

## 复算

```powershell
cd oh6-surface-audit
node bin/gt-build.js
```
