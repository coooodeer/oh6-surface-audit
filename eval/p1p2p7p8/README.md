# P1/P2/P7/P8 fixtures

> 只用于校准 detector/prover；不进入生产 D4 统计，不写生产 O10，不产生 PROVEN-VULN。
> 所有 case 都必须有唯一 id、类别、期望 verdict、证据；pre/post/mutant 或 original/mutant 期望明确。

## 目录

```text
eval/p1p2p7p8/
  p1/cases.js   # 5 正 + 5 负 synthetic；本地 bounds-check-added 2 条；历史正例 CWE-121/122
  p2/cases.js   # 5 正 + 5 负 synthetic；本地 lifetime-guard-added 8 条；历史 UAF CWE-416
  p7/cases.js   # 4 类 dosClass × 2 正/负；5 条 amplification fixture；external-cve 匹配配置
  p8/cases.js   # 3 种 invariant × 2 正 + 1 负；本地 state-guard-added 4 条
```

## 纪律

- `test/fuzz/unittest` 路径不作为产品 fixture；本地记录剔除 test/fuzz 后使用。
- `history-invariants.jsonl` 的 pre/post 通过 `git show <sha>^:<file>` / `git show <sha>:<file>` 提取；
  witness 必须“前无、后有”；mutant = post 去掉 witness 行（或 case 指定的删除行）。
- `positives.jsonl` 的 before/after code 直接用作 history-positive fixture。
- `eval/external-cve/p7-cases.js` 的 4 条只作义务/裁决校准：`production:false`，不映射 target，
  不写 `inTarget`/`codeState`，不进入 D4。
- 运行：`node --test` 或 `node bin/run-p1p2p7p8.js`；产物在 `out/report/p1p2p7p8-*.md`。

## 期望口径

- 正例 original = `VIOLATION`（T2），mutant = `SATISFIED`（T4）；
- 负例 original = `SATISFIED`（T4），mutant = `VIOLATION`（T2）；
- 历史 fixture：pre = `VIOLATION`，post = `SATISFIED`，mutant = `VIOLATION`（pre-already 例外会显式标注）。
- 任一 fixture 出现 `PROVEN-VULN` 都是错误：O10 固定 unproven。
