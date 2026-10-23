# External CVE calibration（只测试义务编排/裁决）

> **定位：与 OH6.0 无关的外部 CVE 只用于测试当前 agent 的漏洞义务编排和裁决能力。**
> 它们不映射到当前扫描范围，不产生 `codeState`，不进入 D4/R1 统计，不产生 T1/T2/T3/T4。
> 不把“外部 CVE 在 OH6.0 有相似代码”当作发现；如果目标代码里也有，应由 target/historical/miner 自己的候选链路发现。

## 允许的用途

- 测试 P1/P2/P7/P8 的 O1–O10 义务是否能覆盖该 CVE 的漏洞机制；
- 测试 prover 的 T2/T3/T4 判定是否符合预定义期望；
- 测试“check 存在但未覆盖”“修复后应 T4”“信息不足应 T3”等反例；
- 为 P7 的 DoS 判据提供语义样本（放大、持久化、跨应用）。

## 禁止

- 把外部 CVE 的 repo/file 映射到 OH6.0；
- 给外部 CVE 记录写 `codeState` 或 `inTarget: true`；
- 把外部 CVE 的 verdict 计入生产 headline；
- 用外部 CVE 数量填充 P1/P2/P7/P8 的 D4 覆盖率。

## 文件

```text
eval/external-cve/
  README.md
  schema.json          # 单条 case 的字段约束
  p7-cases.js          # P7 义务/裁决校准记录（inline source snippet）
  cases.jsonl          # 可选；每行一条外部 CVE 校准用例
```

没有真实外部 CVE 样本时，目录可以只有 README/schema；不得伪造 CVE 条目。

## 当前 P7 cases

`p7-cases.js` 现有 4 条，覆盖 CWE-400/617/674：

| id | CVE | CWE | 类型 | 修复点 |
| --- | --- | --- | --- | --- |
| EXT-P7-001 | CVE-2018-16452 | 674 | 递归栈耗尽 | tcpdump `smb_fdata` depth cap |
| EXT-P7-002 | CVE-2019-16163 | 674 | 解析递归栈耗尽 | Oniguruma `parse_exp` ParseDepthLimit |
| EXT-P7-003 | CVE-2016-9388 | 617 | 可达断言 | JasPer `ras_getcmap` assert → return -1 |
| EXT-P7-004 | CVE-2016-6307 | 400 | 内存耗尽 | OpenSSL 先检查 excessive length 再 grow |

这些 source 是**函数片段**（`sourceKind:'inline-snippet'`, `completeFunction:false`），用于义务映射/裁决测试，不是完整可编译文件。

## 单条 case 最低字段

```json
{
  "id": "EXT-P7-001",
  "cveId": "CVE-XXXX-YYYY",
  "class": "P7",
  "cwe": ["400"],
  "language": "c",
  "source": {
    "pre": "eval/external-cve/src/EXT-P7-001/pre.c",
    "post": "eval/external-cve/src/EXT-P7-001/post.c"
  },
  "affected": {
    "component": "upstream-project",
    "file": "src/foo.c",
    "function": "foo"
  },
  "expected": {
    "obligations": ["O2", "O3", "O4", "O5", "O6"],
    "preVerdict": "VIOLATION",
    "postVerdict": "SATISFIED",
    "product": "PROVEN-WEAKNESS"
  },
  "usage": "obligation-calibration | verdict-calibration | negative-control",
  "production": false
}
```

`production` 必须为 `false`；`inTarget`/`codeState` 不得出现。

## 使用方式

- 校验：`node bin/external-cve-validate.js`；
- 用独立 runner 读 `p7-cases.js` / `cases.jsonl`，逐条跑义务映射/prover；
- 结果写 `out/external-cve/`，不写 `out/verdicts/`；
- 报告放 `out/report/external-cve-calibration.md`；
- 外部样本不参与 P1/P2/P7/P8 的 D4 覆盖率、T1/T2/T3/T4 headline 或生产门禁。
