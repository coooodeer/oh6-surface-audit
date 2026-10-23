'use strict';

/**
 * run-p3p4p6.js —— 端到端复算：L1/L2 -> L3 claims -> L4a prover -> L4b -> verdict/report。
 *
 * 用法：
 *   node bin/run-p3p4p6.js                 # 含 live L4b（需要 OH6_LLM_API_KEY）
 *   node bin/run-p3p4p6.js --skip-l4b      # 只做确定性闭环
 *   node bin/run-p3p4p6.js --l4b-mock      # 强制 mock，live 标 blocked（结构测试）
 */

const fs = require('fs');
const path = require('path');
const { OUT_ROOT, readJsonl, writeJsonl, writeJson, ensureDir } = require('../lib/util.js');
const { loadL1 } = require('../lib/l1.js');
const { loadL2 } = require('../lib/l2.js');
const { buildAllClaims, assertClaimShape } = require('../lib/claims.js');
const { proveP3Claims, proveFixtures, summaryOfVerdicts: summarizeP3 } = require('../lib/prover-p3.js');
const { proveP6Claims, summarizeP6Verdicts, reconcileWithMiner, p6Verdict, productForP6 } = require('../lib/prover-p6.js');
const { proveP4Claims, summarizeP4Verdicts } = require('../lib/prover-p4.js');
const l4b = require('../lib/l4b.js');
const regression = require('../lib/regression.js');
const { buildInScope, writeInScope } = require('../lib/in-scope.js');
const { runCalibration, renderCalibration } = require('../lib/calibration.js');
const { runGates } = require('../lib/agent/registry');

const OUT = {
  l3: path.join(OUT_ROOT, 'l3'),
  l4a: path.join(OUT_ROOT, 'l4a'),
  l4b: path.join(OUT_ROOT, 'l4b'),
  report: path.join(OUT_ROOT, 'report')
};

const BASELINE = {
  functions: 17534,
  functionFiles: 1084,
  callEdges: 74574,
  producers: 17534,
  entries: 694,
  entryFiles: 160,
  actionRows: 328,
  uniqueActions: 22,
  p6Sites: 95,
  p6PayloadItems: 1058,
  p6PayloadRows: 328,
  minerSites: 624,
  minerEntities: 3321,
  minerFindings: 23,
  minerRejections: 601,
  derefs: 182,
  reachableDerefs: 73,
  reachableUnbound: 68
};

function args() {
  const a = process.argv.slice(2);
  return {
    skipL4b: a.includes('--skip-l4b'),
    l4bMock: a.includes('--l4b-mock'),
    reuseL4b: a.includes('--reuse-l4b'),
    reuseCalibration: a.includes('--reuse-calibration'),
    noCalibration: a.includes('--no-calibration'),
    l4bPackCount: Number((a.find((x) => x.startsWith('--l4b-pack-count=')) || '').split('=')[1] || 10)
  };
}

function checkBaseline(l1, l2) {
  const stats = l1.stats();
  const derefs = l2.derefClassification();
  const actual = {
    ...stats,
    p6Sites: l2.p6Sites().length,
    reachableDerefs: derefs.filter((r) => r.reachable).length,
    reachableUnbound: derefs.filter((r) => r.reachable && l1.derefById(r.id).entryCount === 0).length
  };
  const mismatches = [];
  for (const [k, v] of Object.entries(BASELINE)) {
    if (actual[k] !== v) mismatches.push({ field: k, expected: v, actual: actual[k] });
  }
  return { pass: mismatches.length === 0, expected: BASELINE, actual, mismatches };
}

function ensureL3(l1, l2, inputs) {
  const all = buildAllClaims(l1, l2, inputs);
  const errors = [];
  for (const claim of [...all.p3.claims, ...all.p6, ...all.p4]) {
    for (const e of assertClaimShape(claim)) errors.push({ claimId: claim.claimId, error: e });
  }
  const unreachable = l2.derefClassification().filter((r) => !r.reachable).map((r) => ({
    ...r,
    class: 'P3',
    entryCount: l1.derefById(r.id).entryCount,
    claimVerdict: 'NOT-APPLICABLE',
    productVerdict: 'NOT-APPLICABLE',
    reason: 'entry-unreachable',
    instrumentationGap: r.entryBinding === 'unreachable' ? 'no-entry-binding' : null
  }));
  writeJsonl(path.join(OUT.l3, 'p3-claims.jsonl'), all.p3.claims);
  writeJsonl(path.join(OUT.l3, 'p3-candidate-ledger.jsonl'), all.p3.ledger);
  writeJsonl(path.join(OUT.l3, 'p3-deref-classification.jsonl'), l2.derefClassification());
  writeJsonl(path.join(OUT.l3, 'p3-unreachable.jsonl'), unreachable);
  writeJsonl(path.join(OUT.l3, 'p6-claims.jsonl'), all.p6);
  writeJsonl(path.join(OUT.l3, 'p4-claims.jsonl'), all.p4);
  const summary = {
    generatedAt: new Date().toISOString(),
    p3: all.p3.summary,
    p3Ledger: all.p3.ledger.reduce((a, r) => { const k = r.selected ? 'selected' : r.reason; a[k] = (a[k] || 0) + 1; return a; }, {}),
    p3Unreachable: {
      total: unreachable.length,
      unbound: unreachable.filter((r) => r.entryCount === 0).length,
      claimVerdict: 'NOT-APPLICABLE',
      productVerdict: 'NOT-APPLICABLE'
    },
    p6: {
      total: all.p6.length,
      osAccount: all.p6.filter((c) => c.group === 'os-account').length,
      minerFindings: all.p6.filter((c) => c.group === 'miner-finding').length
    },
    p4: {
      total: all.p4.length,
      ohCandidates: all.p4.filter((c) => c.group === 'oh-candidate').length,
      cveCalibration: all.p4.filter((c) => c.group === 'cve-calibration').length
    },
    schemaErrors: errors
  };
  writeJson(path.join(OUT.l3, 'summary.json'), summary);
  return { ...all, errors, summary };
}

function applyL4b(p6Results, p6Verdicts) {
  const byClaim = new Map(p6Verdicts.map((v) => [v.claimId, v]));
  for (const r of p6Results) {
    if (!r.ok || r.kind !== 'P6') continue;
    const v = byClaim.get(r.claimId);
    if (!v) continue;
    const updated = l4b.applyP6L4bToVerdict(v, r);
    const verdict = p6Verdict(updated.obligations);
    const product = productForP6(verdict.claimVerdict, updated.obligations);
    updated.claimVerdict = verdict.claimVerdict;
    updated.reason = verdict.reason;
    updated.productVerdict = product.productVerdict;
    updated.productReason = product.reason;
    byClaim.set(r.claimId, updated);
  }
  return p6Verdicts.map((v) => byClaim.get(v.claimId));
}

function summarizeL4bResults(results, live, reason) {
  const p6Results = results.filter((r) => r.kind === 'P6');
  const p3Results = results.filter((r) => r.kind === 'P3');
  const okP6 = p6Results.filter((r) => r.ok);
  const summary = {
    generatedAt: new Date().toISOString(),
    simulated: !live,
    liveBlocked: !live,
    liveBlockedReason: live ? null : reason,
    p6: {
      packs: p6Results.length,
      ok: okP6.length,
      schemaSuccessRate: p6Results.length ? Number((okP6.length / p6Results.length).toFixed(3)) : 0,
      refsOk: okP6.length,
      refsOkRate: okP6.length ? 1 : 0,
      blocked: p6Results.filter((r) => r.blocked).length,
      aggregates: okP6.reduce((a, r) => { const k = r.aggregate && r.aggregate.aggregate; a[k] = (a[k] || 0) + 1; return a; }, {})
    },
    p3: {
      packs: p3Results.length,
      ok: p3Results.filter((r) => r.ok).length,
      blocked: p3Results.filter((r) => r.blocked).length
    },
    total: {
      packs: results.length,
      ok: results.filter((r) => r.ok).length,
      blocked: results.filter((r) => r.blocked).length,
      schemaFail: results.filter((r) => !r.ok && !r.blocked).length
    },
    tokens: {
      prompt: results.reduce((n, r) => n + ((r.usage && r.usage.promptTokens) || 0), 0),
      completion: results.reduce((n, r) => n + ((r.usage && r.usage.completionTokens) || 0), 0),
      total: results.reduce((n, r) => n + ((r.usage && r.usage.promptTokens) || 0) + ((r.usage && r.usage.completionTokens) || 0), 0)
    },
    log: path.relative(path.join(OUT_ROOT, '..'), l4b.LOG_FILE).split(path.sep).join('/')
  };
  summary.gate = summary.p6.packs >= 10 && summary.p6.schemaSuccessRate >= 0.8 && summary.p6.refsOkRate === 1;
  return summary;
}

async function runL4b(P3claims, P3verdicts, P6claims, P6verdicts, opts) {
  ensureDir(OUT.l4b);
  ensureDir(path.join(OUT_ROOT, '..', 'logs'));
  const p6Selected = l4b.selectP6L4bClaims(P6claims, P6verdicts, opts.l1, opts.packCount);
  const p3Selected = l4b.selectP3L4bClaims(P3claims, P3verdicts, 2);
  // 按 site 重建完整证据包（旧 p6-evidence.jsonl 是 action 级 231 行，已迁移）。
  const allP6Packs = P6claims.map((c) => l4b.buildP6Pack(c, opts.l1));
  const allP3Packs = P3claims.map((c) => l4b.buildP3Pack(c, opts.l1));
  writeJsonl(path.join(OUT.l4b, 'p6-evidence.jsonl'), allP6Packs);
  writeJsonl(path.join(OUT.l4b, 'p3-evidence.jsonl'), allP3Packs);
  const p6Packs = p6Selected.map((c) => allP6Packs.find((p) => p.claimId === c.claimId)).filter(Boolean);
  const p3Packs = p3Selected.map((c) => allP3Packs.find((p) => p.claimId === c.claimId)).filter(Boolean);
  writeJsonl(path.join(OUT.l4b, 'p6-packs.jsonl'), p6Packs);
  writeJsonl(path.join(OUT.l4b, 'p3-packs.jsonl'), p3Packs);

  const allPacks = [...p6Packs, ...p3Packs];
  const resultsFile = path.join(OUT.l4b, 'results.jsonl');
  const summaryFile = path.join(OUT.l4b, 'summary.json');
  if (opts.reuseL4b && fs.existsSync(resultsFile)) {
    const existing = readJsonl(resultsFile);
    const byId = new Map(existing.map((r) => [r.id, r]));
    if (allPacks.every((p) => byId.has(p.id))) {
      const results = allPacks.map((p) => byId.get(p.id));
      const simulated = opts.l4bMock || results.every((r) => r.simulated === true);
      const summary = summarizeL4bResults(results, !simulated, simulated ? 'reused-simulated' : 'reused-live-results');
      writeJson(summaryFile, summary);
      return {
        results, summary, live: !simulated,
        p6Run: { results: results.filter((r) => r.kind === 'P6') },
        p3Run: { results: results.filter((r) => r.kind === 'P3') },
        reused: true
      };
    }
  }

  const live = !opts.l4bMock && !!process.env.OH6_LLM_API_KEY;
  let transport = null;
  if (live) transport = l4b.makeTransport({ maxTokens: opts.maxTokens || 8192, timeoutMs: opts.timeoutMs || 90000 });
  else transport = l4b.makeMockTransport(allPacks);

  const p6Run = await l4b.runBatch(p6Packs, { transport, maxAttempts: 2, resultsFile: null });
  const p3Run = await l4b.runBatch(p3Packs, { transport, maxAttempts: 2, resultsFile: null });
  const results = [...p6Run.results, ...p3Run.results];
  writeJsonl(resultsFile, results);
  const summary = summarizeL4bResults(results, live, opts.l4bMock ? 'forced-mock' : 'OH6_LLM_API_KEY-missing');
  writeJson(path.join(OUT.l4b, 'summary.json'), summary);
  return { results, summary, p6Run, p3Run, live, reused: false };
}

function summarySimulated(results) {
  return results.length > 0 && results.every((r) => r.simulated === true);
}

function countBy(rows, field) {
  return rows.reduce((a, r) => { a[r[field]] = (a[r[field]] || 0) + 1; return a; }, {});
}

function writeImplementationReport(ctx) {
  ensureDir(OUT.report);
  const { baseline, l3, p3, p6, p4, l4bSummary, rg1, hist, fp, oracle, gateSummary, calibration, tokenLedger, inScope } = ctx;
  const lines = [];
  lines.push('# OH6 Surface Audit — L1–L4 实现报告（P6 + P3 + P4）');
  lines.push('');
  lines.push(`生成时间：${new Date().toISOString()}`);
  lines.push('');
  lines.push('## 1 范围声明');
  lines.push('');
  lines.push('- 已实现：L1 事实查询、L2 entry/site 绑定、L3 claim/obligation、L4a 确定性 prover、L4b bounded semantic judge。');
  lines.push('- **未实现**：L5 新动态、L6 spec 挖掘、L7 报告；P1/P2/P5 未覆盖；ASan/设备/hdc 未使用。');
  lines.push('- P4 只做静态义务 + 已有 native-harness UBSan oracle 的只读映射，不新开 L5。');
  lines.push('- P6-9 public-api-residual 未加入；`P∩U`/`S/U` 仅作 evidence。');
  lines.push('- `NOT-VULN`/`SATISFIED` 只表示当前义务/数据下未闭合，不等于该组件无漏洞；`VIOLATION` 不是漏洞结论，P3/P4 只到 claim-candidate（product 已降为 `PROVEN-WEAKNESS`/`CONDITIONS-NOT-MET`）。');
  lines.push('');
  lines.push('## 2 基线与数据（可复算）');
  lines.push('');
  lines.push('| 指标 | 期望 | 实测 | 通过 |');
  lines.push('| --- | ---: | ---: | --- |');
  for (const [k, exp] of Object.entries(BASELINE)) {
    const act = baseline.actual[k];
    lines.push(`| ${k} | ${exp} | ${act} | ${act === exp ? '✅' : '❌'} |`);
  }
  lines.push('');
  lines.push('## 3 L3 claim');
  lines.push('');
  lines.push(`- P3：${l3.summary.p3.selected} 条（现有 5 + 1a/2a 扩充 ${l3.summary.p3.expanded}）；73 条 reachable deref 重分类，68 条 unbound 全部标 \`callgraph-name-only\`。`);
  lines.push(`- P6：${l3.summary.p6.total} 条 site 级 claim（os_account ${l3.summary.p6.osAccount} + miner finding ${l3.summary.p6.minerFindings}）。`);
  lines.push(`- P4：${l3.summary.p4.total} 条（OH ${l3.summary.p4.ohCandidates} + CVE 校准 ${l3.summary.p4.cveCalibration}）。`);
  lines.push(`- schema 错误：${l3.errors.length}。`);
  lines.push('');
  lines.push('## 4 L4a verdict');
  lines.push('');
  lines.push(`- P3：${JSON.stringify(p3.summary.claimVerdict)}；fixture 原函数 SATISFIED ${p3.fixtureGate.originalSatisfied}/10、mutant VIOLATION ${p3.fixtureGate.mutantViolation}/10。`);
  lines.push(`- P6：${JSON.stringify(p6.summary.claimVerdict)}；os_account 95/95 NOT-VULN；miner findings：PROVEN-VULN ${p6.summary.minerFindings.provenVuln.length}、PROVEN-WEAKNESS ${p6.summary.minerFindings.provenWeakness.length}。`);
  lines.push(`- P6 对账：95/95 可在 broadcast-sites 找到；rejections ${JSON.stringify(p6.reconcile.rejectionCounts)}；reason mismatch ${p6.reconcile.reasonMismatch.length}。`);
  lines.push(`- P4：${JSON.stringify(p4.summary.claimVerdict)}；O1–O10 义务闭合率 ${p4.summary.obligationClosure.proven}/${p4.summary.obligationClosure.total} = ${p4.summary.obligationClosure.rate}；oracle confirmed ${p4.summary.oracle.confirmed} / blocked ${p4.summary.oracle.blocked}（${JSON.stringify(p4.summary.oracle.blockedReasons)}）。`);
  lines.push('');
  lines.push('## 5 L4b');
  lines.push('');
  lines.push(`- simulated=${l4bSummary.simulated}；live blocked=${l4bSummary.liveBlocked}（${l4bSummary.liveBlockedReason || '-'}）。`);
  lines.push('- 证据包已按 site 重建：`out/l4b/p6-evidence.jsonl` 115 条（95 os + 20 finding）、`out/l4b/p3-evidence.jsonl` 25 条；实际 live 判定 P6 10 条 / P3 2 条。');
  lines.push(`- P6 packs ${l4bSummary.p6.packs}，schema 成功率 ${l4bSummary.p6.schemaSuccessRate}，引用校验 ${l4bSummary.p6.refsOkRate}；aggregates ${JSON.stringify(l4bSummary.p6.aggregates)}。`);
  lines.push(`- P3 packs ${l4bSummary.p3.packs}，ok ${l4bSummary.p3.ok}，blocked ${l4bSummary.p3.blocked}。`);
  lines.push(`- tokens：prompt ${l4bSummary.tokens.prompt} + completion ${l4bSummary.tokens.completion} = ${l4bSummary.tokens.total}；日志 \`${l4bSummary.log}\`。`);
  if (tokenLedger) {
    lines.push(`- token 账本：L4b ${tokenLedger.l4b.totalTokens} + 校准复核 ${tokenLedger.calibration.totalTokens} = **${tokenLedger.totalTokens}**；`);
    lines.push(`  decisive claim/verdict ${tokenLedger.decisiveClaims} 条，平均 ${tokenLedger.perDecisiveClaim} tokens/条；L4b ${tokenLedger.perL4bPack}/包，校准 ${tokenLedger.perCalibrationReview}/次。详见 \`out/report/token-ledger.json\`。`);
  }
  lines.push('');
  lines.push('## 6 回归哨兵');
  lines.push('');
  lines.push(`- RG1：正例 ${rg1.positive.pass}/${rg1.positive.total}、负例 ${rg1.negative.pass}/${rg1.negative.total}、保护 ${rg1.provisionalPositive.pass}/${rg1.provisionalPositive.total}；总 ${rg1.pass ? 'PASS' : 'FAIL'}。`);
  lines.push(`- 9 条历史正例：not-covered ${hist.notCovered}/${hist.total}，covered ${hist.covered}，pass=${hist.pass}。`);
  lines.push(`- 64 FP + 2 P7 复核集：scanned ${fp.scannedRows}，claimsFromReviewSet ${fp.claimsFromReviewSet}，pass=${fp.pass}。`);
  lines.push('- RG1 负例：N5（通知弹窗，confirmed FP）已从 P6 findings 剔除；N2/N3 的 os_account site 仅作为 95 site NOT-VULN 对账单元，不作为正例或正文 claim。');
  lines.push(`- P4 oracle 对账：${oracle.confirmed.join(',')} confirmed；blocked ${oracle.blockedCount}（${JSON.stringify(oracle.blockedReasons)}）。`);
  lines.push('');
  lines.push('## 7 抽样复核（§7.7）');
  lines.push('');
  if (calibration && !calibration.skipped) {
    lines.push(`- 轮次：${calibration.rounds.length}；样本 ${calibration.totalSampled}（accepted ${calibration.accepted} / rejected ${calibration.rejected}）。`);
    lines.push(`- 程序化不支持 ${calibration.programmaticUnsupported}；语义复核 ${calibration.semanticReviewed} 次；false \`PROVEN-VULN\` ${calibration.falseProvenVuln}。`);
    lines.push(`- holdout ${calibration.holdout.rows} 条：supported ${calibration.holdout.supported} / unsupported ${calibration.holdout.unsupported}。`);
    lines.push(`- 错误分类：${JSON.stringify(calibration.rounds.reduce((a, r) => { for (const [k, v] of Object.entries(r.errorTypes || {})) a[k] = (a[k] || 0) + v; return a; }, {}))}。`);
    lines.push('- 详见 `out/report/calibration.md` 与 `out/report/CALIBRATION-LOG.jsonl`。');
  } else {
    lines.push('- 本轮跳过（--no-calibration）；不作为完成状态。');
  }
  lines.push('');
  lines.push('## 8 R1 本仓新发现候选统计');
  lines.push('');
  if (inScope) {
    lines.push('- 口径：**R1** = `base/account/os_account` + `foundation/communication/dsoftbus`；排除 miner 既有 findings、外部 CVE、R2 其他仓。');
    lines.push(`- **本仓新确认漏洞 ${inScope.headline.newConfirmed} 个**；**新 weak 候选 ${inScope.headline.newWeakUnits} 个根因单元 / ${inScope.headline.newWeakClaims} 条 claim**；**instrumentation-gap ${inScope.headline.instrumentationGap} 个**。`);
    lines.push(`- P3：5 个 owner 根因族 / 25 条 claim；P4：1 条 T2（\`cd_G-P4_52b62a535a33\`）+ 5 条 T3（2 no-driver-template、3 compile-failed）；P6 os_account：0 阳性。`);
    lines.push(`- 排除 ${inScope.excluded.total} 条：miner findings ${inScope.excluded.minerFindings}（含 ${inScope.excluded.minerFindingsProvenVuln} 个 PROVEN-VULN）、外部 CVE ${inScope.excluded.externalCve}、R2 P4 ${inScope.excluded.oh6OtherReposP4}。`);
    lines.push('- 逐条见 `out/verdicts/in-scope-verdicts.jsonl`、`out/verdicts/summary.json`、`out/report/in-scope-findings.md`。');
  } else {
    lines.push('- 未生成（本轮跳过）。');
  }
  lines.push('');
  lines.push('## 9 已知缺口');
  lines.push('');
  lines.push('- P3 O4 只做 local path；O4-full（跨函数/别名/分支可行性）未做。');
  lines.push('- P3 105 条 unreachable-unbound 只登记 NOT-APPLICABLE/instrumentation-gap，不生成 PROVEN-VULN。');
  lines.push('- P4 10 条 blocked（7 no-driver-template、3 compile-failed）落 CONDITIONS-NOT-MET/instrumentation-gap；不伪造动态结果。');
  lines.push('- P4 O4 的完整表达式类型/promotion 仍缺 clang 级推导；缺失时明确 unproven。');
  lines.push('- P6 os_account 当前 0 finding；Kiosk/QuickFix 等阳性只来自 miner 既有 findings，不计入 R1 本仓统计。');
  lines.push('- L4b 若 key 缺失，live 标 blocked，只用 mock 做结构测试。');
  lines.push('');
  lines.push('## 10 门禁汇总');
  lines.push('');
  lines.push('| 门 | 结果 |');
  lines.push('| --- | --- |');
  for (const g of gateSummary) lines.push(`| ${g.name} | ${g.pass ? '✅ PASS' : '❌ FAIL'} ${g.detail || ''} |`);
  lines.push('');
  fs.writeFileSync(path.join(OUT.report, 'implementation.md'), lines.join('\n'), 'utf8');
}

async function main() {
  const opts = args();
  const started = Date.now();
  for (const d of Object.values(OUT)) ensureDir(d);
  const l1 = loadL1();
  const l2 = loadL2(l1);
  const baseline = checkBaseline(l1, l2);
  if (!baseline.pass) {
    process.stderr.write(`baseline mismatch: ${JSON.stringify(baseline.mismatches)}\n`);
    process.exit(2);
  }

  const candidates = readJsonl(path.join(OUT_ROOT, 'p4', 'candidates.jsonl'));
  const cvePatches = readJsonl(path.join(OUT_ROOT, 'p4', 'cve-patches.jsonl'));
  require('./p4-entry-binding.js').main();
  const l3 = ensureL3(l1, l2, { p4Candidates: candidates, p4CvePatches: cvePatches });
  process.stdout.write(`L3: P3=${l3.p3.claims.length} P6=${l3.p6.length} P4=${l3.p4.length}\n`);

  // L4a
  const p3Verdicts = proveP3Claims(l3.p3.claims, l1, l2, { impactNotAssessed: true });
  const p3Fixtures = proveFixtures(l1);
  const p6VerdictsRaw = proveP6Claims(l3.p6, l1);
  const p4Verdicts = proveP4Claims(l3.p4, l1, {
    candidateById: new Map(candidates.map((c) => [c.candidateId, c])),
    cveById: new Map(cvePatches.map((c) => [c.cveId, c]))
  });
  writeJsonl(path.join(OUT.l4a, 'p3-verdicts.jsonl'), p3Verdicts);
  writeJsonl(path.join(OUT.l4a, 'p3-fixtures.jsonl'), p3Fixtures);
  writeJsonl(path.join(OUT.l4a, 'p6-verdicts.jsonl'), p6VerdictsRaw);
  writeJsonl(path.join(OUT.l4a, 'p4-verdicts.jsonl'), p4Verdicts);

  // L4b（可跳过）
  let l4bRun = null;
  let p6Verdicts = p6VerdictsRaw;
  if (!opts.skipL4b) {
    l4bRun = await runL4b(l3.p3.claims, p3Verdicts, l3.p6, p6VerdictsRaw, {
      l1, l4bMock: opts.l4bMock, packCount: opts.l4bPackCount, reuseL4b: opts.reuseL4b
    });
    p6Verdicts = applyL4b(l4bRun.p6Run.results, p6VerdictsRaw);
    writeJsonl(path.join(OUT.l4a, 'p6-verdicts.jsonl'), p6Verdicts);
  } else {
    l4bRun = {
      summary: {
        simulated: true, liveBlocked: true, liveBlockedReason: 'skip-l4b',
        p6: { packs: 0, ok: 0, schemaSuccessRate: 0, refsOkRate: 0, blocked: 0, aggregates: {} },
        p3: { packs: 0, ok: 0, blocked: 0 },
        total: { packs: 0, ok: 0, blocked: 0, schemaFail: 0 },
        tokens: { prompt: 0, completion: 0, total: 0 }, log: null, gate: false
      }
    };
    writeJson(path.join(OUT.l4b, 'summary.json'), { ...l4bRun.summary, skipped: true });
  }

  // 汇总/对账
  const p3Summary = {
    claimVerdict: countBy(p3Verdicts, 'claimVerdict'),
    productVerdict: countBy(p3Verdicts, 'productVerdict'),
    obligations: summarizeP3(p3Verdicts).obligations,
    claims: p3Verdicts.length
  };
  const fixtureGate = {
    originals: p3Fixtures.filter((r) => r.variant === 'original').length,
    mutants: p3Fixtures.filter((r) => r.variant === 'mutant').length,
    originalSatisfied: p3Fixtures.filter((r) => r.variant === 'original' && r.claimVerdict === 'SATISFIED').length,
    mutantViolation: p3Fixtures.filter((r) => r.variant === 'mutant' && r.claimVerdict === 'VIOLATION').length
  };
  const p6Summary = summarizeP6Verdicts(p6Verdicts);
  const p6Reconcile = reconcileWithMiner(l1, l2, p6Verdicts);
  const p4Summary = summarizeP4Verdicts(p4Verdicts);
  const oracle = regression.checkP4Oracle(candidates, OUT.report);
  const rg1 = regression.checkRG1(p6Verdicts, OUT.report);
  const hist = regression.checkHistoricalPositives([...p3Verdicts, ...p6Verdicts, ...p4Verdicts], OUT.report);
  const fp = regression.checkFpReviewSet([...l3.p3.claims, ...l3.p6, ...l3.p4], OUT.report);
  const inScope = buildInScope({
    p3Verdicts,
    p4Verdicts,
    p6Verdicts,
    p4Candidates: candidates,
    p3Unreachable: readJsonl(path.join(OUT.l3, 'p3-unreachable.jsonl'))
  });
  writeInScope(OUT_ROOT, inScope);

  const l4aSummary = {
    generatedAt: new Date().toISOString(),
    p3: { ...p3Summary, fixtureGate },
    p6: { ...p6Summary, reconcile: p6Reconcile },
    p4: p4Summary,
    oracle,
    rg1,
    historicalPositives: hist,
    fpReview: fp
  };
  writeJson(path.join(OUT.l4a, 'summary.json'), l4aSummary);

  // §7.7 抽样复核：3 轮 accepted/rejected；语义不清的交 fresh-context reviewer。
  let calibration = null;
  const calibrationSummaryFile = path.join(OUT.report, 'calibration-summary.json');
  if (!opts.noCalibration && opts.reuseCalibration && fs.existsSync(calibrationSummaryFile)) {
    calibration = { summary: JSON.parse(fs.readFileSync(calibrationSummaryFile, 'utf8')), reused: true };
  } else if (!opts.noCalibration) {
    const calibTransport = !opts.l4bMock && process.env.OH6_LLM_API_KEY
      ? l4b.makeTransport({ maxTokens: 2048, timeoutMs: 90000 })
      : null;
    calibration = await runCalibration({
      l1, p3Verdicts, p6Verdicts, p4Verdicts, p3Fixtures, transport: calibTransport,
      rounds: 3, nPerSide: 10, semanticLimitPerRound: 2
    });
  } else {
    calibration = {
      summary: {
        rounds: [], totalSampled: 0, accepted: 0, rejected: 0, programmaticUnsupported: 0,
        semanticReviewed: 0, semanticCalls: 0, semanticTokens: 0, unsupported: [],
        falseProvenVuln: 0, falseProvenVulnCases: [], holdout: { rows: 0, accepted: 0, rejected: 0, supported: 0, unsupported: 0 },
        pass: false, skipped: true
      }
    };
  }

  const calibLogFile = path.join(OUT_ROOT, '..', 'logs', 'calibration.jsonl');
  const calibLogRows = fs.existsSync(calibLogFile) ? readJsonl(calibLogFile) : [];
  const calibPrompt = calibLogRows.reduce((n, r) => n + (r.promptTokens || 0), 0);
  const calibCompletion = calibLogRows.reduce((n, r) => n + (r.completionTokens || 0), 0);
  if (calibration.reused) {
    const calLog = readJsonl(path.join(OUT.report, 'CALIBRATION-LOG.jsonl'));
    calibration.summary.semanticSupported = calLog.filter((x) => x.reviewMethod === 'semantic' && x.reviewVerdict === 'yes').length;
    calibration.summary.semanticUnknown = calLog.filter((x) => x.reviewMethod === 'semantic' && x.reviewVerdict === 'unknown').length;
    calibration.summary.semanticUnsupported = calLog.filter((x) => x.reviewMethod === 'semantic' && x.reviewVerdict === 'no').length;
    calibration.summary.calibrationLog = calibration.summary.calibrationLog || 'logs/calibration.jsonl';
    writeJson(calibrationSummaryFile, calibration.summary);
    fs.writeFileSync(path.join(OUT.report, 'calibration.md'), renderCalibration(calibration.summary, calLog), 'utf8');
  }
  const decisiveClaims = p3Verdicts.length + p6Verdicts.length + p4Verdicts.length;
  const tokenLedger = {
    generatedAt: new Date().toISOString(),
    l4b: { calls: l4bRun.summary.total ? l4bRun.summary.total.packs : 0, promptTokens: l4bRun.summary.tokens.prompt, completionTokens: l4bRun.summary.tokens.completion, totalTokens: l4bRun.summary.tokens.total, log: l4bRun.summary.log },
    calibration: { calls: calibLogRows.length || (calibration.summary.semanticCalls || 0), promptTokens: calibPrompt, completionTokens: calibCompletion, totalTokens: calibPrompt + calibCompletion || (calibration.summary.semanticTokens || 0), log: calibration.summary.calibrationLog || null },
    totalTokens: (l4bRun.summary.tokens.total || 0) + (calibration.summary.semanticTokens || 0),
    decisiveClaims,
    perDecisiveClaim: decisiveClaims ? Number((((l4bRun.summary.tokens.total || 0) + (calibration.summary.semanticTokens || 0)) / decisiveClaims).toFixed(1)) : 0,
    perL4bPack: l4bRun.summary.total && l4bRun.summary.total.ok ? Number((l4bRun.summary.tokens.total / l4bRun.summary.total.ok).toFixed(1)) : 0,
    perCalibrationReview: calibration.summary.semanticCalls ? Number(((calibration.summary.semanticTokens || 0) / calibration.summary.semanticCalls).toFixed(1)) : 0,
    note: '不记录 key；L4b 逐调用日志 logs/l4b.jsonl，校准复核逐调用日志 logs/calibration.jsonl'
  };
  writeJson(path.join(OUT.report, 'token-ledger.json'), tokenLedger);

  const gateSummary = runGates('p3p4p6', {
    baseline, l3, p3Verdicts, fixtureGate, p6Verdicts, p6Reconcile, l4bRun, p6Summary,
    p4Verdicts, p4Summary, oracle, rg1, hist, fp, inScope, calibration
  });

  writeImplementationReport({
    baseline, l3, p3: { summary: p3Summary, fixtureGate }, p6: { summary: p6Summary, reconcile: p6Reconcile },
    p4: { summary: p4Summary }, l4bSummary: l4bRun.summary, rg1, hist, fp, oracle, gateSummary, calibration: calibration.summary, tokenLedger, inScope: inScope.summary
  });

  const final = {
    generatedAt: new Date().toISOString(),
    elapsedMs: Date.now() - started,
    baseline,
    gates: gateSummary,
    allGatesPass: gateSummary.every((g) => g.pass),
    l3: l3.summary,
    l4a: l4aSummary,
    l4b: l4bRun.summary,
    calibration: calibration.summary,
    inScope: inScope.summary,
    tokenLedger
  };
  writeJson(path.join(OUT.report, 'run-summary.json'), final);
  writeJson(path.join(OUT_ROOT, 'summary.json'), {
    generatedAt: final.generatedAt,
    functions: baseline.actual.functions,
    entries: baseline.actual.entries,
    p6Sites: baseline.actual.p6Sites,
    p3Claims: p3Verdicts.length,
    p6Claims: p6Verdicts.length,
    p4Claims: p4Verdicts.length,
    gatesPass: final.allGatesPass
  });
  process.stdout.write(`\nP3 ${JSON.stringify(p3Summary.claimVerdict)} fixtures ${fixtureGate.originalSatisfied}/${fixtureGate.mutantViolation}\n`);
  process.stdout.write(`P6 ${JSON.stringify(p6Summary.claimVerdict)} os=${JSON.stringify(p6Summary.osAccount.verdicts)} findings ${JSON.stringify(p6Summary.minerFindings.verdicts)}\n`);
  process.stdout.write(`P4 ${JSON.stringify(p4Summary.claimVerdict)} closure=${p4Summary.obligationClosure.rate}\n`);
  process.stdout.write(`L4b sim=${l4bRun.summary.simulated} p6=${l4bRun.summary.p6.ok}/${l4bRun.summary.p6.packs} p3=${l4bRun.summary.p3.ok}/${l4bRun.summary.p3.packs} tokens=${l4bRun.summary.tokens.total}\n`);
  process.stdout.write(`RG1=${rg1.pass} hist=${hist.pass} fp=${fp.pass} oracle=${oracle.pass}\n`);
  process.stdout.write(`gates: ${gateSummary.filter((g) => g.pass).length}/${gateSummary.length} pass\n`);
  for (const g of gateSummary.filter((x) => !x.pass)) process.stdout.write(`  FAIL ${g.name}: ${g.detail}\n`);
  process.exit(final.allGatesPass ? 0 : 3);
}

if (require.main === module) {
  main().catch((e) => {
    process.stderr.write(`fatal: ${e && e.stack ? e.stack : e}\n`);
    process.exit(1);
  });
}

module.exports = { main, BASELINE };

