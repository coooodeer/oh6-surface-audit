'use strict';

/**
 * p5-verdicts.js —— P5 R1 统计/verdict 文件。
 *
 * T1 PROVEN-VULN；T2 PROVEN-WEAKNESS；T3 CONDITIONS-NOT-MET；T4 negative 不写入 in-scope verdicts。
 */

const fs = require('fs');
const path = require('path');
const { OUT_ROOT, ensureDir, writeJsonl, writeJson } = require('./util.js');

function tierOf(claim) {
  if (claim.productVerdict === 'PROVEN-VULN') return 'T1-confirmed';
  if (claim.productVerdict === 'PROVEN-WEAKNESS') return 'T2-weak-candidate';
  if (claim.productVerdict === 'CONDITIONS-NOT-MET' || claim.productVerdict === 'UNPROVEN') return 'T3-instrumentation-gap';
  if (claim.productVerdict === 'NOT-VULN' || claim.claimVerdict === 'SATISFIED') return 'T4-negative';
  if (claim.productVerdict === 'NOT-APPLICABLE') return 'T5-not-applicable';
  return 'T3-instrumentation-gap';
}

function gapReason(claim) {
  const ids = ['O6', 'O7', 'O8'];
  const reasons = [];
  for (const id of ids) {
    const o = (claim.obligations || []).find((x) => x.id === id);
    if (o && o.status !== 'proven') reasons.push(`${id}:${o.reason || o.status}`);
  }
  return reasons.join(';') || claim.productReason || null;
}

function buildP5Verdicts(claims, ctx = {}) {
  const rows = claims.map((c) => {
    const tier = tierOf(c);
    return {
      verdictId: c.claimId,
      scope: 'R1',
      class: 'P5',
      unitId: c.unitId,
      repo: c.entry.repo,
      interface: c.entry.interface,
      method: c.entry.method,
      origin: c.origin || null,
      inTarget: c.inTarget === true,
      codeState: c.codeState || null,
      productionEligible: c.productionEligible === true,
      novelty: c.novelty || null,
      file: c.sink.file,
      line: c.sink.line,
      sinkFunction: c.sink.functionName,
      tier,
      counted: tier === 'T1-confirmed' || tier === 'T2-weak-candidate',
      claimVerdict: c.claimVerdict,
      productVerdict: c.productVerdict,
      impactStatus: c.impact ? c.impact.status : 'not-assessed',
      impactReason: c.impact ? c.impact.reason || null : null,
      gapReason: tier === 'T3-instrumentation-gap' ? gapReason(c) : null,
      claimIds: [c.claimId],
      evidenceRefs: [`${c.sink.file}:${c.sink.line}`],
      obligations: (c.obligations || []).map((o) => ({ id: o.id, status: o.status, reason: o.reason || null }))
    };
  });
  const byTier = rows.reduce((a, r) => { a[r.tier] = (a[r.tier] || 0) + 1; return a; }, {});
  const byInterface = rows.reduce((a, r) => { a[r.interface] = (a[r.interface] || 0) + 1; return a; }, {});
  const inScopeRows = rows.filter((r) => r.productionEligible === true && (r.tier === 'T1-confirmed' || r.tier === 'T2-weak-candidate' || r.tier === 'T3-instrumentation-gap'));
  const fixtures = ctx.fixtures || null;
  const audit = ctx.audit || null;
  const l4b = ctx.l4b || null;
  const calibration = ctx.calibration || null;
  const summary = {
    generatedAt: new Date().toISOString(),
    standardVersion: 'P5-R1-1',
    scope: { name: 'R1', repos: ['base/account/os_account', 'foundation/communication/dsoftbus'] },
    claims: { total: rows.length, byTier, byInterface },
    impact: claims.reduce((a, c) => { const k = c.impact ? c.impact.status : 'not-assessed'; a[k] = (a[k] || 0) + 1; return a; }, {}),
    headline: {
      newConfirmed: rows.filter((r) => r.tier === 'T1-confirmed').length,
      newWeak: rows.filter((r) => r.tier === 'T2-weak-candidate').length,
      conditions: rows.filter((r) => r.tier === 'T3-instrumentation-gap').length,
      negative: rows.filter((r) => r.tier === 'T4-negative').length
    },
    verdicts: { inScopeRows: inScopeRows.length },
    provenance: {
      productionEligible: rows.filter((r) => r.productionEligible).length,
      nonProduction: rows.filter((r) => !r.productionEligible).length,
      byOrigin: rows.reduce((a, r) => { const k = r.origin || 'unknown'; a[k] = (a[k] || 0) + 1; return a; }, {}),
      byNovelty: rows.reduce((a, r) => { const k = r.novelty || 'unknown'; a[k] = (a[k] || 0) + 1; return a; }, {})
    },
    audit: audit ? {
      candidates: audit.candidates,
      units: audit.units,
      pairing: audit.pairing,
      checks: audit.checks,
      paths: audit.paths
    } : null,
    fixtures: fixtures ? {
      gate: fixtures.gate,
      historical: fixtures.historical,
      synthetic: fixtures.synthetic
    } : null,
    l4b: l4b ? {
      simulated: l4b.simulated === true,
      packs: l4b.packs,
      ok: l4b.ok,
      schemaSuccessRate: l4b.schemaSuccessRate,
      refsOkRate: l4b.refsOkRate,
      gate: l4b.gate,
      aggregates: l4b.aggregates
    } : null,
    calibration: calibration ? {
      pass: calibration.pass,
      rounds: calibration.rounds ? calibration.rounds.length : 0,
      samples: calibration.totalSampled,
      falseProvenVuln: calibration.falseProvenVuln
    } : null,
    excluded: {
      outOfR1P5Candidates: audit ? audit.units.outOfR1Aggregates : 73,
      note: 'out-of-R1 只作 calibration；不计入 R1 P5 verdicts'
    }
  };
  return { rows, inScopeRows, summary };
}

function renderReport(summary, rows) {
  const lines = [];
  lines.push('# P5 R1 实现报告（权限提升/访问控制绕过）');
  lines.push('');
  lines.push(`生成时间：${summary.generatedAt}`);
  lines.push('');
  lines.push('## 1 范围与口径');
  lines.push('');
  lines.push('- 只做 **R1**：`base/account/os_account` + `foundation/communication/dsoftbus`。');
  lines.push('- 只做 IPC 权限/身份/对象校验；不做 SELinux/文件系统权限/进程模型。');
  lines.push('- 32 个 P5 聚合候选拆成 method-level unit；verdict 只来自 unit，不用聚合候选。');
  lines.push('- T1 `PROVEN-VULN` / T2 `PROVEN-WEAKNESS` / T3 `CONDITIONS-NOT-MET` / T4 negative（不写入 in-scope verdicts）。');
  lines.push('- out-of-R1 73 条 P5 候选不进入 R1 统计。');
  lines.push('');
  lines.push('## 2 数据/配对/检查/路径');
  lines.push('');
  if (summary.audit) {
    lines.push(`- R1 聚合候选 ${summary.audit.units.r1Aggregates}，unique entries ${summary.audit.units.uniqueEntries}，units ${summary.audit.units.units}。`);
    lines.push(`- 方向：service ${summary.audit.units.serviceUnits} / callback ${summary.audit.units.callbackUnits} / unknown ${summary.audit.units.unknownUnits}。`);
    lines.push(`- pairing：service resolved ${summary.audit.pairing.serviceResolved}/${summary.audit.pairing.service}（${summary.audit.pairing.serviceResolvedRate}），gap ${summary.audit.pairing.serviceGap}，overload ${summary.audit.pairing.overload}。`);
    lines.push(`- checks：${summary.audit.checks.total} 站点，${summary.audit.checks.checks} checks，${summary.audit.checks.identitySources} identity；server/client/unknown 分开。`);
    lines.push(`- paths：pathScoped ${summary.audit.paths.pathScoped}/${summary.audit.paths.service}（${summary.audit.paths.pathScopedRate}），noCheck ${summary.audit.paths.noCheckOnPath}，truncated ${summary.audit.paths.truncated}。`);
  }
  lines.push('');
  lines.push('## 3 Fixtures');
  lines.push('');
  if (summary.fixtures) {
    lines.push(`- 历史：pre VIOLATION ${summary.fixtures.historical.preViolation}/1，post SATISFIED ${summary.fixtures.historical.postSatisfied}/1。`);
    lines.push(`- Synthetic：original SATISFIED ${summary.fixtures.synthetic.originalSatisfied}/${summary.fixtures.synthetic.cases}，mutant VIOLATION ${summary.fixtures.synthetic.mutantViolation}/${summary.fixtures.synthetic.cases}。`);
    lines.push(`- fixture gate：${summary.fixtures.gate ? 'PASS' : 'FAIL'}。`);
  }
  lines.push('');
  lines.push('## 4 L4b / 校准');
  lines.push('');
  if (summary.l4b) {
    lines.push(`- L4b：simulated=${summary.l4b.simulated}，packs ${summary.l4b.ok}/${summary.l4b.packs}，schema ${summary.l4b.schemaSuccessRate}，refs ${summary.l4b.refsOkRate}，gate=${summary.l4b.gate}。`);
    lines.push(`- covers 分布：${JSON.stringify(summary.l4b.aggregates)}。`);
  } else {
    lines.push('- L4b 未运行。');
  }
  if (summary.calibration) {
    lines.push(`- 校准：${summary.calibration.rounds} 轮 / ${summary.calibration.samples} 样本，false PROVEN-VULN ${summary.calibration.falseProvenVuln}，pass=${summary.calibration.pass}。`);
  } else {
    lines.push('- 校准未运行。');
  }
  lines.push('');
  lines.push('## 5 Claim / Verdict');  lines.push('');
  lines.push(`- claim 总数 ${summary.claims.total}；tier 分布 ${JSON.stringify(summary.claims.byTier)}。`);
  const o3 = rows.reduce((a, r) => { const o = (r.obligations || []).find((x) => x.id === 'O3'); const k = o ? o.status : 'missing'; a[k] = (a[k] || 0) + 1; return a; }, {});
  const o2 = rows.reduce((a, r) => { const o = (r.obligations || []).find((x) => x.id === 'O2'); const k = o ? o.status : 'missing'; a[k] = (a[k] || 0) + 1; return a; }, {});
  const impact = rows.reduce((a, r) => { const k = r.impactStatus || 'not-assessed'; a[k] = (a[k] || 0) + 1; return a; }, {});
  lines.push(`- 身份闭合：O2 ${JSON.stringify(o2)}；O3 ${JSON.stringify(o3)}；impact ${JSON.stringify(impact)}。`);
  lines.push(`- 本仓新确认 P5 漏洞 **${summary.headline.newConfirmed}**；weak 候选 **${summary.headline.newWeak}**；conditions **${summary.headline.conditions}**；negative ${summary.headline.negative}。`);
  lines.push('');
  lines.push('| verdictId | interface | method | tier | claim | product | gap |');
  lines.push('| --- | --- | --- | --- | --- | --- | --- |');
  for (const r of rows) {
    lines.push(`| ${r.verdictId} | ${r.interface} | ${r.method} | ${r.tier} | ${r.claimVerdict} | ${r.productVerdict} | ${r.gapReason || '-'} |`);
  }
  lines.push('');
  lines.push('## 6 已知缺口');
  lines.push('');
  if (summary.l4b) {
    lines.push(`- L4b ${summary.l4b.simulated ? 'mock（live blocked）' : 'live'}：packs ${summary.l4b.ok}/${summary.l4b.packs}，schema ${summary.l4b.schemaSuccessRate}，covers ${JSON.stringify(summary.l4b.aggregates)}。`);
  } else {
    lines.push('- L4b 未运行。');
  }
  if (summary.calibration) {
    lines.push(`- 校准：${summary.calibration.rounds} 轮 / ${summary.calibration.samples} 样本，false PROVEN-VULN ${summary.calibration.falseProvenVuln}，pass=${summary.calibration.pass}。`);
  } else {
    lines.push('- 3 轮 P5 抽样复核未运行。');
  }
  lines.push(`- 当前 ${summary.headline.newWeak} 条 T2 是 claim-candidate；需人工复核 check 覆盖与身份语义。`);
  lines.push('- R1 single-entry 全部为 callback，single-service pairing 分母为 0。');
  lines.push('- out-of-R1 73 条未判定；window/notification 只作 calibration。');
  lines.push('');
  return lines.join('\n');
}

function writeP5Verdicts(result) {
  const p5dir = path.join(OUT_ROOT, 'p5');
  const verdictDir = path.join(OUT_ROOT, 'verdicts');
  const reportDir = path.join(OUT_ROOT, 'report');
  ensureDir(p5dir); ensureDir(verdictDir); ensureDir(reportDir);
  writeJsonl(path.join(p5dir, 'verdicts.jsonl'), result.rows);
  writeJsonl(path.join(verdictDir, 'p5-in-scope-verdicts.jsonl'), result.inScopeRows);
  writeJson(path.join(verdictDir, 'p5-summary.json'), result.summary);
  writeJson(path.join(p5dir, 'summary.json'), result.summary);
  fs.writeFileSync(path.join(reportDir, 'p5-implementation.md'), renderReport(result.summary, result.rows), 'utf8');
  return {
    rows: result.rows.length,
    inScopeRows: result.inScopeRows.length,
    files: ['out/p5/verdicts.jsonl', 'out/verdicts/p5-in-scope-verdicts.jsonl', 'out/verdicts/p5-summary.json', 'out/report/p5-implementation.md']
  };
}

module.exports = { tierOf, gapReason, buildP5Verdicts, writeP5Verdicts, renderReport };
