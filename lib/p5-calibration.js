'use strict';

/**
 * p5-calibration.js —— P5 §7.7 抽样复核（3 轮 × 10 accepted + 10 rejected）。
 *
 * 程序化复核：O1–O10 证据、file:line、verdict 真值表、T1 gating。
 * 语义复核：优先复用 P5 L4b 的 fresh-context check 覆盖结论；没有则记 programmatic。
 */

const fs = require('fs');
const path = require('path');
const { OUT_ROOT, ensureDir, writeJsonl, writeJson, sha256 } = require('./util.js');
const { p5Verdict, productForP5 } = require('./prover-p5.js');

const ACCEPTED = new Set(['PROVEN-VULN', 'PROVEN-WEAKNESS', 'VIOLATION']);
const REJECTED = new Set(['SATISFIED', 'NOT-VULN', 'NOT-APPLICABLE', 'CONDITIONS-NOT-MET']);

function stableHash(obj) {
  return sha256(JSON.stringify(obj)).slice(0, 16);
}
function holdout(id) {
  return parseInt(sha256(id).slice(0, 8), 16) % 5 === 0;
}
function stratify(rows) {
  const groups = new Map();
  for (const r of rows) {
    const k = `${r.entry.interface}|${r.claimVerdict}`;
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(r);
  }
  const buckets = [...groups.values()].sort((a, b) => a[0].claimId.localeCompare(b[0].claimId));
  const out = [];
  let i = 0;
  while (out.length < rows.length) {
    let added = false;
    for (const b of buckets) { if (b[i]) { out.push(b[i]); added = true; } }
    if (!added) break;
    i += 1;
  }
  return out;
}
function sample(rows, pred, n, offset) {
  const pool = stratify(rows.filter(pred));
  if (!pool.length) return [];
  const start = offset % pool.length;
  return [...pool.slice(start), ...pool.slice(0, start)].slice(0, n);
}

function truthTable(claim) {
  const v = p5Verdict(claim.obligations);
  const p = productForP5(v.claimVerdict, claim.obligations, claim.impact ? { impact: claim.impact } : { impactNotAssessed: true });
  return { claimVerdict: v.claimVerdict, productVerdict: p.productVerdict };
}

function programmaticCheck(claim) {
  const problems = [];
  if (!Array.isArray(claim.obligations) || claim.obligations.length !== 10) problems.push('obligation-count');
  for (const o of claim.obligations || []) {
    if (!o.id || !o.kind) problems.push(`obligation-missing:${o.id || '?'}`);
    if (!['proven', 'disproven', 'unproven', 'invalid'].includes(o.status)) problems.push(`bad-status:${o.id}`);
    if (!o.evidence || typeof o.evidence !== 'object' || !Object.keys(o.evidence).length) problems.push(`missing-evidence:${o.id}`);
  }
  const tt = truthTable(claim);
  if (tt.claimVerdict !== claim.claimVerdict) problems.push(`truth-table:${claim.claimVerdict}->${tt.claimVerdict}`);
  if (tt.productVerdict !== claim.productVerdict) problems.push(`product:${claim.productVerdict}->${tt.productVerdict}`);
  if (claim.productVerdict === 'PROVEN-VULN') {
    const o = (id) => claim.obligations.find((x) => x.id === id) || { status: 'unproven' };
    if (o('O10').status !== 'proven') problems.push('T1-without-O10');
    for (const id of ['O6', 'O7', 'O8']) if (o(id).status !== 'proven') problems.push(`T1-without-${id}`);
  }
  if (!claim.sink || !claim.sink.file || !claim.sink.line) problems.push('sink-file-line-missing');
  return { ok: problems.length === 0, problems, truthTable: tt };
}

function errorFor(claim, program, l4b) {
  if (!program.ok) return { errorType: 'evidence-mismatch', action: 'rollback-and-recheck' };
  if (!l4b) return { errorType: null, action: 'none' };
  if (l4b.aggregate && l4b.aggregate.covers === 'no') return { errorType: 'over-strict-obligation', action: 'keep-weakness-and-add-regression-case' };
  if (l4b.aggregate && l4b.aggregate.covers === 'unknown') return { errorType: 'review-inconclusive', action: 'record-only' };
  return { errorType: null, action: 'none' };
}

function runP5Calibration({ claims, l4bResults = [], rounds = 3, nPerSide = 10 }) {
  ensureDir(path.join(OUT_ROOT, 'report'));
  const l4bByClaim = new Map(l4bResults.map((r) => [r.claimId, r]));
  const acceptedPred = (c) => c.productVerdict === 'PROVEN-VULN' || c.productVerdict === 'PROVEN-WEAKNESS';
  const rejectedPred = (c) => REJECTED.has(c.claimVerdict) || c.productVerdict === 'NOT-VULN' || c.productVerdict === 'CONDITIONS-NOT-MET';
  const log = [];
  const roundSummaries = [];
  for (let round = 1; round <= rounds; round += 1) {
    const accepted = sample(claims, acceptedPred, nPerSide, (round - 1) * nPerSide);
    const rejected = sample(claims, rejectedPred, nPerSide, (round - 1) * nPerSide);
    const rows = [...accepted.map((c) => ({ c, side: 'accepted' })), ...rejected.map((c) => ({ c, side: 'rejected' }))];
    const roundRows = [];
    for (const { c, side } of rows) {
      const program = programmaticCheck(c);
      const l4b = l4bByClaim.get(c.claimId) || null;
      const reviewVerdict = program.ok
        ? (l4b ? (l4b.ok ? (l4b.aggregate && l4b.aggregate.covers) || 'unknown' : 'unknown') : 'supported-by-programmatic-checks')
        : 'unsupported-by-programmatic-checks';
      const error = errorFor(c, program, l4b);
      const row = {
        round,
        side,
        caseId: c.claimId,
        class: 'P5',
        unitId: c.unitId,
        interface: c.entry.interface,
        method: c.entry.method,
        originalVerdict: c.claimVerdict,
        originalProductVerdict: c.productVerdict,
        evidenceHash: stableHash({ claimId: c.claimId, obligations: c.obligations }),
        programmaticOk: program.ok,
        programmaticProblems: program.problems,
        reviewVerdict,
        reviewMethod: l4b ? 'l4b-fresh-context' : 'programmatic',
        reviewReason: l4b && l4b.aggregate ? `l4b covers=${l4b.aggregate.covers}` : '程序化复核通过',
        errorType: error.errorType,
        action: error.action,
        regressionCase: `out/p5/verdicts.jsonl#${c.claimId}`,
        holdout: holdout(c.claimId)
      };
      log.push(row);
      roundRows.push(row);
    }
    roundSummaries.push({
      round,
      accepted: roundRows.filter((x) => x.side === 'accepted').length,
      rejected: roundRows.filter((x) => x.side === 'rejected').length,
      programmaticUnsupported: roundRows.filter((x) => !x.programmaticOk).length,
      semanticReviewed: roundRows.filter((x) => x.reviewMethod === 'l4b-fresh-context').length,
      semanticUnsupported: roundRows.filter((x) => x.reviewVerdict === 'no').length,
      errorTypes: roundRows.reduce((a, x) => { if (x.errorType) a[x.errorType] = (a[x.errorType] || 0) + 1; return a; }, {})
    });
  }
  const logFile = path.join(OUT_ROOT, 'report', 'P5-CALIBRATION-LOG.jsonl');
  writeJsonl(logFile, log);
  const falsePV = log.filter((x) => x.originalProductVerdict === 'PROVEN-VULN' && x.reviewVerdict === 'no');
  const holdoutRows = log.filter((x) => x.holdout);
  const summary = {
    generatedAt: new Date().toISOString(),
    rounds: roundSummaries,
    totalSampled: log.length,
    accepted: log.filter((x) => x.side === 'accepted').length,
    rejected: log.filter((x) => x.side === 'rejected').length,
    programmaticUnsupported: log.filter((x) => !x.programmaticOk).length,
    semanticReviewed: log.filter((x) => x.reviewMethod === 'l4b-fresh-context').length,
    falseProvenVuln: falsePV.length,
    falseProvenVulnCases: falsePV,
    holdout: {
      rows: holdoutRows.length,
      accepted: holdoutRows.filter((x) => x.side === 'accepted').length,
      rejected: holdoutRows.filter((x) => x.side === 'rejected').length,
      supported: holdoutRows.filter((x) => x.reviewVerdict === 'yes' || x.reviewVerdict === 'supported-by-programmatic-checks').length,
      unsupported: holdoutRows.filter((x) => x.reviewVerdict === 'no' || x.reviewVerdict === 'unsupported-by-programmatic-checks').length
    },
    log: 'out/report/P5-CALIBRATION-LOG.jsonl',
    pass: roundSummaries.length >= 3 && log.filter((x) => !x.programmaticOk).length === 0 && falsePV.length === 0
  };
  writeJson(path.join(OUT_ROOT, 'report', 'p5-calibration-summary.json'), summary);
  fs.writeFileSync(path.join(OUT_ROOT, 'report', 'p5-calibration.md'), render(summary, log), 'utf8');
  return { log, summary };
}

function render(summary, log) {
  const lines = [];
  lines.push('# P5 校准报告（§7.7 抽样复核）');
  lines.push('');
  lines.push(`生成时间：${summary.generatedAt}`);
  lines.push('');
  lines.push('## 1 抽样与结论');
  lines.push('');
  lines.push(`- 轮次：${summary.rounds.length}；每轮 10 accepted + 10 rejected。`);
  lines.push(`- 总样本 ${summary.totalSampled}（accepted ${summary.accepted} / rejected ${summary.rejected}）。`);
  lines.push(`- 程序化复核不支持：${summary.programmaticUnsupported}；语义复核 ${summary.semanticReviewed} 次（复用 L4b fresh-context）。`);
  lines.push(`- false \`PROVEN-VULN\`：${summary.falseProvenVuln}。`);
  lines.push(`- holdout ${summary.holdout.rows} 条：supported ${summary.holdout.supported} / unsupported ${summary.holdout.unsupported}。`);
  lines.push(`- 门禁：${summary.pass ? 'PASS' : 'FAIL'}。`);
  lines.push('');
  lines.push('## 2 逐轮统计');
  lines.push('');
  lines.push('| 轮 | accepted | rejected | 程序化不支持 | 语义复核 | errorTypes |');
  lines.push('| ---: | ---: | ---: | ---: | ---: | --- |');
  for (const r of summary.rounds) lines.push(`| ${r.round} | ${r.accepted} | ${r.rejected} | ${r.programmaticUnsupported} | ${r.semanticReviewed} | ${JSON.stringify(r.errorTypes)} |`);
  lines.push('');
  lines.push('## 3 错误分类与动作');
  lines.push('');
  lines.push('| caseId | original | review | errorType | action |');
  lines.push('| --- | --- | --- | --- | --- |');
  for (const x of log.filter((r) => r.errorType)) lines.push(`| ${x.caseId} | ${x.originalVerdict} | ${x.reviewVerdict} | ${x.errorType} | ${x.action} |`);
  lines.push('');
  lines.push('## 4 口径');
  lines.push('');
  lines.push('- accepted = `PROVEN-VULN`/`PROVEN-WEAKNESS`/`VIOLATION`；rejected = `SATISFIED`/`NOT-VULN`/`NOT-APPLICABLE`/`CONDITIONS-NOT-MET`。');
  lines.push('- 程序化复核覆盖 O1–O10 证据、file:line、真值表、T1 gating；语义复核复用 P5 L4b 的 check 覆盖结论，不直接改 verdict。');
  lines.push('- 约 20% case 由 claimId 哈希固定为 holdout。');
  lines.push('');
  return lines.join('\n');
}

module.exports = { runP5Calibration, programmaticCheck, truthTable };
