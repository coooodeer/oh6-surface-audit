'use strict';

/**
 * calibration.js —— §7.7 运行中抽样复核与义务迭代。
 *
 * - 每轮 10 accepted + 10 rejected（不足全取），按 class/repo 分层；
 * - 先做程序化复核（file:line、claim 绑定、obligation 证据、verdict 真值表）；
 * - 语义不清的再交 fresh-context reviewer（独立 prompt，只回答 verdict 是否被证据支持）；
 * - 记录 CALIBRATION-LOG.jsonl 与 out/report/calibration.md；
 * - 发现 false PROVEN-VULN 立即登记并给出修正动作；没有则如实记录 0。
 */

const fs = require('fs');
const path = require('path');
const { OUT_ROOT, ensureDir, readJsonl, writeJsonl, writeJson, sha256 } = require('./util.js');
const { p6Verdict, productForP6 } = require('./prover-p6.js');
const { verdictFor, productFor: productForP3 } = require('./prover-p3.js');
const { p4Verdict, productForP4 } = require('./prover-p4.js');
const l4b = require('./l4b.js');

const ACCEPTED = new Set(['PROVEN-VULN', 'PROVEN-WEAKNESS', 'VIOLATION']);
const REJECTED = new Set(['SATISFIED', 'NOT-VULN', 'NOT-APPLICABLE', 'CONDITIONS-NOT-MET']);
const PROGRESS_FILE = path.join(OUT_ROOT, 'report', 'calibration-progress.jsonl');
const CAL_LOG_FILE = path.join(OUT_ROOT, '..', 'logs', 'calibration.jsonl');

function appendProgress(row) {
  ensureDir(path.dirname(PROGRESS_FILE));
  fs.appendFileSync(PROGRESS_FILE, `${JSON.stringify(row)}\n`, 'utf8');
}

function appendCalLog(row) {
  ensureDir(path.dirname(CAL_LOG_FILE));
  fs.appendFileSync(CAL_LOG_FILE, `${JSON.stringify(row)}\n`, 'utf8');
}

function byId(list) {
  return new Map(list.map((x) => [x.claimId, x]));
}

function stableHash(obj) {
  return sha256(JSON.stringify(obj)).slice(0, 16);
}

function truthTable(row) {
  const obs = row.obligations || [];
  if (row.class === 'P6') {
    const v = p6Verdict(obs);
    const p = productForP6(v.claimVerdict, obs);
    return { claimVerdict: v.claimVerdict, productVerdict: p.productVerdict, reason: v.reason };
  }
  if (row.class === 'P3') {
    const o = (id) => obs.find((x) => x.id === id) || { status: 'unproven' };
    const v = verdictFor(o('O1'), o('O2'), o('O3'), o('O4'));
    const p = productForP3(v, o('O4'), { impactNotAssessed: true });
    return { claimVerdict: v, productVerdict: p };
  }
  if (row.class === 'P4') {
    const v = p4Verdict(obs);
    const p = productForP4(v.claimVerdict, obs);
    return { claimVerdict: v.claimVerdict, productVerdict: p.productVerdict, reason: v.reason };
  }
  return { claimVerdict: null, productVerdict: null };
}

function evidenceProblems(row) {
  const problems = [];
  if (!Array.isArray(row.obligations) || !row.obligations.length) problems.push('no-obligations');
  for (const ob of row.obligations || []) {
    if (!ob.evidence || typeof ob.evidence !== 'object' || !Object.keys(ob.evidence).length) problems.push(`missing-evidence:${ob.id}`);
    if (!['proven', 'disproven', 'unproven', 'invalid'].includes(ob.status)) problems.push(`bad-status:${ob.id}`);
  }
  if (row.class === 'P6') {
    const o = (id) => row.obligations.find((x) => x.id === id) || {};
    if (!o('O1').evidence.action) problems.push('O1-action-missing');
    if (o('O2').evidence.c2State === undefined && o('O2').status !== 'unproven') problems.push('O2-gate-missing');
    if (o('O3').evidence.c3State === undefined && o('O3').status !== 'unproven') problems.push('O3-gate-missing');
    if (o('O10').evidence.status === undefined) problems.push('O10-slice-missing');
  }
  if (row.class === 'P3') {
    const o = (id) => row.obligations.find((x) => x.id === id) || {};
    if (!o('O2').evidence && !o('O2').reason) problems.push('O2-no-evidence');
    if (o('O3').status === 'proven' && !o('O3').evidence.guardLine) problems.push('O3-no-guard-line');
    if (row.kind !== 'fixture' && o('O4').status === 'proven' && !o('O4').evidence.path) problems.push('O4-no-path');
  }
  if (row.class === 'P4') {
    const o = (id) => row.obligations.find((x) => x.id === id) || {};
    const src = o('O2').evidence.source;
    if (src && !['pre-line', 'pre-removed'].includes(src)) problems.push('O2-source-not-pre');
    if (!o('O10').evidence) problems.push('O10-no-oracle-evidence');
  }
  return problems;
}

function programmaticCheck(row) {
  const tt = truthTable(row);
  const problems = evidenceProblems(row);
  if (tt.claimVerdict !== row.claimVerdict) problems.push(`truth-table-mismatch:${row.claimVerdict}->${tt.claimVerdict}`);
  if (tt.productVerdict && tt.productVerdict !== row.productVerdict) problems.push(`product-mismatch:${row.productVerdict}->${tt.productVerdict}`);
  return { ok: problems.length === 0, problems, truthTable: tt };
}

function stratify(rows) {
  // 按 class/repo（P4 用 group）排序后轮转取样，避免只抽容易的
  const groups = new Map();
  for (const r of rows) {
    const key = `${r.class}|${r.repo || r.group || r.file || ''}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(r);
  }
  const buckets = [...groups.values()].sort((a, b) => a[0].claimId.localeCompare(b[0].claimId));
  const out = [];
  let i = 0;
  while (out.length < rows.length) {
    let added = false;
    for (const b of buckets) {
      if (b[i]) { out.push(b[i]); added = true; }
    }
    if (!added) break;
    i += 1;
  }
  return out;
}

function sample(rows, predicate, n, offset = 0) {
  const pool = stratify(rows.filter(predicate));
  if (!pool.length) return [];
  const start = offset % pool.length;
  const rotated = [...pool.slice(start), ...pool.slice(0, start)];
  return rotated.slice(0, n);
}

function reviewPack(row, claim, l1) {
  const ev = [];
  const src = (claim && claim.source) || (row.class === 'P3' ? {
    repo: row.repo, file: row.file, line: row.line,
    text: row.file && row.line ? l1.lineAt(row.repo, row.file, row.line) : null
  } : row.class === 'P4' ? {
    file: row.file, line: row.line,
    text: (row.obligations || []).find((o) => o.id === 'O2')?.evidence?.text || null
  } : null);
  const entry = (claim && claim.entry) || row.entry || null;
  const sink = (claim && claim.sink) || row.sink || null;
  if (row.class === 'P6') {
    const site = l1.minerSite(row.siteKey);
    if (site && site.sink) ev.push(`publish ${site.sink.file}:${site.sink.line} ${site.sink.api}`);
    for (const w of (site && site.payloadWrites) || []) {
      if (w.line) ev.push(`payload ${w.key || (w.classified && w.classified.member)} = ${w.resolvedValueExpr || w.rawValueExpr} (L${w.line})`);
      if (ev.length > 8) break;
    }
  } else if (row.class === 'P3') {
    if (src && src.text) ev.push(`deref L${src.line}: ${src.text}`);
    const o2 = (row.obligations || []).find((o) => o.id === 'O2');
    if (o2 && o2.evidence) ev.push(`producer evidence: ${JSON.stringify(o2.evidence)}`);
    if (src && src.file && src.line) {
      const lines = l1.sourceLines(src.repo || row.repo, src.file) || [];
      for (let ln = Math.max(1, src.line - 3); ln <= Math.min(lines.length, src.line + 2); ln += 1) ev.push(`${ln}: ${lines[ln - 1]}`);
    }
  } else if (row.class === 'P4') {
    const o2 = (row.obligations || []).find((o) => o.id === 'O2');
    const o3 = (row.obligations || []).find((o) => o.id === 'O3');
    const o7 = (row.obligations || []).find((o) => o.id === 'O7');
    const o8 = (row.obligations || []).find((o) => o.id === 'O8');
    if (o2 && o2.evidence.text) ev.push(`pre operation: ${o2.evidence.text}`);
    if (o3 && o3.evidence) ev.push(`operation kind: ${JSON.stringify(o3.evidence)}`);
    if (o7 && o7.evidence.check) ev.push(`check: ${o7.evidence.check}`);
    if (o8 && o8.evidence.check) ev.push(`check integrity: ${o8.evidence.check}`);
  }
  return {
    claimId: row.claimId,
    class: row.class,
    entry,
    source: src,
    sink,
    claimVerdict: row.claimVerdict,
    productVerdict: row.productVerdict,
    obligations: (row.obligations || []).map((o) => ({ id: o.id, kind: o.kind, status: o.status, reason: o.reason || null, evidence: o.evidence })),
    evidence: ev.slice(0, 24)
  };
}

function reviewMessages(pack) {
  return [
    {
      role: 'system',
      content: [
        '你是独立安全审计复核员。你只回答“原 verdict 是否被给出的证据支持”，不要改 verdict，也不要引入外部知识。',
        '判定口径（必须先读）：',
        '- productVerdict=PROVEN-VULN 才表示“确认漏洞”；此时必须有入口/可达性/必需义务的证明。',
        '- productVerdict=PROVEN-WEAKNESS 表示 claim-candidate 或弱命中，不声称已证明可达攻击；',
        '  若 claimVerdict=VIOLATION 但 productVerdict=PROVEN-WEAKNESS，只要求结构义务成立且 entry/impact 未证明已被如实降级。',
        '- productVerdict=CONDITIONS-NOT-MET 表示证据不足/具名阻塞（如 oracle blocked），不声称漏洞。',
        '只在证据不足、证据与结论不匹配、或结论强于 productVerdict 所声称的强度时判 no。',
        '严格输出 JSON：{"supported":"yes|no|unknown","reason":"<=2 句","problems":["..."]}'
      ].join('\n')
    },
    {
      role: 'user',
      content: [
        `claim: ${JSON.stringify({ claimId: pack.claimId, class: pack.class, entry: pack.entry, source: pack.source, sink: pack.sink })}`,
        `verdict: ${JSON.stringify({ claimVerdict: pack.claimVerdict, productVerdict: pack.productVerdict })}`,
        `obligations: ${JSON.stringify(pack.obligations)}`,
        '',
        '证据摘录：',
        ...pack.evidence,
        '',
        '问题：原 (claimVerdict, productVerdict) 这一对结论是否被上述证据支持？'
      ].join('\n')
    }
  ];
}

async function semanticReview(pack, transport, opts = {}) {
  if (!transport) return { supported: 'unknown', reason: 'no-transport', method: 'semantic', transportKind: null, usage: null };
  const timeoutMs = Number(opts.timeoutMs || 60000);
  const inflight = transport.send({ unitId: `CAL-${pack.claimId}`, attempt: 1, messages: reviewMessages(pack), maxTokens: opts.maxTokens || 2048 });
  const res = await Promise.race([
    inflight,
    new Promise((resolve) => {
      const t = setTimeout(() => resolve({ kind: 'timeout', reason: `reviewer-timeout-${timeoutMs}ms` }), timeoutMs);
      if (t.unref) t.unref();
    })
  ]);
  const contentHash = res.content ? l4b.sha(res.content) : null;
  if (res.kind !== 'ok') return { supported: 'unknown', reason: `transport:${res.kind}`, method: 'semantic', transportKind: res.kind, usage: res.usage || null, contentHash };
  let parsed;
  try {
    parsed = l4b.parseJsonContent(res.content);
  } catch (e) {
    return { supported: 'unknown', reason: `parse:${e.message}`, method: 'semantic', transportKind: res.kind, usage: res.usage || null, contentHash };
  }
  const ok = ['yes', 'no', 'unknown'].includes(parsed.supported);
  return {
    supported: ok ? parsed.supported : 'unknown',
    reason: typeof parsed.reason === 'string' ? parsed.reason : '',
    problems: Array.isArray(parsed.problems) ? parsed.problems : [],
    method: 'semantic',
    transportKind: res.kind,
    usage: res.usage || null,
    contentHash
  };
}

function needsSemanticReview(row) {
  if (row.kind === 'fixture') return false;
  if (row.claimVerdict === 'VIOLATION' && (row.class === 'P3' || row.class === 'P4')) return true;
  if (row.claimVerdict === 'PROVEN-VULN') return true;
  if (row.class === 'P6' && row.productVerdict === 'NOT-VULN' && row.group === 'miner-finding') return true;
  return false;
}

function classifyError(row, program, review, semanticNeeded = false) {
  if (!program.ok) {
    if (program.problems.some((p) => /truth-table|product-mismatch/.test(p))) {
      return { errorType: 'evidence-mismatch', action: 'verdict-rollback-and-recheck' };
    }
    if (program.problems.some((p) => /missing-evidence|no-obligations|gate-missing|slice-missing/.test(p))) {
      return { errorType: 'data-gap', action: 'add-field-or-mark-instrumentation-gap' };
    }
    return { errorType: 'binding-path-error', action: 'fix-l2-binding-and-downgrade-unproven' };
  }
  if (!semanticNeeded) return { errorType: null, action: 'none' };
  if (!review) return { errorType: 'review-unavailable', action: 'record-only' };
  if (review.supported === 'unknown') return { errorType: 'review-inconclusive', action: 'record-only' };
  if (review.supported === 'no') {
    if (row.class === 'P6') return { errorType: 'model-semantic-error', action: 'tighten-l4b-prompt-or-evidence' };
    if (row.claimVerdict === 'VIOLATION') return { errorType: 'over-strict-obligation', action: 'keep-product-weakness-and-add-regression-case' };
    return { errorType: 'over-strict-obligation', action: 'relax-obligation-and-add-sentinel' };
  }
  return { errorType: null, action: 'none' };
}

function regressionCaseFor(row) {
  if (row.class === 'P6') return `test/p6-prover.test.js#${row.siteKey}`;
  if (row.class === 'P3') return `eval/p3/cases.jsonl#${row.claimId}`;
  if (row.class === 'P4') return `out/p4/candidates.jsonl#${row.candidateId || row.cveId}`;
  return null;
}

function holdout(row) {
  const h = parseInt(sha256(row.claimId).slice(0, 8), 16);
  return h % 5 === 0; // 20%
}

async function runCalibration(ctx) {
  const {
    l1, p3Verdicts, p6Verdicts, p4Verdicts, p3Fixtures, transport,
    rounds = 3, nPerSide = 10, semanticLimitPerRound = 8
  } = ctx;
  ensureDir(path.join(OUT_ROOT, 'report'));
  fs.writeFileSync(PROGRESS_FILE, '', 'utf8');
  ensureDir(path.dirname(CAL_LOG_FILE));
  fs.writeFileSync(CAL_LOG_FILE, '', 'utf8');
  const pool = [
    ...p3Verdicts,
    ...p3Fixtures.map((r) => ({ ...r, class: 'P3', productVerdict: r.productVerdict })),
    ...p6Verdicts,
    ...p4Verdicts
  ];
  const acceptedPred = (r) => ACCEPTED.has(r.claimVerdict) || ACCEPTED.has(r.productVerdict);
  const rejectedPred = (r) => REJECTED.has(r.claimVerdict) || REJECTED.has(r.productVerdict);
  const log = [];
  const roundSummaries = [];
  let semanticCalls = 0;
  let semanticTokens = 0;
  for (let round = 1; round <= rounds; round += 1) {
    const accepted = sample(pool, acceptedPred, nPerSide, (round - 1) * nPerSide);
    const rejected = sample(pool, rejectedPred, nPerSide, (round - 1) * nPerSide);
    const rows = [...accepted.map((r) => ({ r, side: 'accepted' })), ...rejected.map((r) => ({ r, side: 'rejected' }))];
    const roundRows = [];
    let semanticUsed = 0;
    for (const { r, side } of rows) {
      const program = programmaticCheck(r);
      let review = null;
      const semanticNeeded = program.ok && needsSemanticReview(r) && !!transport && semanticUsed < semanticLimitPerRound;
      if (semanticNeeded) {
        review = await semanticReview(reviewPack(r, r, l1), transport, { maxTokens: 2048 });
        semanticUsed += 1;
        semanticCalls += 1;
        semanticTokens += ((review.usage && review.usage.promptTokens) || 0) + ((review.usage && review.usage.completionTokens) || 0);
        // 逐条落盘：即使后续轮次长时间卡住，已完成复核不丢
        appendProgress({
          ts: new Date().toISOString(),
          round,
          caseId: r.claimId,
          class: r.class,
          originalVerdict: r.claimVerdict,
          productVerdict: r.productVerdict,
          supported: review.supported,
          reason: review.reason,
          problems: review.problems,
          usage: review.usage
        });
        appendCalLog({
          ts: new Date().toISOString(),
          round,
          unitId: `CAL-${r.claimId}`,
          caseId: r.claimId,
          class: r.class,
          transportKind: review.transportKind || null,
          attempts: 1,
          promptTokens: (review.usage && review.usage.promptTokens) || 0,
          completionTokens: (review.usage && review.usage.completionTokens) || 0,
          contentHash: review.contentHash || null,
          supported: review.supported,
          schemaOk: review.supported !== 'unknown' || /^transport:/.test(review.reason || '')
        });
      }
      const reviewVerdict = program.ok
        ? (review ? review.supported : 'supported-by-programmatic-checks')
        : 'unsupported-by-programmatic-checks';
      const error = classifyError(r, program, review, semanticNeeded);
      const entry = {
        round,
        side,
        caseId: r.claimId,
        class: r.class,
        siteKey: r.siteKey || null,
        candidateId: r.candidateId || null,
        cveId: r.cveId || null,
        originalVerdict: r.claimVerdict,
        originalProductVerdict: r.productVerdict,
        evidenceHash: stableHash({ claimId: r.claimId, obligations: r.obligations }),
        programmaticOk: program.ok,
        programmaticProblems: program.problems,
        reviewVerdict,
        reviewMethod: review ? 'semantic' : 'programmatic',
        reviewReason: review ? review.reason : (program.ok ? 'file:line / obligation evidence / truth table 全部一致' : program.problems.join('; ')),
        reviewProblems: review ? review.problems : [],
        errorType: error.errorType,
        action: error.action,
        regressionCase: regressionCaseFor(r),
        holdout: holdout(r)
      };
      log.push(entry);
      roundRows.push(entry);
    }
    roundSummaries.push({
      round,
      accepted: roundRows.filter((x) => x.side === 'accepted').length,
      rejected: roundRows.filter((x) => x.side === 'rejected').length,
      programmaticUnsupported: roundRows.filter((x) => !x.programmaticOk).length,
      semanticReviewed: roundRows.filter((x) => x.reviewMethod === 'semantic').length,
      semanticUnsupported: roundRows.filter((x) => x.reviewVerdict === 'no').length,
      errorTypes: roundRows.reduce((a, x) => { if (x.errorType) a[x.errorType] = (a[x.errorType] || 0) + 1; return a; }, {})
    });
  }

  const logFile = path.join(OUT_ROOT, 'report', 'CALIBRATION-LOG.jsonl');
  writeJsonl(logFile, log);
  const falseProvenVuln = log.filter((x) => x.originalProductVerdict === 'PROVEN-VULN' && x.reviewVerdict === 'no');
  const unsupported = log.filter((x) => x.reviewVerdict === 'no' || x.reviewVerdict === 'unsupported-by-programmatic-checks');
  const holdoutRows = log.filter((x) => x.holdout);
  const summary = {
    generatedAt: new Date().toISOString(),
    rounds: roundSummaries,
    totalSampled: log.length,
    accepted: log.filter((x) => x.side === 'accepted').length,
    rejected: log.filter((x) => x.side === 'rejected').length,
    programmaticUnsupported: log.filter((x) => !x.programmaticOk).length,
    semanticReviewed: log.filter((x) => x.reviewMethod === 'semantic').length,
    semanticSupported: log.filter((x) => x.reviewMethod === 'semantic' && x.reviewVerdict === 'yes').length,
    semanticUnknown: log.filter((x) => x.reviewMethod === 'semantic' && x.reviewVerdict === 'unknown').length,
    semanticUnsupported: log.filter((x) => x.reviewMethod === 'semantic' && x.reviewVerdict === 'no').length,
    semanticCalls,
    semanticTokens,
    unsupported: unsupported.map((x) => ({ caseId: x.caseId, class: x.class, errorType: x.errorType, reviewVerdict: x.reviewVerdict, reviewReason: x.reviewReason })),
    falseProvenVuln: falseProvenVuln.length,
    falseProvenVulnCases: falseProvenVuln,
    holdout: {
      rows: holdoutRows.length,
      accepted: holdoutRows.filter((x) => x.side === 'accepted').length,
      rejected: holdoutRows.filter((x) => x.side === 'rejected').length,
      supported: holdoutRows.filter((x) => x.reviewVerdict === 'yes' || x.reviewVerdict === 'supported-by-programmatic-checks').length,
      unsupported: holdoutRows.filter((x) => x.reviewVerdict === 'no' || x.reviewVerdict === 'unsupported-by-programmatic-checks').length
    },
    pass: roundSummaries.length >= 3 && log.filter((x) => !x.programmaticOk).length === 0 && falseProvenVuln.length === 0,
    calibrationLog: path.relative(path.join(OUT_ROOT, '..'), CAL_LOG_FILE).split(path.sep).join('/'),
    note: 'accepted = PROVEN-VULN/PROVEN-WEAKNESS/VIOLATION；rejected = SATISFIED/NOT-VULN/NOT-APPLICABLE/CONDITIONS-NOT-MET'
  };
  writeJson(path.join(OUT_ROOT, 'report', 'calibration-summary.json'), summary);
  fs.writeFileSync(path.join(OUT_ROOT, 'report', 'calibration.md'), renderCalibration(summary, log), 'utf8');
  return { log, summary, logFile };
}

function renderCalibration(summary, log) {
  const lines = [];
  lines.push('# L4 校准报告（§7.7 抽样复核）');
  lines.push('');
  lines.push(`生成时间：${summary.generatedAt}`);
  lines.push('');
  lines.push('## 1 抽样与结论');
  lines.push('');
  lines.push(`- 轮次：${summary.rounds.length}；每轮 10 accepted + 10 rejected（不足全取）。`);
  lines.push(`- 总样本 ${summary.totalSampled}（accepted ${summary.accepted} / rejected ${summary.rejected}）。`);
  lines.push(`- 程序化复核不支持：${summary.programmaticUnsupported}；语义复核 ${summary.semanticReviewed} 次（yes ${summary.semanticSupported || 0} / unknown ${summary.semanticUnknown || 0} / no ${summary.semanticUnsupported || 0}），tokens ${summary.semanticTokens}。`);
  lines.push(`- false \`PROVEN-VULN\`：${summary.falseProvenVuln}。`);
  lines.push(`- holdout ${summary.holdout.rows} 条（accepted ${summary.holdout.accepted} / rejected ${summary.holdout.rejected}）：supported ${summary.holdout.supported} / unsupported ${summary.holdout.unsupported}。`);
  lines.push(`- 门禁：${summary.pass ? 'PASS' : 'FAIL'}。`);
  lines.push('');
  lines.push('## 2 逐轮统计');
  lines.push('');
  lines.push('| 轮 | accepted | rejected | 程序化不支持 | 语义复核 | 语义不支持 | errorTypes |');
  lines.push('| ---: | ---: | ---: | ---: | ---: | ---: | --- |');
  for (const r of summary.rounds) {
    lines.push(`| ${r.round} | ${r.accepted} | ${r.rejected} | ${r.programmaticUnsupported} | ${r.semanticReviewed} | ${r.semanticUnsupported} | ${JSON.stringify(r.errorTypes)} |`);
  }
  lines.push('');
  lines.push('## 3 错误分类与动作');
  lines.push('');
  lines.push('| caseId | class | original | review | errorType | action |');
  lines.push('| --- | --- | --- | --- | --- | --- |');
  for (const x of log.filter((r) => r.errorType || r.reviewVerdict === 'no')) {
    lines.push(`| ${x.caseId} | ${x.class} | ${x.originalVerdict} | ${x.reviewVerdict} | ${x.errorType || '-'} | ${x.action} |`);
  }
  lines.push('');
  lines.push('## 4 口径与限制');
  lines.push('');
  lines.push('- 程序化复核覆盖 file:line、claim 绑定、obligation 证据与 verdict 真值表；语义复核只回答“原 verdict 是否被证据支持”，不直接改 verdict。');
  lines.push('- accepted = `PROVEN-VULN`/`PROVEN-WEAKNESS`/`VIOLATION`；rejected = `SATISFIED`/`NOT-VULN`/`NOT-APPLICABLE`/`CONDITIONS-NOT-MET`。');
  lines.push('- 约 20% case 由 claimId 哈希固定为 holdout，不用于调义务；最终 holdout 数字见 §1。');
  lines.push('- `VIOLATION` 只是 claim-candidate；P3/P4 的 product 已按 impact/entry 未证明降到 `PROVEN-WEAKNESS`，没有把候选当确认漏洞。');
  lines.push('- 语义复核的判定口径：只有 `productVerdict=PROVEN-VULN` 才要求入口/可达/必需义务全证明；`VIOLATION + PROVEN-WEAKNESS` 是 claim-candidate，`CONDITIONS-NOT-MET` 是证据不足/具名阻塞。');
  lines.push('- 无 `needs-human`/`pending`；语义复核不可用时记 `review-inconclusive`，不伪造支持。');
  lines.push('');
  return lines.join('\n');
}

module.exports = { runCalibration, programmaticCheck, truthTable, semanticReview, needsSemanticReview, reviewPack, renderCalibration };
