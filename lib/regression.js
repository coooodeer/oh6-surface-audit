'use strict';

/**
 * regression.js —— 回归哨兵（RG1、9 条历史正例、64 FP + 2 P7、P4 oracle 对账）。
 *
 * 只读消费 oh6-vuln-agent 的既有产物；不修改、不改判。
 */

const fs = require('fs');
const path = require('path');
const { WORKSPACE, OUT_ROOT, readJsonl, writeJson, writeJsonl, ensureDir } = require('./util.js');

const AGENT = path.join(WORKSPACE, 'oh6-vuln-agent');
const MINER = path.join(WORKSPACE, 'oh6-framework-want-leak-miner');
const HIST_POSITIVES = path.join(AGENT, 'result', 'optimization', 'historical-positive-agent-list-20261012-final', 'positives.jsonl');
const RG1_SPEC = path.join(AGENT, 'spec', 'rg1.json');
const NATIVE = path.join(AGENT, 'result', 'optimization', 'native-harness-20261014', 'per-candidate.jsonl');

const CLOSED = new Set(['NOT-VULN', 'NOT-APPLICABLE']);

function actionVerdictIndex(p6Verdicts) {
  const byAction = new Map();
  for (const v of p6Verdicts) {
    const a = v.action;
    if (!a) continue;
    if (!byAction.has(a)) byAction.set(a, []);
    byAction.get(a).push(v);
  }
  return byAction;
}

function bestProduct(verdicts) {
  const rank = { 'PROVEN-VULN': 5, 'PROVEN-WEAKNESS': 4, 'CONDITIONS-NOT-MET': 3, UNPROVEN: 2, 'NOT-VULN': 1, 'NOT-APPLICABLE': 0 };
  let best = null;
  for (const v of verdicts) {
    if (!best || (rank[v.productVerdict] || 0) > (rank[best.productVerdict] || 0)) best = v;
  }
  return best;
}

/** RG1 3 正 / 8 负 / 2 保护（fixture 级最小哨兵） */
function checkRG1(p6Verdicts, outDir) {
  const spec = JSON.parse(fs.readFileSync(RG1_SPEC, 'utf8'));
  const byAction = actionVerdictIndex(p6Verdicts);
  const positives = [];
  for (const p of spec.positive || []) {
    const rows = (p.actions || []).flatMap((a) => byAction.get(a) || []);
    const best = bestProduct(rows);
    const closed = !best || CLOSED.has(best.productVerdict);
    positives.push({
      id: p.id,
      actions: p.actions,
      claims: rows.length,
      bestVerdict: best ? best.productVerdict : null,
      bestReason: best ? best.reason : null,
      pass: !closed,
      expected: p.expected
    });
  }
  const negatives = [];
  for (const n of spec.negative || []) {
    const rows = (n.actions || []).flatMap((a) => byAction.get(a) || []);
    const best = bestProduct(rows);
    const bad = !!best && best.productVerdict === 'PROVEN-VULN';
    negatives.push({
      id: n.id,
      actions: n.actions,
      claims: rows.length,
      bestVerdict: best ? best.productVerdict : null,
      pass: !bad,
      confirmedFp: n.confirmedFp === true
    });
  }
  const protect = [];
  for (const p of spec.provisionalPositive || []) {
    const rows = (p.actions || []).flatMap((a) => byAction.get(a) || []);
    const best = bestProduct(rows);
    const closed = !best || CLOSED.has(best.productVerdict);
    protect.push({
      id: p.id,
      actions: p.actions,
      claims: rows.length,
      bestVerdict: best ? best.productVerdict : null,
      pass: !closed
    });
  }
  const summary = {
    spec: 'spec/rg1.json',
    labelRevision: spec.labelRevision,
    positive: { total: positives.length, pass: positives.filter((x) => x.pass).length, rows: positives },
    negative: { total: negatives.length, pass: negatives.filter((x) => x.pass).length, rows: negatives },
    provisionalPositive: { total: protect.length, pass: protect.filter((x) => x.pass).length, rows: protect },
    pass: positives.every((x) => x.pass) && negatives.every((x) => x.pass) && protect.every((x) => x.pass)
  };
  if (outDir) writeJson(path.join(outDir, 'rg1.json'), summary);
  return summary;
}

/** 9 条历史正例：不得被本管线的 NOT-VULN 静默关闭；未覆盖要显式登记。 */
function checkHistoricalPositives(verdicts, outDir) {
  if (!fs.existsSync(HIST_POSITIVES)) {
    return { total: 0, pass: false, reason: 'historical-positive-fixture-missing' };
  }
  const rows = readJsonl(HIST_POSITIVES);
  const index = new Map();
  for (const v of verdicts) {
    const key = `${v.repo || ''}\u0000${v.file || ''}`;
    if (!index.has(key)) index.set(key, []);
    index.get(key).push(v);
  }
  const results = [];
  for (const p of rows) {
    const roots = (p.roots || []).map((r) => ({
      repo: r.componentRoot,
      file: r.file,
      function: r.function
    }));
    const overlaps = [];
    for (const root of roots) {
      for (const [key, list] of index.entries()) {
        const [repo, file] = key.split('\u0000');
        if (file === root.file) {
          for (const v of list) {
            overlaps.push({
              claimId: v.claimId,
              repo,
              file,
              verdict: v.claimVerdict,
              productVerdict: v.productVerdict,
              closesOnThisRoot: CLOSED.has(v.productVerdict)
            });
          }
        }
      }
    }
    results.push({
      id: p.id,
      cwe: p.cwe && p.cwe.id,
      roots: roots.length,
      status: overlaps.some((o) => o.closesOnThisRoot) ? 'closed-by-pipeline' : (overlaps.length ? 'covered-not-closed' : 'not-covered'),
      overlaps,
      pass: !overlaps.some((o) => o.closesOnThisRoot)
    });
  }
  const summary = {
    fixture: path.relative(WORKSPACE, HIST_POSITIVES).split(path.sep).join('/'),
    total: results.length,
    notCovered: results.filter((r) => r.status === 'not-covered').length,
    covered: results.filter((r) => r.status !== 'not-covered').length,
    pass: results.every((r) => r.pass),
    rows: results
  };
  if (outDir) writeJson(path.join(outDir, 'historical-positives.json'), summary);
  return summary;
}

/** 64 FP + 2 P7：不得进 claim/正文；这里只检查是否被误收为 claim。 */
function checkFpReviewSet(claims, outDir) {
  const dirs = ['p8', 'p5', 'p3', 'remaining'].map((d) => path.join(AGENT, 'result', 'compare', `${d}-triage`));
  const rows = [];
  for (const dir of dirs) {
    if (!fs.existsSync(dir)) continue;
    for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.jsonl'))) {
      rows.push(...readJsonl(path.join(dir, f)));
    }
  }
  const ids = new Set();
  for (const r of rows) {
    const id = r.candidateId || r.unitId || r.id;
    if (id) ids.add(id);
  }
  const claimIds = new Set(claims.map((c) => c.claimId));
  const inClaims = [...ids].filter((id) => claimIds.has(id));
  const p7 = rows.filter((r) => r.verdict === 'true-positive-candidate');
  const fp = rows.filter((r) => r.verdict === 'false-positive');
  const summary = {
    scannedRows: rows.length,
    uniqueIds: ids.size,
    p7Rows: p7.length,
    p7Ids: p7.map((r) => r.unitId),
    fpRows: fp.length,
    claimsFromReviewSet: inClaims.length,
    pass: inClaims.length === 0 && fp.length === 64 && p7.length === 2,
    note: '66 = 64 FP + 2 P7 保护；P7 是受保护真候选，不得被当负例关闭'
  };
  if (outDir) writeJson(path.join(outDir, 'fp-review.json'), summary);
  return summary;
}

/** P4 oracle 对账：1 confirmed / 10 blocked（7 no-driver + 3 compile-failed） */
function checkP4Oracle(candidates, outDir) {
  const summaryPath = path.join(OUT_ROOT, 'p4', 'summary.json');
  const summary = fs.existsSync(summaryPath) ? JSON.parse(fs.readFileSync(summaryPath, 'utf8')) : null;
  const native = fs.existsSync(NATIVE) ? readJsonl(NATIVE) : [];
  const nativeById = new Map(native.map((r) => [r.candidateId, r]));
  const candidateIds = new Set(candidates.map((c) => c.candidateId));
  const rows = candidates.map((c) => {
    const n = nativeById.get(c.candidateId);
    return {
      candidateId: c.candidateId,
      candidateOracle: c.oracle ? c.oracle.state : null,
      candidateReason: c.oracle ? c.oracle.reason : null,
      nativeState: n ? n.state : null,
      nativeReason: n ? n.reason : null,
      match: !!n && n.state === (c.oracle && c.oracle.state)
    };
  });
  const confirmed = rows.filter((r) => r.nativeState === 'confirmed');
  const blocked = rows.filter((r) => r.nativeState === 'blocked');
  const reasons = blocked.reduce((a, r) => { a[r.nativeReason] = (a[r.nativeReason] || 0) + 1; return a; }, {});
  const allNative = {
    total: native.length,
    confirmed: native.filter((r) => r.state === 'confirmed').length,
    blocked: native.filter((r) => r.state === 'blocked').length
  };
  const summaryConsistent = !!summary
    && summary.oracle && summary.oracle.confirmed === confirmed.length && summary.oracle.blocked === blocked.length
    && summary.blockedReasons && summary.blockedReasons['no-driver-template'] === (reasons['no-driver-template'] || 0)
    && summary.blockedReasons['compile-failed'] === (reasons['compile-failed'] || 0);
  const result = {
    source: 'oh6-vuln-agent/result/optimization/native-harness-20261014/per-candidate.jsonl',
    candidates: candidates.length,
    nativeRowsTotal: native.length,
    allNative,
    confirmed: confirmed.map((r) => r.candidateId),
    blockedCount: blocked.length,
    blockedReasons: reasons,
    rows,
    summaryConsistent,
    pass: confirmed.length === 1 && confirmed[0].candidateId === 'cd_G-P4_52b62a535a33'
      && blocked.length === 10 && (reasons['no-driver-template'] || 0) === 7 && (reasons['compile-failed'] || 0) === 3
      && allNative.confirmed === 1 && allNative.blocked === 663 && summaryConsistent
  };
  if (outDir) writeJson(path.join(outDir, 'p4-oracle.json'), result);
  return result;
}

module.exports = {
  checkRG1,
  checkHistoricalPositives,
  checkFpReviewSet,
  checkP4Oracle,
  CLOSED
};
