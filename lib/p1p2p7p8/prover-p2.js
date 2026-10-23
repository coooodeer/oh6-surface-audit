'use strict';

/**
 * prover-p2.js —— P2（释放后使用 / 生命周期）L4a 确定性判定。
 *
 * 反假阴性纪律：
 *   - “存在 async capture”本身不是 UAF；
 *   - 只有所有权转移（异步体自己 delete/free）、引用计数持有（shared_ptr/sptr/GetSelf）、
 *     blocking join/wait、纯值捕获，才能判 T4；
 *   - `&local` 引用捕获 + detach、窗口内 free 且无 anchor 判 T2；
 *   - 只有 capture 没有任何生命周期证据 -> T3，不硬判 T2/T4。
 */

const {
  obligation, claimVerdictFor, productFor, tierOfProduct, analyzeGuards, stripLine, isCommentLine
} = require('./common');

function p2ObligationsFromUnit(u) {
  const l = u.lifetime || {};
  const t4 = ['ownership-transfer', 'refcount-hold', 'blocking-wait', 'value-capture'].includes(l.classification);
  const t2 = ['dangling-reference', 'free-without-anchor'].includes(l.classification);
  const anchorStatus = t4 ? 'proven' : (t2 ? 'disproven' : 'unproven');
  const guardStatus = t4 ? 'proven' : (t2 ? 'disproven' : 'unproven');
  const hasSink = Boolean(l.freeInsideLambda || (l.freeOps && l.freeOps.length));
  return [
    obligation('O1', (u.entry && u.entry.id) ? 'proven' : 'unproven', {
      entryId: (u.entry && u.entry.id) || null,
      bindingScope: (u.entry && u.entry.bindingScope) || 'unknown',
      moduleInherited: (u.entry && u.entry.bindingScope) === 'module-inherited'
    }, (u.entry && u.entry.id) ? null : 'no-entry'),
    obligation('O2', (u.source && u.source.captured && u.source.captured.length) ? 'proven' : 'disproven', {
      asyncKind: u.source && u.source.kind,
      asyncApi: u.source && u.source.api,
      captured: u.source && u.source.captured,
      captureKind: u.source && u.source.captureKind,
      lifecycleEvidence: 'syntactic'
    }, (u.source && u.source.captured && u.source.captured.length) ? null : 'no-capture'),
    obligation('O3', hasSink ? 'proven' : 'unproven', {
      sink: u.sink || null,
      freeInsideLambda: Boolean(l.freeInsideLambda),
      freeOps: l.freeOps || []
    }, hasSink ? null : 'no-lifecycle-sink-observed'),
    obligation('O4', anchorStatus, {
      classification: l.classification,
      classificationReason: l.classificationReason,
      captureKind: l.captureKind,
      refcountHold: Boolean(l.refcountHold),
      blockingWait: Boolean(l.blockingWait),
      ownershipTransfer: Boolean(l.ownershipTransfer),
      lockInWindow: Boolean(l.lockInWindow),
      lifecycleEvidence: 'syntactic'
    }, t4 ? null : (t2 ? l.classification : 'lifecycle-anchor-unproven')),
    obligation('O5', guardStatus, {
      freeOrdering: l.freeOps || [],
      freeInsideLambda: Boolean(l.freeInsideLambda),
      anchor: {
        refcountHold: Boolean(l.refcountHold),
        blockingWait: Boolean(l.blockingWait),
        lockInWindow: Boolean(l.lockInWindow)
      }
    }, t4 ? null : (t2 ? l.classification : 'lifecycle-order-unproven')),
    obligation('O6', guardStatus, {
      coversAsyncUse: t4,
      classification: l.classification,
      note: 'syntactic window; aliasing/smart-pointer ownership may be missed'
    }, t4 ? null : (t2 ? l.classification : 'lifecycle-coverage-unproven')),
    obligation('O7', (u.entry && u.entry.bindingScope === 'path-scoped') ? 'proven' : 'unproven', {
      bindingScope: (u.entry && u.entry.bindingScope) || 'unknown'
    }, 'module-inherited-entry'),
    obligation('O8', (u.entry && u.entry.id && u.entry.bindingScope === 'path-scoped') ? 'proven' : 'unproven', {
      entryCovered: Boolean(u.entry && u.entry.id)
    }, 'entry-binding-not-path-scoped'),
    obligation('O9', 'unproven', {
      impact: 'uaf-static-only',
      basis: 'static',
      note: '静态影响；不写可利用或已触发'
    }, 'no-dynamic-oracle'),
    obligation('O10', 'unproven', { oracle: 'l5-deferred', sanitizer: 'not-run', basis: 'l5-deferred' }, 'l5-deferred')
  ];
}

function proveP2Candidate(u) {
  const obligations = p2ObligationsFromUnit(u);
  const v = claimVerdictFor(obligations, {
    structural: ['O1', 'O2', 'O3'],
    guardIds: ['O5', 'O6'],
    gapIds: ['O4', 'O7', 'O8'],
    notApplicableReason: 'p2-structural-fact-absent',
    satisfiedReason: 'lifetime-anchor-or-ownership-proven',
    violationReason: u.lifetime ? u.lifetime.classificationReason : 'lifecycle-order-unproven',
    unprovenReason: 'p2-lifecycle-evidence-unproven'
  });
  const p = productFor(v.claimVerdict, {
    satisfiedReason: 'lifetime-anchor-or-ownership-proven',
    violationReason: 'free-delete-interleaved-without-ownership-proof',
    unprovenReason: 'p2-lifecycle-evidence-unproven',
    notApplicableReason: 'p2-structural-fact-absent'
  });
  return {
    candidateId: u.candidateId,
    unitId: u.unitId,
    class: 'P2',
    obligations,
    claimVerdict: v.claimVerdict,
    claimReason: v.reason,
    productVerdict: p.productVerdict,
    productReason: p.reason,
    factValidation: (!u.source || !u.source.captureType) && u.source && u.source.captureKind === 'raw-pointer'
      ? 'needs-validation' : 'confirmed',
    tier: tierOfProduct(p.productVerdict, (!u.source || !u.source.captureType) && u.source && u.source.captureKind === 'raw-pointer'
      ? 'needs-validation' : 'confirmed'),
    t1Eligible: false
  };
}

// ---------------------------------------------------------------- fixtures

function detectCaptureVars(src, cfg) {
  if (cfg.captured && cfg.captured.length) return cfg.captured;
  const m = /\[([^\]]*)\]/.exec(src);
  if (!m) return [];
  return m[1].split(',').map((x) => x.trim().replace(/^&/, '').split('=')[0].trim()).filter(Boolean);
}

function classifyP2Source(src, cfg = {}) {
  const text = String(src || '');
  const lines = text.split(/\r?\n/);
  const capLine = lines.findIndex((l) => (cfg.capturePattern ? new RegExp(cfg.capturePattern).test(l) : /\[[^\]]+\]\s*\(/.test(l)));
  if (cfg.mode === 'guard-differential') {
    const guardRe = new RegExp(cfg.guardPattern);
    const guardLine = lines.findIndex((l) => guardRe.test(l) && !isCommentLine(l));
    const sinkIdx = cfg.sinkPattern ? lines.findIndex((l) => new RegExp(cfg.sinkPattern).test(l)) : -1;
    const beforeSink = guardLine >= 0 && (sinkIdx < 0 || guardLine < sinkIdx);
    return {
      verdict: beforeSink ? 'SATISFIED' : 'VIOLATION',
      classification: beforeSink ? 'blocking-wait' : 'free-without-anchor',
      reason: beforeSink ? 'guard-present' : (guardLine >= 0 ? 'guard-after-sink' : 'guard-missing'),
      evidence: { guardLine: guardLine + 1, sinkLine: sinkIdx + 1, guardPattern: cfg.guardPattern }
    };
  }
  if (capLine < 0) return { verdict: 'UNPROVEN', reason: 'capture-not-found', evidence: {} };
  const capVars = detectCaptureVars(lines[capLine], cfg);
  const bracket = /\[([^\]]*)\]/.exec(lines[capLine]);
  const byRef = Boolean(bracket && /(^|,)\s*&/.test(bracket[1]));
  const isThis = /\bthis\b/.test(lines[capLine]) && !cfg.captureKind;
  const scalarDecl = capVars.find((v) => new RegExp(`\\b(?:int|int32_t|uint32_t|uint64_t|int64_t|bool|size_t|long)\\s+${v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`).test(text));
  const kind = cfg.captureKind || (isThis ? 'this' : byRef ? 'reference' : (cfg.kind === 'value' || scalarDecl) ? 'value' : 'raw-pointer');
  const window = lines.slice(capLine, Math.min(lines.length, capLine + 40)).join('\n');
  let lambdaEnd = -1;
  for (let i = capLine; i < Math.min(lines.length, capLine + 40); i += 1) {
    if (/\}\s*\)\s*(?:\.detach\(\))?\s*;?/.test(stripLine(lines[i]))) { lambdaEnd = i; break; }
  }
  const freeIdx = cfg.freePattern
    ? lines.findIndex((l) => new RegExp(cfg.freePattern).test(l))
    : lines.findIndex((l) => /\b(delete|free)\s*[(_A-Za-z]/.test(l));
  const freeInsideLambda = cfg.freeInsideLambda != null
    ? Boolean(cfg.freeInsideLambda)
    : (freeIdx >= 0 && lambdaEnd >= 0 && freeIdx > capLine && freeIdx <= lambdaEnd);
  const join = /\.join\s*\(|\bjoin\s*\(/.test(window);
  const wait = /\.wait\s*\(|\bWait\s*\(|\bwait\s*\(/i.test(window);
  const smart = /std::(?:shared_ptr|weak_ptr|unique_ptr)|sptr<|GetSelf\s*\(|shared_from_this\s*\(/.test(text);
  const lock = /lock_guard|unique_lock/.test(window);
  const detached = /\.detach\s*\(\)/.test(text);
  let classification;
  if (cfg.classification) classification = cfg.classification;
  else if (cfg.kind === 'value' || kind === 'value') classification = 'value-capture';
  else if (freeInsideLambda) classification = 'ownership-transfer';
  else if (smart && kind !== 'this') classification = 'refcount-hold';
  else if (join || wait) classification = 'blocking-wait';
  else if (kind === 'reference' && detached) classification = 'dangling-reference';
  else if (freeIdx >= 0 && !lock) classification = 'free-without-anchor';
  else classification = 'no-lifecycle-evidence';
  const t4 = ['ownership-transfer', 'refcount-hold', 'blocking-wait', 'value-capture'].includes(classification);
  const t2 = ['dangling-reference', 'free-without-anchor'].includes(classification);
  return {
    verdict: t4 ? 'SATISFIED' : (t2 ? 'VIOLATION' : 'UNPROVEN'),
    classification,
    reason: classification,
    evidence: {
      captureLine: capLine + 1,
      captured: capVars,
      captureKind: kind,
      freeLine: freeIdx + 1,
      freeInsideLambda,
      join,
      wait,
      smart,
      detached,
      lock,
      lifecycleEvidence: 'syntactic'
    }
  };
}

function analyzeP2FixtureSource(caseRow, sourceKey) {
  const src = caseRow.source && caseRow.source[sourceKey] != null
    ? caseRow.source[sourceKey]
    : caseRow[`${sourceKey}Source`];
  const cfg = {
    ...(caseRow.analysis || {}),
    ...((caseRow.analysisBySource && caseRow.analysisBySource[sourceKey]) || {})
  };
  if (typeof src !== 'string') return { verdict: 'UNPROVEN', reason: 'fixture-source-missing', evidence: {} };
  return classifyP2Source(src, cfg);
}

function proveP2Fixture(caseRow) {
  const rows = [];
  for (const key of ['pre', 'post', 'mutant', 'original']) {
    if (!(caseRow.source && caseRow.source[key] != null)) continue;
    rows.push({ sourceKey: key, ...analyzeP2FixtureSource(caseRow, key) });
  }
  return rows;
}

module.exports = { proveP2Candidate, p2ObligationsFromUnit, classifyP2Source, analyzeP2FixtureSource, proveP2Fixture };
