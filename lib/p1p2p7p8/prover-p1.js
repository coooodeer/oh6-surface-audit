'use strict';

/**
 * prover-p1.js —— P1（内存破坏）L4a 确定性判定。
 *
 * 反假阴性纪律：
 *   - 只有“上界/容量”检查支配 sink 才算 O5/O6 proven；
 *   - 下界检查（len <= 0）、null 检查、sink 之后的检查、检查错变量、死分支都不算；
 *   - module-inherited 入口只能说明“部件内有入口”，不能单独支撑 T4；
 *   - O10 固定 unproven（l5-deferred），因此永不 PROVEN-VULN。
 */

const {
  obligation, claimVerdictFor, productFor, tierOfProduct,
  analyzeGuards, mentionsAny, stripLine
} = require('./common');
const { upperBoundLike } = require('./facts-p1');

function entryStatus(c) {
  const e = c.entry || {};
  if (!e.id) return { status: 'unproven', reason: 'no-entry' };
  if (e.bindingScope === 'path-scoped') return { status: 'proven', reason: null };
  return { status: 'proven', reason: null, scope: 'module-inherited' };
}

function proveP1Candidate(c) {
  const b = c.boundCheck || {};
  const a = c.analysis || {};
  const fn = (c.window && c.window.function) || {};
  const visible = fn.startLine != null && fn.endLine != null;
  const sinkKind = c.sink && c.sink.kind;
  const memorySink = ['alloc', 'memcpy', 'write', 'index', 'memset'].includes(sinkKind);
  const factValidation = memorySink ? 'confirmed' : 'needs-validation';
  const classFact = memorySink ? 'parcel-read-size-to-memory-sink' : 'parcel-read-size-to-non-memory-sink';
  const entry = entryStatus(c);
  const guardStatus = (b.covering && b.sameVariable && !b.deadBranch)
    ? 'proven'
    : ((b.afterSink || b.wrongVariable || b.deadBranch || (visible && !b.present)) ? 'disproven' : 'unproven');
  const guardReason = guardStatus === 'proven'
    ? null
    : (b.afterSink ? 'check-after-sink'
      : b.wrongVariable ? 'wrong-variable-check'
        : b.deadBranch ? 'check-in-dead-branch'
          : (visible && !b.present ? 'no-bound-check-before-sink' : 'window-not-visible'));
  const obligations = [
    obligation('O1', entry.status, {
      entryId: (c.entry && c.entry.id) || null,
      kind: (c.entry && c.entry.kind) || null,
      bindingScope: (c.entry && c.entry.bindingScope) || 'unknown',
      moduleInherited: (c.entry && c.entry.bindingScope) === 'module-inherited'
    }, entry.reason),
    obligation('O2', c.source && c.source.file ? 'proven' : 'disproven', {
      sourceKind: c.source && c.source.kind,
      file: c.source && c.source.file,
      line: c.source && c.source.line,
      var: c.source && c.source.var,
      vars: (c.source && c.source.vars) || []
    }, c.source && c.source.file ? null : 'source-missing'),
    obligation('O3', c.sink && c.sink.file ? 'proven' : 'disproven', {
      sinkKind: c.sink && c.sink.kind,
      callee: c.sink && c.sink.callee,
      file: c.sink && c.sink.file,
      line: c.sink && c.sink.line,
      sizeExpr: c.sink && c.sink.sizeExpr
    }, c.sink && c.sink.file ? null : 'sink-missing'),
    obligation('O4', 'proven', {
      classFact,
      sinkKind,
      memorySink,
      window: a.window,
      distance: a.distance,
      sizeArithmetic: a.sizeArithmetic,
      functionVisible: visible
    }),
    obligation('O5', guardStatus, {
      present: Boolean(b.present),
      covering: Boolean(b.covering),
      sameVariable: Boolean(b.sameVariable),
      afterSink: Boolean(b.afterSink),
      wrongVariable: Boolean(b.wrongVariable),
      deadBranch: Boolean(b.deadBranch),
      basis: b.basis || 'source-window',
      guards: (b.guards || []).filter((g) => g.upperBound).slice(0, 6)
    }, guardReason),
    obligation('O6', guardStatus === 'proven' ? 'proven' : (guardStatus === 'disproven' ? 'disproven' : 'unproven'), {
      coversSink: Boolean(b.covering && b.sameVariable),
      basis: b.basis || 'source-window'
    }, guardReason),
    obligation('O7', (c.entry && c.entry.bindingScope === 'path-scoped') ? 'proven' : 'unproven', {
      bindingScope: (c.entry && c.entry.bindingScope) || 'unknown',
      note: 'module-inherited 不能单独支撑 T4'
    }, (c.entry && c.entry.bindingScope === 'path-scoped') ? null : 'module-inherited-entry'),
    obligation('O8', (c.entry && c.entry.id && c.entry.bindingScope === 'path-scoped') ? 'proven' : 'unproven', {
      entryCovered: Boolean(c.entry && c.entry.id),
      bindingScope: (c.entry && c.entry.bindingScope) || 'unknown'
    }, 'entry-binding-not-path-scoped'),
    obligation('O9', 'unproven', {
      impact: 'memory-corruption-static-only',
      basis: 'static',
      note: '静态影响，不写“可利用”；无动态 oracle'
    }, 'no-dynamic-oracle'),
    obligation('O10', 'unproven', {
      oracle: 'l5-deferred',
      sanitizer: 'not-run',
      basis: 'l5-deferred'
    }, 'l5-deferred')
  ];
  const v = claimVerdictFor(obligations, {
    structural: ['O1', 'O2', 'O3'],
    guardIds: ['O5', 'O6'],
    gapIds: ['O4', 'O7', 'O8'],
    notApplicableReason: 'p1-structural-fact-absent',
    satisfiedReason: 'upper-bound-check-dominates-sink',
    violationReason: guardReason || 'no-dominating-upper-bound-check',
    unprovenReason: 'p1-window-or-path-unproven'
  });
  const p = productFor(v.claimVerdict, {
    satisfiedReason: 'upper-bound-check-dominates-sink',
    violationReason: guardReason || 'no-dominating-upper-bound-check',
    unprovenReason: 'p1-window-or-path-unproven',
    notApplicableReason: 'p1-structural-fact-absent'
  });
  return {
    claimId: c.claimId || null,
    candidateId: c.candidateId,
    unitId: c.unitId,
    class: 'P1',
    obligations,
    claimVerdict: v.claimVerdict,
    claimReason: v.reason,
    productVerdict: p.productVerdict,
    productReason: p.reason,
    factValidation,
    tier: tierOfProduct(p.productVerdict, factValidation),
    t1Eligible: false
  };
}

// ---------------------------------------------------------------- fixtures

function findSinkLine(lines, pattern) {
  const re = pattern instanceof RegExp ? pattern : new RegExp(pattern);
  for (let i = 0; i < lines.length; i += 1) {
    if (re.test(stripLine(lines[i]))) return i;
  }
  return -1;
}

/**
 * Fixture 级 P1 分析：只使用 caseRow.analysis 里的 sinkPattern / checkVars，
 * 与生产 prover 共用 upperBoundLike + 支配/死分支/错变量语义。
 */
function analyzeP1FixtureSource(caseRow, sourceKey) {
  const src = caseRow.source && caseRow.source[sourceKey] != null
    ? caseRow.source[sourceKey]
    : caseRow[`${sourceKey}Source`];
  const cfg = {
    ...(caseRow.analysis || {}),
    ...((caseRow.analysisBySource && caseRow.analysisBySource[sourceKey]) || {})
  };
  if (typeof src !== 'string' || !cfg.sinkPattern) {
    return { verdict: 'UNPROVEN', reason: 'fixture-source-or-pattern-missing', evidence: {} };
  }
  const lines = src.split(/\r?\n/);
  const sinkIdx = findSinkLine(lines, cfg.sinkPattern);
  if (sinkIdx < 0) return { verdict: 'UNPROVEN', reason: 'fixture-sink-not-found', evidence: { lines: lines.length } };
  const vars = cfg.checkVars || (cfg.sinkVar ? [cfg.sinkVar] : []);
  const checkRe = cfg.checkPattern ? new RegExp(cfg.checkPattern) : null;
  const g = analyzeGuards(lines, { targetVars: vars, sinkIndex: sinkIdx });
  const guards = g.guards.map((x) => ({
    line: x.line,
    kind: x.kind,
    condition: x.condition,
    targetMention: x.targetMention,
    coversSink: Boolean(x.coversSink),
    dead: x.dead,
    deadAncestor: Boolean(x.deadAncestor),
    upperBound: upperBoundLike(x.condition, x.kind === 'call' ? x.condition : ''),
    explicitCheck: Boolean(checkRe && checkRe.test(x.text))
  }));
  const bound = guards.filter((x) => x.upperBound || x.explicitCheck);
  const before = bound.filter((x) => x.line - 1 < sinkIdx);
  const covering = before.filter((x) => x.coversSink && !x.dead && !x.deadAncestor && x.targetMention);
  const after = bound.filter((x) => x.line - 1 > sinkIdx);
  const dead = before.filter((x) => x.dead || x.deadAncestor);
  const structurallyCovering = guards.filter((x) => (x.coversSink || x.dead) && x.line - 1 < sinkIdx);
  const wrong = structurallyCovering.filter((x) => !x.targetMention && x.condition && /[<>]=?|MAX|LIMIT|CAP/.test(x.condition));
  let loopBound = null;
  if (cfg.loopBoundPattern) {
    const re = new RegExp(cfg.loopBoundPattern);
    for (let i = Math.max(0, sinkIdx - 12); i <= sinkIdx; i += 1) {
      if (re.test(stripLine(lines[i]))) { loopBound = { line: i + 1, text: stripLine(lines[i]).trim() }; break; }
    }
  }
  let verdict = 'VIOLATION';
  let reason = 'no-dominating-upper-bound-check';
  if (covering.length || loopBound) {
    verdict = 'SATISFIED';
    reason = loopBound ? 'loop-bound-covers-sink' : 'upper-bound-check-dominates-sink';
  } else if (after.length) {
    reason = 'check-after-sink';
  } else if (wrong.length) {
    reason = 'wrong-variable-check';
  } else if (dead.length) {
    reason = 'check-in-dead-branch';
  }
  // 历史样本可以要求“修复后的见证必须存在且支配 sink”。
  if (cfg.requireGuard && !(guards.some((x) => x.explicitCheck && (x.coversSink || x.line - 1 < sinkIdx)))) {
    verdict = 'VIOLATION';
    reason = 'required-guard-missing';
  }
  return {
    verdict,
    reason,
    evidence: {
      sinkLine: sinkIdx + 1,
      sinkText: stripLine(lines[sinkIdx]).trim().slice(0, 200),
      checkVars: vars,
      covering: covering.map((x) => ({ line: x.line, condition: x.condition })),
      afterSink: after.map((x) => ({ line: x.line, condition: x.condition })),
      wrongVariable: wrong.map((x) => ({ line: x.line, condition: x.condition })),
      deadBranch: dead.map((x) => ({ line: x.line, condition: x.condition })),
      loopBound
    }
  };
}

function proveP1Fixture(caseRow) {
  const rows = [];
  for (const key of ['pre', 'post', 'mutant', 'original']) {
    if (!(caseRow.source && caseRow.source[key] != null)) continue;
    const a = analyzeP1FixtureSource(caseRow, key);
    rows.push({ sourceKey: key, ...a });
  }
  return rows;
}

module.exports = { proveP1Candidate, analyzeP1FixtureSource, proveP1Fixture, entryStatus };
