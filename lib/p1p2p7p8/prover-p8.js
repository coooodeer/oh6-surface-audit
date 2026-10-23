'use strict';

/**
 * prover-p8.js —— P8（逻辑漏洞）L4a 确定性判定。
 *
 * 反假阴性纪律：
 *   - “函数内没有校验调用”只是候选信号，不能直接判 T2；
 *   - 先判 invariant 是否适用（状态机/返回契约/生命周期），不适用 -> T4 或 T3；
 *   - 只有“适用 + 写点可见 + 无支配性守卫”才判 T2；
 *   - O10 固定 unproven。
 */

const {
  obligation, claimVerdictFor, productFor, tierOfProduct, stripLine
} = require('./common');
const { INVARIANTS } = require('./invariants');

function proveP8Candidate(u) {
  const a = u.analysis || {};
  const inv = u.invariant || {};
  const guardStatus = a.guardStatus || 'unproven';
  const guardReason = a.guardReason || null;
  const applicable = inv.applicable === true;
  const entryFile = u.entry && u.entry.file
    ? (u.entry.repo && u.entry.file.startsWith(u.entry.repo + '/') ? u.entry.file.slice(u.entry.repo.length + 1) : u.entry.file)
    : null;
  const sourceFileRaw = u.source && u.source.file;
  const sourceFile = sourceFileRaw && u.entry && u.entry.repo && sourceFileRaw.startsWith(u.entry.repo + '/')
    ? sourceFileRaw.slice(u.entry.repo.length + 1)
    : sourceFileRaw;
  const fn = u.source && u.source.function;
  const directEntry = Boolean(entryFile && sourceFile && entryFile === sourceFile && fn
    && u.entry.line >= fn.startLine && u.entry.line <= fn.endLine);
  const obligations = [
    obligation('O1', (u.entry && u.entry.id) ? 'proven' : 'unproven', {
      entryId: (u.entry && u.entry.id) || null,
      bindingScope: (u.entry && u.entry.bindingScope) || 'unknown',
      moduleInherited: (u.entry && u.entry.bindingScope) === 'module-inherited'
    }, (u.entry && u.entry.id) ? null : 'no-entry'),
    obligation('O2', u.source && u.source.text ? 'proven' : 'unproven', {
      writeKind: u.source && u.source.kind,
      file: u.source && u.source.file,
      line: u.source && u.source.line,
      stateVar: u.source && u.source.stateVar,
      text: u.source && u.source.text
    }, u.source && u.source.text ? null : 'write-point-missing'),
    obligation('O3', u.sink && u.sink.line ? 'proven' : 'unproven', {
      sinkKind: u.sink && u.sink.kind,
      file: u.sink && u.sink.file,
      line: u.sink && u.sink.line,
      stateVar: u.sink && u.sink.stateVar,
      lifecycleOp: u.sink && u.sink.lifecycleOp
    }, u.sink && u.sink.line ? null : 'state-change-point-missing'),
    obligation('O4', applicable ? 'proven' : 'disproven', {
      pattern: inv.pattern,
      authority: inv.authority,
      applicable,
      applicabilityReason: inv.applicabilityReason,
      proposition: (INVARIANTS[inv.pattern] || {}).proposition || null
    }, applicable ? null : 'invariant-not-applicable'),
    obligation('O5', guardStatus, {
      covering: a.covering || [],
      after: a.after || [],
      wrong: a.wrong || [],
      dead: a.dead || [],
      switchGuard: a.switchGuard || null,
      validationLikeCallInFunction: Boolean(a.validationLikeCallInFunction),
      generatorSaysNoValidationCall: Boolean(a.generatorSaysNoValidationCall)
    }, guardReason),
    obligation('O6', guardStatus, {
      coversWrite: (a.covering || []).length > 0,
      switchCoversState: Boolean(a.switchGuard),
      note: 'no-validation-call alone is not enough for T2'
    }, guardReason),
    obligation('O7', (u.entry && (u.entry.bindingScope === 'path-scoped' || directEntry)) ? 'proven' : 'unproven', {
      bindingScope: (u.entry && u.entry.bindingScope) || 'unknown',
      directEntry,
      entryFile: entryFile || null,
      entryLine: (u.entry && u.entry.line) || null,
      sourceFunction: fn || null
    }, directEntry ? null : 'module-inherited-entry'),
    obligation('O8', (u.entry && u.entry.id && u.entry.bindingScope === 'path-scoped') ? 'proven' : 'unproven', {
      entryCovered: Boolean(u.entry && u.entry.id)
    }, 'entry-binding-not-path-scoped'),
    obligation('O9', 'unproven', {
      impact: 'logic-invariant-static-only',
      basis: 'static',
      note: '静态影响；不写“已利用”'
    }, 'no-dynamic-oracle'),
    obligation('O10', 'unproven', { oracle: 'l5-deferred', basis: 'l5-deferred' }, 'l5-deferred')
  ];
  const v = claimVerdictFor(obligations, {
    structural: ['O1', 'O2', 'O3'],
    guardIds: ['O5', 'O6'],
    gapIds: ['O4', 'O7', 'O8'],
    notApplicableReason: 'p8-structural-fact-absent',
    satisfiedReason: guardReason === 'invariant-not-applicable' ? 'invariant-not-applicable' : 'guard-covers-write',
    violationReason: guardReason || 'no-dominating-guard',
    unprovenReason: 'p8-window-or-path-unproven'
  });
  const p = productFor(v.claimVerdict, {
    satisfiedReason: guardReason === 'invariant-not-applicable' ? 'invariant-not-applicable' : 'guard-covers-write',
    violationReason: guardReason || 'no-dominating-guard',
    unprovenReason: 'p8-window-or-path-unproven',
    notApplicableReason: 'p8-structural-fact-absent'
  });
  return {
    candidateId: u.candidateId,
    unitId: u.unitId,
    class: 'P8',
    obligations,
    claimVerdict: v.claimVerdict,
    claimReason: v.reason,
    productVerdict: p.productVerdict,
    productReason: p.reason,
    factValidation: 'confirmed',
    tier: tierOfProduct(p.productVerdict, 'confirmed'),
    t1Eligible: false
  };
}

// ---------------------------------------------------------------- fixtures

function analyzeP8FixtureSource(caseRow, sourceKey) {
  const src = caseRow.source && caseRow.source[sourceKey] != null
    ? caseRow.source[sourceKey]
    : caseRow[`${sourceKey}Source`];
  const cfg = {
    ...(caseRow.analysis || {}),
    ...((caseRow.analysisBySource && caseRow.analysisBySource[sourceKey]) || {})
  };
  if (typeof src !== 'string') return { verdict: 'UNPROVEN', reason: 'fixture-source-missing', evidence: {} };
  const lines = src.split(/\r?\n/);
  if (cfg.mode === 'guard-differential') {
    const guardRe = new RegExp(cfg.guardPattern);
    const guardIdx = lines.findIndex((l) => guardRe.test(l) && !/^\s*(\/\/|\*)/.test(l));
    const writeRe = cfg.writePattern ? new RegExp(cfg.writePattern) : null;
    const writeIdx = writeRe ? lines.findIndex((l) => writeRe.test(l)) : -1;
    const satisfied = guardIdx >= 0 && (writeIdx < 0 || guardIdx <= writeIdx);
    return {
      verdict: satisfied ? 'SATISFIED' : 'VIOLATION',
      reason: satisfied ? 'guard-dominates-write' : (guardIdx >= 0 ? 'guard-after-write' : 'guard-missing'),
      evidence: { guardLine: guardIdx + 1, writeLine: writeIdx + 1, invariant: cfg.invariant || null }
    };
  }
  const writeIdx = lines.findIndex((l) => (cfg.writePattern ? new RegExp(cfg.writePattern) : /(?:=|\+\+|--|delete|free|return)/).test(l));
  if (writeIdx < 0) return { verdict: 'UNPROVEN', reason: 'write-not-found', evidence: { lines: lines.length } };
  if (cfg.invariantApplicable === false) {
    return { verdict: 'SATISFIED', reason: 'invariant-not-applicable', evidence: { writeLine: writeIdx + 1 } };
  }
  const varMatch = /\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|\+\+|--)/.exec(stripLine(lines[writeIdx]));
  const vars = cfg.checkVars || (varMatch ? [varMatch[1]] : []);
  const { analyzeGuards } = require('./common');
  const g = analyzeGuards(lines, { targetVars: vars, sinkIndex: writeIdx });
  const enclosingGuard = (g.guards || []).find((x) => x.index <= writeIdx && writeIdx < (x.blockEnd || 0));
  const writeLine = stripLine(lines[writeIdx]);
  const successReturn = /return\s+(?:ERR_OK|true|0)\s*;/.test(writeLine);
  const failureCondition = enclosingGuard && /nullptr|NULL|!\s*[A-Za-z_]|<=?\s*0\b|!=\s*0\b/.test(enclosingGuard.condition);
  if (successReturn && failureCondition) {
    return {
      verdict: 'VIOLATION',
      reason: 'error-path-reports-success',
      evidence: { writeLine: writeIdx + 1, guardLine: enclosingGuard.line, guardCondition: enclosingGuard.condition, writeText: writeLine.trim() }
    };
  }
  let covering = (g.covering || []).filter((x) => x.targetMention && !x.dead && !x.deadAncestor);
  if (cfg.anyGuardCovers) covering = (g.guards || []).filter((x) => (x.exitBeforeSink || x.sinkInsideBlock) && !x.dead && !x.deadAncestor);
  const after = (g.after || []).filter((x) => x.targetMention);
  if (cfg.requireGuardPattern) {
    const re = new RegExp(cfg.requireGuardPattern);
    covering = covering.filter((x) => re.test(x.condition));
  }
  let verdict;
  let reason;
  if (cfg.expected === 'SATISFIED' && cfg.invariantApplicable !== false && !covering.length && !cfg.allowNoGuard) {
    // 合成负例必须由“守卫支配写点/不适用/异常路径合法”之一支撑；否则仍判 violation。
    verdict = (g.after || []).length ? 'VIOLATION' : 'VIOLATION';
    reason = 'no-dominating-guard';
  } else if (covering.length) {
    verdict = 'SATISFIED';
    reason = 'guard-dominates-write';
  } else if (after.length) {
    verdict = 'VIOLATION';
    reason = 'guard-after-write';
  } else {
    verdict = 'VIOLATION';
    reason = 'no-dominating-guard';
  }
  return { verdict, reason, evidence: { writeLine: writeIdx + 1, checkVars: vars, covering: covering.map((x) => ({ line: x.line, condition: x.condition })) } };
}

function proveP8Fixture(caseRow) {
  const rows = [];
  for (const key of ['pre', 'post', 'mutant', 'original']) {
    if (!(caseRow.source && caseRow.source[key] != null)) continue;
    rows.push({ sourceKey: key, ...analyzeP8FixtureSource(caseRow, key) });
  }
  return rows;
}

module.exports = { proveP8Candidate, analyzeP8FixtureSource, proveP8Fixture };
