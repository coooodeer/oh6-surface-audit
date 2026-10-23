'use strict';

/**
 * prover-p7.js —— P7（拒绝服务）L4a 确定性判定。
 *
 * 反假阴性纪律：
 *   - amplification 只有 static-proxy，不能写成实测比率；
 *   - T4 必须有 literal cap / limiter / 明确有界（非攻击者可控）；
 *   - module-inherited 的 cross-app-impact 只算模块级线索，不能单独支撑 T2/T4 的跨应用结论；
 *   - T3 只用于缺 entry/结构/判据，必须具名；
 *   - O10 固定 unproven，永不 PROVEN-VULN。
 */

const {
  obligation, productFor, tierOfProduct, stripLine
} = require('./common');

function p7Verdict(obligations, u) {
  const o = (id) => obligations.find((x) => x.id === id) || { status: 'unproven' };
  if (o('O3').status === 'disproven' || o('O4').status === 'disproven') {
    return { claimVerdict: 'NOT-APPLICABLE', reason: 'structural-fact-absent' };
  }
  if (o('O5').status === 'proven' && o('O6').status === 'proven') {
    return { claimVerdict: 'SATISFIED', reason: (u.bound && u.bound.basis) || 'bounded-or-limited' };
  }
  if (o('O5').status === 'disproven' && o('O6').status === 'disproven') {
    if (o('O9').status === 'disproven') return { claimVerdict: 'UNPROVEN', reason: 'no-dos-criterion-evidence' };
    return { claimVerdict: 'VIOLATION', reason: (u.analysis && u.analysis.violationReason) || 'unbounded-or-unlimited' };
  }
  if (o('O1').status === 'unproven') return { claimVerdict: 'UNPROVEN', reason: 'entry-unproven' };
  if (o('O7').status !== 'proven' || o('O8').status !== 'proven') {
    return { claimVerdict: 'UNPROVEN', reason: 'path-or-entry-coverage-unproven' };
  }
  return { claimVerdict: 'UNPROVEN', reason: 'dos-data-incomplete' };
}

function proveP7Candidate(u) {
  const bound = u.bound || {};
  const criteria = u.criteria || {};
  const pathScoped = u.entry && u.entry.bindingScope === 'path-scoped';
  const crossAppReal = Boolean(criteria.crossAppImpact && criteria.crossAppImpact.met
    && !criteria.crossAppImpact.moduleInherited && pathScoped);
  const boundStatus = bound.t4 ? 'proven' : (u.source && u.source.attackerControlled ? 'disproven' : 'unproven');
  const boundReason = boundStatus === 'proven' ? null
    : (boundStatus === 'disproven' ? (u.analysis && u.analysis.violationReason) || 'no-literal-cap-or-limiter' : 'bound-data-missing');
  const o9Status = crossAppReal ? 'proven'
    : (criteria.anyMet ? 'unproven' : 'disproven');
  const obligations = [
    obligation('O1', (u.entry && u.entry.id) ? 'proven' : 'unproven', {
      entryId: (u.entry && u.entry.id) || null,
      bindingScope: (u.entry && u.entry.bindingScope) || 'unknown',
      bindingStatus: (u.entry && u.entry.bindingStatus) || 'unknown'
    }, (u.entry && u.entry.id) ? null : 'no-entry'),
    obligation('O2', (u.source && u.source.attackerControlled) ? 'proven' : 'unproven', {
      attackerControlled: Boolean(u.source && u.source.attackerControlled),
      sizeTokens: (u.source && u.source.sizeTokens) || [],
      conditionText: u.structure && u.structure.conditionText
    }, (u.source && u.source.attackerControlled) ? null : 'attacker-control-unproven'),
    obligation('O3', u.dosClass ? 'proven' : 'disproven', {
      dosClass: u.dosClass,
      sourceKind: u.source && u.source.kind,
      structure: u.structure
    }, u.dosClass ? null : 'dos-structure-missing'),
    obligation('O4', u.dosClass ? 'proven' : 'disproven', {
      dosClass: u.dosClass,
      classFact: 'dos-structural-fact',
      amplification: u.amplification,
      amplificationBasis: 'static-proxy',
      note: 'amplification 是静态代理，不是实测放大比'
    }, u.dosClass ? null : 'dos-class-fact-missing'),
    obligation('O5', boundStatus, {
      boundedInWindow: u.structure && u.structure.boundedInWindow,
      literalCaps: bound.literalCaps || [],
      limiter: Boolean(bound.limiter),
      boundedByInput: Boolean(bound.boundedByInput),
      basis: bound.basis,
      comparisons: bound.comparisons || []
    }, boundReason),
    obligation('O6', boundStatus, {
      sameInputBounded: Boolean(bound.t4),
      basis: bound.basis,
      note: 'literal cap / limiter 必须约束同一攻击者输入量'
    }, boundReason),
    obligation('O7', pathScoped ? 'proven' : 'unproven', {
      bindingScope: (u.entry && u.entry.bindingScope) || 'unknown',
      note: 'module-inherited 不能单独支撑跨应用结论'
    }, pathScoped ? null : 'module-inherited-entry'),
    obligation('O8', (u.entry && u.entry.id && pathScoped) ? 'proven' : 'unproven', {
      entryCovered: Boolean(u.entry && u.entry.id)
    }, 'entry-binding-not-path-scoped'),
    obligation('O9', o9Status, {
      criteria: {
        amplification: criteria.amplification,
        persistence: criteria.persistence,
        crossAppImpact: criteria.crossAppImpact
      },
      crossAppReal,
      note: 'static-proxy / module-inherited 只算线索，不算实测'
    }, o9Status === 'disproven' ? 'no-dos-criterion' : (crossAppReal ? null : 'criterion-not-runtime-proven')),
    obligation('O10', 'unproven', { oracle: 'l5-deferred', amplificationMeasurement: 'not-run', basis: 'l5-deferred' }, 'l5-deferred')
  ];
  const v = p7Verdict(obligations, u);
  const p = productFor(v.claimVerdict, {
    satisfiedReason: v.reason,
    violationReason: v.reason,
    unprovenReason: v.reason,
    notApplicableReason: 'p7-structural-fact-absent'
  });
  return {
    candidateId: u.candidateId,
    unitId: u.unitId,
    class: 'P7',
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

function analyzeP7FixtureSource(caseRow, sourceKey) {
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
  const sinkRe = new RegExp(cfg.sinkPattern);
  const sinkIdx = lines.findIndex((l) => sinkRe.test(stripLine(l)));
  if (sinkIdx < 0) return { verdict: 'UNPROVEN', reason: 'fixture-sink-not-found', evidence: { lines: lines.length } };
  const capRe = cfg.capPattern ? new RegExp(cfg.capPattern) : null;
  const guardRe = cfg.guardPattern ? new RegExp(cfg.guardPattern) : null;
  const capIdx = (capRe || guardRe) ? lines.findIndex((l) => (capRe && capRe.test(l)) || (guardRe && guardRe.test(l))) : -1;
  const cap = capIdx >= 0 && capIdx <= sinkIdx;
  const after = (capRe || guardRe) ? lines.findIndex((l, i) => i > sinkIdx && ((capRe && capRe.test(l)) || (guardRe && guardRe.test(l)))) : -1;
  let verdict;
  let reason;
  if (cap) { verdict = 'SATISFIED'; reason = 'literal-cap-or-limiter'; }
  else if (after >= 0) { verdict = 'VIOLATION'; reason = 'check-after-sink'; }
  else if ((cfg.criteria || []).length) { verdict = 'VIOLATION'; reason = (cfg.criteria || []).join('+'); }
  else { verdict = 'UNPROVEN'; reason = 'no-dos-criterion'; }
  return {
    verdict,
    reason,
    evidence: { sinkLine: sinkIdx + 1, capLine: capIdx + 1, afterLine: after + 1, amplitudeBasis: 'static-proxy' }
  };
}

function proveP7Fixture(caseRow) {
  const rows = [];
  for (const key of ['pre', 'post', 'mutant', 'original']) {
    if (!(caseRow.source && caseRow.source[key] != null)) continue;
    rows.push({ sourceKey: key, ...analyzeP7FixtureSource(caseRow, key) });
  }
  return rows;
}

module.exports = { proveP7Candidate, p7Verdict, analyzeP7FixtureSource, proveP7Fixture };
