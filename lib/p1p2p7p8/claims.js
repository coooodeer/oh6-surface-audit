'use strict';

/**
 * claims.js —— P1/P2/P7/P8 的 L3 claim 汇总。
 *
 * 每个 claim 都带统一 O1–O10；O10 固定 unproven（l5-deferred），t1Eligible=false。
 * production 资格只经 lib/candidate-origin.js 判定；fixture claim 永不 production。
 */

const {
  obligation, claimVerdictFor, productFor, tierOfProduct, provenanceOf, claimId, sha256
} = require('./common');
const { proveP1Candidate } = require('./prover-p1');
const { proveP2Candidate } = require('./prover-p2');
const { proveP7Candidate } = require('./prover-p7');
const { proveP8Candidate } = require('./prover-p8');

function fixtureObligations(cls, unit, productVerdict, opts = {}) {
  const violation = productVerdict === 'PROVEN-WEAKNESS';
  const status = violation ? 'disproven' : 'proven';
  return [
    obligation('O1', 'unproven', { fixture: true, note: 'fixture has no production entry binding' }, 'fixture-entry-not-production'),
    obligation('O2', 'proven', { fixture: true, source: unit.source || null }),
    obligation('O3', 'proven', { fixture: true, sink: unit.sink || null }),
    obligation('O4', 'proven', { fixture: true, classFact: cls, note: opts.classFact || 'fixture-class-fact' }),
    obligation('O5', status, { fixture: true, note: opts.guardNote || 'fixture-guard' }, violation ? (opts.violationReason || 'fixture-guard-missing') : null),
    obligation('O6', status, { fixture: true, note: 'fixture guard coverage' }, violation ? (opts.violationReason || 'fixture-guard-missing') : null),
    obligation('O7', 'unproven', { fixture: true }, 'fixture-path-not-production'),
    obligation('O8', 'unproven', { fixture: true }, 'fixture-entry-not-production'),
    obligation('O9', 'unproven', { fixture: true, impact: 'static-only' }, 'no-dynamic-oracle'),
    obligation('O10', 'unproven', { fixture: true, oracle: 'l5-deferred', basis: 'l5-deferred' }, 'l5-deferred')
  ];
}

function baseRow(cls, unit, proof, opts = {}) {
  const prov = unit.provenance || provenanceOf(unit);
  const isFixture = opts.fixture === true || prov.origin === 'oracle-fixture' || prov.constructed === true;
  if (!isFixture && !prov.productionEligible) {
    throw new Error(`${cls} claim ${unit.candidateId}: non-production candidate cannot enter production claims`);
  }
  const id = isFixture
    ? `L3-${cls}-FIX-${sha256(`${unit.unitId || unit.candidateId || unit.id}`).slice(0, 12)}`
    : claimId(cls, unit.unitId || unit.candidateId);
  return {
    claimId: id,
    class: cls,
    candidateId: unit.candidateId || unit.id,
    unitId: unit.unitId || `FIX-${sha256(String(unit.id || unit.candidateId)).slice(0, 12)}`,
    fixture: isFixture,
    entry: unit.entry || { id: null, kind: null, repo: unit.componentRoot || null, file: null, line: null, bindingScope: 'fixture' },
    source: unit.source || null,
    sink: unit.sink || null,
    obligations: proof.obligations,
    claimVerdict: proof.claimVerdict,
    claimReason: proof.claimReason || null,
    productVerdict: proof.productVerdict,
    productReason: proof.productReason || null,
    tier: proof.tier,
    t1Eligible: false,
    reason: 'no-dynamic-oracle',
    origin: prov.origin,
    dosClass: unit.dosClass || null,
    invariantPattern: unit.invariant ? unit.invariant.pattern : null,
    invariantAuthority: unit.invariant ? unit.invariant.authority : null,
    inTarget: prov.inTarget,
    codeState: prov.codeState,
    constructed: prov.constructed,
    productionEligible: prov.productionEligible,
    novelty: prov.novelty,
    fixtureExpected: opts.fixtureExpected || null,
    evidenceRefs: unit.evidenceRefs || (unit.source ? [`${unit.source.file}:${unit.source.line}`] : [])
  };
}

function p1FixtureClaim(row, cls = 'P1') {
  const key = row.actual.pre ? 'pre' : (row.actual.original ? 'original' : 'post');
  const actual = row.actual[key] || {};
  const productVerdict = actual.verdict === 'VIOLATION' ? 'PROVEN-WEAKNESS' : actual.verdict === 'SATISFIED' ? 'NOT-VULN' : 'CONDITIONS-NOT-MET';
  const unit = {
    candidateId: row.id,
    unitId: `FIX-${row.id}`,
    origin: 'oracle-fixture',
    inTarget: false,
    codeState: null,
    constructed: true,
    componentRoot: row.kind === 'history-positive' ? 'eval/history-positive' : 'eval/p1p2p7p8',
    source: { kind: 'fixture', file: `eval/p1p2p7p8/${cls.toLowerCase()}`, line: actual.evidence ? actual.evidence.sinkLine : 0 },
    sink: { kind: 'fixture-sink', line: actual.evidence ? actual.evidence.sinkLine : 0 },
    entry: { id: null, kind: null, repo: 'eval/p1p2p7p8', file: null, line: null, bindingScope: 'fixture' },
    evidenceRefs: [`eval/p1p2p7p8/${cls.toLowerCase()}/${row.id}`]
  };
  unit.provenance = provenanceOf(unit);
  const proof = {
    obligations: fixtureObligations(cls, unit, productVerdict, { violationReason: actual.reason }),
    claimVerdict: actual.verdict === 'VIOLATION' ? 'VIOLATION' : actual.verdict === 'SATISFIED' ? 'SATISFIED' : 'UNPROVEN',
    productVerdict,
    tier: tierOfProduct(productVerdict),
    claimReason: actual.reason || null,
    productReason: actual.reason || null
  };
  return baseRow(cls, unit, proof, { fixture: true, fixtureExpected: row.expected });
}

function buildP1Claims(facts, fixtures) {
  const claims = [];
  for (const unit of facts.units) {
    const proof = proveP1Candidate(unit);
    claims.push(baseRow('P1', unit, proof));
  }
  for (const group of [fixtures.synthetic.rows, fixtures.historyLocal.rows, fixtures.historyPositive.rows]) {
    for (const row of group) if (row.pass) claims.push(p1FixtureClaim(row, 'P1'));
  }
  return claims;
}

function buildP2Claims(facts, fixtures) {
  const claims = [];
  for (const unit of facts.units) {
    const proof = proveP2Candidate(unit);
    claims.push(baseRow('P2', unit, proof));
  }
  for (const group of [fixtures.synthetic.rows, fixtures.historyLocal.rows, fixtures.historyPositive.rows]) {
    for (const row of group) if (row.pass) claims.push(p1FixtureClaim(row, 'P2'));
  }
  return claims;
}

function buildP7Claims(facts, selectedUnits, fixtures) {
  const claims = [];
  for (const unit of selectedUnits) {
    const proof = proveP7Candidate(unit);
    claims.push(baseRow('P7', unit, proof));
  }
  // amplification 不足 6：用 fixture claim 补齐；fixture 不进入 D4 统计。
  const ampClaims = fixtures.fixtureClaims || [];
  for (const c of ampClaims) {
    const proved = require('./prover-p7').proveP7Fixture(c).find((x) => x.sourceKey === 'original');
    const productVerdict = proved && proved.verdict === 'VIOLATION' ? 'PROVEN-WEAKNESS' : 'NOT-VULN';
    const unit = {
      candidateId: c.id,
      unitId: `FIX-${c.id}`,
      origin: 'oracle-fixture',
      inTarget: false,
      codeState: null,
      constructed: true,
      componentRoot: 'eval/p1p2p7p8',
      dosClass: c.dosClass,
      source: { kind: 'fixture', file: 'eval/p1p2p7p8/p7', line: 0, attackerControlled: true, sizeTokens: [] },
      sink: { kind: c.dosClass, line: 0 },
      structure: { boundedInWindow: false },
      bound: { t4: false, basis: 'fixture' },
      amplification: { basis: 'static-proxy', note: 'fixture static proxy' },
      criteria: { anyMet: true, amplification: { met: true, basis: 'static-proxy' }, persistence: { met: false }, crossAppImpact: { met: false } },
      entry: { id: null, kind: null, repo: 'eval/p1p2p7p8', file: null, line: null, bindingScope: 'fixture' },
      analysis: { violationReason: proved ? proved.reason : 'fixture' },
      evidenceRefs: [`eval/p1p2p7p8/p7/${c.id}`]
    };
    unit.provenance = provenanceOf(unit);
    const proof = {
      obligations: fixtureObligations('P7', unit, productVerdict, { violationReason: proved && proved.reason, classFact: `amplification:${c.dosClass}` }),
      claimVerdict: productVerdict === 'PROVEN-WEAKNESS' ? 'VIOLATION' : 'SATISFIED',
      productVerdict,
      tier: tierOfProduct(productVerdict),
      claimReason: proved && proved.reason,
      productReason: proved && proved.reason
    };
    claims.push(baseRow('P7', unit, proof, { fixture: true }));
  }
  return claims;
}

function buildP8Claims(facts, selectedUnits) {
  const claims = [];
  for (const unit of selectedUnits) {
    const proof = proveP8Candidate(unit);
    claims.push(baseRow('P8', unit, proof));
  }
  return claims;
}

module.exports = {
  fixtureObligations, baseRow, p1FixtureClaim,
  buildP1Claims, buildP2Claims, buildP7Claims, buildP8Claims
};
