'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const OUT = path.join(__dirname, '..', 'out');
const readJsonl = (p) => fs.readFileSync(p, 'utf8').split(/\r?\n/).filter(Boolean).map((l) => JSON.parse(l));
const claims = readJsonl(path.join(OUT, 'p1p2p7p8', 'claims.jsonl')).filter((c) => c.class === 'P2');
const candidates = readJsonl(path.join(OUT, 'p1p2p7p8', 'p2-candidates.jsonl'));

test('P2 fixtures: 5 positive + 5 negative + >=6 local across >=2 components + CWE-416', () => {
  const { runP2Fixtures } = require('../lib/p1p2p7p8/fixtures.js');
  const fx = runP2Fixtures();
  assert.equal(fx.summary.gate, true, JSON.stringify(fx.summary.historyLocal.unavailable));
  assert.equal(fx.summary.positiveFixtures, 5);
  assert.equal(fx.summary.negativeFixtures, 5);
  assert.ok(fx.summary.localValidated >= 6);
  assert.ok(fx.summary.localRepos.length >= 2);
  assert.equal(fx.summary.historyPositive.validated, 1);
  assert.equal(fx.summary.synthetic.failed, 0);
});

test('P2 claims: D4 seed + >=8 total, no capture-only T2, no PROVEN-VULN', () => {
  assert.ok(claims.length >= 8, `claims=${claims.length}`);
  assert.ok(claims.some((c) => c.candidateId === 'cd_G-P2_623da2b57413'), 'P2 seed missing');
  assert.ok(claims.every((c) => c.productVerdict !== 'PROVEN-VULN' && c.t1Eligible === false));
  for (const c of claims) {
    assert.equal(c.obligations.length, 10, c.claimId);
    assert.equal(c.obligations.find((o) => o.id === 'O10').status, 'unproven', c.claimId);
  }
  for (const c of claims.filter((x) => !x.fixture && x.tier === 'T2-weak-candidate')) {
    const u = candidates.find((x) => x.unitId === c.unitId);
    assert.ok(u, c.claimId);
    assert.ok(['dangling-reference', 'free-without-anchor'].includes(u.lifetime.classification), `${c.claimId} ${u.lifetime.classification}`);
    assert.equal(u.lifetime.lifecycleEvidence, 'syntactic');
    assert.ok((u.lifetime.freeOps || []).length > 0 || u.lifetime.captureKind === 'reference');
  }
  assert.ok(claims.some((c) => !c.fixture && c.productVerdict === 'NOT-VULN'));
});

test('P2 synthetic negatives cover free-after-use / ownership / refcount / synchronized wait', () => {
  const { synthetic } = require('../eval/p1p2p7p8/p2/cases.js');
  const coverage = new Set(synthetic.filter((c) => c.kind === 'synthetic-negative').map((c) => c.expected.negativeCoverage));
  for (const k of ['refcount-hold', 'synchronized-wait', 'value-capture', 'ownership-transfer', 'lock-and-wait']) {
    assert.ok(coverage.has(k), k);
  }
});
