'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const OUT = path.join(__dirname, '..', 'out');
const readJsonl = (p) => fs.readFileSync(p, 'utf8').split(/\r?\n/).filter(Boolean).map((l) => JSON.parse(l));
const claims = readJsonl(path.join(OUT, 'p1p2p7p8', 'claims.jsonl')).filter((c) => c.class === 'P1');
const candidates = readJsonl(path.join(OUT, 'p1p2p7p8', 'p1-candidates.jsonl'));

test('P1 fixtures: 5 positive + 5 negative + 2 local + 2 historical positives', () => {
  const { runP1Fixtures } = require('../lib/p1p2p7p8/fixtures.js');
  const fx = runP1Fixtures();
  assert.equal(fx.summary.gate, true, JSON.stringify(fx.summary.historyLocal.unavailable));
  assert.equal(fx.summary.positiveFixtures, 5);
  assert.equal(fx.summary.negativeFixtures, 5);
  assert.equal(fx.summary.historyPositive.validated, 2);
  assert.equal(fx.summary.historyLocal.validated, 2);
  assert.equal(fx.summary.historyLocal.preAlready, 1);
  assert.equal(fx.summary.synthetic.failed, 0);
});

test('P1 claims: real D4 seed + >=8 total, no PROVEN-VULN', () => {
  assert.ok(claims.length >= 8, `claims=${claims.length}`);
  assert.ok(claims.some((c) => c.candidateId === 'cd_G-P1_4ec01349f150'), 'P1 seed missing');
  assert.ok(claims.some((c) => c.productionEligible === true), 'no production P1 claim');
  assert.ok(claims.every((c) => c.productVerdict !== 'PROVEN-VULN'));
  assert.ok(claims.every((c) => c.t1Eligible === false));
  for (const c of claims) {
    assert.equal(c.obligations.length, 10, c.claimId);
    assert.equal(c.obligations.find((o) => o.id === 'O10').status, 'unproven', c.claimId);
  }
});

test('P1 real verdicts match source-window bound facts', () => {
  for (const c of claims.filter((x) => !x.fixture)) {
    const u = candidates.find((x) => x.unitId === c.unitId);
    assert.ok(u, c.claimId);
    if (u.analysis.bounded) {
      assert.equal(c.productVerdict, 'NOT-VULN', `${c.claimId} bounded should be T4`);
    } else {
      assert.equal(c.productVerdict, 'PROVEN-WEAKNESS', `${c.claimId} unbounded should be T2`);
    }
  }
  assert.ok(claims.some((c) => !c.fixture && c.productVerdict === 'NOT-VULN'));
  assert.ok(claims.some((c) => !c.fixture && c.productVerdict === 'PROVEN-WEAKNESS'));
});

test('P1 fixtures: expected pre/post/mutant verdicts all match', () => {
  const { runP1Fixtures } = require('../lib/p1p2p7p8/fixtures.js');
  const fx = runP1Fixtures();
  for (const row of [...fx.synthetic.rows, ...fx.historyLocal.rows, ...fx.historyPositive.rows]) {
    assert.equal(row.pass, true, `${row.id}: ${JSON.stringify(row.failures)}`);
    assert.ok(row.id && row.class === 'P1');
    assert.ok(row.expected && Object.keys(row.expected).length > 0);
  }
});
