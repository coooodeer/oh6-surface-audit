'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const OUT = path.join(__dirname, '..', 'out');
const readJson = (p) => JSON.parse(fs.readFileSync(p, 'utf8'));
const readJsonl = (p) => fs.readFileSync(p, 'utf8').split(/\r?\n/).filter(Boolean).map((l) => JSON.parse(l));
const claims = readJsonl(path.join(OUT, 'p1p2p7p8', 'claims.jsonl')).filter((c) => c.class === 'P8');
const summary = readJson(path.join(OUT, 'p1p2p7p8', 'summary.json'));

test('P8 claims: 24 claims covering 3 invariant patterns (8/8/8)', () => {
  assert.equal(claims.length, 24);
  const patterns = {};
  for (const c of claims) patterns[c.invariantPattern] = (patterns[c.invariantPattern] || 0) + 1;
  assert.equal(patterns['INV-PAT-STATE-GUARD'], 8);
  assert.equal(patterns['INV-PAT-RETURN-CONTRACT'], 8);
  assert.equal(patterns['INV-PAT-LIFECYCLE'], 8);
  assert.equal(summary.classes.P8.tiers.T1, 0);
});

test('P8 every claim has invariant authority, write point and guard status', () => {
  for (const c of claims) {
    assert.ok(c.invariantPattern, c.claimId);
    assert.ok(c.invariantAuthority && c.invariantAuthority.length > 20, c.claimId);
    assert.ok(c.source && c.source.file && c.source.line, c.claimId);
    assert.ok(c.sink && c.sink.kind, c.claimId);
    const o4 = c.obligations.find((o) => o.id === 'O4');
    const o5 = c.obligations.find((o) => o.id === 'O5');
    assert.ok(o4 && o5, c.claimId);
    assert.ok(['proven', 'disproven', 'unproven'].includes(o5.status), c.claimId);
    assert.equal(c.obligations.find((o) => o.id === 'O10').status, 'unproven', c.claimId);
  }
});

test('P8 T4 (guard/not-applicable) and T2 (applicable + no guard) are distinguishable', () => {
  assert.ok(claims.some((c) => c.tier === 'T4-negative'));
  assert.ok(claims.some((c) => String(c.tier || '').startsWith('T2')));
  for (const c of claims.filter((x) => String(x.tier || '').startsWith('T2'))) {
    const o4 = c.obligations.find((o) => o.id === 'O4');
    const o5 = c.obligations.find((o) => o.id === 'O5');
    assert.equal(o4.status, 'proven', c.claimId);
    assert.equal(o5.status, 'disproven', c.claimId);
  }
  assert.ok(claims.every((c) => c.productVerdict !== 'PROVEN-VULN'));
});

test('P8 fixtures: 3 invariants x 2 positive + 1 negative, local >=4', () => {
  const { runP8Fixtures } = require('../lib/p1p2p7p8/fixtures.js');
  const fx = runP8Fixtures();
  assert.equal(fx.summary.gate, true, JSON.stringify(fx.summary.historyLocal.unavailable));
  assert.equal(fx.summary.synthetic.total, 9);
  assert.equal(fx.summary.synthetic.failed, 0);
  assert.ok(fx.summary.localValidated >= 4);
  const mod = require('../eval/p1p2p7p8/p8/cases.js');
  const cov = new Set(mod.synthetic.filter((c) => c.kind === 'synthetic-negative').map((c) => c.expected.negativeCoverage));
  for (const k of ['invariant-not-applicable', 'validation-dominates-write', 'exception-path-legal']) assert.ok(cov.has(k), k);
});
