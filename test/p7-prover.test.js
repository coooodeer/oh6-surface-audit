'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const OUT = path.join(__dirname, '..', 'out');
const readJson = (p) => JSON.parse(fs.readFileSync(p, 'utf8'));
const readJsonl = (p) => fs.readFileSync(p, 'utf8').split(/\r?\n/).filter(Boolean).map((l) => JSON.parse(l));
const claims = readJsonl(path.join(OUT, 'p1p2p7p8', 'claims.jsonl')).filter((c) => c.class === 'P7');
const summary = readJson(path.join(OUT, 'p1p2p7p8', 'summary.json'));

test('P7 claims: 24 claims, four dosClass each >=6', () => {
  assert.equal(claims.length, 24);
  const counts = {};
  for (const c of claims) {
    const cls = c.dosClass || (c.fixture ? 'amplification' : null);
    counts[cls] = (counts[cls] || 0) + 1;
  }
  for (const cls of ['unbounded-loop', 'unbounded-alloc', 'blocking-hold', 'amplification']) {
    assert.ok(counts[cls] >= 6, `${cls}=${counts[cls]}`);
  }
  assert.equal(summary.classes.P7.tiers.T1, 0);
});

test('P7 amplification is static-proxy, never measured ratio', () => {
  for (const c of claims.filter((x) => x.dosClass === 'amplification' || x.fixture)) {
    const o4 = c.obligations.find((o) => o.id === 'O4');
    assert.ok(o4);
    if (o4.evidence && o4.evidence.amplificationBasis) assert.equal(o4.evidence.amplificationBasis, 'static-proxy');
  }
  const audit = readJson(path.join(OUT, 'p1p2p7p8', 'data-audit.json'));
  assert.equal(audit.facts.P7.amplificationCandidates, 1);
});

test('P7 T4 and T2 are distinguishable; T3 has named reason', () => {
  assert.ok(claims.some((c) => c.tier === 'T4-negative'));
  assert.ok(claims.some((c) => String(c.tier || '').startsWith('T2')));
  const t3 = claims.filter((c) => c.tier === 'T3-instrumentation-gap');
  assert.ok(t3.length > 0);
  for (const c of t3) {
    const unproven = c.obligations.filter((o) => o.status === 'unproven' && o.reason);
    assert.ok(unproven.length > 0, c.claimId);
  }
  assert.ok(claims.every((c) => c.productVerdict !== 'PROVEN-VULN'));
});

test('P7 fixtures: 4 synthetic classes + external CVE validation and pre/post verdicts', () => {
  const { runP7Fixtures } = require('../lib/p1p2p7p8/fixtures.js');
  const fx = runP7Fixtures();
  assert.equal(fx.summary.gate, true, JSON.stringify(fx.external.rows.filter((r) => !r.pass)));
  assert.equal(fx.external.validation.ok, true);
  assert.equal(fx.external.summary.total, 4);
  const classes = new Set(fx.synthetic.rows.map((r) => {
    const c = require('../eval/p1p2p7p8/p7/cases.js').synthetic.find((x) => x.id === r.id);
    return c && c.dosClass;
  }));
  for (const cls of ['unbounded-loop', 'unbounded-alloc', 'blocking-hold', 'amplification']) assert.ok(classes.has(cls), cls);
});
