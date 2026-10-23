'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const OUT = path.join(ROOT, 'out');
const readJson = (p) => JSON.parse(fs.readFileSync(p, 'utf8'));
const readJsonl = (p) => fs.readFileSync(p, 'utf8').split(/\r?\n/).filter(Boolean).map((l) => JSON.parse(l));

const gates = readJson(path.join(OUT, 'report', 'p1p2p7p8-run-summary.json'));
const summary = readJson(path.join(OUT, 'p1p2p7p8', 'summary.json'));
const claims = readJsonl(path.join(OUT, 'p1p2p7p8', 'claims.jsonl'));

test('P1P2P7P8 gates: 15/15 pass', () => {
  assert.equal(gates.allGatesPass, true);
  assert.equal(gates.gates.length, 15);
  assert.equal(gates.gates.filter((g) => g.pass).length, 15);
});

test('P1P2P7P8 artifacts: T1=0, no PROVEN-VULN, O10 all unproven', () => {
  assert.equal(summary.headline.T1, 0);
  assert.equal(summary.t1Eligible, false);
  assert.equal(summary.o10.unproven, summary.o10.total);
  for (const c of claims) {
    assert.notEqual(c.productVerdict, 'PROVEN-VULN', c.claimId);
    assert.equal(c.t1Eligible, false, c.claimId);
    assert.equal(c.obligations.find((o) => o.id === 'O10').status, 'unproven', c.claimId);
  }
});

test('P1P2P7P8 report and status files exist and state the headline', () => {
  const md = fs.readFileSync(path.join(OUT, 'report', 'p1p2p7p8-implementation.md'), 'utf8');
  assert.match(md, /T1=0/);
  assert.match(md, /L5/);
  assert.match(md, /static-proxy/);
  assert.match(md, /PROVEN-VULN/);
  assert.ok(fs.existsSync(path.join(ROOT, 'IMPLEMENTATION-STATUS-P1P2P7P8.md')));
});

test('P1P2P7P8 outputs are UTF-8 without BOM or U+FFFD', () => {
  for (const f of ['data-audit.json', 'claims.jsonl', 'verdicts.jsonl', 'summary.json']) {
    const buf = fs.readFileSync(path.join(OUT, 'p1p2p7p8', f));
    assert.ok(!(buf[0] === 0xEF && buf[1] === 0xBB && buf[2] === 0xBF), f);
    assert.ok(!buf.toString('utf8').includes('\uFFFD'), f);
  }
});

test('P1P2P7P8 regression: P3/P4/P6 and P5 summaries still pass', () => {
  const old = readJson(path.join(OUT, 'report', 'run-summary.json'));
  assert.equal(old.allGatesPass, true);
  const p5 = readJson(path.join(OUT, 'report', 'p5-run-summary.json'));
  assert.equal(p5.allGatesPass, true);
  assert.equal(p5.gates.length, 13);
  const p5Summary = readJson(path.join(OUT, 'verdicts', 'p5-summary.json'));
  assert.equal(p5Summary.headline.newConfirmed, 0);
});

test('P1P2P7P8 production scope: all non-fixture claims are D4 production', () => {
  const roots = new Set(summary.scope.roots);
  for (const c of claims.filter((x) => !x.fixture)) {
    assert.equal(c.productionEligible, true, c.claimId);
    assert.ok(roots.has(c.entry.repo), `${c.claimId} ${c.entry.repo}`);
    assert.equal(c.inTarget, true, c.claimId);
    assert.equal(c.codeState, 'current-head', c.claimId);
  }
  for (const c of claims.filter((x) => x.fixture)) assert.equal(c.productionEligible, false, c.claimId);
});
