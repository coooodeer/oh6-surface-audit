'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const OUT = path.join(__dirname, '..', 'out');
const readJson = (p) => JSON.parse(fs.readFileSync(p, 'utf8'));
const audit = readJson(path.join(OUT, 'p1p2p7p8', 'data-audit.json'));

test('P1P2P7P8 audit: D4 baseline 1/1/660/821', () => {
  assert.equal(audit.baselineMatches, true);
  assert.deepEqual(audit.candidateCounts, { P1: 1, P2: 1, P7: 660, P8: 821 });
  assert.equal(audit.scope.roots.length, 5);
  for (const root of audit.scope.roots) {
    assert.ok(audit.d4Distribution[root] && audit.d4Distribution[root].total > 0, root);
  }
});

test('P1P2P7P8 audit: field completeness has no missing required signal fields', () => {
  for (const cls of ['P1', 'P2', 'P7', 'P8']) {
    const c = audit.fieldCompleteness[cls];
    for (const [field, missing] of Object.entries(c.missing)) {
      assert.equal(missing, 0, `${cls}.${field} missing=${missing}`);
    }
  }
  assert.equal(audit.fieldCompleteness.P1SignalOriginal.useSink, 1);
  assert.equal(audit.fieldCompleteness.P1SignalOriginal.boundCheckInWindow, 1);
});

test('P1P2P7P8 audit: local history classes and test/fuzz filter', () => {
  assert.equal(audit.localHistory.bounds.total, 6);
  assert.equal(audit.localHistory.bounds.product, 2);
  assert.equal(audit.localHistory.lifetime.total, 42);
  assert.equal(audit.localHistory.state.total, 7);
  assert.ok(audit.localHistory.bounds.testOrFuzz >= 1);
});

test('P1P2P7P8 audit: external CVE never production and validates', () => {
  assert.equal(audit.externalCve.ok, true);
  assert.equal(audit.externalCve.production, false);
  assert.equal(audit.externalCve.count, 4);
});

test('P1P2P7P8 audit: candidate-origin discipline self-check', () => {
  assert.equal(audit.candidateOrigin.pass, true);
  const names = audit.candidateOrigin.checks.map((c) => c.name);
  for (const n of ['external-never-production', 'fixed-never-production', 'snapshot-never-production', 'miner-current-head-production', 'target-current-head-production']) {
    assert.ok(names.includes(n), n);
  }
});
