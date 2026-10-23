'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const OUT = path.join(__dirname, '..', 'out');
const readJson = (p) => JSON.parse(fs.readFileSync(p, 'utf8'));
const readJsonl = (p) => fs.readFileSync(p, 'utf8').split(/\r?\n/).filter(Boolean).map((l) => JSON.parse(l));

test('P3/P4/P6 provenance is explicit and production is target-only', () => {
  const s = readJson(path.join(OUT, 'verdicts', 'summary.json'));
  assert.equal(s.provenance.P3.productionEligible, 25);
  assert.equal(s.provenance.P3.byOrigin.target, 25);
  assert.equal(s.provenance.P4.byOrigin.target, 11);
  assert.equal(s.provenance.P4.byOrigin['external-cve'], 13);
  assert.equal(s.provenance.P4.productionEligible, 6);
  assert.equal(s.provenance.P6.byOrigin.target, 95);
  assert.equal(s.provenance.P6.byOrigin['miner-existing'], 20);
  assert.equal(s.provenance.P6.productionEligible, 95);
  const rows = readJsonl(path.join(OUT, 'verdicts', 'in-scope-verdicts.jsonl'));
  assert.ok(rows.length > 0);
  assert.ok(rows.every((r) => r.origin === 'target' && r.productionEligible === true && r.novelty === 'new'));
});

test('P4 external CVE claims are never production; target R1 are', () => {
  const claims = readJsonl(path.join(OUT, 'l3', 'p4-claims.jsonl'));
  for (const c of claims.filter((x) => x.group === 'cve-calibration')) {
    assert.equal(c.origin, 'external-cve');
    assert.equal(c.inTarget, false);
    assert.equal(c.productionEligible, false);
    assert.equal(c.novelty, 'not-applicable');
  }
  const target = claims.filter((c) => c.group === 'oh-candidate' && c.inTarget === true);
  assert.equal(target.length, 6);
  assert.ok(target.every((c) => c.productionEligible === true));
});

test('P5 provenance is target-only; no non-production claims', () => {
  const p5 = readJson(path.join(OUT, 'verdicts', 'p5-summary.json'));
  assert.equal(p5.provenance.productionEligible, 30);
  assert.equal(p5.provenance.nonProduction, 0);
  assert.deepEqual(p5.provenance.byOrigin, { target: 30 });
});
