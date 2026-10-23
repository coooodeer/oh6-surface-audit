'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const OUT = path.join(ROOT, 'out');
const readJson = (p) => JSON.parse(fs.readFileSync(p, 'utf8'));
const readJsonl = (p) => fs.readFileSync(p, 'utf8').split(/\r?\n/).filter(Boolean).map((l) => JSON.parse(l));

test('pipeline artifacts exist: L3 claims, L4a verdicts, L4b results, reports', () => {
  for (const f of [
    'l3/p3-claims.jsonl', 'l3/p6-claims.jsonl', 'l3/p4-claims.jsonl', 'l3/summary.json',
    'l4a/p3-verdicts.jsonl', 'l4a/p6-verdicts.jsonl', 'l4a/p4-verdicts.jsonl', 'l4a/summary.json',
    'l4b/results.jsonl', 'l4b/summary.json',
    'verdicts/in-scope-verdicts.jsonl', 'verdicts/summary.json',
    'report/implementation.md', 'report/run-summary.json', 'report/rg1.json', 'report/p4-oracle.json',
    'report/in-scope-findings.md', 'report/token-ledger.json'
  ]) {
    assert.ok(fs.existsSync(path.join(OUT, f)), f);
  }
});

test('L3 claim counts: 25 P3 / 115 P6 / 24 P4; schema errors 0', () => {
  const s = readJson(path.join(OUT, 'l3', 'summary.json'));
  assert.equal(s.p3.selected, 25);
  assert.equal(s.p6.total, 115);
  assert.equal(s.p4.total, 24);
  assert.equal(s.schemaErrors.length, 0);
  assert.equal(s.p3.unboundReclassified, 68);
  assert.equal(s.p3.callgraphNameOnly, 25);
});

test('L4a summary gates: P3 fixtures, P6 reconciliation, P4 oracle, RG1', () => {
  const s = readJson(path.join(OUT, 'l4a', 'summary.json'));
  assert.equal(s.p3.fixtureGate.originalSatisfied, 10);
  assert.equal(s.p3.fixtureGate.mutantViolation, 10);
  assert.equal(s.p6.reconcile.allNotVuln, true);
  assert.equal(s.p6.reconcile.foundInMiner, 95);
  assert.equal(s.p6.reconcile.reasonMismatch.length, 0);
  assert.equal(s.p4.oracle.confirmed, 1);
  assert.equal(s.p4.oracle.blocked, 10);
  assert.equal(s.oracle.pass, true);
  assert.equal(s.rg1.pass, true);
  assert.equal(s.historicalPositives.pass, true);
  assert.equal(s.fpReview.pass, true);
});

test('no needs-human / pending in produced claim/verdict rows', () => {
  const files = ['l3/p3-claims.jsonl', 'l3/p6-claims.jsonl', 'l3/p4-claims.jsonl',
    'l4a/p3-verdicts.jsonl', 'l4a/p6-verdicts.jsonl', 'l4a/p4-verdicts.jsonl'];
  for (const f of files) {
    const text = fs.readFileSync(path.join(OUT, f), 'utf8');
    assert.ok(!/needs-human|"pending"|: pending/i.test(text), f);
  }
});

test('P6 verdicts: 95/95 os NOT-VULN; no PROVEN-VULN in os_account', () => {
  const rows = readJsonl(path.join(OUT, 'l4a', 'p6-verdicts.jsonl'));
  const os = rows.filter((r) => r.group === 'os-account');
  assert.equal(os.length, 95);
  assert.ok(os.every((r) => r.productVerdict === 'NOT-VULN'));
});

test('P4 verdicts: every OH candidate closed; confirmed fixture reproduced; no fake PROVEN-VULN', () => {
  const rows = readJsonl(path.join(OUT, 'l4a', 'p4-verdicts.jsonl'));
  const oh = rows.filter((r) => r.group === 'oh-candidate');
  assert.equal(oh.length, 11);
  assert.ok(oh.every((r) => r.claimVerdict));
  assert.ok(oh.every((r) => r.productVerdict !== 'PROVEN-VULN'));
  const confirmed = oh.find((r) => r.candidateId === 'cd_G-P4_52b62a535a33');
  assert.equal(confirmed.claimVerdict, 'VIOLATION');
  assert.equal(confirmed.productVerdict, 'PROVEN-WEAKNESS');
});

test('L4b summary gate passes (schema >=8/10, refs 100%)', () => {
  const s = readJson(path.join(OUT, 'l4b', 'summary.json'));
  assert.ok(s.p6.packs >= 10);
  assert.ok(s.p6.schemaSuccessRate >= 0.8);
  assert.equal(s.p6.refsOkRate, 1);
});

test('run-summary all gates pass', () => {
  const s = readJson(path.join(OUT, 'report', 'run-summary.json'));
  const failed = s.gates.filter((g) => !g.pass);
  assert.deepEqual(failed, []);
});
