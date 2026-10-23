'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const OUT = path.join(__dirname, '..', 'out', 'p5');
const readJson = (p) => JSON.parse(fs.readFileSync(p, 'utf8'));
const readJsonl = (p) => fs.readFileSync(p, 'utf8').split(/\r?\n/).filter(Boolean).map((l) => JSON.parse(l));

const audit = readJson(path.join(OUT, 'data-audit.json'));
const units = readJsonl(path.join(OUT, 'method-units.jsonl'));
const pairing = readJsonl(path.join(OUT, 'pairing.jsonl'));
const checks = readJsonl(path.join(OUT, 'check-sites.jsonl'));
const paths = readJsonl(path.join(OUT, 'paths.jsonl'));

test('P5 audit: R1 32 aggregates -> 288 unique entries + 1 supplementary', () => {
  assert.equal(audit.candidates.total, 105);
  assert.equal(audit.candidates.singleEntry, 27);
  assert.equal(audit.candidates.multiEntry, 78);
  assert.equal(audit.units.r1Aggregates, 32);
  assert.equal(audit.units.r1SingleEntryAggregates, 10);
  assert.equal(audit.units.r1MultiEntryAggregates, 22);
  assert.equal(audit.units.outOfR1Aggregates, 73);
  assert.equal(audit.units.uniqueEntries, 288);
  assert.equal(audit.units.units, 289);
  assert.equal(audit.units.supplementary, 1);
});

test('P5 direction: 228 service / 61 callback / 0 unknown', () => {
  assert.deepEqual(audit.units.direction, { service: 228, callback: 61 });
  const by = units.reduce((a, u) => { a[u.direction] = (a[u.direction] || 0) + 1; return a; }, {});
  assert.deepEqual(by, { service: 228, callback: 61 });
  assert.equal(units.filter((u) => !['base/account/os_account', 'foundation/communication/dsoftbus'].includes(u.repo)).length, 0);
});

test('P5 pairing: service resolved >= 99%, every gap has reason, callback not applicable', () => {
  assert.equal(audit.pairing.service, 228);
  assert.equal(audit.pairing.serviceResolved, 226);
  assert.ok(audit.pairing.serviceResolvedRate >= 0.99);
  assert.equal(audit.pairing.serviceGap, 2);
  for (const p of pairing) {
    if (p.direction === 'callback') assert.equal(p.pairingStatus, 'not-applicable');
    if (p.pairingStatus === 'gap') assert.ok(p.reason, p.unitId);
    if (p.resolved) assert.ok(p.implFile && p.implFunction, p.unitId);
  }
  assert.deepEqual(audit.pairing.gaps, { 'method-missing': 2 });
});

test('P5 checks: server/client/test separated; identity sources not counted as checks', () => {
  assert.equal(audit.checks.total, 383);
  assert.equal(audit.checks.checks, 202);
  assert.equal(audit.checks.identitySources, 181);
  assert.equal(audit.checks.checksBySide.server, 150);
  assert.equal(audit.checks.checksBySide.client, 30);
  for (const c of checks) {
    assert.ok(['server', 'client', 'test', 'unknown'].includes(c.side));
    assert.ok(c.functionId, c.checkId);
    if (c.kind === 'get-calling-uid') assert.equal(c.isCheck, false);
  }
});

test('P5 paths: pathScoped 160 / noCheck 66 / truncated 0', () => {
  assert.equal(audit.paths.service, 228);
  assert.equal(audit.paths.pathScoped, 160);
  assert.equal(audit.paths.noCheckOnPath, 66);
  assert.equal(audit.paths.truncated, 0);
  assert.ok(audit.paths.pathScopedRate >= 0.6);
  for (const p of paths.filter((x) => x.direction === 'service')) {
    if (p.pathScoped) assert.ok(p.serverChecks > 0, p.unitId);
    if (p.noCheckOnPath) assert.equal(p.serverChecks, 0, p.unitId);
  }
});

test('P5 local fixtures: CWE-862 3 (R1 1), P5 invariant 1', () => {
  assert.equal(audit.localFixtures.cwe862, 3);
  assert.equal(audit.localFixtures.cwe862InR1, 1);
  assert.equal(audit.localFixtures.p5Invariants, 1);
  assert.equal(audit.localFixtures.cwe862InR1Cases[0].id, 'HIST-02c200267f908be2');
});

test('P5 units are method-level, not aggregate verdicts', () => {
  assert.equal(new Set(units.map((u) => u.unitId)).size, units.length);
  assert.equal(units.filter((u) => u.entrySource === 'candidate').length, 288);
  assert.equal(units.filter((u) => u.entrySource === 'l2-supplementary').length, 1);
  assert.equal(units.filter((u) => u.direction === 'service' && u.method === 'SendMessage').length, 1);
});
