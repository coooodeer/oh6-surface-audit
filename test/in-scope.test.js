'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const OUT = path.join(__dirname, '..', 'out');
const readJson = (p) => JSON.parse(fs.readFileSync(p, 'utf8'));
const readJsonl = (p) => fs.readFileSync(p, 'utf8').split(/\r?\n/).filter(Boolean).map((l) => JSON.parse(l));

const summary = readJson(path.join(OUT, 'verdicts', 'summary.json'));
const rows = readJsonl(path.join(OUT, 'verdicts', 'in-scope-verdicts.jsonl'));

test('in-scope: R1 strict scope only (os_account + dsoftbus)', () => {
  assert.equal(summary.scope.name, 'R1');
  assert.deepEqual(summary.scope.repos, ['base/account/os_account', 'foundation/communication/dsoftbus']);
  for (const r of rows) {
    assert.equal(r.scope, 'R1', r.verdictId);
    assert.ok(summary.scope.repos.includes(r.repo), `${r.verdictId} ${r.repo}`);
  }
  assert.equal(rows.length, 11);
});

test('in-scope: no miner finding / external CVE / R2 rows', () => {
  for (const r of rows) {
    assert.equal(r.cveId, undefined, r.verdictId);
    assert.equal(r.group, undefined, r.verdictId);
    assert.notEqual(r.class, 'CVE', r.verdictId);
  }
  const text = fs.readFileSync(path.join(OUT, 'verdicts', 'in-scope-verdicts.jsonl'), 'utf8');
  for (const forbidden of ['KIOSK', 'QUICK_FIX', 'CVE-']) {
    assert.ok(!text.includes(forbidden), `verdicts file contains ${forbidden}`);
  }
});

test('in-scope headline: 0 confirmed / 6 weak units / 26 claims / 5 gaps', () => {
  assert.deepEqual(summary.headline, {
    newConfirmed: 0,
    newWeakUnits: 6,
    newWeakClaims: 26,
    instrumentationGap: 5
  });
  assert.equal(summary.verdicts.total, 11);
  assert.deepEqual(summary.verdicts.byClass, { P3: 5, P4: 6 });
  assert.deepEqual(summary.verdicts.byTier, { 'T2-weak-candidate': 6, 'T3-instrumentation-gap': 5 });
});

test('in-scope P3: 5 owner root-cause families cover 25 claims', () => {
  const p3 = rows.filter((r) => r.class === 'P3');
  assert.equal(p3.length, 5);
  assert.ok(p3.every((r) => r.unitType === 'root-cause-owner-family'));
  assert.ok(p3.every((r) => r.tier === 'T2-weak-candidate' && r.counted === true));
  assert.equal(p3.reduce((n, r) => n + r.claimCount, 0), 25);
  assert.equal(p3.reduce((n, r) => n + r.claimIds.length, 0), 25);
  assert.deepEqual(new Set(p3.map((r) => r.owner)), new Set([
    'AbilityManagerAdapter',
    'BundleManagerAdapter',
    'DistributedAccountEventService',
    'OsAccountConstraintSubscriberManager',
    'AppAccountEventListener'
  ]));
});

test('in-scope P4: 1 T2 (UBSan confirmed) + 5 T3 with named gaps', () => {
  const p4 = rows.filter((r) => r.class === 'P4');
  assert.equal(p4.length, 6);
  const t2 = p4.filter((r) => r.tier === 'T2-weak-candidate');
  const t3 = p4.filter((r) => r.tier === 'T3-instrumentation-gap');
  assert.equal(t2.length, 1);
  assert.equal(t2[0].candidateId, 'cd_G-P4_52b62a535a33');
  assert.equal(t2[0].counted, true);
  assert.equal(t3.length, 5);
  assert.ok(t3.every((r) => r.counted === false));
  assert.equal(t3.filter((r) => r.gapReason === 'no-driver-template').length, 2);
  assert.equal(t3.filter((r) => r.gapReason === 'compile-failed').length, 3);
});

test('in-scope excluded: 20 miner findings (4 PV + 16 weak) + 13 CVE + 5 R2 = 38', () => {
  assert.deepEqual(summary.excluded, {
    minerFindings: 20,
    minerFindingsProvenVuln: 4,
    minerFindingsWeak: 16,
    externalCve: 13,
    oh6OtherReposP4: 5,
    total: 38
  });
  assert.equal(summary.negatives.p6OsSitesNotVuln, 95);
  assert.equal(summary.negatives.p6OsSitesTotal, 95);
  assert.equal(summary.negatives.p3UnreachableNotApplicable, 109);
  assert.equal(summary.negatives.p3UnreachableUnbound, 105);
});

test('in-scope report file exists and states the headline', () => {
  const md = fs.readFileSync(path.join(OUT, 'report', 'in-scope-findings.md'), 'utf8');
  assert.match(md, /本仓新确认漏洞：0 个/);
  assert.match(md, /6 个根因单元/);
  assert.match(md, /26 条 claim/);
  assert.match(md, /PROVEN-VULN/);
});
