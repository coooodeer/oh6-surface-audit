'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const OUT = path.join(__dirname, '..', 'out');
const LOG = path.join(OUT, 'report', 'P1P2P7P8-CALIBRATION-LOG.jsonl');
const readJsonl = (p) => fs.readFileSync(p, 'utf8').split(/\r?\n/).filter(Boolean).map((l) => JSON.parse(l));
const log = readJsonl(LOG);

test('P1P2P7P8 calibration: 3 rounds x (10 accepted + 10 rejected) = 60', () => {
  assert.equal(log.length, 60);
  const rounds = new Set(log.map((r) => r.round));
  assert.deepEqual([...rounds].sort(), [1, 2, 3]);
  for (const r of [1, 2, 3]) {
    const rows = log.filter((x) => x.round === r);
    assert.equal(rows.filter((x) => x.kind === 'accepted').length, 10);
    assert.equal(rows.filter((x) => x.kind === 'rejected').length, 10);
  }
});

test('P1P2P7P8 calibration: programmatic recheck 100%, false PROVEN-VULN 0', () => {
  for (const row of log) {
    assert.equal(row.pass, true, `${row.claimId}: ${JSON.stringify(row.checks.filter((c) => !c.pass))}`);
    assert.notEqual(row.productVerdict, 'PROVEN-VULN');
    assert.ok(row.checks.some((c) => c.name === 'obligations-10'));
    assert.ok(row.checks.some((c) => c.name === 'o10-unproven'));
  }
  const summary = require('../out/p1p2p7p8/summary.json');
  assert.equal(summary.headline.T1, 0);
});

test('P1P2P7P8 calibration: at least one round covers P1/P2 check present/missing boundary', () => {
  const p1Accepted = log.some((r) => r.kind === 'accepted' && r.class === 'P1' && String(r.tier || '').startsWith('T2'));
  const p1Rejected = log.some((r) => r.kind === 'rejected' && r.class === 'P1' && r.tier === 'T4-negative');
  const p2Rejected = log.some((r) => r.kind === 'rejected' && r.class === 'P2' && r.tier === 'T4-negative');
  // capture 类型修正后 P2 不再需要 T2；保留 P2 negative 边界即可。
  assert.ok(p1Accepted && p1Rejected && p2Rejected);
});
