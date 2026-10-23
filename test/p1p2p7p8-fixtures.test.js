'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('path');

const { runAllFixtures } = require('../lib/p1p2p7p8/fixtures.js');

test('all P1/P2/P7/P8 fixture sets pass their expected verdicts', () => {
  const fx = runAllFixtures();
  assert.equal(fx.gate, true);
  for (const cls of ['P1', 'P2', 'P7', 'P8']) {
    const set = fx.classes[cls];
    assert.equal(set.summary.gate, true, `${cls}: ${JSON.stringify(set.summary)}`);
  }
});

test('every fixture row has id/class/expected/actual/evidence; mutant or post expectations explicit', () => {
  const fx = runAllFixtures();
  for (const cls of ['P1', 'P2', 'P7', 'P8']) {
    const set = fx.classes[cls];
    const rows = [...set.synthetic.rows];
    if (set.historyLocal) rows.push(...set.historyLocal.rows);
    if (set.historyPositive) rows.push(...set.historyPositive.rows);
    for (const row of rows) {
      assert.ok(row.id, cls);
      assert.equal(row.class, cls);
      assert.ok(row.expected && Object.keys(row.expected).length > 0, row.id);
      assert.ok(row.actual && Object.keys(row.actual).length > 0, row.id);
      assert.equal(row.pass, true, `${row.id}: ${JSON.stringify(row.failures)}`);
      const keys = Object.keys(row.actual);
      assert.ok(keys.includes('pre') || keys.includes('original') || keys.includes('post'), row.id);
      for (const k of keys) assert.ok(row.actual[k].evidence, `${row.id}.${k}`);
    }
  }
});

test('external P7 cases stay production:false and are not fixtures counted into D4', () => {
  const { cases, validateAll } = require('../eval/external-cve/p7-cases.js');
  assert.equal(validateAll().ok, true);
  for (const c of cases) {
    assert.equal(c.production, false);
    assert.ok(!('inTarget' in c));
    assert.ok(!('codeState' in c));
  }
});
