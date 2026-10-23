'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const OUT = path.join(__dirname, '..', 'out');
const readJson = (p) => JSON.parse(fs.readFileSync(p, 'utf8'));

const gates = readJson(path.join(OUT, 'report', 'p5-run-summary.json'));

test('P5 gates: 13/13 pass; live/mock state is explicit', () => {
  assert.equal(gates.allGatesPass, true);
  assert.equal(gates.gates.length, 13);
  assert.equal(gates.gates.filter((g) => g.pass).length, 13);
  assert.equal(typeof gates.l4bSimulated, 'boolean');
  assert.equal(typeof gates.liveBlocked, 'boolean');
  if (gates.liveBlocked) assert.equal(gates.l4bSimulated, true);
});

test('P5 gate report exists and states pass', () => {
  const md = fs.readFileSync(path.join(OUT, 'report', 'p5-gates.md'), 'utf8');
  assert.match(md, /allGatesPass：\*\*true\*\*/);
  assert.match(md, /liveBlocked：(true|false)/);
});

test('P5 regression gate: existing P6/P3/P4 run-summary still all pass', () => {
  const old = readJson(path.join(OUT, 'report', 'run-summary.json'));
  assert.equal(old.allGatesPass, true);
});
