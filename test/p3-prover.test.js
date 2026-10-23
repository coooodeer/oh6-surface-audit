'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { loadL1 } = require('../lib/l1.js');
const { loadL2 } = require('../lib/l2.js');
const { selectP3Candidates } = require('../lib/claims.js');
const { verdictFor, productFor, evalGuardFromText, proveFixtures } = require('../lib/prover-p3.js');

const l1 = loadL1();
const l2 = loadL2(l1);

const o = (status) => ({ status, evidence: {} });

test('P3 truth table: O2 unproven + O3 disproven is UNPROVEN, not VIOLATION', () => {
  assert.equal(verdictFor(o('proven'), o('unproven'), o('disproven'), o('unproven')), 'UNPROVEN');
});

test('P3 truth table: O2 disproven is NOT-VULN even when guard is missing', () => {
  assert.equal(verdictFor(o('proven'), o('disproven'), o('disproven'), o('unproven')), 'NOT-VULN');
});

test('P3 truth table: O1 disproven is NOT-APPLICABLE', () => {
  assert.equal(verdictFor(o('disproven'), o('proven'), o('disproven'), o('unproven')), 'NOT-APPLICABLE');
});

test('P3 truth table: VIOLATION + O4 unproven cannot be PROVEN-VULN', () => {
  const v = verdictFor(o('proven'), o('proven'), o('disproven'), o('unproven'));
  assert.equal(v, 'VIOLATION');
  assert.equal(productFor(v, o('unproven')), 'CONDITIONS-NOT-MET');
});

test('P3 truth table: VIOLATION + O4 proven is claim-candidate; impact gate downgrades', () => {
  const v = verdictFor(o('proven'), o('proven'), o('disproven'), o('proven'));
  assert.equal(v, 'VIOLATION');
  assert.equal(productFor(v, o('proven'), { impactNotAssessed: true }), 'PROVEN-WEAKNESS');
  assert.equal(productFor(v, o('proven')), 'PROVEN-VULN');
});

function fn(body) {
  return `int f() {\n${body}\n}\n`;
}

test('P3 guard: !p with return', () => {
  const r = evalGuardFromText(fn('    Foo *p = GetFoo();\n    if (!p) { return -1; }\n    return p->x;'), 'f', 'p');
  assert.equal(r.status, 'proven');
});

test('P3 guard: p == nullptr with return', () => {
  const r = evalGuardFromText(fn('    Foo *p = GetFoo();\n    if (p == nullptr) {\n        return -1;\n    }\n    return p->x;'), 'f', 'p');
  assert.equal(r.status, 'proven');
});

test('P3 guard: positive branch enclosing deref', () => {
  const r = evalGuardFromText(fn('    Foo *p = GetFoo();\n    if (p != nullptr) {\n        return p->x;\n    }\n    return 0;'), 'f', 'p');
  assert.equal(r.status, 'proven');
});

test('P3 guard: compound OR null guard with exit', () => {
  const r = evalGuardFromText(fn('    Foo *a = GetA();\n    if (a == nullptr || b == 0) {\n        return -1;\n    }\n    return a->x;'), 'f', 'a');
  assert.equal(r.status, 'proven');
});

test('P3 guard: member/return-value null check', () => {
  const r = evalGuardFromText(fn('    if (x.y == nullptr) {\n        return -1;\n    }\n    return x.y->z;'), 'f', 'x.y');
  assert.equal(r.status, 'proven');
});

test('P3 guard: test-only EXPECT_* is not a production guard', () => {
  const r = evalGuardFromText(fn('    Foo *p = GetFoo();\n    EXPECT_NE(p, nullptr);\n    return p->x;'), 'f', 'p');
  assert.equal(r.status, 'disproven');
});

test('P3 guard: guard without exit is unproven', () => {
  const r = evalGuardFromText(fn('    Foo *p = GetFoo();\n    if (p == nullptr) {\n        log();\n    }\n    return p->x;'), 'f', 'p');
  assert.equal(r.status, 'unproven');
});

test('P3 candidates: 1a+2a yields 20–30 candidates (existing 5 + expansion)', () => {
  const sel = selectP3Candidates(l1, l2);
  assert.ok(sel.claims.length >= 20 && sel.claims.length <= 30, `candidates=${sel.claims.length}`);
  assert.equal(sel.summary.existing, 5);
  assert.equal(sel.summary.expanded, sel.claims.length - 5);
  assert.equal(sel.summary.unboundReclassified, 68);
  assert.equal(sel.summary.callgraphNameOnly, sel.claims.length);
});

test('P3 fixtures: 10/10 original SATISFIED and 10/10 mutant VIOLATION', () => {
  const rows = proveFixtures(l1);
  const orig = rows.filter((r) => r.variant === 'original');
  const mut = rows.filter((r) => r.variant === 'mutant');
  assert.equal(orig.length, 10);
  assert.equal(mut.length, 10);
  assert.equal(orig.filter((r) => r.claimVerdict === 'SATISFIED').length, 10);
  assert.equal(mut.filter((r) => r.claimVerdict === 'VIOLATION').length, 10);
});
