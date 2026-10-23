'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { classify, sanitizerHit } = require('../lib/l5/classify.js');
const { buildCommand, runCommand, FIXTURES } = require('../lib/l5/fixtures.js');

test('L5 classifier: sanitizer signal is confirmed, clean exit is no-signal', () => {
  assert.equal(classify({ buildOk: true, status: 1, stderr: 'ERROR: AddressSanitizer: heap-buffer-overflow' }).result, 'confirmed');
  assert.equal(classify({ buildOk: true, status: 1, stderr: 'runtime error: load of null pointer' }).result, 'confirmed');
  assert.equal(classify({ buildOk: true, status: 0, stderr: '' }).result, 'no-signal');
  assert.equal(classify({ buildOk: false, status: null, stderr: '' }).result, 'blocked');
  assert.equal(classify({ buildOk: true, status: 124, stderr: '' }).reason, 'timeout');
  assert.equal(sanitizerHit('SUMMARY: UndefinedBehaviorSanitizer'), true);
});

test('L5 fixture commands carry sanitizer and timeout', () => {
  const p1 = FIXTURES.find((f) => f.id === 'P1-heap-oob');
  const p3 = FIXTURES.find((f) => f.id === 'P3-null-deref');
  assert.match(buildCommand(p1), /-fsanitize=address,undefined/);
  assert.match(buildCommand(p3), /-fsanitize=undefined/);
  assert.match(runCommand(p1), /ASAN_OPTIONS/);
  assert.match(runCommand(p3), /UBSAN_OPTIONS/);
  assert.ok(FIXTURES.some((f) => f.expected === 'confirmed'));
  assert.ok(FIXTURES.some((f) => f.expected === 'no-signal'));
});
