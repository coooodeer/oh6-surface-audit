'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { buildEntries } = require('../lib/autonomy/index');

test('R3 exact IPC entry filter excludes adjacent helpers without changing legacy scopes', () => {
  const functions = ['OnRemoteRequest', 'OnRemoteRequestInner', 'GetJsOnRemoteRequestCallback']
    .map((name, i) => ({ name, role: 'production', qualified: `Stub::${name}`,
      factId: `F:${i}`, sourceRange: { file: 'src/stub.cpp' }, startLine: i + 1 }));
  functions.push({ ...functions[0], role: 'test', factId: 'F:test' });
  const facts = { index: () => ({ functions, metadata: { idl: [], sa: [], napi: [] } }) };
  assert.equal(buildEntries(facts, { entryFilter: { exactOnRemoteRequest: true } }).length, 1);
  assert.equal(buildEntries(facts, {}).length, 3);
  assert.equal(buildEntries(facts, { entryFilter: { exactOnRemoteRequest: true } })[0].qualified,
    'Stub::OnRemoteRequest');
});
