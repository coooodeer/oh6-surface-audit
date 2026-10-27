'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { AutonomyFacts } = require('../lib/autonomy/facts');
const { buildEntries, buildIndex } = require('../lib/autonomy/index');
const { exportsOf } = require('../lib/autonomy/napi');
const discovery = require('../lib/autonomy/discovery');

const scope = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'K/policies/autonomy-r3-napi-scope.json')));
const facts = AutonomyFacts.open({ snapshot: scope.snapshotId, scope });
const row = facts.index().metadata.napi.find((item) => item.payload.module === 'privacyManager');
const binding = scope.napiBindings.privacyManager;

test('real privacyManager registration resolves ten literal exports to handlers', () => {
  const entries = buildEntries(facts, scope).filter((entry) => entry.kind === 'napi-export');
  assert.equal(entries.length, 10);
  assert.equal(entries.filter((entry) => entry.factRef).length, 10);
  const start = entries.find((entry) => entry.method === 'startUsingPermission');
  const anchors = discovery.buildAnchors(facts, scope).anchors;
  assert.equal(discovery.resolveBinding(start.entityId, { facts, scope, anchors }).bound.name,
    'StartUsingPermission');
  assert.equal(buildIndex(facts, scope).relations.filter((rel) => rel.kind === 'registers' &&
    rel.payload.resolution === 'napi-module-init-literal-export').length, 10);
});

test('stale source or missing registration does not invent exports', () => {
  assert.deepEqual(exportsOf({ ...facts, verifyFile: () => ({ ok: false }) }, row, binding), []);
  const idx = facts.index();
  const withoutRegistration = { ...idx, calls: idx.calls.filter((call) =>
    !(call.sourceRange?.file === row.sourceFile && call.calleeName === 'napi_module_register')) };
  assert.deepEqual(exportsOf({ sourceRoot: facts.sourceRoot, verifyFile: () => ({ ok: true }),
    index: () => withoutRegistration }, row, binding), []);
});

test('ambiguous same-owner handler remains suspect with no registers edge', () => {
  const idx = facts.index();
  const original = idx.functions.find((fn) => fn.qualified ===
    'OHOS::Security::AccessToken::StartUsingPermission' &&
    fn.sourceRange.file.startsWith(binding.handlerRoot + '/'));
  const duplicate = { ...original, factId: 'F:duplicate' };
  const synthetic = { sourceRoot: facts.sourceRoot, verifyFile: () => ({ ok: true }),
    index: () => ({ ...idx, functions: [...idx.functions, duplicate] }) };
  const start = exportsOf(synthetic, row, binding).find((entry) => entry.method === 'startUsingPermission');
  assert.equal(start.factRef, null);
  assert.equal(start.registration.candidateCount, 2);
  const anchor = { ...start, entityId: 'ENT:aaaaaaaaaaaaaaaa' };
  const result = discovery.resolveBinding(anchor.entityId,
    { facts: synthetic, scope, anchors: new Map([[anchor.entityId, anchor]]) });
  assert.equal(result.binding, 'suspect');
});
