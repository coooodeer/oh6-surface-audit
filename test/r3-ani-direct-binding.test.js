'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { AutonomyFacts } = require('../lib/autonomy/facts');
const { buildIndex } = require('../lib/autonomy/index');
const { buildAnchors, resolveBinding } = require('../lib/autonomy/discovery');
const { resolve } = require('../lib/autonomy/ani');

const scope = require('../K/policies/autonomy-access-token-arkts-direct-scope-v2.json');
const facts = AutonomyFacts.open({ snapshot: scope.snapshotId, scope });
const cfg = scope.aniBinding;
const read = (rel) => fs.readFileSync(path.join(facts.sourceRoot, ...rel.split('/')), 'utf8');
const texts = { ets: read(cfg.etsFile), cpp: read(cfg.cppFile), build: read(cfg.buildFile) };
const functions = facts.index().functions;

test('real synchronous ArkTS on binds through ANI conditionally, without treating other exports as adjudicated', () => {
  const built = buildIndex(facts, scope);
  assert.equal(built.reconciliation.ok, true);
  assert.equal(built.entries.filter((e) => e.kind === 'arkts-export').length, 15);
  const entry = built.entries.find((e) => e.kind === 'arkts-export' && e.method === 'on');
  assert.equal(entry.qualified, 'privacyManager::on');
  assert.deepEqual(entry.aniBridge, {
    status: 'resolved', shape: 'direct-namespace', registrationConditional: 'ANI_OK',
    nativeName: 'onExecute', nativeFactRef: 'F:1a2bc61ea705:function:93a012f720780014',
    callLine: 280, nativeLine: 315, tableLine: 907
  });
  assert.equal(built.relations.filter((r) => r.kind === 'bridges-to-native').length, 1);
  assert.equal(built.relations.find((r) => r.kind === 'bridges-to-native').payload.resolution,
    'arkts-direct-ani-table-conditional');
  const anchors = buildAnchors(facts, scope).anchors;
  assert.equal(anchors.size, 1);
  assert.equal(resolveBinding(entry.entityId, { facts, scope, anchors }).binding, 'resolved');
});

test('direct call, declaration, registration, build and handler drift stay unknown', () => {
  const entry = buildIndex(facts, scope).entries.find((e) => e.kind === 'arkts-export' && e.method === 'on');
  assert.equal(resolve(entry, cfg, { ...texts, ets: texts.ets.replace(
    'onExecute(type, permissionList, callback);', 'offExecute(type, permissionList, callback);') }, functions).status,
  'direct-call-ambiguous');
  assert.equal(resolve(entry, cfg, { ...texts, ets: texts.ets.replace(
    'loadLibrary("privacy_ani.z")', 'loadLibrary("other.z")') }, functions).status,
  'native-declaration-unresolved');
  assert.equal(resolve(entry, cfg, { ...texts, ets: texts.ets.replace(
    'onExecute(type, permissionList, callback);', 'onExecute(type, permissionList, ;') }, functions).status,
  'arkts-function-ambiguous');
  const row = 'ani_native_function {"onExecute", nullptr, reinterpret_cast<void *>(RegisterPermActiveStatusCallback)},';
  assert.equal(resolve(entry, cfg, { ...texts, cpp: texts.cpp.replace(row, `${row}\n${row}`) }, functions).status,
  'ani-table-unresolved');
  assert.equal(resolve(entry, cfg, { ...texts, cpp: texts.cpp.replace(
    '    InitPrivacyFunction(env);', '    // InitPrivacyFunction(env);') }, functions).status,
  'ani-table-unresolved');
  assert.equal(resolve(entry, cfg, { ...texts, build: texts.build.replace(
    'generate_static_abc("privacy_manager")', 'generate_static_abc("other")') }, functions).status,
  'build-proof-unresolved');
  assert.equal(resolve(entry, cfg, texts, []).status, 'native-handler-ambiguous');
});
