'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { AutonomyFacts } = require('../lib/autonomy/facts');
const { buildEntries, buildIndex } = require('../lib/autonomy/index');
const { resolve } = require('../lib/autonomy/ani');
const knowledge = require('../lib/autonomy/knowledge');

const scope = require('../K/policies/autonomy-ces-ani-scope.json');
const facts = AutonomyFacts.open({ snapshot: scope.snapshotId, scope });
const cfg = scope.aniBinding;
const read = (rel) => fs.readFileSync(path.join(facts.sourceRoot, ...rel.split('/')), 'utf8');
const texts = { ets: read(cfg.etsFile), cpp: read(cfg.cppFile), build: read(cfg.buildFile) };
const functions = facts.index().functions;
const entries = buildEntries(facts, { entryFilter: { entryKinds: ['arkts-export'] } })
  .filter((entry) => entry.method === cfg.method);

test('two real ArkTS overloads bind through taskpool and ANI to one native function', () => {
  assert.equal(entries.length, 2);
  const built = buildIndex(facts, scope);
  assert.equal(built.reconciliation.ok, true);
  assert.equal(built.entries.filter((entry) => entry.kind === 'arkts-export').length, 14);
  const bridges = built.relations.filter((rel) => rel.kind === 'bridges-to-native');
  assert.equal(bridges.length, 2);
  assert.equal(new Set(bridges.map((rel) => rel.payload.targetRef)).size, 1);
  for (const entry of entries) {
    const result = resolve(entry, cfg, texts, functions);
    assert.equal(result.status, 'resolved');
    assert.equal(result.tableLine, 713);
    assert.equal(result.nativeLine, 251);
    assert.equal(built.entries.find((e) => e.entityId === entry.entityId).aniBridge.nativeFactRef,
      result.nativeFactRef);
  }
});

test('wrong namespace, duplicate table row, absent build and syntax error stay unknown', () => {
  const entry = entries[0];
  assert.equal(resolve(entry, cfg, { ...texts, ets: texts.ets.replaceAll(
    'taskpool.execute(commonEventManager.removeStickyCommonEventExecute, event)',
    'taskpool.execute(other.removeStickyCommonEventExecute, event)') }, functions).status,
  'taskpool-target-ambiguous');
  const declaration = 'export native function removeStickyCommonEventExecute(event: string):int;';
  assert.equal(resolve(entry, cfg, { ...texts, ets: texts.ets.replace(declaration,
    'export native function missingExecute(event: string):int;') +
    `\nnamespace other { ${declaration} }` }, functions).status, 'native-declaration-unresolved');
  const row = texts.cpp.match(/ani_native_function\s*\{\s*"removeStickyCommonEventExecute"[\s\S]*?\},/)[0];
  assert.equal(resolve(entry, cfg, { ...texts, cpp: texts.cpp.replace(row, `${row}\n${row}`) }, functions).status,
    'ani-table-unresolved');
  assert.equal(resolve(entry, cfg, { ...texts, build: texts.build.replace(
    'ohos_shared_library("ani_commoneventmanager")', 'ohos_shared_library("other")') }, functions).status,
  'build-proof-unresolved');
  assert.equal(resolve(entry, cfg, { ...texts, ets: texts.ets.replaceAll(
    'taskpool.execute(commonEventManager.removeStickyCommonEventExecute, event)',
    'taskpool.execute(commonEventManager.removeStickyCommonEventExecute, ;') }, functions).status,
  'arkts-function-ambiguous');
  assert.equal(resolve(entry, cfg, texts, []).status, 'native-handler-ambiguous');
});

test('ANI snapshot proposal is distinct while CES document and service stay fixed', () => {
  const oldScope = require('../K/policies/autonomy-ces-icommonevent-scope-v2.json');
  const oldFacts = AutonomyFacts.open({ snapshot: oldScope.snapshotId, scope: oldScope });
  const old = knowledge.loadFromDocSet(oldFacts, 'ces-icommonevent', 'COMMONEVENT_STICKY');
  const current = knowledge.loadFromDocSet(facts, 'ces-ani-icommonevent', 'COMMONEVENT_STICKY');
  assert.equal(current.snapshotId, scope.snapshotId);
  assert.equal(current.norm.source.sha256, old.norm.source.sha256);
  assert.equal(current.norm.header.sha256, old.norm.header.sha256);
  assert.notEqual(current.knowledgeVersion, old.knowledgeVersion);
  assert.notEqual(current.norm.normId, old.norm.normId);
  assert.equal(knowledge.proposalFor(facts, current.norm.permission).knowledgeVersion,
    current.knowledgeVersion);
});
