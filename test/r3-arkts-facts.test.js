'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { extract } = require('../lib/facts/arkts');
const { buildEntries, buildIndex } = require('../lib/autonomy/index');
const { resolveBinding } = require('../lib/autonomy/discovery');
const { validateFact } = require('../lib/facts/schema');
const { rulesVersionFor, PARSE_RULES_VERSION } = require('../lib/facts/manifest');

const snapshotId = `sha256:${'a'.repeat(64)}`;

test('ArkTS parser change has a distinct invalidation version', () => {
  assert.equal(rulesVersionFor({ sourceExtensions: ['.cpp'] }), PARSE_RULES_VERSION);
  assert.equal(rulesVersionFor({ sourceExtensions: ['.cpp', '.ets'] }),
    'K-1.1.1-arkts-default-namespace');
});

function factsFor(text) {
  const buckets = Object.fromEntries(['files', 'functions', 'symbols', 'types', 'calls', 'cfg', 'dfg',
    'sinks', 'guards', 'reads', 'writes', 'locks', 'quality'].map((k) => [k, []]));
  const unsupported = [];
  const rel = 'base/sample/main.ets';
  extract({ file: { rel, repo: 'base/sample', role: 'production' }, snapshotId, text,
    sha256: crypto.createHash('sha256').update(text).digest('hex'), bytes: Buffer.byteLength(text),
    lines: text.split('\n').length, buckets, unsupported });
  const idx = { functions: buckets.functions, calls: buckets.calls, files: buckets.files,
    metadata: { idl: [], sa: [], napi: [] }, counts: { functions: buckets.functions.length,
      calls: buckets.calls.length, files: 1, idl: 0, sa: 0, napi: 0 }, truncated: false };
  return { buckets, unsupported, facts: { snapshotId, index: () => idx,
    findFunctions: (name) => idx.functions.filter((fn) => fn.name === name) } };
}

test('ArkTS overloads remain distinct, self-bound entries with name-only calls', () => {
  const { buckets, facts } = factsFor(`namespace api {
    export function run(x: string): void { taskpool.execute(api.nativeRun, x); }
    export function run(x: string, cb: Function): void { taskpool.execute(api.nativeRun, x); }
    function hidden(): void { taskpool.execute(api.hidden, 1); }
  }`);
  const entries = buildEntries(facts, { entryFilter: { entryKinds: ['arkts-export'] } });
  assert.equal(entries.length, 2);
  assert.notEqual(entries[0].entityId, entries[1].entityId);
  assert.equal(buckets.calls.filter((c) => c.calleeName === 'execute').length, 2);
  assert.ok(buckets.calls.every((c) => c.quality.resolution === 'name-only' && c.callee === null));
  const built = buildIndex(facts, { entryFilter: { entryKinds: ['arkts-export'] } });
  assert.equal(built.reconciliation.ok, true);
  for (const row of [...buckets.files, ...buckets.functions, ...buckets.calls]) {
    assert.deepEqual(validateFact(row).errors, []);
  }
  assert.equal(built.relations.filter((r) => r.kind === 'registers').length, 2);
  for (const entry of entries) {
    const binding = resolveBinding(entry.entityId, { facts, scope: {},
      anchors: new Map([[entry.entityId, entry]]) });
    assert.equal(binding.binding, 'resolved');
    assert.equal(binding.bound.factId, entry.factRef);
  }
});

test('unexported function is not an entry; malformed exported body remains unknown', () => {
  const { buckets, unsupported, facts } = factsFor(`function hidden(): void {}
    export function broken(x: string): void { const v = ; }
    export function good(): void { done(); }`);
  assert.deepEqual(buckets.functions.map((f) => f.name), ['good']);
  assert.equal(buildEntries(facts, {}).length, 1);
  assert.equal(buckets.files[0].quality.parse, 'partial');
  assert.ok(unsupported.some((u) => u.kind === 'file' && u.detail.diagnostics.length));
  assert.ok(unsupported.some((u) => u.kind === 'function' && u.reason === 'ast-error-nodes'));
});

test('ArkTS default namespace preserves owner and local call while native declarations remain unsupported', () => {
  const { buckets, unsupported, facts } = factsFor(`export default namespace privacyManager {
    native function onExecute(callback: Function): void;
    export function on(callback: Function): void { onExecute(callback); }
  }`);
  const entries = buildEntries(facts, { entryFilter: { entryKinds: ['arkts-export'] } });
  assert.equal(entries.length, 1);
  assert.equal(entries[0].qualified, 'privacyManager::on');
  assert.equal(buckets.calls.find((c) => c.calleeName === 'onExecute')?.callerName, 'privacyManager::on');
  assert.equal(buckets.files[0].quality.parse, 'partial');
  assert.ok(unsupported.some((u) => u.kind === 'file' && u.reason === 'ast-error-nodes'));
  assert.equal(resolveBinding(entries[0].entityId, { facts, scope: {},
    anchors: new Map([[entries[0].entityId, entries[0]]]) }).binding, 'resolved');
});
