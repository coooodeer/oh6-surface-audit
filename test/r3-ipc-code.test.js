'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { AutonomyFacts } = require('../lib/autonomy/facts');
const { buildEntries, buildIndex } = require('../lib/autonomy/index');
const { resolveBinding } = require('../lib/autonomy/discovery');
const { dispatchOf, codeDefinition } = require('../lib/autonomy/ipc-dispatch');

const scope = require('../K/policies/autonomy-r3-ipc-code-scope.json');
const sourceRoot = path.resolve(__dirname, '..', '..', 'OpenHarmony');
const facts = AutonomyFacts.open({ snapshot: scope.snapshotId, scope });

test('real DBinder switches bind three distinct code/owner/handler edges', () => {
  const entries = buildEntries(facts, scope);
  const codes = entries.filter((e) => e.kind === 'ipc-code');
  assert.equal(entries.filter((e) => e.kind === 'on-remote-request').length, 7);
  assert.equal(codes.length, 3);
  const outside = entries.filter((e) => e.kind === 'on-remote-request' &&
    e.dispatchStatus === 'build-proof-not-selected');
  assert.equal(outside.length, 5);
  assert.deepEqual(outside.map((e) => e.dispatchShape).sort(),
    ['function-ast-unavailable', 'function-ast-unavailable',
      'switch-code-not-unique', 'switch-code-not-unique', 'switch-code-not-unique']);
  assert.equal(buildIndex(facts, scope).reconciliation.ok, true);
  for (const e of codes) {
    assert.match(e.codeDef, /interfaces\/innerkits\/ipc_core\/include\/ipc_types\.h:(49|55)$/);
    const binding = resolveBinding(e.entityId, { facts, scope, anchors: new Map([[e.entityId, e]]) });
    assert.equal(binding.binding, 'resolved');
    assert.equal(binding.bound.factId, e.factRef);
    assert.ok(e.handlerCallLine > e.line);
    assert.ok(e.defaultLine > e.line);
  }
  assert.equal(new Set(codes.map((e) => `${e.dispatchRef}:${e.ipcCode}`)).size, 3);
  assert.equal(entries.filter((e) => e.kind === 'on-remote-request' &&
    e.dispatchEdges?.some((edge) => edge.status === 'resolved-dispatch')).length, 2);
});

test('missing or duplicate code definition, other owner and conditional switch do not resolve', () => {
  const idx = facts.index();
  const fn = idx.functions.find((f) => f.qualified === 'OHOS::DBinderCallbackStub::OnRemoteRequest');
  const source = fs.readFileSync(path.join(sourceRoot, ...fn.sourceRange.file.split('/')), 'utf8');
  const header = fs.readFileSync(path.join(sourceRoot, ...scope.ipcDispatch.codeHeader.split('/')), 'utf8');
  assert.equal(codeDefinition(header, 'GET_PROTO_INFO'), 49);
  assert.equal(codeDefinition(`${header}\nGET_PROTO_INFO = 1,`, 'GET_PROTO_INFO'), null);
  assert.equal(dispatchOf(fn, source, header.replace(/GET_PROTO_INFO\s*=/, 'OTHER_CODE ='), idx.functions)
    .edges[0].status, 'code-definition-unresolved');
  const wrongOwner = idx.functions.filter((f) => f.qualified !== 'OHOS::DBinderCallbackStub::ProcessProto');
  assert.equal(dispatchOf(fn, source, header, wrongOwner).edges[0].status,
    'same-object-handler-unresolved');
  const fallthrough = source.replace('result = ProcessProto(code, data, reply, option);\n            break;',
    'result = ProcessProto(code, data, reply, option);');
  assert.equal(dispatchOf(fn, fallthrough, header, idx.functions).edges[0].status,
    'fallthrough-unknown');
  const conditional = source.replace('case GET_PROTO_INFO:', '#ifdef FEATURE_X\n        case GET_PROTO_INFO:');
  assert.equal(dispatchOf(fn, conditional, header, idx.functions).status,
    'function-ast-unavailable');
});
