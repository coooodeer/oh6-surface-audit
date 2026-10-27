'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { AutonomyFacts } = require('../lib/autonomy/facts');
const { buildIndex } = require('../lib/autonomy/index');
const { buildAnchors } = require('../lib/autonomy/discovery');
const { dispatchOf } = require('../lib/autonomy/ipc-dispatch');

const scope = require('../K/policies/autonomy-r3-tokensync-code-scope.json');
const facts = AutonomyFacts.open({ snapshot: scope.snapshotId, scope });
const idx = facts.index();
const file = scope.ipcDispatch.buildProofs[0].source;
const read = (rel) => fs.readFileSync(path.join(facts.sourceRoot, ...rel.split('/')), 'utf8');
const source = read(file);
const header = read(scope.ipcDispatch.codeHeader);
const fn = idx.functions.find((f) => f.qualified === 'OHOS::Security::AccessToken::TokenSyncManagerStub::OnRemoteRequest');

test('three real enum codes bind to distinct same-object handlers', () => {
  assert.ok(fn);
  const built = buildIndex(facts, scope);
  assert.equal(built.reconciliation.ok, true);
  const codes = built.entries.filter((e) => e.kind === 'ipc-code');
  assert.deepEqual(codes.sort((a, b) => a.line - b.line)
    .map((e) => [e.ipcCode, e.method, e.codeDef.split(':').at(-1)]), [
    ['GET_REMOTE_HAP_TOKEN_INFO', 'GetRemoteHapTokenInfoInner', '24'],
    ['DELETE_REMOTE_HAP_TOKEN_INFO', 'DeleteRemoteHapTokenInfoInner', '25'],
    ['UPDATE_REMOTE_HAP_TOKEN_INFO', 'UpdateRemoteHapTokenInfoInner', '26']
  ]);
  assert.equal(new Set(codes.map((e) => e.factRef)).size, 3);
  assert.ok(codes.every((e) => e.dispatchRef === fn.factId && e.defaultLine === 56));
});

test('verdict scope selects only the delete code, without changing the three-edge inventory', () => {
  const verdict = require('../K/policies/autonomy-r3-tokensync-verdict-scope.json');
  const anchors = buildAnchors(facts, verdict);
  assert.deepEqual(anchors.entries.map((e) => e.ipcCode), ['DELETE_REMOTE_HAP_TOKEN_INFO']);
  assert.equal(buildIndex(facts, verdict).entries.filter((e) => e.kind === 'ipc-code').length, 3);
});

test('changed enum, other owner, fallthrough and conditional dispatch stay unresolved', () => {
  const resolve = (src = source, hdr = header, functions = idx.functions) =>
    dispatchOf(fn, src, hdr, functions, 'tokensync-enum');
  assert.equal(resolve(source, header.replace('DELETE_REMOTE_HAP_TOKEN_INFO,',
    'OTHER_CODE,')).edges[1].status, 'code-definition-unresolved');
  assert.equal(resolve(source, header.replace('DELETE_REMOTE_HAP_TOKEN_INFO,',
    'DELETE_REMOTE_HAP_TOKEN_INFO,\n    DELETE_REMOTE_HAP_TOKEN_INFO,')).edges[1].status,
  'code-definition-unresolved');
  assert.equal(resolve(source, header.replace('DELETE_REMOTE_HAP_TOKEN_INFO,',
    'DELETE_REMOTE_HAP_TOKEN_INFO = 0x0000,')).edges[1].status, 'code-definition-unresolved');
  assert.equal(resolve(source, header, idx.functions.filter((f) =>
    f.name !== 'DeleteRemoteHapTokenInfoInner')).edges[1].status, 'same-object-handler-unresolved');
  assert.equal(resolve(source.replace('DeleteRemoteHapTokenInfoInner(data, reply);\n            break;',
    'DeleteRemoteHapTokenInfoInner(data, reply);')).edges[1].status, 'fallthrough-unknown');
  assert.equal(resolve(source.replace('case static_cast<uint32_t>(TokenSyncInterfaceCode::DELETE_REMOTE_HAP_TOKEN_INFO):',
    '#ifdef OTHER_VARIANT\n        case static_cast<uint32_t>(TokenSyncInterfaceCode::DELETE_REMOTE_HAP_TOKEN_INFO):')).status,
  'function-ast-unavailable');
  assert.equal(resolve(source.replace('TokenSyncInterfaceCode::DELETE_REMOTE_HAP_TOKEN_INFO):',
    'OtherCode::DELETE_REMOTE_HAP_TOKEN_INFO):')).status, 'code-label-unknown');
});
