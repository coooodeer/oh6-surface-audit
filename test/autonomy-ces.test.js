'use strict';

/**
 * 第三组件（common_event_service / ICommonEvent）的补充快照与 CES 局部词表回归。
 * 固定：17 入口、13 resolved / 4 重载 suspect、RemoveSticky 唯一操作 +
 * combined-gate-unsupported 具名缺口；操作行不得被误报为门禁缺口。
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');

const factsLib = require('../lib/autonomy/facts');
const discovery = require('../lib/autonomy/discovery');
const knowledgeLib = require('../lib/autonomy/knowledge');
const permission = require('../lib/autonomy/permission-argument');
const proofLib = require('../lib/autonomy/static-proof');
const policyLib = require('../lib/autonomy/policy');

const CES_SNAPSHOT = 'sha256:9bbb04f8f62e125dd747e2dc410b46a0634d50515bebac6248166b3483a5f29f';
const CES_SCOPE = JSON.parse(fs.readFileSync(
  path.resolve('K/policies/autonomy-ces-icommonevent-scope.json'), 'utf8'));
const CES_NORM = path.resolve(
  'K/norms/d820f37795abdc5ae65d2b26176bfd86a39847b568d16ac68dad539632981da8/knowledge.json');
const CES_ANCHORS = path.resolve('K/policies/autonomy-security-anchors-ces.json');

let cached = null;
function openCes() {
  if (cached) return cached;
  const facts = factsLib.AutonomyFacts.open({ snapshot: CES_SNAPSHOT, scope: CES_SCOPE });
  const anchors = discovery.buildAnchors(facts, CES_SCOPE);
  const suite = knowledgeLib.loadKnowledgeSuite([CES_NORM], facts);
  const policy = policyLib.load(facts, CES_ANCHORS);
  cached = { facts, anchors, suite, policy };
  return cached;
}

test('ces: 17 ICommonEvent entries bind 13 resolved + 4 overload suspects', () => {
  const { facts, anchors } = openCes();
  assert.equal(anchors.entries.length, 17);
  assert.ok(anchors.entries.every((e) => e.kind === 'idl' &&
    e.interface === 'OHOS.EventFwk.ICommonEvent'));
  const stats = {};
  for (const entry of anchors.entries) {
    const binding = discovery.resolveBinding(entry.entityId,
      { facts, scope: CES_SCOPE, anchors: anchors.anchors });
    stats[binding.binding] = (stats[binding.binding] || 0) + 1;
  }
  assert.deepEqual(stats, { resolved: 13, suspect: 4 });
});

test('ces: member-call recipe binds RemoveSticky operation and keeps combined gate as named gap', () => {
  const { facts, anchors, suite, policy } = openCes();
  const entry = anchors.entries.find((e) => e.method === 'RemoveStickyCommonEvent');
  const binding = discovery.resolveBinding(entry.entityId,
    { facts, scope: CES_SCOPE, anchors: anchors.anchors });
  assert.equal(binding.binding, 'resolved');
  const compared = permission.compare(facts, entry, binding, suite.byMethod.get('RemoveStickyCommonEvent'));
  const proof = proofLib.analyzeSecurity(facts, entry, binding,
    suite.byMethod.get('RemoveStickyCommonEvent'), compared, { policy });
  assert.equal(proof.status, 'insufficient');
  assert.equal(proof.security.reason, 'combined-gate-unsupported');
  assert.ok(proof.operationRef, 'operation must be bound');
  const target = facts.index().functions.find((fn) => fn.factId === proof.operationRef);
  assert.equal(target.qualified, 'OHOS::EventFwk::InnerCommonEventManager::RemoveStickyCommonEvent');
  const codes = (proof.unanalyzable || []).map((u) => u.reasonCode);
  assert.ok(codes.includes('combined-gate-unsupported'));
  assert.ok(codes.includes('unrecognized-caller-guard'));
  // 操作行（602）含 GetCallingUid() 实参，但不是条件行，不得被误报为门禁缺口。
  assert.ok(!(proof.unanalyzable || []).some((u) => u.line === 602));
});

test('facts: latest resolves by scope roots across d4-r1 and the CES supplement', () => {
  const pilot = JSON.parse(fs.readFileSync(path.resolve('K/policies/autonomy-pilot-scope.json'), 'utf8'));
  const d4 = factsLib.resolveFactsDir('latest', pilot).split(path.sep).pop();
  const ces = factsLib.resolveFactsDir('latest', CES_SCOPE).split(path.sep).pop();
  assert.equal(d4, '2142c229d142bdacc472969fe96d73a36da4554f3775dee4f710b79878997a1e');
  const snap = JSON.parse(fs.readFileSync(path.join(factsLib.FACTS_ROOT, ces, 'snapshot.json'), 'utf8'));
  assert.ok(snap.roots.some((root) => root.root === 'base/notification/common_event_service'));
});
