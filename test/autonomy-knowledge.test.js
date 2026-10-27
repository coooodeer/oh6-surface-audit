'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const ids = require('../lib/autonomy/ids');
const factsLib = require('../lib/autonomy/facts');
const knowledgeLib = require('../lib/autonomy/knowledge');
const tools = require('../lib/autonomy/tools');
const discovery = require('../lib/autonomy/discovery');
const scope = require('../K/policies/autonomy-pilot-scope.json');

test('authorization norm preserves the quoted source and does not self-publish', () => {
  const facts = factsLib.AutonomyFacts.open({ snapshot: scope.snapshotId, scope });
  const k = knowledgeLib.loadAuthorization(facts);
  assert.equal(k.norm.state, 'proposed');
  assert.match(k.norm.source.text, /ohos\.permission\.SET_SANDBOX_POLICY/);
  assert.equal(knowledgeLib.applicability(k, 'SetPolicy').status, 'applicable');
  assert.equal(knowledgeLib.applicability(k, 'SetPolicyAsync', 'SetPolicy').status, 'unknown');
  assert.equal(knowledgeLib.applicability(k, 'UnSetPolicy').status, 'not-applicable');
});

test('persistence norm is sourced separately and cannot approve async applicability', async () => {
  const facts = factsLib.AutonomyFacts.open({ snapshot: scope.snapshotId, scope });
  const k = knowledgeLib.loadPersistenceAuthorization(facts);
  assert.equal(k.norm.state, 'proposed');
  assert.equal(k.norm.source.line, 23);
  assert.match(k.norm.source.text, /FILE_ACCESS_PERSIST/);
  assert.equal(knowledgeLib.applicability(k, 'UnSetPolicy').status, 'applicable');
  assert.equal(knowledgeLib.applicability(k, 'UnSetPolicyAsync', 'UnSetPolicy').status, 'unknown');
  assert.equal(knowledgeLib.applicability(k, 'SetPolicy').status, 'not-applicable');
  const anchors = discovery.buildAnchors(facts, scope).anchors;
  const entry = [...anchors.values()].find((e) => e.method === 'UnSetPolicyAsync');
  const r = await tools.run('getApplicableNorms', { entryRef: entry.entityId },
    { facts, scope, anchors, knowledge: k });
  assert.equal(r.payload.observations.norm.normId, k.norm.normId);
  assert.equal(r.payload.observations.applicability.status, 'unknown');
  const stale = Object.create(facts);
  stale.verifyFile = () => ({ ok: false, reason: 'stale-input' });
  assert.throws(() => knowledgeLib.loadPersistenceAuthorization(stale), /persistence-header-stale-input/);
});

test('source or permission drift blocks knowledge rather than reusing a stale norm', () => {
  const facts = factsLib.AutonomyFacts.open({ snapshot: scope.snapshotId, scope });
  const stale = Object.create(facts);
  stale.verifyFile = () => ({ ok: false, reason: 'stale-input' });
  assert.throws(() => knowledgeLib.loadAuthorization(stale), /authorization-header-stale-input/);
});

test('getApplicableNorms returns a sourced proposal, not a published authorization verdict', async () => {
  const facts = factsLib.AutonomyFacts.open({ snapshot: scope.snapshotId, scope });
  const anchors = discovery.buildAnchors(facts, scope).anchors;
  const entry = [...anchors.values()].find((e) => e.kind === 'idl' && e.method === 'SetPolicyAsync');
  const r = await tools.run('getApplicableNorms', { entryRef: entry.entityId }, { facts, scope, anchors });
  assert.equal(r.payload.status, 'ok');
  assert.equal(r.payload.answer.status, 'unknown');
  assert.equal(r.payload.observations.norm.state, 'proposed');
  assert.equal(r.payload.observations.applicability.status, 'unknown');
  assert.equal(r.payload.requiresInterpretation, true);
});

test('a separate, snapshot-bound human review can publish only the literal SetPolicy norm', () => {
  const facts = factsLib.AutonomyFacts.open({ snapshot: scope.snapshotId, scope });
  const proposal = knowledgeLib.loadAuthorization(facts);
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const keyId = `KEY:${ids.sha256Hex(publicKey.export({ type: 'spki', format: 'der' })).slice(0, 16)}`;
  const sign = (fields) => ({ ...fields, signature: crypto.sign(null,
    Buffer.from(ids.canonicalJson(fields)), privateKey).toString('base64') });
  const review = { origin: 'external-human-review', reviewer: 'test-reviewer',
    reviewedAt: '2026-10-22T00:00:00Z', decision: 'accepted',
    normId: proposal.norm.normId, proposalVersion: proposal.knowledgeVersion,
    snapshotId: proposal.snapshotId, appliesTo: ['SetPolicy'],
    rationale: 'Fixture review of the literal README permission statement.', keyId };
  const accepted = knowledgeLib.reviewAuthorization(proposal, sign(review), publicKey);
  assert.equal(accepted.norm.state, 'accepted');
  assert.equal(accepted.review.rationale, review.rationale);
  assert.notEqual(accepted.knowledgeVersion, proposal.knowledgeVersion);
  assert.equal(knowledgeLib.applicability(accepted, 'SetPolicyAsync', 'SetPolicy').status, 'unknown');
  assert.throws(() => knowledgeLib.reviewAuthorization(proposal, review, publicKey), /invalid-or-stale/);
  assert.throws(() => knowledgeLib.reviewAuthorization(proposal, sign(review),
    crypto.generateKeyPairSync('ed25519').publicKey), /invalid-or-stale/);
  assert.throws(() => knowledgeLib.reviewAuthorization(proposal, sign({ ...review, origin: 'model' }), publicKey), /invalid-or-stale/);
  assert.throws(() => knowledgeLib.reviewAuthorization(proposal, sign({ ...review, snapshotId: 'other' }), publicKey), /invalid-or-stale/);
  assert.throws(() => knowledgeLib.reviewAuthorization(proposal, sign({ ...review, appliesTo: ['SetPolicyAsync'] }), publicKey), /invalid-or-stale/);
  assert.throws(() => knowledgeLib.reviewAuthorization({ ...proposal, knowledgeVersion: 'changed' }, sign(review), publicKey), /invalid-or-stale/);
});

test('Builder review accepts exact async delegation but not stale source or invented scope', () => {
  const facts = factsLib.AutonomyFacts.open({ snapshot: scope.snapshotId, scope });
  const review = require('../K/reviews/sandbox-unset-policy-builder.json');
  const proposal = knowledgeLib.loadPersistenceAuthorization(facts);
  const accepted = knowledgeLib.reviewAuthorization(proposal, review, null);
  assert.equal(accepted.norm.authority, 'builder-llm-review');
  assert.equal(knowledgeLib.applicability(accepted, 'UnSetPolicyAsync', 'UnSetPolicy').status, 'applicable');
  assert.equal(knowledgeLib.applicability(accepted, 'UnSetPolicyAsync', 'SetPolicy').status, 'not-applicable');
  assert.equal(knowledgeLib.applicability(accepted, 'SetPolicy').status, 'not-applicable');
  assert.equal(knowledgeLib.loadPublished(path.join(knowledgeLib.PUBLISHED_DIR,
    accepted.knowledgeVersion.slice(7), 'knowledge.json'), null, facts).knowledgeVersion,
  accepted.knowledgeVersion);
  assert.throws(() => knowledgeLib.reviewAuthorization(proposal,
    { ...review, proposalVersion: 'sha256:' + '0'.repeat(64) }, null), /invalid-or-stale/);
  assert.throws(() => knowledgeLib.reviewAuthorization(proposal,
    { ...review, appliesTo: ['UnSetPolicy', 'OtherAsync'] }, null), /invalid-or-stale/);
  const stale = Object.create(facts);
  stale.verifyFile = () => ({ ok: false, reason: 'stale-input' });
  assert.throws(() => knowledgeLib.loadPublished(path.join(knowledgeLib.PUBLISHED_DIR,
    accepted.knowledgeVersion.slice(7), 'knowledge.json'), null, stale), /stale-input/);
});

// ---------------------------------------------------------------------------
// §24.28 阶段 A：来源描述符 / 文档事实 / 适用范围分离；通用 suite；策略锚点。
// ---------------------------------------------------------------------------

test('pilot source descriptors reproduce published norms byte-identically and reject unknown permissions', () => {
  const facts = factsLib.AutonomyFacts.open({ snapshot: scope.snapshotId, scope });
  assert.equal(knowledgeLib.PILOT_SOURCES.length, 2);
  for (const [source, version] of [
    [knowledgeLib.PILOT_SOURCES[0], '050e10d78c6e93541813beb477a3c1000cbfd46817a5bf8fbf7bc5dc21b7572c'],
    [knowledgeLib.PILOT_SOURCES[1], '7b1ad465ab401111ad3bfa060d31e4e790e390ad3c6f68d7b30b74ee09fd215f']
  ]) {
    const proposal = knowledgeLib.proposalFor(facts, source.permission);
    const published = knowledgeLib.loadPublished(path.join(knowledgeLib.PUBLISHED_DIR, version, 'knowledge.json'),
      null, facts);
    assert.equal(proposal.norm.normId, published.norm.normId, source.id);
    assert.equal(proposal.knowledgeVersion, published.review.proposalVersion, source.id);
    assert.equal(knowledgeLib.sourceByPermission(source.permission).id, source.id);
  }
  assert.equal(knowledgeLib.sourceByPermission('ohos.permission.NOWHERE'), null);
  assert.throws(() => knowledgeLib.proposalFor(facts, 'ohos.permission.NOWHERE'),
    /authorization-norm-unsupported/);
});

test('knowledge suite is generic: single version loads and method conflicts are rejected', () => {
  const facts = factsLib.AutonomyFacts.open({ snapshot: scope.snapshotId, scope });
  const single = knowledgeLib.loadKnowledgeSuite([path.join(knowledgeLib.PUBLISHED_DIR,
    '050e10d78c6e93541813beb477a3c1000cbfd46817a5bf8fbf7bc5dc21b7572c', 'knowledge.json')], facts);
  assert.equal(single.byMethod.size, 2);
  const pair = knowledgeLib.loadKnowledgeSuite([path.join(knowledgeLib.PUBLISHED_DIR,
    '050e10d78c6e93541813beb477a3c1000cbfd46817a5bf8fbf7bc5dc21b7572c', 'knowledge.json'),
  path.join(knowledgeLib.PUBLISHED_DIR,
    '7b1ad465ab401111ad3bfa060d31e4e790e390ad3c6f68d7b30b74ee09fd215f', 'knowledge.json')], facts);
  assert.equal(pair.byMethod.size, 16);
  assert.throws(() => knowledgeLib.loadKnowledgeSuite([path.join(knowledgeLib.PUBLISHED_DIR,
    '050e10d78c6e93541813beb477a3c1000cbfd46817a5bf8fbf7bc5dc21b7572c', 'knowledge.json'),
  path.join(knowledgeLib.PUBLISHED_DIR,
    '050e10d78c6e93541813beb477a3c1000cbfd46817a5bf8fbf7bc5dc21b7572c', 'knowledge.json')], facts),
  /knowledge-suite-duplicate-or-unreviewed/);
  assert.throws(() => knowledgeLib.loadKnowledgeSuite([], facts), /knowledge-suite-requires/);
});

test('security policy anchors pin external files by hash and bound subject capability without set inclusion', () => {
  const policy = require('../lib/autonomy/policy');
  const facts = factsLib.AutonomyFacts.open({ snapshot: scope.snapshotId, scope });
  const pol = policy.load(facts);
  assert.equal(pol.permissionDefinitions.entries['ohos.permission.SET_SANDBOX_POLICY'].availableLevel,
    'system_core');
  assert.equal(pol.permissionDefinitions.entries['ohos.permission.SET_SANDBOX_POLICY'].provisionEnable, true);
  // §24.28 复核修正：ACL 使能的权限可获得性依赖部署签名配置，等级不单独排除持有。
  assert.deepEqual(policy.subjectCanHold(pol, 'ohos.permission.SET_SANDBOX_POLICY'),
    { status: 'unknown', reason: 'acl-enabled-obtainability-deployment-dependent',
      basis: 'system_core/SYSTEM/acl-enabled' });
  assert.deepEqual(policy.subjectCanHold(pol, 'ohos.permission.FILE_ACCESS_PERSIST'),
    { status: 'yes', basis: 'normal/NORMAL' });
  assert.equal(policy.anchorQualifies(pol, 'ohos.permission.SET_SANDBOX_POLICY').qualified, false);
  assert.equal(policy.anchorQualifies(pol, 'ohos.permission.SET_SANDBOX_POLICY').reason,
    'acl-enabled-obtainability-deployment-dependent');
  assert.equal(policy.anchorQualifies(pol, 'ohos.permission.FILE_ACCESS_PERSIST').cap, 'candidate');
  assert.equal(policy.subjectCanHold(pol, 'ohos.permission.UNKNOWN').status, 'unknown');
  // 等级排除且 ACL 未使能的权限才可支撑 finding（受控桩，非本仓真实权限）。
  const stub = { ...pol, permissionDefinitions: { ...pol.permissionDefinitions,
    entries: { ...pol.permissionDefinitions.entries,
      'ohos.permission.TEST_ACL_OFF': { availableLevel: 'system_core', availableType: 'SYSTEM',
        grantMode: 'system_grant', since: 1, provisionEnable: false } } } };
  assert.deepEqual(policy.subjectCanHold(stub, 'ohos.permission.TEST_ACL_OFF'),
    { status: 'no', basis: 'system_core/SYSTEM/acl-disabled' });
  assert.equal(policy.anchorQualifies(stub, 'ohos.permission.TEST_ACL_OFF').qualified, true);

  // 锚点文件漂移必须拒绝：改写锚点文档中的固定哈希。
  const anchorsDoc = JSON.parse(fs.readFileSync(policy.ANCHORS_FILE, 'utf8'));
  const drifted = path.join(os.tmpdir(), `anchors-drift-${process.pid}.json`);
  fs.writeFileSync(drifted, JSON.stringify({
    ...anchorsDoc, permissionDefinitions: { ...anchorsDoc.permissionDefinitions, sha256: '0'.repeat(64) }
  }), 'utf8');
  try {
    assert.throws(() => policy.load(facts, drifted), /policy-anchor-stale/);
  } finally {
    fs.rmSync(drifted, { force: true });
  }
});