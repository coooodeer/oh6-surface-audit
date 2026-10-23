'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
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
