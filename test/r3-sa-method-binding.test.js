'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { AutonomyFacts } = require('../lib/autonomy/facts');
const { buildIndex } = require('../lib/autonomy/index');
const discovery = require('../lib/autonomy/discovery');
const knowledgeLib = require('../lib/autonomy/knowledge');
const permissionArgument = require('../lib/autonomy/permission-argument');
const policyLib = require('../lib/autonomy/policy');
const staticProof = require('../lib/autonomy/static-proof');
const { resolve, bridgeOf } = require('../lib/autonomy/sa');

const scope = require('../K/policies/autonomy-ces-sa-method-scope.json');
const facts = AutonomyFacts.open({ snapshot: scope.snapshotId, scope });
const cfg = scope.saMethodBinding;
const idx = facts.index();
const entry = { kind: 'idl', interface: cfg.interface, method: cfg.method };
const row = idx.metadata.sa.find((item) => item.sourceFile === cfg.profileFile);
const read = (file) => fs.readFileSync(path.join(facts.sourceRoot, ...file.split('/')), 'utf8');
const texts = { profile: read(cfg.profileFile), ability: read(cfg.abilityFile),
  serviceHeader: read(cfg.serviceHeader) };
for (const [key, pinned] of Object.entries(cfg.pinned)) texts[key] = read(pinned.file);

test('real CES SA 3299 publishes generated ICommonEvent stub and binds method', () => {
  const result = bridgeOf(facts, entry, cfg, idx);
  assert.equal(result.status, 'resolved');
  assert.equal(result.profileRef, row.metadataId);
  assert.equal(result.serviceFactRef, resolve(entry, cfg, row, texts, idx.functions).serviceFactRef);
  const built = buildIndex(facts, scope);
  assert.equal(built.reconciliation.ok, true);
  assert.equal(built.relations.filter((rel) => rel.kind === 'sa-exposes-method').length, 1);
});

test('wrong SA ID, absent successful initialization, and drifted build do not bind', () => {
  assert.equal(resolve(entry, cfg, row, { ...texts, profile: texts.profile.replace('3299', '3300') },
    idx.functions).status, 'sa-profile-mismatch');
  assert.equal(resolve(entry, cfg, row, { ...texts, ability: texts.ability.replace(
    'if (errorCode != ERR_OK)', 'if (errorCode == ERR_OK)') }, idx.functions).status,
  'sa-publish-unresolved');
  assert.equal(resolve(entry, cfg, row, { ...texts, serviceBuild: texts.serviceBuild.replace(
    'src/common_event_manager_service.cpp', 'src/missing.cpp') }, idx.functions).status,
  'sa-build-unresolved');
  assert.equal(bridgeOf(facts, entry, { ...cfg, pinned: { ...cfg.pinned,
    coreBuild: { ...cfg.pinned.coreBuild, sha256: 'stale' } } }, idx).status, 'sa-dependency-stale');
});

test('duplicate registration or implementation and missing profile stay ambiguous', () => {
  const registration = 'REGISTER_SYSTEM_ABILITY_BY_ID(CommonEventManagerServiceAbility, COMMON_EVENT_SERVICE_ID, true);';
  assert.equal(resolve(entry, cfg, row, { ...texts, ability: texts.ability + registration },
    idx.functions).status, 'sa-registration-ambiguous');
  const method = idx.functions.find((fn) => fn.factId === bridgeOf(facts, entry, cfg, idx).serviceFactRef);
  assert.equal(resolve(entry, cfg, row, texts, [...idx.functions, { ...method, factId: 'F:duplicate' }]).status,
    'sa-method-ambiguous');
  assert.equal(bridgeOf(facts, entry, cfg, { ...idx, metadata: { ...idx.metadata, sa: [] } }).status,
    'sa-profile-ambiguous');
});

test('SA proof requires matching service fact before scoped security verdict', () => {
  const anchors = discovery.buildAnchors(facts, scope).anchors;
  const anchor = [...anchors.values()].find((item) => item.method === cfg.method);
  const binding = discovery.resolveBinding(anchor.entityId, { facts, scope, anchors });
  const knowledge = knowledgeLib.loadKnowledgeSuite([path.join(__dirname, '..',
    'K/norms/d820f37795abdc5ae65d2b26176bfd86a39847b568d16ac68dad539632981da8/knowledge.json')], facts)
    .byMethod.get(cfg.method);
  const comparison = permissionArgument.compare(facts, anchor, binding, knowledge);
  const policy = policyLib.load(facts, path.join(__dirname, '..',
    'K/policies/autonomy-security-anchors-ces.json'));
  const options = { policy, requireSaMethod: true };
  const proof = staticProof.analyzeSecurity(facts, anchor, binding, knowledge, comparison, options);
  assert.equal(proof.status, 'excluded');
  assert.equal(proof.saMethod.serviceFactRef, binding.bound.factId);
  assert.equal(proof.security.subject.kind, 'normal-application');
  assert.equal(proof.operationRef.startsWith('F:'), true);
  for (const saRegistration of [null, { ...anchor.saRegistration, status: 'sa-build-unresolved' },
    { ...anchor.saRegistration, serviceFactRef: 'F:wrong' }]) {
    const held = staticProof.analyzeSecurity(facts, { ...anchor, saRegistration }, binding,
      knowledge, comparison, options);
    assert.equal(held.status, 'insufficient');
    assert.equal(held.reason, 'sa-method-binding-unresolved');
  }
});
