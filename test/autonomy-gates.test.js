'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const factsLib = require('../lib/autonomy/facts');
const discovery = require('../lib/autonomy/discovery');
const vertical = require('../lib/autonomy/vertical');
const gates = require('../lib/autonomy/gates');
const knowledgeLib = require('../lib/autonomy/knowledge');
const permission = require('../lib/autonomy/permission-argument');
const proofLib = require('../lib/autonomy/static-proof');
const policyLib = require('../lib/autonomy/policy');
const scope = require('../K/policies/autonomy-pilot-scope.json');

function localOf(facts, anchors, method, delegate = null) {
  const entry = anchors.entries.find((e) => e.kind === 'idl' && e.method === method);
  const binding = discovery.resolveBinding(entry.entityId, { facts, scope, anchors: anchors.anchors });
  return { entry, binding, local: vertical.selectEvidence(facts, binding.bound, delegate) };
}

function headerResolver(facts, knowledge) {
  const text = require('node:fs').readFileSync(
    path.join(facts.sourceRoot, ...knowledge.norm.header.file.split('/')), 'utf8');
  const table = new Map();
  for (const row of text.split(/\r?\n/)) {
    const decl = /^\s*const\s+std::string\s+([A-Z][A-Z0-9_]*)\s*=\s*"([^"]+)"\s*;\s*$/.exec(row);
    if (decl) table.set(decl[1], decl[2]);
  }
  return (symbol) => (table.has(symbol) ? table.get(symbol) : null);
}

function openAll() {
  const facts = factsLib.AutonomyFacts.open({ snapshot: scope.snapshotId, scope });
  const anchors = discovery.buildAnchors(facts, scope);
  const suite = knowledgeLib.loadKnowledgeSuite([
    path.resolve('K/norms/050e10d78c6e93541813beb477a3c1000cbfd46817a5bf8fbf7bc5dc21b7572c/knowledge.json'),
    path.resolve('K/norms/7b1ad465ab401111ad3bfa060d31e4e790e390ad3c6f68d7b30b74ee09fd215f/knowledge.json')
  ], facts);
  return { facts, anchors, suite, policy: policyLib.load(facts) };
}

// ---------------------------------------------------------------------------
// B1 门禁目录：每种门禁 1 正例 + 1 reasonCode 负例。
// ---------------------------------------------------------------------------

test('gate catalog: permission-check positive resolves constant and blocks the operation', () => {
  const { facts, anchors, suite } = openAll();
  const { local } = localOf(facts, anchors, 'UnSetPolicy');
  assert.equal(local.status, 'observed');
  const knowledge = suite.byMethod.get('UnSetPolicy');
  const enumerated = gates.enumerate(facts, local.callee, { text: local.text }, {
    operationLine: local.operationCandidates[0].source.line,
    resolvePermissionConstant: headerResolver(facts, knowledge)
  });
  const gate = enumerated.gates.find((g) => g.kind === 'permission-check');
  assert.ok(gate, 'permission gate recognized');
  assert.equal(gate.permission, 'ohos.permission.SET_SANDBOX_POLICY');
  assert.equal(gate.subjectScope, 'caller');
  assert.deepEqual(gate.rejectBranch, { type: 'early-return', code: 'PERMISSION_DENIED' });
  assert.equal(gate.blocksOperation, true);
  assert.equal(enumerated.unanalyzable.length, 0);
  const eval1 = gates.evaluateSubject(enumerated.gates,
    { kind: 'normal-application', holdsPermissions: ['ohos.permission.FILE_ACCESS_PERSIST'],
      nativeToken: 'other', uid: 'app' });
  assert.equal(eval1.status, 'rejected');
});

test('gate catalog: permission-check negatives give named reasonCodes', () => {
  const { facts, anchors, suite } = openAll();
  const { local } = localOf(facts, anchors, 'UnSetPolicy');
  const knowledge = suite.byMethod.get('UnSetPolicy');
  const opLine = local.operationCandidates[0].source.line;
  // 常量解析失败 → permission-constant-unresolved，主体评估 unknown。
  const unresolved = gates.enumerate(facts, local.callee, { text: local.text },
    { operationLine: opLine, resolvePermissionConstant: () => null });
  const gate = unresolved.gates.find((g) => g.kind === 'permission-check');
  assert.equal(gate.unresolved, 'permission-constant-unresolved');
  assert.equal(gates.evaluateSubject(unresolved.gates,
    { kind: 'normal-application', holdsPermissions: [], nativeToken: null, uid: null }).status, 'unknown');
  // 组合条件 → combined-gate-unsupported。
  const synthetic = gates.enumerate(facts, { startLine: 1 }, {
    text: 'if (!CheckPermission(callingTokenId, A) && !CheckPermission(callingTokenId, B)) {\n  return PERMISSION_DENIED;\n}\nMutate();'
  }, { operationLine: 5, resolvePermissionConstant: () => null });
  assert.deepEqual(synthetic.unanalyzable.map((u) => u.reasonCode), ['combined-gate-unsupported']);
  assert.equal(synthetic.gates.length, 0);
  // 检查存在但不早退 → 门禁记录为 none-observed，不阻断。
  const fallThrough = gates.enumerate(facts, { startLine: 1 }, {
    text: 'if (!CheckPermission(callingTokenId, A)) {\n  Log();\n}\nMutate();'
  }, { operationLine: 4, resolvePermissionConstant: () => 'ohos.permission.X' });
  assert.equal(fallThrough.gates[0].rejectBranch.type, 'none-observed');
  assert.notEqual(fallThrough.gates[0].blocksOperation, true);
});

test('gate catalog: native-token-match resolves the helper body; unresolved helpers stay unknown', () => {
  const { facts, anchors } = openAll();
  const { local } = localOf(facts, anchors, 'CleanPolicyByUserId');
  assert.equal(local.status, 'observed');
  const enumerated = gates.enumerate(facts, local.callee, { text: local.text }, {
    operationLine: local.operationCandidates[0].source.line
  });
  const gate = enumerated.gates.find((g) => g.kind === 'native-token-match');
  assert.ok(gate, 'native-token gate recognized');
  assert.equal(gate.nativeProcess, 'file_manager_service');
  assert.equal(gate.blocksOperation, true);
  assert.equal(gates.evaluateSubject(enumerated.gates,
    { kind: 'normal-application', holdsPermissions: [], nativeToken: 'other', uid: 'app' }).status, 'rejected');
  assert.equal(gates.evaluateSubject(enumerated.gates,
    { kind: 'system-service', holdsPermissions: [], nativeToken: 'file_manager_service', uid: 'x' }).status,
  'passes');
  // 负例 1：辅助函数无法唯一解析 → native-token-helper-unresolved。
  const broken = Object.create(facts);
  broken.findFunctions = () => [{ role: 'production' }, { role: 'production' }];
  const negative = gates.enumerate(broken, local.callee, { text: local.text }, {
    operationLine: local.operationCandidates[0].source.line
  });
  assert.equal(negative.gates.find((g) => g.kind === 'native-token-match').unresolved,
    'native-token-helper-unresolved');
  // 负例 2（复核修正）：GetNativeTokenId 赋值变量与 return 比较变量不一致 → 形状不支持。
  const mismatched = Object.create(facts);
  mismatched.findFunctions = () => [{
    role: 'production', name: 'IsFileManagerCalling',
    sourceRange: { file: 'base/accesscontrol/sandbox_manager/services/sandbox_manager/main/cpp/src/service/sandbox_manager_service.cpp' },
    startLine: 778, endLine: 786
  }];
  mismatched.sourceWindow = () => ({
    file: 'stub-helper.cpp', startLine: 1, endLine: 6, truncated: false,
    sha256: 'stub', text: [
      'bool SandboxManagerService::IsFileManagerCalling(uint32_t tokenCaller)',
      '{',
      '    uint32_t tokenFileManagerId_ = AccessTokenKit::GetNativeTokenId("file_manager_service");',
      '    uint32_t otherId_ = AccessTokenKit::GetNativeTokenId("someone_else");',
      '    return tokenCaller == otherId_;',
      '}'
    ].join('\n')
  });
  mismatched.verifyFile = () => ({ ok: true, actual: 'stub' });
  const imprecise = gates.enumerate(mismatched, local.callee, { text: local.text }, {
    operationLine: local.operationCandidates[0].source.line
  });
  assert.equal(imprecise.gates.find((g) => g.kind === 'native-token-match').unresolved,
    'native-token-helper-shape-unsupported');
});

test('gate catalog: unrecognized caller-identity guards become named gaps, not absent gates', () => {
  const { facts } = openAll();
  const synthetic = gates.enumerate(facts, { startLine: 1 }, {
    text: 'int32_t f()\n{\n    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();\n    if (!VerifyAuthorized(callingTokenId)) {\n        return PERMISSION_DENIED;\n    }\n    return Mutate();\n}'
  }, { operationLine: 7 });
  assert.equal(synthetic.gates.length, 0);
  assert.deepEqual(synthetic.unanalyzable.map((u) => u.reasonCode), ['unrecognized-caller-guard']);
  // 非 if 上下文仅声明/获取身份不构成门禁，也不产生缺口。
  const declared = gates.enumerate(facts, { startLine: 1 }, {
    text: 'int32_t f()\n{\n    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();\n    return Mutate(callingTokenId);\n}'
  }, { operationLine: 3 });
  assert.equal(declared.gates.length, 0);
  assert.equal(declared.unanalyzable.length, 0);
});

test('gate catalog: uid-match rejects non-foundation callers; allow-shape becomes a modifier', () => {
  const { facts, anchors } = openAll();
  const uidEntry = localOf(facts, anchors, 'StartAccessingByTokenId');
  const enumerated = gates.enumerate(facts, uidEntry.local.callee, { text: uidEntry.local.text }, {
    operationLine: uidEntry.local.operationCandidates[0].source.line
  });
  const uidGate = enumerated.gates.find((g) => g.kind === 'uid-match');
  assert.ok(uidGate, 'uid gate recognized');
  assert.equal(uidGate.uidSymbol, 'FOUNDATION_UID');
  assert.equal(uidGate.blocksOperation, true);
  assert.equal(gates.evaluateSubject(enumerated.gates,
    { kind: 'normal-application', holdsPermissions: [], nativeToken: null, uid: 'app' }).status, 'rejected');

  const persist = localOf(facts, anchors, 'PersistPolicy');
  const allowEnumerated = gates.enumerate(facts, persist.local.callee, { text: persist.local.text }, {
    operationLine: persist.local.operationCandidates[0].source.line,
    resolvePermissionConstant: headerResolver(facts, { norm: { header: { file:
      'base/accesscontrol/sandbox_manager/services/sandbox_manager/main/cpp/include/service/sandbox_manager_const.h' } } })
  });
  assert.ok(allowEnumerated.modifiers.some((m) => m.kind === 'allow-shape-modifier'),
    'positive == comparison recorded as modifier');
  assert.equal(allowEnumerated.gates.filter((g) => g.kind === 'uid-match').length, 0);
  assert.equal(allowEnumerated.unanalyzable.length, 0);
});

// ---------------------------------------------------------------------------
// B2 双命题裁决：真实入口的契约差异 + 安全裁决 + 旧契约命题并存。
// ---------------------------------------------------------------------------

test('dual proposition: the six legacy findings become contract deviations with scoped security outcomes', () => {
  const { facts, anchors, suite, policy } = openAll();
  const expected = {
    UnSetPolicy: ['permission-mismatch', 'excluded', 'permission-check'],
    UnSetPolicyAsync: ['permission-mismatch', 'excluded', 'permission-check'],
    UnSetAllPolicyByToken: ['permission-mismatch', 'excluded', 'permission-check'],
    CleanPolicyByUserId: ['alternate-identity-gate', 'excluded', 'native-token-match'],
    CleanPersistPolicyByPath: ['alternate-identity-gate', 'excluded', 'native-token-match'],
    StartAccessingByTokenId: ['alternate-identity-gate', 'excluded', 'uid-match']
  };
  for (const [method, [contractFamily, securityStatus, rejectingKind]] of Object.entries(expected)) {
    const entry = anchors.entries.find((e) => e.kind === 'idl' && e.method === method);
    const binding = discovery.resolveBinding(entry.entityId, { facts, scope, anchors: anchors.anchors });
    const knowledge = suite.byMethod.get(method);
    const comparison = permission.compare(facts, entry, binding, knowledge);
    const proof = proofLib.analyzeSecurity(facts, entry, binding, knowledge, comparison, { policy });
    assert.equal(proof.contract.family, contractFamily, `${method} contract family`);
    assert.equal(proof.contract.status, 'deviation', `${method} contract is a deviation`);
    assert.equal(proof.security.status, securityStatus, `${method} security status`);
    assert.equal(proof.status, 'excluded', `${method} task level`);
    assert.ok(proof.security.subject.description.includes('holds'),
      `${method} carries a concrete subject`);
    assert.ok(proof.security.rejectingGates.some((g) => g.kind === rejectingKind),
      `${method} rejected by ${rejectingKind}`);
    assert.match(proof.limitation, /not whole-entry safety/);
  }
});

test('dual proposition: compliant entries stay excluded for the lacking-permission subject only', () => {
  const { facts, anchors, suite, policy } = openAll();
  for (const method of ['SetPolicy', 'SetPolicyAsync', 'PersistPolicy', 'UnPersistPolicy',
    'StartAccessingPolicy', 'StopAccessingPolicy']) {
    const entry = anchors.entries.find((e) => e.kind === 'idl' && e.method === method);
    const binding = discovery.resolveBinding(entry.entityId, { facts, scope, anchors: anchors.anchors });
    const knowledge = suite.byMethod.get(method);
    const comparison = permission.compare(facts, entry, binding, knowledge);
    const proof = proofLib.analyzeSecurity(facts, entry, binding, knowledge, comparison, { policy });
    assert.equal(proof.contract.status, 'none', method);
    assert.equal(proof.security.status, 'excluded', method);
    assert.ok(proof.security.subject.holdsPermissions.length === 0,
      `${method} excluded subject lacks the anchored permission`);
  }
});

test('dual proposition: combined conditions and ambiguous chains keep named insufficiency', () => {
  const { facts, anchors, suite, policy } = openAll();
  const checkPolicy = anchors.entries.find((e) => e.kind === 'idl' && e.method === 'CheckPolicy');
  const checkBinding = discovery.resolveBinding(checkPolicy.entityId, { facts, scope, anchors: anchors.anchors });
  const checkProof = proofLib.analyzeSecurity(facts, checkPolicy, checkBinding,
    suite.byMethod.get('CheckPolicy'),
    permission.compare(facts, checkPolicy, checkBinding, suite.byMethod.get('CheckPolicy')), { policy });
  assert.equal(checkProof.status, 'insufficient');
  assert.equal(checkProof.security.reason, 'combined-gate-unsupported');

  const bundle = anchors.entries.find((e) => e.kind === 'idl' && e.method === 'SetPolicyByBundleName');
  const bundleBinding = discovery.resolveBinding(bundle.entityId, { facts, scope, anchors: anchors.anchors });
  const bundleProof = proofLib.analyzeSecurity(facts, bundle, bundleBinding,
    suite.byMethod.get('SetPolicyByBundleName'),
    permission.compare(facts, bundle, bundleBinding, suite.byMethod.get('SetPolicyByBundleName')), { policy });
  assert.equal(bundleProof.status, 'insufficient');
  assert.equal(bundleProof.reason, 'call-chain-or-operation-ambiguous');
});

test('dual proposition: old contract analyze stays unchanged for legacy recomputation', () => {
  const { facts, anchors, suite } = openAll();
  const entry = anchors.entries.find((e) => e.kind === 'idl' && e.method === 'UnSetPolicyAsync');
  const binding = discovery.resolveBinding(entry.entityId, { facts, scope, anchors: anchors.anchors });
  const knowledge = suite.byMethod.get('UnSetPolicyAsync');
  const comparison = permission.compare(facts, entry, binding, knowledge);
  const legacy = proofLib.analyze(facts, entry, binding, knowledge, comparison, { includeNewFamilies: true });
  assert.equal(legacy.status, 'finding');
  assert.equal(legacy.family, 'permission-mismatch');
  assert.equal(legacy.observedPermission, 'ohos.permission.SET_SANDBOX_POLICY');
});

test('dual proposition: model counterexample downgrades a scoped exclusion but never upgrades', () => {
  const { facts, anchors, suite, policy } = openAll();
  const entry = anchors.entries.find((e) => e.kind === 'idl' && e.method === 'UnSetPolicy');
  const binding = discovery.resolveBinding(entry.entityId, { facts, scope, anchors: anchors.anchors });
  const knowledge = suite.byMethod.get('UnSetPolicy');
  const comparison = permission.compare(facts, entry, binding, knowledge);
  const proof = proofLib.analyzeSecurity(facts, entry, binding, knowledge, comparison, { policy });
  const downgraded = proofLib.arbitrateSecurity(proof, { gate: 'accepted', decision: 'refuted',
    rationale: 'counterexample', modelCallRef: 'CALL:test' });
  assert.equal(downgraded.status, 'candidate');
  assert.equal(downgraded.reasonCode, 'prover-model-conflict');
  const upheld = proofLib.arbitrateSecurity(proof, { gate: 'accepted', decision: 'supported',
    rationale: 'agrees', modelCallRef: 'CALL:test' });
  assert.equal(upheld.status, 'excluded');
  assert.equal(proofLib.arbitrateSecurity({ status: 'candidate' },
    { gate: 'accepted', decision: 'supported', rationale: 'x' }).status, 'candidate');
});

test('dual proposition: security proof cache reuses the shared delegate body', () => {
  const { facts, anchors, suite, policy } = openAll();
  const cache = new Map();
  let hits = 0;
  for (const method of ['UnSetPolicy', 'UnSetPolicyAsync']) {
    const entry = anchors.entries.find((e) => e.kind === 'idl' && e.method === method);
    const binding = discovery.resolveBinding(entry.entityId, { facts, scope, anchors: anchors.anchors });
    const knowledge = suite.byMethod.get(method);
    const comparison = permission.compare(facts, entry, binding, knowledge);
    const proof = proofLib.analyzeSecurity(facts, entry, binding, knowledge, comparison,
      { policy, cache, onCacheHit: () => { hits += 1; } });
    assert.equal(proof.status, 'excluded');
  }
  assert.equal(hits, 1);
});

// ---------------------------------------------------------------------------
// C1：双命题语义变异体（真实门禁家族）；旧标签与旧评测保持隔离。
// ---------------------------------------------------------------------------

test('security-verdict mutants: identity gates exclude, ACL-capped positives stay candidate, ambiguity insufficient', () => {
  const staticEval = require('../tools/autonomy-static-eval');
  const result = staticEval.evaluateSecurityMutants();
  assert.equal(result.labelSource, 'builder-llm-oracle');
  assert.equal(result.labelAuthority, 'builder-llm-oracle');
  assert.equal(result.semantics, '1.0.20-security-verdict');
  assert.equal(result.sampleCount, 10);
  assert.equal(result.judgmentAccuracy, 1);
  assert.equal(result.familyAccuracy, 1);
  // ACL 修正后本仓没有等级排除且 ACL 未使能的锚点权限：预期正例全部为 candidate，
  // finding 精度/召回分母为 0，如实报 null，不虚构 finding 命中。
  assert.equal(result.findingPrecision, null);
  assert.equal(result.givenMutantFindingRecall, null);
  assert.equal(result.falseCertaintyRate, 0);
  assert.equal(result.discoveryRecall, null);
  assert.equal(result.independentAccuracy, null);
  const byFamily = Object.fromEntries(result.rows.map((row) => [row.familyId, row]));
  assert.equal(byFamily['gate-permission-weakened'].observed, 'candidate');
  assert.equal(byFamily['gate-permission-weakened'].observedSecurityReason,
    'acl-enabled-obtainability-deployment-dependent');
  assert.equal(byFamily['no-gate-normal-level'].observed, 'candidate');
  assert.equal(byFamily['no-gate-normal-level'].observedSecurityReason, 'permission-obtainable-by-subject');
  assert.equal(byFamily['no-gate-core-level'].observed, 'candidate');
  assert.equal(byFamily['gate-non-early-return'].observed, 'candidate');
  assert.equal(byFamily['gate-subject-mismatch'].observed, 'candidate');
  assert.equal(byFamily['gate-native-token'].observed, 'excluded');
  assert.equal(byFamily['gate-uid'].observed, 'excluded');
  assert.equal(byFamily['combined-gate-ambiguous'].observed, 'insufficient');
  assert.equal(byFamily['combined-gate-ambiguous'].observedSecurityReason, 'combined-gate-unsupported');
});

test('security finding machinery still fires under a qualified stub anchor (ACL-disabled)', () => {
  const { facts, anchors, suite, policy } = openAll();
  // 受控桩锚点：等级排除且 ACL 未使能（本仓真实权限均 ACL 使能，仅用于验证 finding 机制）。
  const stubPolicy = { ...policy, permissionDefinitions: { ...policy.permissionDefinitions,
    entries: { ...policy.permissionDefinitions.entries,
      'ohos.permission.SET_SANDBOX_POLICY': { ...policy.permissionDefinitions.entries['ohos.permission.SET_SANDBOX_POLICY'],
        provisionEnable: false } } } };
  const staticEval = require('../tools/autonomy-static-eval');
  const label = require('../eval/autonomy/security-verdict-mutants.json').labels
    .find((row) => row.familyId === 'no-gate-core-level');
  const entry = anchors.entries.find((e) => e.kind === 'idl' && e.method === label.method);
  const original = discovery.resolveBinding(entry.entityId, { facts, scope, anchors: anchors.anchors });
  const { facts: mutantFacts, fn } = staticEval.securityMutantFacts(facts, original.bound, label);
  const knowledge = suite.byMethod.get(label.method);
  const comparison = permission.compare(mutantFacts, entry, { binding: 'resolved', bound: fn }, knowledge);
  const stubProof = proofLib.analyzeSecurity(mutantFacts, entry, { binding: 'resolved', bound: fn },
    knowledge, comparison, { policy: stubPolicy });
  // 合格锚点（等级排除且 ACL 关闭）下，无门禁路径的缺权主体到达操作 → finding。
  assert.equal(stubProof.status, 'finding');
  assert.equal(stubProof.security.family, 'no-analyzable-gate');
  assert.equal(stubProof.security.anchor.qualified, true);
  // 真实锚点（ACL 使能）下同一变异体 → candidate，reason 具名。
  const realProof = proofLib.analyzeSecurity(mutantFacts, entry, { binding: 'resolved', bound: fn },
    knowledge, comparison, { policy });
  assert.equal(realProof.status, 'candidate');
  assert.equal(realProof.security.reason, 'acl-enabled-obtainability-deployment-dependent');
});

test('dual proposition: model review conflicts downgrade findings as well as exclusions', () => {
  const findingProof = { status: 'finding', security: { family: 'no-analyzable-gate',
    subject: { description: 'stub subject' }, proposition: 'stub proposition' } };
  const downgraded = proofLib.arbitrateSecurity(findingProof,
    { gate: 'accepted', decision: 'supported', rationale: 'gates do block this subject', modelCallRef: 'CALL:t' });
  assert.equal(downgraded.status, 'candidate');
  assert.equal(downgraded.reasonCode, 'prover-model-conflict');
  const conflictToo = proofLib.arbitrateSecurity(findingProof,
    { gate: 'accepted', decision: 'conflict', rationale: 'x', modelCallRef: 'CALL:t' });
  assert.equal(conflictToo.status, 'candidate');
  const upheld = proofLib.arbitrateSecurity(findingProof,
    { gate: 'accepted', decision: 'refuted', rationale: 'x', modelCallRef: 'CALL:t' });
  assert.equal(upheld.status, 'finding');
});

test('dual proposition: arbitration is null-safe without a model review (off mode)', () => {
  // off 模式没有模型意见：任何 proof 状态都不得崩溃，等级原样返回。
  for (const proof of [{ status: 'finding' }, { status: 'excluded' }, { status: 'candidate' },
    { status: 'insufficient' }, null, undefined]) {
    const verdict = proofLib.arbitrateSecurity(proof, null);
    assert.equal(verdict.status, proof ? proof.status : 'insufficient');
    const undefinedCheck = proofLib.arbitrateSecurity(proof, undefined);
    assert.equal(undefinedCheck.status, proof ? proof.status : 'insufficient');
  }
});

test('security-verdict mutants stay isolated from the frozen legacy mutant labels', () => {
  const staticEval = require('../tools/autonomy-static-eval');
  const legacy = staticEval.evaluateMutants();
  const security = staticEval.evaluateSecurityMutants();
  assert.equal(legacy.sampleCount, 5);
  assert.equal(legacy.semantics, undefined);
  assert.equal(security.sampleCount, 10);
  // 同一受控变异体（如 weakened/no-check 的 SetPolicy 体）允许在新旧两套语义下分别标注；
  // 隔离要求是标签与评测流程分离：旧 5 标签文件与旧目录不动，新标签走新文件与新目录。
  const fs = require('node:fs');
  const path = require('node:path');
  const legacyFiles = fs.readdirSync(path.join(__dirname, '..', 'test/fixtures/autonomy/mutants')).sort();
  assert.deepEqual(legacyFiles, ['ambiguous-operation.cpp', 'compliant-excluded.cpp',
    'guard-non-dominating.cpp', 'missing-permission-check.cpp', 'permission-mismatch.cpp']);
  const securityFiles = fs.readdirSync(path.join(__dirname, '..', 'test/fixtures/autonomy/security-mutants')).sort();
  assert.equal(securityFiles.length, 10);
  assert.ok(securityFiles.every((file) => !legacyFiles.includes(file)));
  const legacyLabels = require('../eval/autonomy/static-builder-mutants.json');
  assert.equal(legacyLabels.labels.length, 5);
  assert.equal(require('../eval/autonomy/security-verdict-mutants.json').labels.length, 10);
});
