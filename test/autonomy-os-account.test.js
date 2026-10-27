'use strict';

/**
 * 第二组件（base/account/os_account, IAccountIAM）纵向路径的直接测试。
 *
 * 覆盖 E1 新增的四个可配置/可识别点：
 *   1. 接口级绑定 owner（scope.modelMetadata.interfaces）；
 *   2. 组件局部 operationRecipe（InnerAccountIAMManager::GetInstance().X）；
 *   3. 本地 helper 委托的权限门禁（CheckPermission(CONST) → VerifyPermission）；
 *   4. permission-argument 的 helper 形状与 `const char SYMBOL[]` 常量表。
 * 另外固定“无文档入口保持具名 norm 缺口”和“ACL 使能权限不支撑 finding”的边界。
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');

const factsLib = require('../lib/autonomy/facts');
const discovery = require('../lib/autonomy/discovery');
const vertical = require('../lib/autonomy/vertical');
const gates = require('../lib/autonomy/gates');
const knowledgeLib = require('../lib/autonomy/knowledge');
const permission = require('../lib/autonomy/permission-argument');
const proofLib = require('../lib/autonomy/static-proof');
const policyLib = require('../lib/autonomy/policy');

const SCOPE = JSON.parse(fs.readFileSync(
  path.resolve('K/policies/autonomy-os-account-iam-scope.json'), 'utf8'));
const ANCHORS_FILE = path.resolve('K/policies/autonomy-security-anchors-os-account.json');
const NORMS = {
  manage: path.resolve('K/norms/71191d8bd0eadd5e7b7a05d6ab55e0e3df4d38918663a21e34520e3ed47236a4/knowledge.json'),
  use: path.resolve('K/norms/ffed41e7fdd596e26b7a02eef58bbdb1cadb69c14c4079d1940c8c892ccb9472/knowledge.json'),
  authInternal: path.resolve('K/norms/2046964ca080ff6fee5c0540775d2815482c573bd59e8b6b8180246ec7c6896a/knowledge.json')
};

let cached = null;
function openAll() {
  if (cached) return cached;
  const facts = factsLib.AutonomyFacts.open({ snapshot: SCOPE.snapshotId, scope: SCOPE });
  const anchors = discovery.buildAnchors(facts, SCOPE);
  const suite = knowledgeLib.loadKnowledgeSuite([NORMS.manage, NORMS.use, NORMS.authInternal], facts);
  const policy = policyLib.load(facts, ANCHORS_FILE);
  cached = { facts, anchors, suite, policy };
  return cached;
}

function entryOf(anchors, method) {
  const entry = anchors.entries.find((e) => e.kind === 'idl' && e.method === method);
  assert.ok(entry, `entry ${method} present`);
  return entry;
}

function bindOf(facts, scope, anchors, method) {
  return discovery.resolveBinding(entryOf(anchors, method).entityId, { facts, scope, anchors: anchors.anchors });
}

function stubFacts({ calls, helper, text, verified = true }) {
  const sha = 'f'.repeat(64);
  return {
    callsOf: () => calls,
    index: () => ({ functions: helper ? [helper] : [], calls: calls.filter((c) => c.callee) }),
    verifyFile: () => verified ? { ok: true, actual: sha } : { ok: false, reason: 'stale-input' },
    sourceWindow: () => ({ truncated: false, sha256: sha, text })
  };
}

// ---------------------------------------------------------------------------
// 绑定与入口分母
// ---------------------------------------------------------------------------

test('os_account: entryFilter keeps exactly the 17 IAccountIAM IDL methods and all bind uniquely', () => {
  const { facts, anchors } = openAll();
  assert.equal(anchors.entries.length, 17);
  assert.ok(anchors.entries.every((e) => e.kind === 'idl'));
  assert.ok(anchors.entries.every((e) => e.interface === 'OHOS.AccountSA.IAccountIAM'));
  const stats = {};
  for (const entry of anchors.entries) {
    const binding = discovery.resolveBinding(entry.entityId,
      { facts, scope: SCOPE, anchors: anchors.anchors });
    stats[binding.binding] = (stats[binding.binding] || 0) + 1;
    assert.equal(binding.binding, 'resolved', `${entry.method} binding`);
    assert.match(binding.bound.qualified, /::AccountIAMService::/);
  }
  assert.deepEqual(stats, { resolved: 17 });
});

test('os_account: interface-level owner override does not change pilot binding semantics', () => {
  const { facts, anchors } = openAll();
  // pilot scope 仍使用默认 implOwnerSuffix；os_account 的接口级 owner 只在自身 scope 生效。
  const pilotScope = JSON.parse(fs.readFileSync(path.resolve('K/policies/autonomy-pilot-scope.json'), 'utf8'));
  const osBinding = bindOf(facts, SCOPE, anchors, 'OpenSession');
  assert.match(osBinding.note, /AccountIAMService/);
  // 用 pilot owner 段显式解析第二组件入口时必须 unbound/suspect，而不是误绑定。
  const mismatched = discovery.resolveBinding(entryOf(anchors, 'OpenSession').entityId, {
    facts, scope: { ...pilotScope, roots: SCOPE.roots, modelMetadata: pilotScope.modelMetadata }, anchors: anchors.anchors
  });
  assert.notEqual(mismatched.binding, 'resolved');
});

// ---------------------------------------------------------------------------
// 操作 recipe
// ---------------------------------------------------------------------------

test('os_account: operationRecipe resolves InnerAccountIAMManager::OpenSession as the single suspect operation', () => {
  const { facts, anchors } = openAll();
  const binding = bindOf(facts, SCOPE, anchors, 'OpenSession');
  const local = vertical.selectEvidence(facts, binding.bound, null);
  assert.equal(local.status, 'observed');
  assert.equal(local.operationCallsites.length, 1);
  assert.equal(local.operationCandidates.length, 1);
  const op = local.operationCandidates[0];
  assert.equal(op.status, 'suspect');
  const target = facts.index().functions.find((fn) => fn.factId === op.targetRef);
  assert.equal(target.qualified, 'OHOS::AccountSA::InnerAccountIAMManager::OpenSession');
  assert.equal(op.source.line, 106);
  assert.match(op.source.sha256, /^[0-9a-f]{64}$/);
});

test('os_account: pilot operation recipe does not recognize InnerAccountIAMManager operations', () => {
  const { facts, anchors } = openAll();
  const binding = bindOf(facts, SCOPE, anchors, 'OpenSession');
  const pilotScope = { ...SCOPE, operationRecipe: {
    instanceExpression: 'PolicyInfoManager::GetInstance', targetClass: 'PolicyInfoManager',
    entryOwnerSuffix: 'SandboxManagerService' } };
  const pilotFacts = Object.create(facts);
  pilotFacts.scope = pilotScope;
  const local = vertical.selectEvidence(pilotFacts, binding.bound, null);
  assert.equal(local.status, 'observed');
  assert.equal(local.operationCandidates.length, 0);
});

// ---------------------------------------------------------------------------
// 门禁：本地 helper 委托 + 权限拒绝码族
// ---------------------------------------------------------------------------

test('os_account: local helper permission gate is recognized, resolves constant and blocks the operation', () => {
  const { facts, anchors, suite } = openAll();
  const binding = bindOf(facts, SCOPE, anchors, 'OpenSession');
  const local = vertical.selectEvidence(facts, binding.bound, null);
  const enumerated = gates.enumerate(facts, local.callee, { text: local.text }, {
    operationLine: local.operationCandidates[0].source.line,
    resolvePermissionConstant: (symbol) => symbol === 'PERMISSION_MANAGE_USER_IDM'
      ? 'ohos.permission.MANAGE_USER_IDM' : null,
    resolvePermissionHelper: (name, line) => gates.resolvePermissionHelper(facts,
      { ...local.callee, qualified: 'OHOS::AccountSA::AccountIAMService::OpenSession' }, name, line)
  });
  assert.equal(enumerated.unanalyzable.length, 0);
  assert.equal(enumerated.gates.length, 1);
  const gate = enumerated.gates[0];
  assert.equal(gate.kind, 'permission-check');
  assert.equal(gate.via, 'local-helper');
  assert.equal(gate.permission, 'ohos.permission.MANAGE_USER_IDM');
  assert.equal(gate.subjectScope, 'caller');
  assert.deepEqual(gate.rejectBranch, { type: 'early-return', code: 'ERR_ACCOUNT_COMMON_PERMISSION_DENIED' });
  assert.equal(gate.blocksOperation, true);
  assert.equal(gate.verifyCall, 'VerifyPermission');
  assert.equal(gates.evaluateSubject(enumerated.gates,
    { kind: 'normal-application', holdsPermissions: [], nativeToken: 'other', uid: 'app' }).status, 'rejected');
  assert.equal(gates.evaluateSubject(enumerated.gates,
    { kind: 'normal-application', holdsPermissions: ['ohos.permission.MANAGE_USER_IDM'],
      nativeToken: 'other', uid: 'app' }).status, 'passes');
  assert.ok(suite.byMethod.get('OpenSession'));
});

test('os_account: helper resolver rejects non-caller, unresolved and non-blocking shapes with named reasons', () => {
  const sha = 'a'.repeat(64);
  const entry = { name: 'Entry', qualified: 'NS::Svc::Entry', startLine: 10, endLine: 20,
    sourceRange: { file: 'x.cpp' } };
  const helper = { name: 'CheckPermission', qualified: 'NS::Svc::CheckPermission', factId: 'h1',
    signature: 'bool Svc::CheckPermission(const std::string &permission)',
    sourceRange: { file: 'x.cpp' }, startLine: 30, endLine: 36 };

  // 正例：校验形参本身并 return false。
  const positive = gates.resolvePermissionHelper(stubFacts({
    calls: [{ line: 12, calleeName: 'CheckPermission', callee: 'h1' }],
    helper,
    text: 'if (AccountPermissionManager::VerifyPermission(permission) != ERR_OK) {\n  return false;\n}\nreturn true;'
  }), entry, 'CheckPermission', 12);
  assert.equal(positive.status, 'caller-permission');
  assert.equal(positive.verifyCall, 'VerifyPermission');

  // 负例 1：校验的不是 helper 形参 → 不是调用方权限门。
  const wrongVar = gates.resolvePermissionHelper(stubFacts({
    calls: [{ line: 12, calleeName: 'CheckPermission', callee: 'h1' }],
    helper,
    text: 'if (AccountPermissionManager::VerifyPermission(other) != ERR_OK) {\n  return false;\n}'
  }), entry, 'CheckPermission', 12);
  assert.equal(wrongVar.status, 'not-caller-permission');
  assert.equal(wrongVar.reason, 'permission-helper-not-caller-scoped');

  // 负例 2：校验后没有失败返回 → 不构成拒绝分支。
  const noReturn = gates.resolvePermissionHelper(stubFacts({
    calls: [{ line: 12, calleeName: 'CheckPermission', callee: 'h1' }],
    helper,
    text: 'if (AccountPermissionManager::VerifyPermission(permission) != ERR_OK) {\n  Log();\n}'
  }), entry, 'CheckPermission', 12);
  assert.equal(noReturn.status, 'not-caller-permission');

  // 负例 3：同一行多个同名调用 → 无法唯一定位 helper。
  const ambiguous = gates.resolvePermissionHelper(stubFacts({
    calls: [{ line: 12, calleeName: 'CheckPermission', callee: 'h1' },
      { line: 12, calleeName: 'CheckPermission', callee: 'h2' }],
    helper, text: ''
  }), entry, 'CheckPermission', 12);
  assert.equal(ambiguous.status, 'unresolved');
  assert.equal(ambiguous.reason, 'permission-helper-unresolved');

  // 负例 4：helper 源码漂移 → stale-input。
  const stale = gates.resolvePermissionHelper(stubFacts({
    calls: [{ line: 12, calleeName: 'CheckPermission', callee: 'h1' }], helper, text: '', verified: false
  }), entry, 'CheckPermission', 12);
  assert.equal(stale.status, 'unresolved');
  assert.equal(stale.reason, 'stale-input');

  // 负例 5：helper 形状无法解析（非调用方权限）时，enumerate 登记具名缺口而不是门禁。
  const enumerated = gates.enumerate(stubFacts({ calls: [], helper: null, text: '' }), { startLine: 1 }, {
    text: 'if (!CheckPermission(PERM)) {\n  return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;\n}\nInnerAccountIAMManager::GetInstance().Op();'
  }, {
    operationLine: 4,
    resolvePermissionConstant: () => 'ohos.permission.MANAGE_USER_IDM',
    resolvePermissionHelper: () => ({ status: 'not-caller-permission',
      reason: 'permission-helper-not-caller-scoped' })
  });
  assert.equal(enumerated.gates.length, 0);
  assert.deepEqual(enumerated.unanalyzable.map((u) => u.reasonCode), ['permission-helper-not-caller-scoped']);
});

test('gates: denial-code family accepts only *PERMISSION_DENIED early returns', () => {
  const accepted = gates.enumerate(null, { startLine: 1 }, {
    text: 'if (!CheckPermission(callingTokenId, A)) {\n  Log();\n  return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;\n}\nOp();'
  }, { operationLine: 5, resolvePermissionConstant: () => 'ohos.permission.X' });
  assert.deepEqual(accepted.gates[0].rejectBranch,
    { type: 'early-return', code: 'ERR_ACCOUNT_COMMON_PERMISSION_DENIED' });
  const rejected = gates.enumerate(null, { startLine: 1 }, {
    text: 'if (!CheckPermission(callingTokenId, A)) {\n  return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;\n}\nOp();'
  }, { operationLine: 5, resolvePermissionConstant: () => 'ohos.permission.X' });
  assert.equal(rejected.gates[0].rejectBranch.type, 'none-observed');
});

// ---------------------------------------------------------------------------
// permission-argument 与双命题裁决
// ---------------------------------------------------------------------------

test('os_account: permission-argument resolves the helper shape and const char[] constant table', () => {
  const { facts, anchors, suite } = openAll();
  const binding = bindOf(facts, SCOPE, anchors, 'OpenSession');
  const compared = permission.compare(facts, entryOf(anchors, 'OpenSession'), binding,
    suite.byMethod.get('OpenSession'));
  assert.equal(compared.status, 'supported');
  assert.equal(compared.checkShape, 'local-helper');
  assert.equal(compared.symbol, 'PERMISSION_MANAGE_USER_IDM');
  assert.equal(compared.observedPermission, 'ohos.permission.MANAGE_USER_IDM');
  assert.equal(compared.expectedPermission, 'ohos.permission.MANAGE_USER_IDM');
});

test('os_account: security decision is a scoped gate rejection, not a finding', () => {
  const { facts, anchors, suite, policy } = openAll();
  const anchor = entryOf(anchors, 'OpenSession');
  const binding = bindOf(facts, SCOPE, anchors, 'OpenSession');
  const compared = permission.compare(facts, anchor, binding, suite.byMethod.get('OpenSession'));
  const proof = proofLib.analyzeSecurity(facts, anchor, binding, suite.byMethod.get('OpenSession'),
    compared, { policy });
  assert.equal(proof.status, 'excluded');
  assert.equal(proof.contract.status, 'none');
  assert.equal(proof.contract.family, 'compliant');
  assert.equal(proof.security.status, 'excluded');
  assert.equal(proof.security.family, 'scoped-gate-rejection');
  assert.ok(proof.security.rejectingGates.length >= 1);
  assert.match(proof.security.note, /scoped/);
  const anchorCheck = policyLib.anchorQualifies(policy, 'ohos.permission.MANAGE_USER_IDM');
  assert.equal(anchorCheck.qualified, false);
  assert.equal(anchorCheck.reason, 'acl-enabled-obtainability-deployment-dependent');
  assert.equal(anchorCheck.cap, 'candidate');
});

test('os_account: GetCredentialInfo and GetAccountState stay named gaps, not silently covered', () => {
  const { facts, anchors, suite } = openAll();
  assert.equal(suite.byMethod.get('GetCredentialInfo'), undefined);
  assert.equal(suite.byMethod.get('GetAccountState'), undefined);
  const binding = bindOf(facts, SCOPE, anchors, 'GetAccountState');
  const proof = proofLib.analyzeSecurity(facts, entryOf(anchors, 'GetAccountState'), binding, undefined, null, {});
  assert.equal(proof.status, 'insufficient');
  assert.equal(proof.reason, 'entry-or-builder-norm-unresolved');
  const covered = [...suite.byMethod.keys()].filter((m) =>
    anchors.entries.some((e) => e.method === m));
  assert.equal(covered.length, 15);
});

test('os_account: scope staticSuite opt-in is required and pilot scope is unchanged', () => {
  assert.equal(SCOPE.staticSuite, true);
  const pilot = JSON.parse(fs.readFileSync(path.resolve('K/policies/autonomy-pilot-scope.json'), 'utf8'));
  assert.equal(pilot.scopeId, 'sandbox_manager-pilot');
  assert.equal(pilot.staticSuite, undefined);
  assert.equal(pilot.modelMetadata.implOwnerSuffix, 'SandboxManagerService');
});
