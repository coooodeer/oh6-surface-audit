'use strict';

/**
 * 新增门禁/操作形状的最小三态测试：
 *   - 成立：system-app-check、system-app-or-native、inline literal、argument-type 消歧；
 *   - 不成立：缺少早退 / 主体满足门禁；
 *   - 无法判定：权限常量未解析。
 * 每个测试只覆盖本次新增的有界形状，不把合成文本当成真实组件结论。
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const factsLib = require('../lib/autonomy/facts');
const discovery = require('../lib/autonomy/discovery');
const gates = require('../lib/autonomy/gates');
const knowledgeLib = require('../lib/autonomy/knowledge');
const permission = require('../lib/autonomy/permission-argument');
const vertical = require('../lib/autonomy/vertical');

const CES_SCOPE = require('../K/policies/autonomy-ces-icommonevent-vertical-scope.json');
const CES_NORM = path.resolve('K/norms/d820f37795abdc5ae65d2b26176bfd86a39847b568d16ac68dad539632981da8/knowledge.json');

function synthetic(lines, operationLine, startLine = 1, gateVocabulary = {}) {
  const callee = { startLine, endLine: startLine + lines.length - 1, factId: 'F:test:function:1',
    qualified: 'NS::TestService::Run', name: 'Run', signature: 'ErrCode Run()' };
  return gates.enumerate({}, callee, { text: lines.join('\n') },
    { operationLine, gateVocabulary });
}

test('system-app-check: early return holds for a normal app, absent return does not', () => {
  const holds = synthetic([
    'ErrCode Run() {',
    '    std::int32_t ret = AccountPermissionManager::CheckSystemApp();',
    '    if (ret != ERR_OK) {',
    '        return ret;',
    '    }',
    '    return Do();',
    '}'
  ], 6, 1, { systemAppShape: true });
  const gate = holds.gates.find((g) => g.kind === 'system-app-check');
  assert.ok(gate);
  assert.equal(gate.blocksOperation, true);
  assert.equal(gates.evaluateSubject(holds.gates,
    { kind: 'normal-application', holdsPermissions: [], nativeToken: 'other', uid: 'app',
      isSystemApp: false }).status, 'rejected');
  assert.equal(gates.evaluateSubject(holds.gates,
    { kind: 'system-application', holdsPermissions: [], nativeToken: 'other', uid: 'system',
      isSystemApp: true }).status, 'passes');

  const absent = synthetic([
    'ErrCode Run() {',
    '    std::int32_t ret = AccountPermissionManager::CheckSystemApp();',
    '    if (ret != ERR_OK) {',
    '        LOG("not system app");',
    '    }',
    '    return Do();',
    '}'
  ], 6, 1, { systemAppShape: true });
  const absentGate = absent.gates.find((g) => g.kind === 'system-app-check');
  assert.ok(absentGate);
  assert.ok(!absentGate.blocksOperation);
  assert.equal(gates.evaluateSubject(absent.gates,
    { kind: 'normal-application', holdsPermissions: [], nativeToken: 'other', uid: 'app',
      isSystemApp: false }).status, 'passes');

  // 无法判定：门禁已识别但权限常量未解析。
  assert.equal(gates.evaluateSubject([
    { kind: 'permission-check', blocksOperation: true, subjectScope: 'caller',
      unresolved: 'permission-constant-unresolved' }
  ], { kind: 'normal-application', holdsPermissions: [], nativeToken: 'other', uid: 'app' }).status, 'unknown');
});

test('system-app-or-native + native bypass: normal app rejected, native token passes', () => {
  const lines = [
    'ErrCode Run() {',
    '    auto tokenId = IPCSkeleton::GetCallingTokenID();',
    '    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(tokenId);',
    '    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {',
    '        funcResult = ERR_NOT_SYSTEM_APP;',
    '        return ERR_OK;',
    '    }',
    '    const std::string permission = "ohos.permission.COMMONEVENT_STICKY";',
    '    bool ret = AccessTokenHelper::VerifyAccessToken(tokenId, permission);',
    '    if (!ret && (!isSubsystem || bypass)) {',
    '        funcResult = ERR_PERMISSION_DENIED;',
    '        return ERR_OK;',
    '    }',
    '    funcResult = Do();',
    '    return ERR_OK;',
    '}'
  ];
  const enumerated = synthetic(lines, 14, 1, { systemAppOrNativeShape: true });
  assert.deepEqual(enumerated.gates.map((g) => g.kind), ['system-app-or-native', 'permission-check']);
  assert.equal(enumerated.gates[1].permission, 'ohos.permission.COMMONEVENT_STICKY');
  assert.equal(enumerated.gates.every((g) => g.blocksOperation === true), true);
  assert.equal(enumerated.unanalyzable.length, 0);
  assert.equal(gates.evaluateSubject(enumerated.gates,
    { kind: 'normal-application', holdsPermissions: [], nativeToken: 'other', uid: 'app',
      isSystemApp: false }).status, 'rejected');
  assert.equal(gates.evaluateSubject(enumerated.gates,
    { kind: 'normal-application', holdsPermissions: [], nativeToken: 'native', uid: 'native',
      isSystemApp: false }).status, 'passes');
  assert.equal(gates.evaluateSubject(enumerated.gates,
    { kind: 'system-application', holdsPermissions: ['ohos.permission.COMMONEVENT_STICKY'],
      nativeToken: 'other', uid: 'system', isSystemApp: true }).status, 'passes');
  assert.equal(gates.evaluateSubject(enumerated.gates,
    { kind: 'system-application', holdsPermissions: [], nativeToken: 'other', uid: 'system',
      isSystemApp: true }).status, 'rejected');

  // 不成立：拒绝分支没有 return，门禁不阻断。
  const noReturn = synthetic(lines.filter((_, index) => ![5, 11].includes(index)), 12, 1,
    { systemAppOrNativeShape: true });
  assert.equal(noReturn.gates.every((g) => !g.blocksOperation), true);
  assert.equal(gates.evaluateSubject(noReturn.gates,
    { kind: 'system-application', holdsPermissions: ['ohos.permission.COMMONEVENT_STICKY'],
      nativeToken: 'other', uid: 'system', isSystemApp: true }).status, 'passes');

  // 无法判定：内联权限字面量缺失 → permission gate unresolved。
  const noLiteral = synthetic(lines.filter((_, index) => index !== 7), 13, 1,
    { systemAppOrNativeShape: true });
  assert.equal(noLiteral.gates.find((g) => g.kind === 'permission-check').unresolved,
    'permission-constant-unresolved');
  assert.equal(gates.evaluateSubject(noLiteral.gates,
    { kind: 'normal-application', holdsPermissions: [], nativeToken: 'other', uid: 'app',
      isSystemApp: false }).status, 'unknown');
});

test('CES inline literal contract: VerifyAccessToken + local const compares as supported', () => {
  const facts = factsLib.AutonomyFacts.open({ snapshot: CES_SCOPE.snapshotId, scope: CES_SCOPE });
  const anchors = discovery.buildAnchors(facts, CES_SCOPE);
  const entry = anchors.entries.find((e) => e.method === 'RemoveStickyCommonEvent');
  const binding = discovery.resolveBinding(entry.entityId, { facts, scope: CES_SCOPE,
    anchors: anchors.anchors });
  assert.equal(binding.binding, 'resolved');
  const suite = knowledgeLib.loadKnowledgeSuite([CES_NORM], facts);
  const result = permission.compare(facts, entry, binding, suite.byMethod.get('RemoveStickyCommonEvent'));
  assert.equal(result.status, 'supported');
  assert.equal(result.checkShape, 'inline-literal');
  assert.equal(result.observedPermission, 'ohos.permission.COMMONEVENT_STICKY');
  assert.equal(result.expectedPermission, 'ohos.permission.COMMONEVENT_STICKY');
});

test('argument-type overload disambiguation picks exactly one compatible target', () => {
  const callee = { signature: 'ErrCode AccountMgrService::SetOsAccountDistributedInfo(' +
    'int32_t localId, const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr)' };
  const line = '    ret = OhosAccountManager::GetInstance().OhosAccountStateChange(' +
    'localId, ohosAccountInfo, eventStr);';
  const targets = [
    { qualified: 'A::OhosAccountStateChange', signature: 'ErrCode OhosAccountManager::OhosAccountStateChange(' +
      'const std::string &name, const std::string &uid, const std::string &eventStr)' },
    { qualified: 'B::OhosAccountStateChange', signature: 'ErrCode OhosAccountManager::OhosAccountStateChange(' +
      'int32_t userId, const OhosAccountInfo &info, const std::string &eventStr)' }
  ];
  assert.equal(vertical.disambiguateByArgumentType(callee, line, 'OhosAccountStateChange', targets),
    targets[1]);
  // 无法唯一：两个候选参数类型都兼容。
  assert.equal(vertical.disambiguateByArgumentType(callee, line, 'OhosAccountStateChange',
    [targets[1], { ...targets[1], qualified: 'C' }]), null);
});
