'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { AutonomyFacts } = require('../lib/autonomy/facts');
const gates = require('../lib/autonomy/gates');
const scope = require('../K/policies/autonomy-r3-napi-scope.json');

const facts = AutonomyFacts.open({ snapshot: scope.snapshotId, scope });
const file = 'base/security/access_token/services/privacymanager/src/service/privacy_manager_service.cpp';
const fn = facts.index().functions.find((item) => item.qualified ===
  'OHOS::Security::AccessToken::PrivacyManagerService::RegisterPermActiveStatusCallback');
const source = fs.readFileSync(path.join(facts.sourceRoot, ...file.split('/')), 'utf8');
const constant = /constexpr const char\* PERMISSION_USED_STATS = "([^"]+)";/.exec(source)?.[1];
const original = facts.sourceWindow(file, fn.startLine, fn.endLine);
const options = { operationLine: 323, gateVocabulary: { privacyManagerShape: true },
  resolvePermissionConstant: (symbol) => symbol === 'PERMISSION_USED_STATS' ? constant : null };
const subject = (extra = {}) => ({ kind: 'application', tokenType: 'hap', isSystemApp: false,
  holdsPermissions: [constant], nativeToken: 'other', uid: 'app', ...extra });

test('real privacyManager registration gates reject non-system HAP and missing permission', () => {
  assert.equal(facts.verifyFile(file).ok, true);
  assert.equal(original.truncated, false);
  const result = gates.enumerate(facts, fn, original, options);
  assert.deepEqual(result.gates.map((gate) => gate.kind), ['hap-system-app-check', 'permission-check']);
  assert.deepEqual(result.gates.map((gate) => gate.blocksOperation), [true, true]);
  assert.deepEqual(result.gates.map((gate) => gate.rejectBranch.code),
    ['PrivacyError::ERR_NOT_SYSTEM_APP', 'PrivacyError::ERR_PERMISSION_DENIED']);
  assert.equal(result.gates[1].permission, 'ohos.permission.PERMISSION_USED_STATS');
  assert.deepEqual(result.unanalyzable, []);
  assert.equal(gates.evaluateSubject(result.gates, subject()).status, 'rejected');
  assert.equal(gates.evaluateSubject(result.gates, subject({ isSystemApp: true })).status, 'passes');
  assert.equal(gates.evaluateSubject(result.gates, subject({ isSystemApp: true,
    holdsPermissions: [] })).status, 'rejected');
  assert.equal(gates.evaluateSubject(result.gates, subject({ tokenType: 'native',
    holdsPermissions: [] })).status, 'rejected');
});

test('return removed, helper identity changed, and unknown token type do not establish exclusion', () => {
  const noReturn = gates.enumerate(facts, fn, { ...original, text: original.text.replace(
    'return PrivacyError::ERR_NOT_SYSTEM_APP;', 'LOGE(PRI_DOMAIN, PRI_TAG, "not system app");') }, options);
  assert.equal(noReturn.gates[0].blocksOperation, null);
  assert.equal(gates.evaluateSubject(noReturn.gates, subject()).status, 'passes');

  const changedHelper = { ...facts, sourceWindow: (rel, start, end) => {
    const window = facts.sourceWindow(rel, start, end);
    return start === 546 ? { ...window, text: window.text.replace(
      'IPCSkeleton::GetCallingTokenID()', 'IPCSkeleton::GetSelfTokenID()') } : window;
  } };
  const unresolved = gates.enumerate(changedHelper, fn, original, options);
  assert.deepEqual(unresolved.gates, []);
  assert.deepEqual(unresolved.unanalyzable.map((row) => row.reasonCode),
    ['privacy-helper-unresolved', 'privacy-helper-unresolved']);

  const alternateHelper = { ...facts, sourceWindow: (rel, start, end) => {
    const window = facts.sourceWindow(rel, start, end);
    return start === 546 ? { ...window, text: window.text.replace('    return true;',
      '    if (OtherCaller()) { return true; }\n    return true;') } : window;
  } };
  assert.equal(gates.enumerate(alternateHelper, fn, original, options).unanalyzable.length, 2);
  const alternateCondition = gates.enumerate(facts, fn, { ...original, text: original.text.replace(
    '&& (!IsSystemAppCalling())', '|| (!IsSystemAppCalling())') }, options);
  assert.equal(alternateCondition.unanalyzable[0].reasonCode, 'unrecognized-caller-guard');
  assert.deepEqual(alternateCondition.gates.map((gate) => gate.kind), ['permission-check']);

  const real = gates.enumerate(facts, fn, original, options);
  assert.equal(gates.evaluateSubject(real.gates, subject({ tokenType: 'unknown' })).status, 'unknown');
  const unknownPermission = gates.enumerate(facts, fn, original,
    { ...options, resolvePermissionConstant: () => null });
  assert.equal(gates.evaluateSubject(unknownPermission.gates, subject({ isSystemApp: true })).status, 'unknown');
});
