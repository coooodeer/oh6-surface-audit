'use strict';

/**
 * test/r2-binding-types.test.js —— R2-D1 参数类型族消歧的正反用例（纯函数，无快照依赖）。
 *
 * 正例：同 argc、不同容器/字符串类型 → 唯一幸存。
 * 反例 1：别名未解（AccessTokenID 等 → other）⇒ 无可判位 → 不收敛（保持多候选）。
 * 反例 2：类型族信息不足以区分（两个候选都兼容）⇒ 全部幸存 → 不收敛。
 * 反例 3：签名缺失 ⇒ 不提供证据。
 */

const test = require('node:test');
const assert = require('node:assert');

const discovery = require('../lib/autonomy/discovery');

const IDL_VERIFY_LIST = [
  { direction: 'in', type: 'unsigned int', name: 'tokenID' },
  { direction: 'in', type: 'List<String>', name: 'permissionList' },
  { direction: 'out', type: 'List<int>', name: 'permStateList' }
];
const IDL_VERIFY_STRING = [
  { direction: 'in', type: 'unsigned int', name: 'tokenID' },
  { direction: 'in', type: 'String', name: 'permissionName' },
  { direction: 'out', type: 'int', name: 'state' }
];

const SIG_LIST = 'int AccessTokenManagerService::VerifyAccessToken(AccessTokenID tokenID, '
  + 'const std::vector<std::string>& permissionList, std::vector<int32_t>& permStateList)';
const SIG_STRING = 'int32_t AccessTokenManagerService::VerifyAccessToken('
  + 'AccessTokenID tokenID, const std::string& permissionName, int32_t& state)';

test('正例：真实重载对各自唯一兼容（类型族可判位强制）', () => {
  assert.strictEqual(discovery.paramTypesCompatible(IDL_VERIFY_LIST, SIG_LIST), true);
  assert.strictEqual(discovery.paramTypesCompatible(IDL_VERIFY_STRING, SIG_LIST), false);
  assert.strictEqual(discovery.paramTypesCompatible(IDL_VERIFY_STRING, SIG_STRING), true);
  assert.strictEqual(discovery.paramTypesCompatible(IDL_VERIFY_LIST, SIG_STRING), false);
  // 签名 → 参数类型切分（vector<T> 内的逗号不被切分）
  assert.deepStrictEqual(discovery.signatureParamTypes(SIG_LIST),
    ['AccessTokenID tokenID', 'const std::vector<std::string>& permissionList',
      'std::vector<int32_t>& permStateList']);
});

test('反例：别名未解 ⇒ 无可判位，不收敛', () => {
  // 两候选只有别名参数差异（AccessTokenID vs UserIdType），IDL 侧是 unsigned int
  const idl = [{ type: 'unsigned int', name: 'x' }, { type: 'int', name: 'y' }];
  const sigA = 'int F(AccessTokenID tokenID, int state)';
  const sigB = 'int F(UserIdType userId, int state)';
  const evidence = { count: 0 };
  assert.strictEqual(discovery.paramTypesCompatible(idl, sigA, evidence), false);
  assert.strictEqual(discovery.paramTypesCompatible(idl, sigB, evidence), false);
  assert.strictEqual(evidence.count, 0);
});

test('反例：两个候选都兼容 ⇒ 全部幸存，不收敛', () => {
  const idl = [{ type: 'List<String>', name: 'l' }];
  const sigA = 'int F(const std::vector<std::string>& a, int extra)';
  const sigB = 'int F(const std::vector<std::string>& b, bool flag)';
  assert.strictEqual(discovery.paramTypesCompatible(idl, sigA), true);
  assert.strictEqual(discovery.paramTypesCompatible(idl, sigB), true);
});

test('反例：签名缺失/无名参数不提供证据', () => {
  assert.strictEqual(discovery.paramTypesCompatible(IDL_VERIFY_LIST, ''), false);
  assert.strictEqual(discovery.paramTypesCompatible(IDL_VERIFY_LIST, 'int f()'), false);
});

test('类型族映射边界', () => {
  assert.strictEqual(discovery.idlTypeFamily('List<String>'), 'vector');
  assert.strictEqual(discovery.idlTypeFamily('Map<String, int>'), 'map');
  assert.strictEqual(discovery.idlTypeFamily('String'), 'string');
  assert.strictEqual(discovery.idlTypeFamily('unsigned int'), 'primitive-or-other');
  assert.strictEqual(discovery.idlTypeFamily('Sequence<int>'), 'vector');
  assert.strictEqual(discovery.cppTypeFamily('const std::vector<std::string>&'), 'vector');
  assert.strictEqual(discovery.cppTypeFamily('std::unordered_map<int, std::string>&'), 'map');
  assert.strictEqual(discovery.cppTypeFamily('const std::string&'), 'string');
  assert.strictEqual(discovery.cppTypeFamily('AccessTokenID'), 'other');
  assert.strictEqual(discovery.cppTypeFamily('int32_t&'), 'primitive');
});
