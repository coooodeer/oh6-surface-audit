'use strict';

/**
 * test/fact-metadata.test.js —— AG0.2（P2）解析器单元与失败用例。
 * 覆盖：IDL 前向声明/ipccode/oneway/多行参数、SA + commonevent、permission 两类表、NAPI 注册点、schema 校验。
 */

const test = require('node:test');
const assert = require('node:assert');

const idl = require('../lib/facts/idl');
const sa = require('../lib/facts/sa');
const permission = require('../lib/facts/permission');
const napi = require('../lib/facts/napi');
const ids = require('../lib/facts/ids');
const schema = require('../lib/facts/schema');

const IDL_SAMPLE = `
package OHOS.AccountSA;
interface_token ohos.accountfwk.IFoo;
interface OHOS.AccountSA.IBar;
sequenceable OHOS.AccountSA.ParcelA;
option_stub_hooks on;

interface OHOS.AccountSA.IFoo {
    void NoArgs();
    void OneArg([in] int userId);
    [ipccode 0xffb0] void WithCode([in] String s, [out] int result);
    [ipccode 0xffb1, oneway] void Fire([in] int code,
                                      [in] String msg);
}
`;

test('IDL：前向声明不吞掉后续 interface，ipccode/oneway/多行参数正确', () => {
  const p = idl.parseIdl(IDL_SAMPLE);
  assert.deepStrictEqual(p.interfaces.map((i) => i.name), ['OHOS.AccountSA.IFoo']);
  const rows = idl.toRows(p, 'x/IFoo.idl');
  assert.strictEqual(rows.length, 4);
  const byName = new Map(rows.map((r) => [r.method, r]));
  assert.strictEqual(byName.get('NoArgs').paramCount, 0);
  assert.strictEqual(byName.get('OneArg').params[0].direction, 'in');
  assert.strictEqual(byName.get('OneArg').params[0].name, 'userId');
  assert.strictEqual(byName.get('WithCode').ipcCode, 0xffb0);
  assert.strictEqual(byName.get('WithCode').paramCount, 2);
  assert.strictEqual(byName.get('Fire').oneway, true);
  assert.strictEqual(byName.get('Fire').paramCount, 2, '多行参数必须合并');
  assert.strictEqual(rows[0].tokenSource, 'interface_token');
  assert.strictEqual(rows[0].token, 'ohos.accountfwk.IFoo');
});

test('IDL：无 token 时 tokenSource=absent（不猜）', () => {
  const p = idl.parseIdl('interface OHOS.X.IY {\n    void F();\n}\n');
  const rows = idl.toRows(p, 'Y.idl');
  assert.strictEqual(rows.length, 1);
  assert.strictEqual(rows[0].token, null);
  assert.strictEqual(rows[0].tokenSource, 'absent');
});

test('IDL：块注释里的 interface 不产生行（失败用例）', () => {
  const p = idl.parseIdl('/*\ninterface OHOS.Fake.INope {}\n*/\ninterface OHOS.X.IY {\n  void F();\n}\n');
  assert.deepStrictEqual(p.interfaces.map((i) => i.name), ['OHOS.X.IY']);
  assert.strictEqual(idl.toRows(p, 'z.idl').length, 1);
});

test('SA：systemability 与 commonevent', () => {
  const text = JSON.stringify({
    process: 'svc',
    systemability: [
      { name: 4700, libpath: 'libsvc.z.so', 'run-on-create': true, distributed: false,
        'start-on-demand': { commonevent: [{ name: 'usual.event.BOOT_COMPLETED' }] } }
    ]
  }, null, 2);
  const saRows = sa.saRows(text, 'a/sa_profile/x.json');
  assert.strictEqual(saRows.length, 1);
  assert.strictEqual(saRows[0].saId, 4700);
  assert.strictEqual(saRows[0].library, 'libsvc.z.so');
  assert.ok(saRows[0].line >= 1);
  const ces = sa.cesRows(text, 'a/sa_profile/x.json');
  assert.strictEqual(ces.length, 1);
  assert.strictEqual(ces[0].action, 'usual.event.BOOT_COMPLETED');
});

test('SA：坏 JSON 返回空且不抛（失败用例）', () => {
  const parsed = sa.parseSaProfile('{ not json');
  assert.strictEqual(parsed.parseError, true);
  assert.deepStrictEqual(parsed.systemabilities, []);
});

test('permission：接口-进程表与权限定义表', () => {
  const t1 = JSON.stringify([{ INTERFACE_NAME: 'SERVER_JOIN_LNN', PROCESS_NAME: ['a', 'b'] }]);
  const r1 = permission.parseInterfaceProcessTable(t1, 'p1.json');
  assert.strictEqual(r1.length, 1);
  assert.deepStrictEqual(r1[0].processes, ['a', 'b']);
  const t2 = JSON.stringify({ definePermissions: [{ name: 'ohos.permission.X', grantMode: 'system_grant', availableLevel: 'normal' }] });
  const r2 = permission.parsePermissionDefinitions(t2, 'p2.json');
  assert.strictEqual(r2.length, 1);
  assert.strictEqual(r2[0].level, 'normal');
  assert.strictEqual(r2[0].grantMode, 'system_grant');
});

test('NAPI：识别注册点与 nm_modname', () => {
  const text = [
    'static napi_module g = {',
    '    .nm_version = 1,',
    '    .nm_modname = "events.emitter",',
    '};',
    'extern "C" __attribute__((constructor)) void Register() {',
    '    napi_module_register(&g);',
    '}'
  ].join('\n');
  const rows = napi.scanText(text, 'x.cpp');
  assert.strictEqual(rows.length, 1);
  assert.strictEqual(rows[0].module, 'events.emitter');
  assert.strictEqual(rows[0].struct, 'g');
  assert.strictEqual(rows[0].line, 6);
});

test('metadataId 与 metadata schema 一致', () => {
  const snap = `sha256:${'b'.repeat(64)}`;
  const locator = { file: 'a.idl', interface: 'I', method: 'F', line: 3 };
  const row = {
    metadataId: ids.metadataIdOf(snap, 'idl', locator),
    kind: 'idl',
    snapshotId: snap,
    sourceFile: 'a.idl',
    sourceLine: 3,
    sha256: 'c'.repeat(64),
    source: 'own',
    producer: 'AG0',
    schemaVersion: '1',
    payload: { interface: 'I', method: 'F' }
  };
  const res = schema.validateMetadata(row);
  assert.deepStrictEqual(res.errors, []);
  const bad = schema.validateMetadata({ ...row, source: 'somewhere' });
  assert.ok(!bad.ok);
  assert.ok(bad.errors.some((e) => /source: not in enum/.test(e)));
});
