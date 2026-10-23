'use strict';

/**
 * test/fact-contract.test.js —— AG0 P0 契约测试。
 * 覆盖：canonicalJson 稳定性、factId 确定性、JSONL 排序去重、schema 校验正反例、scope policy 完整性。
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ids = require('../lib/facts/ids');
const io = require('../lib/facts/io');
const schema = require('../lib/facts/schema');

const SNAP = `sha256:${'a'.repeat(64)}`;

function fixtureFunctionFact(overrides = {}) {
  const locator = { repo: 'base/account/os_account', file: 'frameworks/x.cpp', startLine: 10, name: 'Foo::Bar' };
  return {
    factId: ids.factIdOf(SNAP, 'function', locator),
    snapshotId: SNAP,
    kind: 'function',
    locator,
    sourceRange: { file: 'frameworks/x.cpp', startLine: 10, endLine: 20 },
    role: 'production',
    quality: { parse: 'full', resolution: 'syntax-only' },
    producer: 'AG0',
    schemaVersion: '1',
    name: 'Foo::Bar',
    owner: 'Foo',
    signature: 'int Foo::Bar(int a)',
    startLine: 10,
    endLine: 20,
    bodyHash: 'b'.repeat(64),
    ...overrides
  };
}

test('canonicalJson：键顺序不影响结果', () => {
  const a = ids.canonicalJson({ b: 1, a: [1, 2], c: { z: null, y: 'x' } });
  const b = ids.canonicalJson({ c: { y: 'x', z: null }, a: [1, 2], b: 1 });
  assert.strictEqual(a, b);
  assert.strictEqual(a, '{"a":[1,2],"b":1,"c":{"y":"x","z":null}}');
});

test('canonicalJson：拒绝非有限数字（失败用例）', () => {
  assert.throws(() => ids.canonicalJson({ x: Number.NaN }), /non-finite/);
  assert.throws(() => ids.canonicalJson({ x: Infinity }), /non-finite/);
});

test('canonicalJson：undefined 字段被丢弃，数组内 undefined 变 null', () => {
  assert.strictEqual(ids.canonicalJson({ a: undefined, b: 1 }), '{"b":1}');
  assert.strictEqual(ids.canonicalJson([undefined, 1]), '[null,1]');
});

test('factId / snapshotId：确定且可区分', () => {
  const locator = { repo: 'r', file: 'f.cpp', startLine: 1, name: 'f' };
  const f1 = ids.factIdOf(SNAP, 'function', locator);
  const f2 = ids.factIdOf(SNAP, 'function', { ...locator });
  assert.strictEqual(f1, f2);
  assert.match(f1, /^F:[0-9a-f]{12}:function:[0-9a-f]{16}$/);
  const f3 = ids.factIdOf(SNAP, 'function', { ...locator, startLine: 2 });
  assert.notStrictEqual(f1, f3);
  const s1 = ids.snapshotIdOf({ a: 1 });
  const s2 = ids.snapshotIdOf({ a: 1 });
  assert.strictEqual(s1, s2);
  assert.match(s1, /^sha256:[0-9a-f]{64}$/);
  assert.notStrictEqual(ids.snapshotIdOf({ a: 1 }), ids.snapshotIdOf({ a: 2 }));
});

test('shortSnap：非法 snapshotId 抛错（失败用例）', () => {
  assert.throws(() => ids.shortSnap('sha256:zz'), /bad snapshotId/);
  assert.strictEqual(ids.shortSnap(SNAP), 'aaaaaaaaaaaa');
});

test('writeJsonl：排序 + 去重（重复计数正确）', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ag0-io-'));
  try {
    const file = path.join(dir, 'x.jsonl');
    const rows = [
      { factId: 'F:b', v: 2 },
      { factId: 'F:a', v: 1 },
      { factId: 'F:b', v: 3 }
    ];
    const r = io.writeJsonl(file, rows);
    assert.strictEqual(r.written, 2);
    assert.strictEqual(r.duplicates, 1);
    const back = io.readJsonl(file);
    assert.deepStrictEqual(back.map((x) => x.factId), ['F:a', 'F:b']);
    assert.strictEqual(back[1].v, 2); // 保留第一条
  } finally {
    io.removeDir(dir);
  }
});

test('schema：合法的 function 事实通过', () => {
  const r = schema.validateFact(fixtureFunctionFact());
  assert.deepStrictEqual(r.errors, []);
  assert.ok(r.ok);
});

test('schema：缺必填字段失败（失败用例）', () => {
  const row = fixtureFunctionFact();
  delete row.signature;
  const r = schema.validateFact(row);
  assert.ok(!r.ok);
  assert.ok(r.errors.some((e) => /signature: required/.test(e)), r.errors.join('; '));
});

test('schema：非法 enum 失败（失败用例）', () => {
  const r = schema.validateFact(fixtureFunctionFact({ role: 'unknown-role' }));
  assert.ok(!r.ok);
  assert.ok(r.errors.some((e) => /role: not in enum/.test(e)), r.errors.join('; '));
});

test('schema：非法 factId pattern 失败（失败用例）', () => {
  const r = schema.validateFact(fixtureFunctionFact({ factId: 'F:bad' }));
  assert.ok(!r.ok);
  assert.ok(r.errors.some((e) => /factId: pattern mismatch/.test(e)), r.errors.join('; '));
});

test('schema：未知 kind 失败（失败用例）', () => {
  const r = schema.validateFact(fixtureFunctionFact({ kind: 'memorySink' }));
  assert.ok(!r.ok);
  assert.ok(r.errors.some((e) => /unknown kind 'memorySink'/.test(e)), r.errors.join('; '));
});

test('schema：manifest 正反例', () => {
  const good = {
    manifestId: 'AM-0123456789abcdef',
    snapshotId: SNAP,
    factSchemaVersion: '1',
    rulesVersion: 'K-1.0.0',
    createdAt: '2026-10-19T00:00:00+08:00',
    producer: 'AG0',
    artifactRefs: ['out/facts/x/snapshot.json']
  };
  assert.ok(schema.validateManifest(good).ok, JSON.stringify(schema.validateManifest(good).errors));
  const bad = { ...good, rulesVersion: 'v1', artifactRefs: 'not-array' };
  const r = schema.validateManifest(bad);
  assert.ok(!r.ok);
  assert.ok(r.errors.some((e) => /rulesVersion/.test(e)));
  assert.ok(r.errors.some((e) => /artifactRefs/.test(e)));
});

test('scope policy：5 个 root、4 个 part、external-authority 齐备', () => {
  const policy = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'K', 'policies', 'scope-d4-r1.json'), 'utf8'));
  assert.strictEqual(policy.roots.length, 5);
  assert.deepStrictEqual([...new Set(policy.roots.map((r) => r.part))].sort(), ['accesscontrol', 'account', 'communication', 'notification']);
  assert.deepStrictEqual(policy.compdbParts.sort(), ['accesscontrol', 'account', 'communication', 'notification']);
  const ext = policy.metadataSources.filter((s) => s.scope === 'external-authority');
  assert.strictEqual(ext.length, 2);
  assert.ok(policy.metadataSources.some((s) => s.kind === 'idl'));
  assert.ok(policy.metadataSources.some((s) => s.kind === 'napi' && s.scope === 'code-derived'));
});
