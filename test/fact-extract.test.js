'use strict';

/**
 * test/fact-extract.test.js —— AG0.3（P3）提取器单元与失败用例。
 * 覆盖：函数/owner/宏定义函数体、调用解析三态、类型 kind、通用事实（sink/guard/write/lock）、重复抽取确定性。
 */

const test = require('node:test');
const assert = require('node:assert');
const path = require('path');

const MOD = path.resolve(__dirname, '..', '..', 'oh6-framework-want-leak-miner', 'node_modules');
const Parser = require(path.join(MOD, 'tree-sitter'));
const Cpp = require(path.join(MOD, 'tree-sitter-cpp'));

const { extractFunctions } = require('../lib/facts/functions');
const { extractCalls } = require('../lib/facts/calls');
const { extractTypes } = require('../lib/facts/types');
const { extractGeneric, sinkKindOf } = require('../lib/facts/generic');

const SNAP = `sha256:${'c'.repeat(64)}`;

function parseCpp(text) {
  const parser = new Parser();
  parser.setLanguage(Cpp);
  return parser.parse(text, null, { bufferSize: 1024 * 1024 });
}

function ctxOf(text, role = 'production') {
  return {
    repo: 'r', rel: 'x.cpp', snapshotId: SNAP, role, text,
    quality: { parse: 'full', resolution: 'syntax-only', errorNodes: 0 },
    parse: 'full', errorNodes: 0
  };
}

function all(tree, text, role) {
  const ctx = ctxOf(text, role);
  const fn = extractFunctions(tree, ctx);
  const calls = extractCalls(tree, ctx, fn.byName, fn.macroBodies);
  const types = extractTypes(tree, ctx, fn.records);
  const generic = extractGeneric(tree, ctx, fn.macroBodies);
  return { fn, calls, types, generic };
}

const MAIN = `
namespace demo {
class Widget {
public:
    int Method(int a);
};

int freeFn(int a, int b) { return a + b; }

int Widget::Method(int a)
{
    char *buf = (char *)malloc(16);
    memcpy_s(buf, 16, "x", 1);
    if (buf == nullptr) {
        return -1;
    }
    for (int i = 0; i < a; i++) {
        buf[i] = (char)i;
    }
    mtx.lock();
    mtx.unlock();
    return Helper(buf);
}

int freeFn2() { return freeFn(1, 2); }
}

void Ops()
{
    int (*fp)(int) = nullptr;
    (*fp)(1);
}
`;

const MACRO = `
using namespace testing;
namespace ohos {
HWTEST_F(SuiteName, CaseName, TestSize.Level1)
{
    int localValue = 1;
    localValue = localValue + 2;
    Helper(localValue);
}
}
`;

test('functions：namespace/class/限定名/参数个数', () => {
  const text = MAIN;
  const { fn } = all(parseCpp(text), text);
  const names = fn.functions.map((f) => f.qualified);
  assert.ok(names.includes('demo::freeFn'), names.join(','));
  assert.ok(names.includes('demo::Widget::Method'), names.join(','));
  assert.ok(names.includes('demo::freeFn2'), names.join(','));
  assert.ok(names.includes('Ops'), names.join(','));

  const freeFn = fn.functions.find((f) => f.qualified === 'demo::freeFn');
  assert.strictEqual(freeFn.argc, 2);
  assert.strictEqual(freeFn.role, 'production');
  assert.match(freeFn.bodyHash, /^[0-9a-f]{64}$/);

  const method = fn.functions.find((f) => f.qualified === 'demo::Widget::Method');
  assert.strictEqual(method.owner, 'demo::Widget');
  assert.strictEqual(method.name, 'Method');
  assert.ok(method.startLine > 0 && method.endLine >= method.startLine);
});

test('functions：宏定义函数体（HWTEST_F）被识别并带 macroDefined', () => {
  const text = MACRO;
  const { fn } = all(parseCpp(text), text);
  const macro = fn.functions.find((f) => f.macroDefined);
  assert.ok(macro, fn.functions.map((f) => f.qualified).join(','));
  assert.match(macro.name, /HWTEST_F\(SuiteName, CaseName/);
  assert.strictEqual(macro.owner, 'ohos');
});

test('functions：符号（namespace/class）', () => {
  const text = MAIN;
  const { fn } = all(parseCpp(text), text);
  const kinds = fn.symbols.map((s) => `${s.symbolKind}:${s.name}`);
  assert.ok(kinds.includes('namespace:demo'), kinds.join(','));
  assert.ok(kinds.includes('class:Widget'), kinds.join(','));
});

test('calls：exact / name-only / unsupported 三态', () => {
  const text = MAIN;
  const { calls } = all(parseCpp(text), text);
  const byCallee = new Map();
  for (const c of calls) {
    if (!byCallee.has(c.calleeName)) byCallee.set(c.calleeName, []);
    byCallee.get(c.calleeName).push(c);
  }
  assert.strictEqual(byCallee.get('freeFn')[0].quality.resolution, 'exact');
  assert.ok(byCallee.get('freeFn')[0].callee, 'exact 必须带 callee factId');
  assert.strictEqual(byCallee.get('lock')[0].quality.resolution, 'name-only');
  assert.strictEqual(byCallee.get('lock')[0].callee, null);
  assert.strictEqual(byCallee.get('fp')[0].quality.resolution, 'unsupported');
});

test('calls：调用挂在正确的 caller factId 上（宏体同函数体）', () => {
  const text = MACRO;
  const { fn, calls } = all(parseCpp(text), text);
  const macro = fn.functions.find((f) => f.macroDefined);
  assert.ok(calls.length >= 1);
  for (const c of calls) assert.strictEqual(c.caller, macro.factId);
});

test('types：声明类型与 kind 判定（builtin/unknown，不猜）', () => {
  const text = MAIN;
  const { types } = all(parseCpp(text), text);
  const byExpr = new Map(types.map((t) => [t.expr, t]));
  assert.ok(byExpr.has('freeFn()'), '函数返回类型应入类型表');
  assert.strictEqual(byExpr.get('freeFn()').typeKind, 'builtin');
  const buf = types.find((t) => t.expr === 'buf');
  assert.ok(buf, '局部变量类型应入表');
  assert.strictEqual(buf.typeKind, 'builtin');
  assert.match(buf.type, /char/);
  for (const t of types) assert.strictEqual(t.quality.resolution, 'syntax-only');
});

test('generic：sink / guard / write / lock', () => {
  const text = MAIN;
  const { generic } = all(parseCpp(text), text);
  const sinks = new Set(generic.sinks.map((s) => `${s.sinkKind}:${s.calleeName}`));
  assert.ok([...sinks].some((k) => k.startsWith('alloc:malloc')), [...sinks].join(','));
  assert.ok([...sinks].some((k) => k.startsWith('copy:memcpy_s')), [...sinks].join(','));

  const guardKinds = new Set(generic.guards.map((g) => g.guardKind));
  assert.ok(guardKinds.has('null-check'), [...guardKinds].join(','));
  assert.ok(guardKinds.has('loop'), [...guardKinds].join(','));

  assert.ok(generic.writes.some((w) => w.expr.includes('buf')), 'buf[i] = ... 必须记为 write');
  assert.ok(generic.locks.some((l) => l.lockKind === 'acquire' && l.name.includes('lock')));
  assert.ok(generic.locks.some((l) => l.lockKind === 'release' && l.name.includes('unlock')));
  for (const r of generic.reads) assert.ok(typeof r.function === 'string' && r.function.startsWith('F:'));
});

test('确定性：同一输入两次抽取结果完全一致', () => {
  const a = all(parseCpp(MAIN), MAIN);
  const b = all(parseCpp(MAIN), MAIN);
  assert.deepStrictEqual(a.fn.functions, b.fn.functions);
  assert.deepStrictEqual(a.calls, b.calls);
  assert.deepStrictEqual(a.generic.reads, b.generic.reads);
  assert.deepStrictEqual(a.generic.writes, b.generic.writes);
});

test('失败用例：语法错误代码不抛错，仍产出可解析部分', () => {
  const bad = 'int broken( { return 1; }\nvoid okFn() { freeFn(); }\n';
  let tree;
  assert.doesNotThrow(() => { tree = parseCpp(bad); });
  const { fn, calls } = all(tree, bad);
  assert.ok(Array.isArray(fn.functions) && Array.isArray(calls), '坏语法下仍返回数组且不抛错');
});

test('sinkKindOf：分类边界', () => {
  assert.strictEqual(sinkKindOf('memcpy'), 'copy');
  assert.strictEqual(sinkKindOf('malloc'), 'alloc');
  assert.strictEqual(sinkKindOf('SendEvent'), 'publish');
  assert.strictEqual(sinkKindOf('unknownFn'), null);
});
