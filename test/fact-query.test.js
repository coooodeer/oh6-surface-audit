'use strict';

/**
 * test/fact-query.test.js —— AG0.4（P6）Query API。
 * 用临时 facts 目录 + 临时源码根，验证六个查询与 Qflow unsupported，以及结果可回查字段。
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { FactsIndex, splitConcatenatedJson } = require('../lib/facts/query');

const SNAP = `sha256:${'f'.repeat(64)}`;

function row(kind, id, extra) {
  return {
    factId: `F:ffffffffffff:${kind}:${id}`,
    snapshotId: SNAP,
    kind,
    locator: {},
    sourceRange: { file: extra.file, startLine: extra.line, endLine: extra.line },
    role: 'production',
    quality: { parse: 'full', resolution: 'syntax-only', errorNodes: 0 },
    producer: 'AG0',
    schemaVersion: '1',
    ...extra
  };
}

function makeFacts() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ag0-q-'));
  const src = fs.mkdtempSync(path.join(os.tmpdir(), 'ag0-src-'));
  fs.mkdirSync(path.join(dir, 'l1'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'snapshot.json'), JSON.stringify({
    snapshotId: SNAP,
    scope: 'd4-r1',
    roots: [],
    compdb: { parts: [], totals: { entries: 10, rootFiles: 2 } },
    genVisibility: { referenced: 1, missing: 0 }
  }), 'utf8');

  const write = (name, rows) => fs.writeFileSync(path.join(dir, 'l1', `${name}.jsonl`), rows.map((r) => JSON.stringify(r)).join('\n') + '\n', 'utf8');

  write('functions', [
    row('function', 'a1', { file: 'x/a.cpp', line: 10, name: 'Handle', qualified: 'demo::Handler::Handle', owner: 'demo::Handler', signature: 'void Handle(int)' }),
    row('function', 'a2', { file: 'x/b.cpp', line: 20, name: 'Other', qualified: 'Other', owner: '', signature: 'int Other()' })
  ]);
  write('symbols', [
    row('symbol', 's1', { file: 'x/a.h', line: 3, name: 'Handler', symbolKind: 'class', declFile: 'x/a.h', declLine: 3, scope: 'demo' })
  ]);
  write('calls', [
    row('call', 'c1', { file: 'x/a.cpp', line: 12, caller: 'F:ffffffffffff:function:a1', callerName: 'demo::Handler::Handle', calleeName: 'SendEvent', callee: null, argc: 1 }),
    row('call', 'c2', { file: 'x/b.cpp', line: 22, caller: 'F:ffffffffffff:function:a2', callerName: 'Other', calleeName: 'Handle', callee: 'F:ffffffffffff:function:a1', argc: 1 })
  ]);
  write('guards', [
    row('guard', 'g1', { file: 'x/a.cpp', line: 11, function: 'F:ffffffffffff:function:a1', functionName: 'demo::Handler::Handle', guardKind: 'null-check', variables: ['p'], dominates: false })
  ]);
  write('sinks', [
    row('sink', 'k1', { file: 'x/a.cpp', line: 12, function: 'F:ffffffffffff:function:a1', functionName: 'demo::Handler::Handle', sinkKind: 'publish', calleeName: 'SendEvent', argc: 1 })
  ]);
  write('types', [
    row('type', 't1', { file: 'x/a.cpp', line: 11, expr: 'p', type: 'void *', typeKind: 'builtin', file2: undefined })
  ]);

  fs.mkdirSync(path.join(src, 'x'), { recursive: true });
  fs.writeFileSync(path.join(src, 'x', 'a.cpp'), [
    'void Handle(int a)',
    '{',
    '    int buf = 1;',
    '    if (buf) { SendEvent(buf); }',
    '}'
  ].join('\n'), 'utf8');

  return { dir, src };
}

function cleanup(...dirs) {
  for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
}

test('Qname：函数/符号都能命中，且结果带 snapshotId/factRefs/sourceRange/quality', () => {
  const { dir, src } = makeFacts();
  try {
    const idx = new FactsIndex(dir, { sourceRoot: src });
    const fns = idx.Qname('handle', { kind: 'function' });
    assert.strictEqual(fns.length, 1);
    const both = idx.Qname('handle');
    assert.ok(both.length >= 1, '默认同时搜函数与符号');
    assert.strictEqual(fns[0].kind, 'function');
    assert.deepStrictEqual(Object.keys(fns[0]).filter((k) => ['snapshotId', 'factRefs', 'sourceRange', 'quality'].includes(k)).sort(), ['factRefs', 'quality', 'snapshotId', 'sourceRange']);
    assert.match(fns[0].factRefs[0], /^F:/);
    const syms = idx.Qname('Handler', { kind: 'symbol' });
    assert.strictEqual(syms.length, 1);
    assert.strictEqual(syms[0].symbolKind, 'class');
  } finally { cleanup(dir, src); }
});

test('Qcg：callees 与 callers 两个方向', () => {
  const { dir, src } = makeFacts();
  try {
    const idx = new FactsIndex(dir, { sourceRoot: src });
    const callees = idx.Qcg('demo::Handler::Handle', { direction: 'callees' });
    assert.strictEqual(callees.length, 1);
    assert.strictEqual(callees[0].calleeName, 'SendEvent');
    const callers = idx.Qcg('Handle', { direction: 'callers' });
    assert.strictEqual(callers.length, 1);
    assert.strictEqual(callers[0].callerName, 'Other');
    assert.match(callers[0].callee, /^F:/);
  } finally { cleanup(dir, src); }
});

test('findCheckSites：guards + sinks 合并，factRefs 齐全', () => {
  const { dir, src } = makeFacts();
  try {
    const idx = new FactsIndex(dir, { sourceRoot: src });
    const res = idx.findCheckSites('demo::Handler::Handle');
    assert.strictEqual(res.guards.length, 1);
    assert.strictEqual(res.sinks.length, 1);
    assert.strictEqual(res.guards[0].guardKind, 'null-check');
    assert.strictEqual(res.sinks[0].sinkKind, 'publish');
    assert.strictEqual(res.factRefs.length, 2);
    assert.strictEqual(res.result === undefined, true);
  } finally { cleanup(dir, src); }
});

test('getSource：返回源码窗口且行号正确；缺文件抛错（失败用例）', () => {
  const { dir, src } = makeFacts();
  try {
    const idx = new FactsIndex(dir, { sourceRoot: src });
    const win = idx.getSource('x/a.cpp', 3, 3);
    assert.strictEqual(win.sourceRange.startLine, 2);
    assert.strictEqual(win.sourceRange.endLine, 4);
    assert.match(win.text, /int buf = 1/);
    assert.throws(() => idx.getSource('nope.cpp', 1, 1), /file-missing/);
  } finally { cleanup(dir, src); }
});

test('getType：syntax-only 命中；未知目标返回空（失败用例）', () => {
  const { dir, src } = makeFacts();
  try {
    const idx = new FactsIndex(dir, { sourceRoot: src });
    const hit = idx.getType('p');
    assert.strictEqual(hit.mode, 'syntax-only');
    assert.strictEqual(hit.rows.length, 1);
    assert.strictEqual(hit.rows[0].type, 'void *');
    assert.strictEqual(hit.rows[0].quality.resolution, 'syntax-only');
    const miss = idx.getType('does_not_exist');
    assert.deepStrictEqual(miss.rows, []);
  } finally { cleanup(dir, src); }
});

test('Qast：call/assign 在区间内命中；非法 op 抛错（失败用例）', () => {
  const { dir, src } = makeFacts();
  try {
    const idx = new FactsIndex(dir, { sourceRoot: src });
    const calls = idx.Qast('call', { file: 'x/a.cpp', startLine: 1, endLine: 10 });
    assert.strictEqual(calls.length, 1);
    assert.match(calls[0].text, /SendEvent/);
    const assigns = idx.Qast('assign', { file: 'x/a.cpp' });
    assert.ok(Array.isArray(assigns));
    assert.throws(() => idx.Qast('nonsense', { file: 'x/a.cpp' }), /unsupported-operation/);
    assert.throws(() => idx.Qast('call', {}), /file-required/);
  } finally { cleanup(dir, src); }
});

test('Qflow：固定 unsupported/dfg-incomplete', () => {
  const { dir, src } = makeFacts();
  try {
    const idx = new FactsIndex(dir, { sourceRoot: src });
    const res = idx.Qflow();
    assert.strictEqual(res.status, 'unsupported');
    assert.strictEqual(res.reason, 'dfg-incomplete');
    assert.strictEqual(res.snapshotId, SNAP);
  } finally { cleanup(dir, src); }
});

test('splitConcatenatedJson：拼接对象可切片，坏块被跳过（失败用例）', () => {
  const text = '{"a":1}{"b":{"c":2}}{"bad": }{"d":"}"}';
  const objs = splitConcatenatedJson(text);
  assert.strictEqual(objs.length, 3);
  assert.deepStrictEqual(objs[1], { b: { c: 2 } });
  assert.deepStrictEqual(objs[2], { d: '}' });
});
