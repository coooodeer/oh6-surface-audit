'use strict';

/**
 * test/fact-parity.test.js —— AG0.6（P8）own vs legacy parity。
 * 覆盖：repo-relative 对齐、差异分桶（宏/测试/partial/repo 未覆盖）、legacy 缺失、source=own 不读 legacy。
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const parity = require('../lib/facts/parity');

const SNAP = `sha256:${'9'.repeat(64)}`;

function writeJsonl(file, rows) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, rows.map((r) => JSON.stringify(r)).join('\n') + '\n', 'utf8');
}

function ownRow(repo, file, startLine, extra = {}) {
  return {
    factId: `F:999999999999:function:${String(startLine).padStart(16, '0')}`,
    snapshotId: SNAP,
    kind: 'function',
    locator: { repo, file: `${repo}/${file}`, startLine, name: extra.name || 'f' },
    sourceRange: { file: `${repo}/${file}`, startLine, endLine: startLine + 1 },
    role: extra.role || 'production',
    quality: { parse: 'full', resolution: 'syntax-only', errorNodes: 0 },
    producer: 'AG0',
    schemaVersion: '1',
    name: extra.name || 'f',
    owner: '',
    signature: 'void f()',
    startLine,
    endLine: startLine + 1,
    bodyHash: 'a'.repeat(64),
    ...(extra.macroDefined ? { macroDefined: true } : {})
  };
}

function makeDirs() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ag0-parity-'));
  const facts = path.join(root, 'facts');
  const legacy = path.join(root, 'legacy');
  fs.mkdirSync(path.join(facts, 'l1'), { recursive: true });
  fs.writeFileSync(path.join(facts, 'snapshot.json'), JSON.stringify({ snapshotId: SNAP }), 'utf8');

  const ownFns = [
    ownRow('r/a', 'x.cpp', 10),                       // matched
    ownRow('r/a', 'x.cpp', 20, { role: 'test' }),      // testFiles
    ownRow('r/a', 'x.cpp', 30, { macroDefined: true }),// macroDefined
    ownRow('r/a', 'x.cpp', 40),                        // parsePartial
    ownRow('r/b', 'y.cpp', 50)                         // repoNotInLegacy
  ];
  writeJsonl(path.join(facts, 'l1', 'functions.jsonl'), ownFns);
  writeJsonl(path.join(facts, 'l1', 'calls.jsonl'), [
    { factId: 'F:1:call:1', calleeName: 'Foo', callerName: 'f' },
    { factId: 'F:1:call:2', calleeName: 'Bar', callerName: 'f' }
  ]);
  writeJsonl(path.join(facts, 'l1', 'files.jsonl'), [
    { path: 'r/a/x.cpp', parse: 'full', quality: { parse: 'full' } },
    { path: 'r/a/y.cpp', parse: 'partial', quality: { parse: 'partial' } },
    { path: 'r/b/y.cpp', parse: 'full', quality: { parse: 'full' } }
  ]);

  writeJsonl(path.join(legacy, 'functions.jsonl'), [
    { repo: 'r/a', file: 'x.cpp', startLine: 10, name: 'f' },
    { repo: 'r/a', file: 'x.cpp', startLine: 40, name: 'g' },
    { repo: 'r/a', file: 'x.cpp', startLine: 99, name: 'gone' }
  ]);
  writeJsonl(path.join(legacy, 'call-edges.jsonl'), [
    { from: 'r/a|x.cpp:10', to: 'r/a|x.cpp:10', name: 'Foo', line: 1, resolution: 'name-only' }
  ]);
  return { root, facts, legacy };
}

function cleanup(root) {
  fs.rmSync(root, { recursive: true, force: true });
}

test('parity：repo-relative 对齐与差异分桶', () => {
  const { root, facts, legacy } = makeDirs();
  try {
    const own = parity.loadOwn(facts);
    const leg = parity.loadLegacy(legacy);
    assert.strictEqual(own.functions.size, 5);
    assert.strictEqual(leg.functions.size, 3);

    const r = parity.compare(own, leg);
    assert.strictEqual(r.functions.matched, 2, 'startLine 10/40 应匹配');
    assert.strictEqual(r.functions.onlyOwn, 3);
    assert.strictEqual(r.functions.onlyLegacy, 1);
    assert.strictEqual(r.functions.explained.macroDefined, 1);
    assert.strictEqual(r.functions.explained.testFiles, 1);
    assert.strictEqual(r.functions.explained.repoNotInLegacy, 1);
    assert.strictEqual(r.functions.explained.remaining, 0, '所有 only-own 都应有解释');
    assert.deepStrictEqual(r.functions.samples.onlyOwn, []);
    assert.deepStrictEqual(r.functions.samples.onlyLegacy, ['r/a|x.cpp:99']);
    assert.strictEqual(r.calls.own, 2);
    assert.strictEqual(r.calls.legacy, 1);
    assert.strictEqual(r.calls.calleeNameOverlap, 0.5);
  } finally { cleanup(root); }
});

test('parity：legacy 缺失时 present=false 且不崩（失败用例）', () => {
  const { root, facts } = makeDirs();
  try {
    const own = parity.loadOwn(facts);
    const leg = parity.loadLegacy(path.join(root, 'nope'));
    assert.strictEqual(leg.present, false);
    assert.strictEqual(leg.functions.size, 0);
    const r = parity.compare(own, leg);
    assert.strictEqual(r.legacyPresent, false);
    assert.strictEqual(r.functions.matchRatioVsLegacy, null);
  } finally { cleanup(root); }
});

test('source=own：只调 loadOwn，不打开 legacy（静态+动态证明）', () => {
  const { root, facts } = makeDirs();
  try {
    const own = parity.loadOwn(facts);
    assert.strictEqual(own.functions.size, 5);
    // 动态：legacy 目录不存在也不影响 loadOwn
    assert.strictEqual(fs.existsSync(path.join(root, 'missing-legacy')), false);
    // 静态：只有 parity.js 允许出现 legacy 路径常量
    const dir = path.join(__dirname, '..', 'lib', 'facts');
    const offenders = [];
    for (const f of fs.readdirSync(dir)) {
      if (!f.endsWith('.js') || f === 'parity.js') continue;
      const text = fs.readFileSync(path.join(dir, f), 'utf8');
      if (text.includes("'out', 'l1'") || text.includes('out/l1')) offenders.push(f);
    }
    assert.deepStrictEqual(offenders, [], `除 parity.js 外不应读 legacy：${offenders.join(',')}`);
  } finally { cleanup(root); }
});

test('parity：legacy 的 call 名与 own 的名称集合可比（Jaccard）', () => {
  const { root, facts, legacy } = makeDirs();
  try {
    const r = parity.compare(parity.loadOwn(facts), parity.loadLegacy(legacy));
    assert.ok(r.calls.calleeNameOverlap >= 0 && r.calls.calleeNameOverlap <= 1);
    assert.strictEqual(r.calls.namesOnlyOwn, 1);
    assert.strictEqual(r.calls.sampleNamesOnlyOwn[0], 'Bar');
  } finally { cleanup(root); }
});
