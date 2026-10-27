'use strict';

/**
 * test/r2-fact-compare.test.js —— R2-C 对照器的反例测试（复审修正）。
 *
 * 覆盖：嵌套字段变更必须被检出（canon 不得用 replacer 数组过滤嵌套键）、
 * 重复行按计数对照（Map 收行折叠重复会漏报）、单侧缺表 → 不相等、
 * 身份归一（factId/snap12 占位）不影响真实差异检出。
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const cmp = require('../tools/fact-compare.js');

function makeDir(root, name, files) {
  const dir = path.join(root, name);
  fs.mkdirSync(path.join(dir, 'l1'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'snapshot.json'), JSON.stringify({
    snapshotId: name === 'a' ? 'sha256:1111111111111111111111111111111111111111111111111111111111111111'
      : 'sha256:2222222222222222222222222222222222222222222222222222222222222222'
  }));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, ...rel.split('/')), content);
  }
  return dir;
}

const row = (over) => JSON.stringify({
  factId: '', snapshotId: '', kind: 'function',
  locator: { repo: 'r', file: 'f.cpp', startLine: 1 },
  sourceRange: { file: 'f.cpp', startLine: 1, endLine: 2 },
  name: 'fn', role: 'production', ...over
});

function runCompare(aFiles, bFiles) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'r2-cmp-'));
  const a = makeDir(tmp, 'a', aFiles);
  const b = makeDir(tmp, 'b', bFiles);
  const outFile = path.join(tmp, 'compare.json');
  const orig = process.stdout.write.bind(process.stdout);
  let captured = '';
  process.stdout.write = (c) => { captured += String(c); return true; };
  try { cmp.main([`--a=${a}`, `--b=${b}`, `--out=${outFile}`]); } finally { process.stdout.write = orig; }
  const full = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  fs.rmSync(tmp, { recursive: true, force: true });
  return { summary: JSON.parse(captured.trim().split('\n').filter(Boolean).pop()), full };
}

test('嵌套字段变更被检出（sourceRange.file 不同、factId 同形）', () => {
  const { full: r } = runCompare(
    { 'l1/functions.jsonl': `${row({})}\n` },
    { 'l1/functions.jsonl': `${row({ sourceRange: { file: 'g.cpp', startLine: 1, endLine: 2 } })}\n` }
  );
  assert.strictEqual(r.allEqual, false, '只改嵌套 sourceRange.file 必须判不等');
  const t = r.tables.find((x) => x.kind === 'functions');
  assert.ok(t.onlyInACount === 1 && t.onlyInBCount === 1, JSON.stringify(t));
});

test('重复行按计数对照：A 两行同内容 vs B 一行 ⇒ 不等', () => {
  const line = row({});
  const { full: r } = runCompare(
    { 'l1/functions.jsonl': `${line}\n${line}\n` },
    { 'l1/functions.jsonl': `${line}\n` }
  );
  assert.strictEqual(r.allEqual, false, '重复行数量差异必须被检出');
  const t = r.tables.find((x) => x.kind === 'functions');
  assert.strictEqual(t.countMismatchCount, 1);
  assert.strictEqual(t.rowsA, 2);
  assert.strictEqual(t.rowsB, 1);
});

test('单侧缺表 ⇒ 不相等；两侧都缺 ⇒ equal', () => {
  const { full: r1 } = runCompare(
    { 'l1/functions.jsonl': `${row({})}\n` },
    {}
  );
  assert.strictEqual(r1.allEqual, false);
  const t1 = r1.tables.find((x) => x.kind === 'functions');
  assert.strictEqual(t1.present, true);
  assert.strictEqual(t1.onlyInACount, 1);

  const { full: r2 } = runCompare({}, {});
  const t2 = r2.tables.find((x) => x.kind === 'calls');
  assert.strictEqual(t2.present, false);
  assert.strictEqual(t2.equal, true);
});

test('身份归一不吞掉真实差异：factId 同形占位后内容仍比较', () => {
  // 两行只有 name 不同（factId 由测试手动写成同形占位可比较的结构）
  const { full: r } = runCompare(
    { 'l1/functions.jsonl': `${row({ name: 'fnA' })}\n` },
    { 'l1/functions.jsonl': `${row({ name: 'fnB' })}\n` }
  );
  assert.strictEqual(r.allEqual, false);
});

test('相同输入 ⇒ 相等（归一路径回归）', () => {
  const files = { 'l1/functions.jsonl': `${row({})}\n${row({ name: 'g' })}\n` };
  const { full: r } = runCompare(files, files);
  assert.strictEqual(r.allEqual, true, JSON.stringify(r.tables.find((t) => t.kind === 'functions')));
});
