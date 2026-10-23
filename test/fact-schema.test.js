'use strict';

/**
 * test/fact-schema.test.js —— §5 验收 #4：产物事实必须带 factRef/quality 且过 schema。
 * 从真实 snapshot 的每张 l1 表抽样，用 K/schemas/facts-v1.json 校验。
 * 没有产物时 skip（不把“没跑过”伪装成通过）。
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const schema = require('../lib/facts/schema');

const FACTS_ROOT = path.join(__dirname, '..', 'out', 'facts');

function latestFactsDir() {
  if (!fs.existsSync(FACTS_ROOT)) return null;
  const dirs = fs.readdirSync(FACTS_ROOT, { withFileTypes: true })
    .filter((d) => d.isDirectory() && /^[0-9a-f]{64}$/.test(d.name))
    .map((d) => ({ abs: path.join(FACTS_ROOT, d.name), mtime: fs.statSync(path.join(FACTS_ROOT, d.name)).mtimeMs }))
    .sort((a, b) => b.mtime - a.mtime);
  return dirs.length ? dirs[0].abs : null;
}

const DIR = latestFactsDir();
const KINDS = ['files', 'functions', 'symbols', 'types', 'calls', 'cfg', 'dfg', 'sinks', 'guards', 'reads', 'writes', 'locks'];
const SAMPLE = 100;

test('l1 产物：每张表抽样 100 行全部通过 facts schema', { skip: !DIR && 'no facts dir' }, () => {
  const problems = [];
  for (const kind of KINDS) {
    const file = path.join(DIR, 'l1', `${kind}.jsonl`);
    if (!fs.existsSync(file)) { problems.push(`missing-table: ${kind}`); continue; }
    const lines = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean);
    assert.ok(lines.length > 0, `${kind} 不应为空`);
    const step = Math.max(1, Math.floor(lines.length / SAMPLE));
    let checked = 0;
    for (let i = 0; i < lines.length && checked < SAMPLE; i += step) {
      const row = JSON.parse(lines[i]);
      checked += 1;
      const res = schema.validateFact(row);
      if (!res.ok) problems.push(`${kind}:${row.locator && row.locator.file}: ${res.errors.slice(0, 2).join('; ')}`);
    }
    assert.ok(checked > 0, `${kind} 抽样为 0`);
  }
  assert.deepStrictEqual(problems.slice(0, 10), [], problems.join('\n'));
});

test('每条事实都带 factRef / quality / snapshotId', { skip: !DIR && 'no facts dir' }, () => {
  const snapshot = JSON.parse(fs.readFileSync(path.join(DIR, 'snapshot.json'), 'utf8'));
  for (const kind of KINDS) {
    const file = path.join(DIR, 'l1', `${kind}.jsonl`);
    if (!fs.existsSync(file)) continue;
    const lines = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean);
    const step = Math.max(1, Math.floor(lines.length / 20));
    for (let i = 0; i < lines.length; i += step) {
      const row = JSON.parse(lines[i]);
      if (kind === 'files') {
        assert.ok(row.path && row.quality && row.snapshotId === snapshot.snapshotId, 'files 行缺字段');
      } else {
        assert.ok(/^F:/.test(row.factId), `${kind} 缺 factId`);
        assert.ok(row.quality && row.quality.parse && row.quality.resolution, `${kind} 缺 quality`);
        assert.strictEqual(row.snapshotId, snapshot.snapshotId, `${kind} snapshotId 不一致`);
        assert.ok(row.sourceRange && row.sourceRange.file, `${kind} 缺 sourceRange`);
      }
    }
  }
});

test('metadata 产物：每张表抽样 50 行通过 metadata schema', { skip: !DIR && 'no facts dir' }, () => {
  const dir = path.join(DIR, 'metadata');
  const kinds = ['idl', 'sa', 'napi', 'permission', 'ces', 'harness'];
  let total = 0;
  for (const kind of kinds) {
    const file = path.join(dir, `${kind}.jsonl`);
    if (!fs.existsSync(file)) continue;
    const lines = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean);
    const step = Math.max(1, Math.floor(lines.length / 50));
    for (let i = 0; i < lines.length; i += step) {
      const row = JSON.parse(lines[i]);
      const res = schema.validateMetadata(row);
      assert.deepStrictEqual(res.errors, [], `${kind}: ${res.errors.join('; ')}`);
      total += 1;
    }
  }
  assert.ok(total >= 50, `metadata 抽样过少：${total}`);
});
