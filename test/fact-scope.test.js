'use strict';

/**
 * test/fact-scope.test.js —— §5 验收 #9：AG0 不得输出类特定语义。
 * 两道检查：① 代码层（lib/facts + bin/fact-*.js）不出现禁用词；② 产物层 l1 行里不出现禁用键。
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const TOOL = path.join(__dirname, '..');
const FORBIDDEN = [/memorySink/i, /\bsptr\b/i, /P5 coverage/i, /PROVEN-VULN/i, /T1-confirmed/i];

function scanSource() {
  const offenders = [];
  const walk = (dir) => {
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      const abs = path.join(dir, ent.name);
      if (ent.isDirectory()) { walk(abs); continue; }
      if (!ent.name.endsWith('.js')) continue;
      const text = fs.readFileSync(abs, 'utf8');
      for (const re of FORBIDDEN) {
        if (re.test(text)) offenders.push(`${path.relative(TOOL, abs)}: ${re}`);
      }
    }
  };
  walk(path.join(TOOL, 'lib', 'facts'));
  const binDir = path.join(TOOL, 'bin');
  for (const name of fs.readdirSync(binDir)) {
    if (!/^fact-.*\.js$/.test(name)) continue;
    const text = fs.readFileSync(path.join(binDir, name), 'utf8');
    for (const re of FORBIDDEN) if (re.test(text)) offenders.push(`bin/${name}: ${re}`);
  }
  return offenders;
}

function latestFactsDir() {
  const root = path.join(TOOL, 'out', 'facts');
  if (!fs.existsSync(root)) return null;
  const dirs = fs.readdirSync(root, { withFileTypes: true })
    .filter((d) => d.isDirectory() && /^[0-9a-f]{64}$/.test(d.name))
    .map((d) => ({ abs: path.join(root, d.name), mtime: fs.statSync(path.join(root, d.name)).mtimeMs }))
    .sort((a, b) => b.mtime - a.mtime);
  // out/facts 还可能有第三组件补充快照；本测试固定检查五根 d4-r1 产物，
  // 不把补充快照的数据层当 d4 产物，也不依赖“最新 = d4”这一偶然事实。
  const d4 = dirs.find((d) => {
    try {
      const snap = JSON.parse(fs.readFileSync(path.join(d.abs, 'snapshot.json'), 'utf8'));
      return snap.scope === 'd4-r1';
    } catch (_) { return false; }
  });
  return d4 ? d4.abs : null;
}

test('代码层：lib/facts 与 bin/fact-*.js 不出现类特定语义', () => {
  const offenders = scanSource();
  assert.deepStrictEqual(offenders, [], offenders.join('\n'));
});

test('产物层：l1 行不出现 memorySink / sptr / P5 等键', { skip: !latestFactsDir() && 'no facts dir' }, () => {
  const dir = latestFactsDir();
  const bad = [];
  for (const kind of ['files', 'functions', 'calls', 'cfg', 'dfg', 'sinks', 'guards', 'reads', 'writes', 'locks', 'types', 'symbols']) {
    const file = path.join(dir, 'l1', `${kind}.jsonl`);
    if (!fs.existsSync(file)) continue;
    const lines = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean);
    const step = Math.max(1, Math.floor(lines.length / 30));
    for (let i = 0; i < lines.length; i += step) {
      const text = lines[i];
      for (const re of FORBIDDEN) if (re.test(text)) bad.push(`${kind}: ${text.slice(0, 120)}`);
    }
  }
  assert.deepStrictEqual(bad.slice(0, 5), [], bad.join('\n'));
});

test('产物层：l1 的 kind 集合必须是 AG0 声明的通用 kind', { skip: !latestFactsDir() && 'no facts dir' }, () => {
  const dir = latestFactsDir();
  const allowed = new Set(['file', 'function', 'symbol', 'type', 'call', 'cfg', 'dfg', 'sink', 'guard', 'read', 'write', 'lock']);
  for (const kind of ['files', 'functions', 'calls', 'cfg', 'dfg', 'sinks', 'guards', 'reads', 'writes', 'locks', 'types', 'symbols']) {
    const file = path.join(dir, 'l1', `${kind}.jsonl`);
    if (!fs.existsSync(file)) continue;
    const first = JSON.parse(fs.readFileSync(file, 'utf8').split('\n').filter(Boolean)[0]);
    assert.ok(allowed.has(first.kind), `${kind} 出现未声明 kind: ${first.kind}`);
  }
});
