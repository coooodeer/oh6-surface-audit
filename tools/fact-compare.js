'use strict';

/**
 * tools/fact-compare.js —— R2-C：两个事实输出目录的逐表对照（增量 vs 干净全量）。
 *
 * 身份字段按合同归一化：snapshotId / factId / metadataId 都由 snapshotId 派生，
 * 两边 snapshotId 必然不同（源清单哈希不同）⇒ 比较时剥去 snapshotId，并独立校验
 * factId/metadataId 的派生正确性（factIdOf(自身 snapshotId, kind, locator)）。
 * 除身份字段外的任何差异都计为漂移（fail）。
 *
 * 对照范围：13 张 l1 表 + unsupported.jsonl + metadata/* + includes.jsonl（存在时）。
 *
 * 用法：node tools/fact-compare.js --a=<dir> --b=<dir> [--out=<file>] [--json]
 */

const fs = require('node:fs');
const path = require('node:path');

const idsLib = require('../lib/facts/ids');
const parse = require('../lib/facts/parse');

const TOOL_DIR = path.resolve(__dirname, '..');

function parseArgs(argv) {
  const out = { a: null, b: null, outFile: null, json: false };
  for (const arg of argv) {
    if (arg.startsWith('--a=')) out.a = path.resolve(arg.slice('--a='.length));
    else if (arg.startsWith('--b=')) out.b = path.resolve(arg.slice('--b='.length));
    else if (arg.startsWith('--out=')) out.outFile = path.resolve(arg.slice('--out='.length));
    else if (arg === '--json') out.json = true;
    else throw new Error(`unknown-arg: ${arg}`);
  }
  if (!out.a || !out.b) throw new Error('usage: fact-compare --a=<dir> --b=<dir> [--out=<file>]');
  return out;
}

function readRows(file) {
  if (!fs.existsSync(file)) return null;
  const text = fs.readFileSync(file, 'utf8');
  const rows = [];
  for (const line of text.split('\n')) {
    if (!line) continue;
    try { rows.push(JSON.parse(line)); } catch (_) { rows.push({ __malformed: line.slice(0, 120) }); }
  }
  return rows;
}

function rowKey(kind) {
  return kind === 'files' ? (r) => r.path
    : kind === 'quality' ? (r) => r.id
    : kind === 'unsupported' ? (r) => r.id
    : (r) => r.factId || r.id || null;
}

/**
 * 身份归一：factId/metadataId 及行内所有 F:/M: 引用的 snap12 段都由 snapshotId 派生；
 * sinks/guards 等表的 locator 内嵌 fn 引用，使 factId 稳定段也随 snapshotId 变化。
 * 处理：先按合同校验 factId = factIdOf(自身 snapshotId, 行 kind, locator)（可校验处），
 * 再把整段 factId/metadataId 占位、其余 F:/M: 引用做 snap12 占位，用归一后全文作键。
 */
function normalizeRow(row, kind, snapshotId, derivationErrors) {
  const ownSnapshot = String(row.snapshotId || snapshotId).replace(/^sha256:/, '');
  const snap12 = ownSnapshot.slice(0, 12);
  if (row.factId && row.kind && row.locator) {
    const expected = idsLib.factIdOf(`sha256:${ownSnapshot}`, row.kind, row.locator);
    if (expected !== row.factId) derivationErrors.push({ kind, factId: row.factId, expected });
  } else if (row.factId && !String(row.factId).startsWith(`F:${snap12}:`)) {
    derivationErrors.push({ kind, factId: row.factId, expectedPrefix: `F:${snap12}:` });
  }
  if (row.metadataId && !String(row.metadataId).startsWith(`M:${snap12}:`)) {
    derivationErrors.push({ kind, metadataId: row.metadataId, expectedPrefix: `M:${snap12}:` });
  }
  const clone = JSON.parse(JSON.stringify(row));
  delete clone.snapshotId;
  const walk = (value) => {
    if (typeof value === 'string') {
      return value.split(`F:${snap12}:`).join('F:<SNAP12>:').split(`M:${snap12}:`).join('M:<SNAP12>:');
    }
    if (Array.isArray(value)) return value.map(walk);
    if (value && typeof value === 'object') {
      const out = {};
      for (const [k, v] of Object.entries(value)) out[k] = walk(v);
      return out;
    }
    return value;
  };
  const normalized = walk(clone);
  if (normalized.factId) normalized.factId = '<DERIVED>';
  if (normalized.metadataId) normalized.metadataId = '<DERIVED>';
  return normalized;
}

/** 全深度确定性序列化：每层键排序（不能用 JSON.stringify 的 replacer 数组——
 * 那会在所有嵌套层过滤键，导致只改嵌套字段（如 sourceRange.file）的行被误判相等）。 */
function canon(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canon).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canon(value[k])}`).join(',')}}`;
}

function compareTable(kind, fileA, fileB, snapA, snapB) {
  const rowsA = readRows(fileA);
  const rowsB = readRows(fileB);
  if (rowsA === null && rowsB === null) return { kind, present: false, equal: true };
  const derivationErrors = [];
  // 计数式对照：同键多行必须两侧数量一致（Map 收行会折叠重复行，漏报差异）
  const countA = new Map();
  const countB = new Map();
  const exampleA = new Map();
  const exampleB = new Map();
  const addRows = (rows, counts, examples, snap) => {
    for (const row of rows || []) {
      if (row.__malformed) { const k = `__malformed:${counts.size}`; counts.set(k, (counts.get(k) || 0) + 1); examples.set(k, row); continue; }
      const norm = normalizeRow(row, kind, snap, derivationErrors);
      const key = canon(norm);
      counts.set(key, (counts.get(key) || 0) + 1);
      if (!examples.has(key)) examples.set(key, norm);
    }
  };
  addRows(rowsA, countA, exampleA, snapA);
  addRows(rowsB, countB, exampleB, snapB);
  const onlyInA = [];
  const onlyInB = [];
  const countMismatches = [];
  const keysA = new Set(countA.keys());
  const keysB = new Set(countB.keys());
  for (const [k, n] of countA) {
    if (!countB.has(k)) { onlyInA.push(k); continue; }
    if (countB.get(k) !== n) countMismatches.push(k);
  }
  for (const k of countB.keys()) if (!countA.has(k)) onlyInB.push(k);
  const equal = onlyInA.length === 0 && onlyInB.length === 0 && countMismatches.length === 0
    && derivationErrors.length === 0;
  return {
    kind,
    present: true,
    rowsA: [...countA.values()].reduce((s, n) => s + n, 0),
    rowsB: [...countB.values()].reduce((s, n) => s + n, 0),
    distinctKeysA: countA.size,
    distinctKeysB: countB.size,
    onlyInA: onlyInA.slice(0, 10),
    onlyInB: onlyInB.slice(0, 10),
    onlyInACount: onlyInA.length,
    onlyInBCount: onlyInB.length,
    countMismatchCount: countMismatches.length,
    countMismatches: countMismatches.slice(0, 10),
    derivationErrors: derivationErrors.slice(0, 10),
    derivationErrorCount: derivationErrors.length,
    equal
  };
}

function main(argv = []) {
  const args = parseArgs(argv);
  const snapA = JSON.parse(fs.readFileSync(path.join(args.a, 'snapshot.json'), 'utf8')).snapshotId;
  const snapB = JSON.parse(fs.readFileSync(path.join(args.b, 'snapshot.json'), 'utf8')).snapshotId;
  const tables = [];
  for (const kind of parse.KINDS) {
    tables.push(compareTable(kind, path.join(args.a, 'l1', `${kind}.jsonl`),
      path.join(args.b, 'l1', `${kind}.jsonl`), snapA, snapB));
  }
  tables.push(compareTable('unsupported', path.join(args.a, 'unsupported.jsonl'),
    path.join(args.b, 'unsupported.jsonl'), snapA, snapB));

  const metadataKinds = ['idl', 'sa', 'napi', 'permission', 'ces', 'harness', 'unsupported'];
  const metadata = [];
  for (const kind of metadataKinds) {
    metadata.push(compareTable(`metadata/${kind}`, path.join(args.a, 'metadata', `${kind}.jsonl`),
      path.join(args.b, 'metadata', `${kind}.jsonl`), snapA, snapB));
  }

  const includes = compareTable('includes', path.join(args.a, 'includes.jsonl'),
    path.join(args.b, 'includes.jsonl'), snapA, snapB);

  const all = [...tables, ...metadata, includes];
  const result = {
    compareVersion: 'fact-compare-v1',
    a: args.a, b: args.b,
    snapshotIdA: snapA,
    snapshotIdB: snapB,
    identityNormalization: {
      stripped: ['snapshotId'],
      derivationChecked: ['factId', 'metadataId'],
      contract: 'factId/metadataId 由各目录自身 snapshotId 派生，派生错误计为漂移'
    },
    tables: all,
    mismatched: all.filter((t) => t.present && !t.equal).map((t) => t.kind),
    allEqual: all.every((t) => !t.present || t.equal)
  };
  if (args.outFile) {
    fs.mkdirSync(path.dirname(args.outFile), { recursive: true });
    fs.writeFileSync(args.outFile, `${JSON.stringify(result, null, 2)}\n`, 'utf8');
  }
  process.stdout.write(`${JSON.stringify({
    ok: true, allEqual: result.allEqual, mismatched: result.mismatched,
    tables: all.map((t) => ({ kind: t.kind, equal: t.equal, rowsA: t.rowsA, rowsB: t.rowsB }))
  })}\n`);
  return result.allEqual ? 0 : 2;
}

module.exports = { main, compareTable, normalizeRow };

if (require.main === module) {
  try { process.exitCode = main(process.argv.slice(2)); }
  catch (e) {
    process.stderr.write(`${JSON.stringify({ ok: false, error: e.message })}\n`);
    process.exitCode = 1;
  }
}
