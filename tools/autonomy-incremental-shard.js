'use strict';

/**
 * tools/autonomy-incremental-shard.js —— 文件级 shard 重建的最小实验工具。
 *
 * 只重解析一个文件（parse-worker），把该文件的旧行从各 L1 表移除，再合并新行；
 * 不预建全仓缓存，不跨组件复用。用于对照“全量 fact-build”的事实/入口/缺口/语义。
 *
 * 用法：
 *   node tools/autonomy-incremental-shard.js --snapshot=sha256:<id> --scope=access-token-incr \
 *     --file=<相对 root 的路径> [--deleted] [--out=<目录>] [--json]
 */

const fs = require('node:fs');
const path = require('node:path');
const cp = require('node:child_process');
const scopeLib = require('../lib/facts/scope');
const parseLib = require('../lib/facts/parse');
const io = require('../lib/facts/io');
const ids = require('../lib/facts/ids');

const TOOL_DIR = path.resolve(__dirname, '..');
const SHARD_ROOT = path.join(TOOL_DIR, 'out', 'autonomy', 'incremental', 'shards');

function parseArgs(argv) {
  const out = { snapshot: null, scope: null, file: null, deleted: false, outDir: null, json: false };
  for (const arg of argv) {
    if (arg.startsWith('--snapshot=')) out.snapshot = arg.slice('--snapshot='.length);
    else if (arg.startsWith('--scope=')) out.scope = arg.slice('--scope='.length);
    else if (arg.startsWith('--file=')) out.file = arg.slice('--file='.length);
    else if (arg === '--deleted') out.deleted = true;
    else if (arg.startsWith('--out=')) out.outDir = arg.slice('--out='.length);
    else if (arg === '--json') out.json = true;
    else if (arg === '--help' || arg === '-h') out.help = true;
    else throw new Error(`unknown-arg: ${arg}`);
  }
  return out;
}

function readRows(file) {
  if (!fs.existsSync(file)) return [];
  const text = fs.readFileSync(file, 'utf8');
  return text.split('\n').filter(Boolean).map((line) => JSON.parse(line));
}

function fileOf(row) {
  return row.locator?.file || row.sourceRange?.file || row.file || row.path || null;
}

function tableKey(kind) {
  return kind === 'files' ? (r) => r.path : (r) => r.factId || r.id;
}

function runWorker(policy, snapshotId, target) {
  return new Promise((resolve, reject) => {
    const shardDir = path.join(SHARD_ROOT, `one-${process.pid}-${Date.now()}`);
    fs.rmSync(shardDir, { recursive: true, force: true });
    fs.mkdirSync(shardDir, { recursive: true });
    const child = cp.fork(path.join(TOOL_DIR, 'lib', 'facts', 'parse-worker.js'),
      [], { stdio: ['ignore', 'inherit', 'inherit', 'ipc'] });
    let counts = null;
    child.on('message', (msg) => { if (msg && msg.type === 'done') counts = msg.counts; });
    child.on('error', reject);
    child.on('exit', (code) => {
      if (code !== 0 || !counts) return reject(new Error(`worker-exit-${code}`));
      try {
        const rows = Object.fromEntries(parseLib.KINDS.map((kind) =>
          [kind, readRows(path.join(shardDir, `${kind}.jsonl`))]));
        rows.unsupported = readRows(path.join(shardDir, 'unsupported.jsonl'));
        resolve({ rows, counts, shardDir });
      } catch (e) { reject(e); }
    });
    child.send({ shardDir, snapshotId, files: [target] });
  });
}

async function main(argv) {
  const args = parseArgs(argv);
  if (args.help || !args.snapshot || !args.scope || (!args.file && !args.deleted)) {
    process.stdout.write('usage: node tools/autonomy-incremental-shard.js --snapshot=sha256:<id> ' +
      '--scope=<scopeId> --file=<rel> [--deleted] [--out=<dir>] [--json]\n');
    return args.help ? 0 : 2;
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(args.snapshot)) throw new Error('invalid snapshot id');
  const policy = scopeLib.loadPolicy(args.scope);
  const snapshotId = args.snapshot;
  const list = parseLib.targets(policy);
  const target = args.file
    ? list.find((item) => item.rel === args.file || item.rel.endsWith(`/${args.file}`)) : null;
  if (!args.deleted && !target) throw new Error(`file-not-in-scope: ${args.file}`);

  const sourceDir = path.join(scopeLib.FACTS_ROOT, snapshotId.slice(7));
  const outDir = args.outDir ? path.resolve(args.outDir) : sourceDir;
  if (!fs.existsSync(path.join(sourceDir, 'l1'))) throw new Error('snapshot l1 missing');
  if (outDir !== sourceDir) {
    fs.rmSync(outDir, { recursive: true, force: true });
    fs.cpSync(sourceDir, outDir, { recursive: true });
  }
  const l1 = path.join(outDir, 'l1');
  const t0 = Date.now();
  let parsed = null;
  if (!args.deleted) parsed = await runWorker(policy, snapshotId, target);
  const rel = target ? target.rel : args.file;
  const stats = { written: {}, duplicates: {} };
  for (const kind of parseLib.KINDS) {
    const file = path.join(l1, `${kind}.jsonl`);
    const oldRows = readRows(file);
    const kept = oldRows.filter((row) => fileOf(row) !== rel);
    const added = parsed ? parsed.rows[kind] : [];
    const merged = [...kept, ...added];
    const res = io.writeJsonl(file, merged, { key: tableKey(kind) });
    stats.written[kind] = res.written;
    stats.duplicates[kind] = res.duplicates;
  }
  const unsupportedFile = path.join(outDir, 'unsupported.jsonl');
  const oldUnsupported = readRows(unsupportedFile).filter((row) => fileOf(row) !== rel);
  const newUnsupported = parsed ? parsed.rows.unsupported : [];
  io.writeJsonl(unsupportedFile, [...oldUnsupported, ...newUnsupported], { key: (r) => r.id });
  try { if (parsed) io.removeDir(parsed.shardDir); } catch (_) { /* ignore */ }
  const elapsedMs = Date.now() - t0;
  const readBytes = parsed ? fs.statSync(target.abs).size : 0;
  const result = { ok: true, snapshotId, scope: args.scope, file: rel, deleted: args.deleted,
    outDir: path.relative(TOOL_DIR, outDir).split(path.sep).join('/'),
    elapsedMs, readBytes, counts: stats, parsedFiles: parsed ? 1 : 0 };
  if (args.json) process.stdout.write(`${JSON.stringify(result)}\n`);
  else process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  return 0;
}

module.exports = { main, fileOf, readRows };

if (require.main === module) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; })
    .catch((e) => { process.stderr.write(`${JSON.stringify({ ok: false, error: e.message })}\n`);
      process.exitCode = 1; });
}
