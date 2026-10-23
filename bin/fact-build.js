#!/usr/bin/env node
'use strict';

/**
 * bin/fact-build.js —— AG0.3：L1 结构事实（functions/symbols/types/calls/sinks/guards/reads/writes/locks/files）。
 *
 * 用法：node bin/fact-build.js [--snapshot=<id>] [--jobs=4]
 * 确定性：jobs=1 与 jobs=4 产物逐字节一致（已验证）；默认 4 worker，全量 ~25 s。
 */

const fs = require('fs');
const path = require('path');

const scope = require('../lib/facts/scope');
const parse = require('../lib/facts/parse');
const { updateManifest } = require('../lib/facts/manifest');

function parseArgs(argv) {
  const args = { snapshot: null, scopeId: null, jobs: 4 };
  for (const a of argv) {
    if (a.startsWith('--snapshot=')) args.snapshot = a.slice('--snapshot='.length);
    else if (a.startsWith('--scope=')) args.scopeId = a.slice('--scope='.length);
    else if (a.startsWith('--jobs=')) args.jobs = Math.max(1, Number(a.slice('--jobs='.length)) || 4);
    else if (a === '--help' || a === '-h') args.help = true;
    else throw new Error(`unknown-arg: ${a}`);
  }
  return args;
}

function resolveSnapshotDir(arg) {
  if (!fs.existsSync(scope.FACTS_ROOT)) throw new Error('no-snapshot: 先跑 bin/fact-snapshot.js');
  if (arg) {
    const hex = arg.replace(/^sha256:/, '');
    const dir = path.join(scope.FACTS_ROOT, hex);
    if (!fs.existsSync(dir)) throw new Error(`snapshot-missing: ${hex}`);
    return dir;
  }
  const dirs = fs.readdirSync(scope.FACTS_ROOT, { withFileTypes: true })
    .filter((d) => d.isDirectory() && /^[0-9a-f]{64}$/.test(d.name))
    .map((d) => ({ abs: path.join(scope.FACTS_ROOT, d.name), mtime: fs.statSync(path.join(scope.FACTS_ROOT, d.name)).mtimeMs }))
    .sort((a, b) => b.mtime - a.mtime);
  if (!dirs.length) throw new Error('no-snapshot: out/facts 为空');
  return dirs[0].abs;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log('usage: node bin/fact-build.js [--snapshot=<id>] [--jobs=4]');
    return 0;
  }
  const dir = resolveSnapshotDir(args.snapshot);
  const snapshot = JSON.parse(fs.readFileSync(path.join(dir, 'snapshot.json'), 'utf8'));
  const policy = scope.loadPolicy(args.scopeId || snapshot.scope || 'd4-r1');

  const res = await parse.buildFacts({ snapshotId: snapshot.snapshotId, policy, jobs: args.jobs });
  updateManifest(dir, [
    ...parse.KINDS.map((k) => `l1/${k}.jsonl`),
    'unsupported.jsonl'
  ]);

  console.log(JSON.stringify({
    snapshotId: snapshot.snapshotId,
    targets: res.targets,
    workers: res.workers,
    elapsedMs: res.elapsedMs,
    counts: res.counts,
    unsupported: res.unsupported
  }, null, 2));
  return 0;
}

main().then((code) => { process.exitCode = code; }).catch((e) => {
  console.error(String(e && e.stack || e));
  process.exitCode = 1;
});
