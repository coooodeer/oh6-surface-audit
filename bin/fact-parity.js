#!/usr/bin/env node
'use strict';

/**
 * bin/fact-parity.js —— AG0.6：own vs legacy parity。
 *
 * 用法：
 *   node bin/fact-parity.js [--snapshot=<id>] [--legacy-dir=out/l1]
 *   node bin/fact-parity.js --source=own        # 只读自有 facts，绝不打开 legacy
 *   node bin/fact-parity.js --source=legacy     # 只读 legacy（迁移期回归）
 *
 * 默认 compare：两边都读，写 parity.json。
 */

const fs = require('fs');
const path = require('path');

const io = require('../lib/facts/io');
const scope = require('../lib/facts/scope');
const parity = require('../lib/facts/parity');
const { updateManifest } = require('../lib/facts/manifest');

function parseArgs(argv) {
  const args = { snapshot: null, legacyDir: null, source: 'compare', sampleLimit: 10 };
  for (const a of argv) {
    if (a.startsWith('--snapshot=')) args.snapshot = a.slice('--snapshot='.length);
    else if (a.startsWith('--legacy-dir=')) args.legacyDir = a.slice('--legacy-dir='.length);
    else if (a.startsWith('--source=')) args.source = a.slice('--source='.length);
    else if (a.startsWith('--sample=')) args.sampleLimit = Number(a.slice('--sample='.length)) || 10;
    else if (a === '--help' || a === '-h') args.help = true;
    else throw new Error(`unknown-arg: ${a}`);
  }
  return args;
}

function resolveSnapshotDir(arg) {
  if (!fs.existsSync(scope.FACTS_ROOT)) throw new Error('no-facts: 先跑 bin/fact-snapshot.js');
  if (arg) {
    const dir = path.join(scope.FACTS_ROOT, arg.replace(/^sha256:/, ''));
    if (!fs.existsSync(dir)) throw new Error(`snapshot-missing: ${arg}`);
    return dir;
  }
  const dirs = fs.readdirSync(scope.FACTS_ROOT, { withFileTypes: true })
    .filter((d) => d.isDirectory() && /^[0-9a-f]{64}$/.test(d.name))
    .map((d) => ({ abs: path.join(scope.FACTS_ROOT, d.name), mtime: fs.statSync(path.join(scope.FACTS_ROOT, d.name)).mtimeMs }))
    .sort((a, b) => b.mtime - a.mtime);
  if (!dirs.length) throw new Error('no-facts: out/facts 为空');
  return dirs[0].abs;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log('usage: node bin/fact-parity.js [--snapshot=<id>] [--legacy-dir=<dir>] [--source=compare|own|legacy]');
    return 0;
  }
  const dir = resolveSnapshotDir(args.snapshot);
  const snapshot = JSON.parse(fs.readFileSync(path.join(dir, 'snapshot.json'), 'utf8'));

  if (args.source === 'own') {
    const own = parity.loadOwn(dir);
    console.log(JSON.stringify({
      source: 'own',
      snapshotId: snapshot.snapshotId,
      legacyRead: false,
      functions: own.functions.size,
      calls: own.calls,
      note: '--source=own 只读 out/facts/<id>/l1，不打开 legacy'
    }, null, 2));
    return 0;
  }

  if (args.source === 'legacy') {
    const legacy = parity.loadLegacy(args.legacyDir || parity.LEGACY_DIR);
    console.log(JSON.stringify({
      source: 'legacy',
      legacyDir: scope.posix(path.relative(scope.TOOL_DIR, args.legacyDir || parity.LEGACY_DIR)),
      legacyPresent: legacy.present,
      functions: legacy.functions.size,
      calls: legacy.calls,
      note: 'legacy 记录一律视为 source=legacy，不参与任何 own 口径计算'
    }, null, 2));
    return 0;
  }

  const own = parity.loadOwn(dir);
  const legacy = parity.loadLegacy(args.legacyDir || parity.LEGACY_DIR);
  const report = parity.compare(own, legacy, { sampleLimit: args.sampleLimit });
  report.snapshotId = snapshot.snapshotId;
  io.writeJson(path.join(dir, 'parity.json'), report);
  updateManifest(dir, ['parity.json']);

  console.log(JSON.stringify({
    snapshotId: snapshot.snapshotId,
    dir: scope.posix(path.relative(scope.TOOL_DIR, dir)),
    legacyPresent: report.legacyPresent,
    functions: report.functions,
    calls: report.calls
  }, null, 2));
  return 0;
}

try {
  process.exitCode = main();
} catch (e) {
  console.error(String(e.message || e));
  process.exitCode = 1;
}
