#!/usr/bin/env node
'use strict';

/**
 * bin/fact-quality.js —— AG0.5：quality.json / coverage.jsonl / unsupported.jsonl 汇总。
 *
 * 输入：snapshot.json、l1/quality.jsonl、metadata/unsupported.jsonl、根 unsupported.jsonl（L1 级）
 * 输出：quality.json、coverage.jsonl、合并后的 unsupported.jsonl
 */

const fs = require('fs');
const path = require('path');

const io = require('../lib/facts/io');
const scope = require('../lib/facts/scope');
const quality = require('../lib/facts/quality');
const { updateManifest } = require('../lib/facts/manifest');

function parseArgs(argv) {
  const args = { snapshot: null };
  for (const a of argv) {
    if (a.startsWith('--snapshot=')) args.snapshot = a.slice('--snapshot='.length);
    else if (a === '--help' || a === '-h') args.help = true;
    else throw new Error(`unknown-arg: ${a}`);
  }
  return args;
}

function resolveSnapshotDir(arg) {
  if (!fs.existsSync(scope.FACTS_ROOT)) throw new Error('no-snapshot: 先跑 bin/fact-snapshot.js');
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

/** 流式数行数（calls.jsonl 24 万行 / 240 MB，不能整读） */
function countLines(file) {
  if (!fs.existsSync(file)) return 0;
  const fd = fs.openSync(file, 'r');
  const buf = Buffer.alloc(1 << 20);
  let lines = 0;
  try {
    for (;;) {
      const n = fs.readSync(fd, buf, 0, buf.length, null);
      if (n <= 0) break;
      for (let i = 0; i < n; i += 1) if (buf[i] === 0x0a) lines += 1;
    }
  } finally { fs.closeSync(fd); }
  return lines;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log('usage: node bin/fact-quality.js [--snapshot=<id>]');
    return 0;
  }
  const dir = resolveSnapshotDir(args.snapshot);
  const snapshot = JSON.parse(fs.readFileSync(path.join(dir, 'snapshot.json'), 'utf8'));
  const rows = io.readJsonl(path.join(dir, 'l1', 'quality.jsonl'));
  if (!rows.length) throw new Error('quality-rows-missing: 先跑 bin/fact-build.js');

  const summary = quality.summarize(rows);
  const callsWritten = countLines(path.join(dir, 'l1', 'calls.jsonl'));

  const clangRows = io.readJsonl(path.join(dir, 'clang-status.jsonl'));
  const clangByFile = new Map(clangRows.map((r) => [r.file, r.status]));
  const clangSummary = clangRows.length ? (() => {
    const byStatus = {};
    for (const r of clangRows) byStatus[r.status] = (byStatus[r.status] || 0) + 1;
    return { checked: clangRows.length, ok: byStatus.ok || 0, byStatus, mode: clangRows.length >= 2000 ? 'all' : 'sample' };
  })() : null;

  const doc = {
    snapshotId: snapshot.snapshotId,
    totals: {
      ...summary.totals,
      callsWritten,
      cfgCoverageAvg: summary.cfgCoverageAvg,
      dfgCoverageAvg: summary.dfgCoverageAvg,
      clangChecked: clangSummary ? clangSummary.checked : 0,
      clangOk: clangSummary ? clangSummary.ok : 0
    },
    files: rows.map((r) => ({
      file: r.file,
      repo: r.repo,
      role: r.role,
      language: r.language,
      parse: r.parse,
      errorNodes: r.errorNodes,
      counts: r.counts,
      cfgCoverageAvg: r.cfgCoverageAvg,
      dfgCoverageAvg: r.dfgCoverageAvg,
      clangStatus: clangByFile.get(r.file) || null
    }))
  };
  io.writeJson(path.join(dir, 'quality.json'), doc);

  const coverage = quality.coverageRows({
    totals: summary.totals,
    callsWritten,
    compdb: (snapshot.compdb && snapshot.compdb.totals) || { entries: 0, rootFiles: 0 },
    gen: snapshot.genVisibility || { referenced: 0, missing: 0 },
    cfgAvg: summary.cfgCoverageAvg,
    dfgAvg: summary.dfgCoverageAvg,
    clang: clangSummary
  });
  io.writeJsonl(path.join(dir, 'coverage.jsonl'), coverage, { key: (r) => r.metric });

  const merged = quality.mergeUnsupported([
    io.readJsonl(path.join(dir, 'unsupported.jsonl')),
    io.readJsonl(path.join(dir, 'metadata', 'unsupported.jsonl'))
  ]);
  const res = io.writeJsonl(path.join(dir, 'unsupported.jsonl'), merged, { key: (r) => r.id });

  updateManifest(dir, ['quality.json', 'coverage.jsonl', 'unsupported.jsonl']);

  console.log(JSON.stringify({
    snapshotId: snapshot.snapshotId,
    dir: scope.posix(path.relative(scope.TOOL_DIR, dir)),
    totals: doc.totals,
    coverage: Object.fromEntries(coverage.map((r) => [r.metric, r.value])),
    unsupported: { rows: res.written, byReason: quality.countByReason(merged) }
  }, null, 2));
  return 0;
}

try {
  process.exitCode = main();
} catch (e) {
  console.error(String(e.message || e));
  process.exitCode = 1;
}
