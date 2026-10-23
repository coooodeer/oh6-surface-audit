#!/usr/bin/env node
'use strict';

/**
 * bin/fact-clang.js —— AG0.3/P7：clang 有界校核。
 *
 * 模式（性能差异极大，默认 native）：
 *   --mode=native   Windows 预编译 clang（~0.5 s/文件，语法/宏指纹）
 *   --mode=wsl      WSL Debian 里的 OHOS Linux clang（~16 s/文件，目标语义；9p 读头文件慢约 33×）
 *   --mode=auto    native 跑全部；只对 native 报 compile-error 的文件用 wsl 复核（最多 --wsl-max 个）
 *
 * 用法：
 *   node bin/fact-clang.js [--snapshot=<id>] [--sample=100] [--mode=native]
 *   node bin/fact-clang.js --mode=wsl --only=account_iam_info.cpp
 *   node bin/fact-clang.js --mode=auto --sample=100 --wsl-max=5
 *
 * 产物：out/facts/<id>/clang-status.jsonl（每文件一行）+ manifest 更新。
 */

const fs = require('fs');
const path = require('path');

const io = require('../lib/facts/io');
const scope = require('../lib/facts/scope');
const clang = require('../lib/facts/clang');
const { updateManifest } = require('../lib/facts/manifest');

function parseArgs(argv) {
  const args = { snapshot: null, sample: 100, all: false, jobs: 8, mode: 'native', wslDistro: null, wslMax: 10, only: [] };
  for (const a of argv) {
    if (a.startsWith('--snapshot=')) args.snapshot = a.slice('--snapshot='.length);
    else if (a.startsWith('--sample=')) args.sample = Number(a.slice('--sample='.length)) || 0;
    else if (a === '--all') args.all = true;
    else if (a.startsWith('--jobs=')) args.jobs = Math.max(1, Number(a.slice('--jobs='.length)) || 8);
    else if (a.startsWith('--mode=')) args.mode = a.slice('--mode='.length);
    else if (a.startsWith('--wsl-distro=')) args.wslDistro = a.slice('--wsl-distro='.length);
    else if (a.startsWith('--wsl-max=')) args.wslMax = Math.max(0, Number(a.slice('--wsl-max='.length)) || 0);
    else if (a.startsWith('--only=')) args.only.push(a.slice('--only='.length));
    else if (a === '--help' || a === '-h') args.help = true;
    else throw new Error(`unknown-arg: ${a}`);
  }
  if (!['native', 'wsl', 'auto'].includes(args.mode)) throw new Error(`bad-mode: ${args.mode}（native|wsl|auto）`);
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

async function pool(items, jobs, fn) {
  const out = [];
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(jobs, items.length) }, async () => {
    for (;;) {
      const idx = i;
      i += 1;
      if (idx >= items.length) return;
      out[idx] = await fn(items[idx], idx);
    }
  }));
  return out;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log([
      'usage: node bin/fact-clang.js [--snapshot=<id>] [--sample=100] [--all] [--jobs=8]',
      '       [--mode=native|wsl|auto] [--wsl-distro=debian] [--wsl-max=10] [--only=<substr> ...]'
    ].join('\n'));
    return 0;
  }
  const dir = resolveSnapshotDir(args.snapshot);
  const snapshot = JSON.parse(fs.readFileSync(path.join(dir, 'snapshot.json'), 'utf8'));
  const policy = scope.loadPolicy(snapshot.scope || 'd4-r1');

  const entries = clang.loadEntries(policy);
  if (!entries.size) throw new Error('no-compdb-entries');
  // 只校核事实底座里存在的文件，保证 clangStatus 能挂到 quality 行上
  const known = new Set(io.readJsonl(path.join(dir, 'l1', 'files.jsonl')).map((r) => r.path));
  const byRel = new Map();
  for (const [abs, v] of entries) {
    const rel = abs.replace(/^.*\/OpenHarmony\//, '');
    if (known.has(rel)) byRel.set(rel, v);
  }

  // --only 优先：按子串过滤全部候选（不受抽样限制），用于"只复核有争议的少数文件"
  const allRels = [...byRel.keys()].sort();
  const filtered = args.only.length ? allRels.filter((r) => args.only.some((s) => r.includes(s))) : null;
  const targets = filtered || (args.all ? allRels : clang.sampleTargets(allRels, args.sample));
  if (!targets.length) throw new Error('no-targets: --only 未匹配任何 compdb 文件');

  const t0 = Date.now();
  const opts = { distro: args.wslDistro || undefined, timeoutMs: 120000 };
  // WSL 每次调用要付 ~0.1–0.3 s 进程开销 + 9p 读头文件的成本，并发默认压到 2
  const jobs = args.mode === 'wsl' ? Math.min(args.jobs, 2) : args.jobs;

  let rows = await pool(targets, jobs, (rel) => clang.checkOneAsync({ rel }, byRel.get(rel), { ...opts, mode: args.mode === 'auto' ? 'native' : args.mode }));
  rows = rows.filter(Boolean);

  let wslUsed = 0;
  let wslMax = args.wslMax;
  if (args.mode === 'auto') {
    // 只对 native 判为 compile-error 的文件做目标语义复核（missing-header 复核无意义）
    const disputed = rows.filter((r) => r.status === 'compile-error').slice(0, wslMax);
    for (const row of disputed) {
      const r2 = await clang.checkOneAsync({ rel: row.file }, byRel.get(row.file), { ...opts, mode: 'wsl' });
      wslUsed += 1;
      if (r2 && r2.status !== 'skipped' && r2.status !== 'timeout') {
        row.nativeStatus = row.status;
        row.adjudicated = 'wsl';
        row.status = r2.status;
        row.errors = r2.errors;
        row.wslMs = r2.ms;
      } else {
        row.wslError = r2 ? r2.errors : ['no-result'];
      }
    }
  } else if (args.mode === 'wsl') {
    wslUsed = rows.length;
  }

  const byStatus = {};
  for (const r of rows) byStatus[r.status] = (byStatus[r.status] || 0) + 1;
  const ok = byStatus.ok || 0;

  const withSnapshot = rows.map((r) => ({ ...r, snapshotId: snapshot.snapshotId }));
  io.writeJsonl(path.join(dir, 'clang-status.jsonl'), withSnapshot, { key: (r) => r.file });
  updateManifest(dir, ['clang-status.jsonl']);

  console.log(JSON.stringify({
    snapshotId: snapshot.snapshotId,
    dir: scope.posix(path.relative(scope.TOOL_DIR, dir)),
    mode: args.mode,
    jobs,
    checked: withSnapshot.length,
    ok,
    okRatio: withSnapshot.length ? Number((ok / withSnapshot.length).toFixed(4)) : null,
    byStatus,
    wslUsed,
    viaRsp: withSnapshot.filter((r) => r.viaRsp).length,
    avgMs: withSnapshot.length ? Math.round(withSnapshot.reduce((a, r) => a + r.ms, 0) / withSnapshot.length) : null,
    wallMs: Date.now() - t0
  }, null, 2));
  return 0;
}

main().then((c) => { process.exitCode = c; }).catch((e) => {
  console.error(String(e && e.message || e));
  process.exitCode = 1;
});
