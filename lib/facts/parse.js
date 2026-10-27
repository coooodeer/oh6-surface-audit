'use strict';

/**
 * lib/facts/parse.js —— AG0.3 解析编排：目标枚举、分组 fork、分片合并。
 *
 * - 默认 4 个 worker（每个处理 1/4 语料后退出，规避无 Tree.delete 的内存增长）；
 * - 每个 worker 把结果写成 shard 目录下的 per-kind JSONL；
 * - 主进程按 factId 排序去重合并成 l1/*.jsonl。
 */

const fs = require('fs');
const path = require('path');
const cp = require('child_process');

const io = require('./io');
const scope = require('./scope');

const KINDS = ['files', 'functions', 'symbols', 'types', 'calls', 'cfg', 'dfg', 'sinks', 'guards', 'reads', 'writes', 'locks', 'quality'];
const RUNTIME_TMP = path.join(scope.TOOL_DIR, 'runtime', 'tmp');

function languageOf(rel) {
  return /\.ets$/i.test(rel) ? 'arkts' : /\.c$/i.test(rel) ? 'c' : /\.rs$/i.test(rel) ? 'rust' : 'cpp';
}

function targets(policy) {
  const out = [];
  for (const root of policy.roots) {
    const abs = path.join(scope.SRC_ROOT, root.root.split('/').join(path.sep));
    if (!fs.existsSync(abs)) continue;
    for (const fileAbs of scope.listSourceFiles(abs, policy.sourceExtensions)) {
      const rel = scope.relToSrc(fileAbs);
      out.push({
        abs: fileAbs,
        rel,
        repo: root.root,
        role: scope.isTestPath(rel, policy) ? 'test' : 'production',
        language: languageOf(rel)
      });
    }
  }
  out.sort((a, b) => (a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : 0));
  return out;
}

function splitGroups(list, groups) {
  const out = Array.from({ length: groups }, () => []);
  list.forEach((item, i) => out[i % groups].push(item));
  return out.filter((g) => g.length > 0);
}

function runGroup(group, index, snapshotId) {
  return new Promise((resolve, reject) => {
    const shardDir = path.join(RUNTIME_TMP, `shard-${process.pid}-${index}`);
    fs.rmSync(shardDir, { recursive: true, force: true });
    fs.mkdirSync(shardDir, { recursive: true });
    const child = cp.fork(path.join(__dirname, 'parse-worker.js'), [], { stdio: ['ignore', 'inherit', 'inherit', 'ipc'] });
    let settled = false;
    let counts = null;
    // 等 worker 真正退出再返回：Windows 上子进程未退出时删除 shard 文件会失败
    child.on('message', (msg) => {
      if (msg && msg.type === 'done') counts = msg.counts;
    });
    child.on('error', (e) => { if (!settled) { settled = true; reject(e); } });
    child.on('exit', (code) => {
      if (settled) return;
      settled = true;
      if (code !== 0 || !counts) { reject(new Error(`worker-exit-${code}`)); return; }
      resolve({ shardDir, counts, files: group.length });
    });
    child.send({ shardDir, snapshotId, files: group });
  });
}

function readShard(file) {
  if (!fs.existsSync(file)) return [];
  const text = fs.readFileSync(file, 'utf8');
  if (!text) return [];
  const rows = [];
  for (const line of text.split('\n')) {
    if (!line) continue;
    try { rows.push(JSON.parse(line)); } catch (_) { /* 单行损坏不拖垮整片 */ }
  }
  return rows;
}

/**
 * 构建 L1 事实。
 * @returns {{counts:object, duplicates:object, unsupported:number, elapsedMs:number}}
 */
async function buildFacts({ snapshotId, policy, jobs = 4, onProgress = null }) {
  const t0 = Date.now();
  const list = targets(policy);
  const groups = splitGroups(list, Math.max(1, Math.min(jobs, list.length)));

  const shards = await Promise.all(groups.map((g, i) => runGroup(g, i, snapshotId)));

  const merged = Object.fromEntries(KINDS.map((k) => [k, []]));
  const unsupported = [];
  for (const shard of shards) {
    // 不用 spread：calls 单类可达 28 万行，展开会打爆调用栈
    for (const kind of KINDS) {
      for (const row of readShard(path.join(shard.shardDir, `${kind}.jsonl`))) merged[kind].push(row);
    }
    for (const row of readShard(path.join(shard.shardDir, 'unsupported.jsonl'))) unsupported.push(row);
    if (onProgress) onProgress(shard);
  }

  const dir = path.join(scope.FACTS_ROOT, snapshotId.replace(/^sha256:/, ''));
  const l1 = path.join(dir, 'l1');
  const writeStats = {};
  for (const kind of KINDS) {
    // quality 行没有 factId：key 给错会让排序失效，产物顺序随 worker 分组漂移
    const key = kind === 'files' ? (r) => r.path : (r) => r.factId || r.id;
    const res = io.writeJsonl(path.join(l1, `${kind}.jsonl`), merged[kind], { key });
    writeStats[kind] = { written: res.written, duplicates: res.duplicates };
  }
  io.writeJsonl(path.join(dir, 'unsupported.jsonl'), unsupported, { key: (r) => r.id });

  for (const shard of shards) io.removeDir(shard.shardDir);
  try { io.removeDir(RUNTIME_TMP); } catch (_) { /* 允许非空 */ }

  return {
    targets: list.length,
    workers: groups.length,
    counts: writeStats,
    unsupported: unsupported.length,
    elapsedMs: Date.now() - t0
  };
}

module.exports = { targets, buildFacts, splitGroups, languageOf, KINDS };
