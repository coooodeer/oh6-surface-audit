'use strict';

/**
 * tools/autonomy-fact-shards.js —— R2-B：三样本 shard 清单与截断/解析缺口可见性。
 *
 * 对每个样本（scope policy）输出：
 *   - shard 定位：scope、roots、snapshotId、policy limits；
 *   - 生产/测试目标数与字节（snapshot.json 口径）；
 *   - L1 13 张表行数与字节；
 *   - unsupported 按 reason/kind 分解（具名解析缺口）；
 *   - index 截断账目 callsSeen/callsRetained/callsTruncated（与 functions 同）；
 *   - 入口候选与绑定分布（buildAnchors + resolveBinding，只读，不建 run）；
 *   - 完整性语义：extraction-untruncated ≠ 全部解析成功（unsupported>0 时具名保留）。
 *
 * 只读：不写快照、不改 L1。输出 JSON 到 --out（默认 out/autonomy/inventory/r2-shard-manifest.json）。
 *
 * 用法：node tools/autonomy-fact-shards.js [--scopes=access-token-r2,init-r2,ipc-r2] [--out=<file>]
 */

const fs = require('node:fs');
const path = require('node:path');

const factsLib = require('../lib/autonomy/facts');
const indexLib = require('../lib/autonomy/index');
const discovery = require('../lib/autonomy/discovery');

const TOOL_DIR = path.resolve(__dirname, '..');

function parseArgs(argv) {
  const out = { scopes: ['access-token-r2', 'init-r2', 'ipc-r2'], outFile: null, snapshot: null };
  for (const a of argv) {
    if (a.startsWith('--scopes=')) out.scopes = a.slice('--scopes='.length).split(',').map((s) => s.trim()).filter(Boolean);
    else if (a.startsWith('--out=')) out.outFile = a.slice('--out='.length);
    else if (a.startsWith('--snapshot=')) out.snapshot = a.slice('--snapshot='.length);
    else throw new Error(`unknown-arg: ${a}`);
  }
  return out;
}

function readJsonlRows(file) {
  if (!fs.existsSync(file)) return [];
  const text = fs.readFileSync(file, 'utf8');
  const rows = [];
  for (const line of text.split('\n')) {
    if (!line) continue;
    try { rows.push(JSON.parse(line)); } catch (_) { /* 单行损坏计数 */ }
  }
  return rows;
}

function shardReport(scopeId, snapshotArg) {
  const policy = JSON.parse(fs.readFileSync(path.join(TOOL_DIR, 'K', 'policies', `scope-${scopeId}.json`), 'utf8'));
  const facts = factsLib.AutonomyFacts.open({ snapshot: snapshotArg || 'latest', scope: policy });
  const idx = facts.index();

  // L1 表行数与字节
  const tables = {};
  for (const kind of factsLib.TABLES) {
    const file = facts.l1(kind);
    const rows = readJsonlRows(file);
    tables[kind] = { rows: rows.length, bytes: fs.existsSync(file) ? fs.statSync(file).size : 0 };
  }
  const unsupportedRows = readJsonlRows(facts.dir && path.join(facts.dir, 'unsupported.jsonl'));
  const unsupportedByReason = {};
  const unsupportedByKind = {};
  for (const row of unsupportedRows) {
    unsupportedByReason[row.reason || 'unknown'] = (unsupportedByReason[row.reason || 'unknown'] || 0) + 1;
    unsupportedByKind[row.kind || 'unknown'] = (unsupportedByKind[row.kind || 'unknown'] || 0) + 1;
  }

  // 生产/测试目标（snapshot 口径）
  const snap = facts.snapshot();
  const rootRows = (snap.roots || []).map((r) => ({
    root: r.root, files: r.files, productionFiles: r.productionFiles,
    bytes: r.bytes, sourceManifestHash: r.sourceManifestHash
  }));

  // 入口与绑定分布（只读清点）
  const anchorsInfo = discovery.buildAnchors(facts, policy);
  const bindingByKind = {};
  const bindingSamples = [];
  for (const [ref, anchor] of anchorsInfo.anchors) {
    const b = discovery.resolveBinding(ref, { facts, scope: policy, anchors: anchorsInfo.anchors });
    const key = `${anchor.kind}:${b.binding}`;
    bindingByKind[key] = (bindingByKind[key] || 0) + 1;
    if (b.binding !== 'resolved' && bindingSamples.length < 200) {
      bindingSamples.push({ kind: anchor.kind, method: anchor.method || null, saId: anchor.saId || null,
        interface: anchor.interface || null, binding: b.binding,
        candidates: (b.candidates || []).slice(0, 4).map((c) => ({ file: c.file, line: c.startLine })),
        note: b.note });
    }
  }

  // 完整性语义：上限未触发 ≠ 解析全部成功
  const trunc = idx.truncation;
  const extraction = {
    indexCallsSeen: trunc.calls.seen,
    indexCallsRetained: trunc.calls.retained,
    indexCallsTruncated: trunc.calls.truncated,
    indexFunctionsSeen: trunc.functions.seen,
    indexFunctionsRetained: trunc.functions.retained,
    indexFunctionsTruncated: trunc.functions.truncated,
    extractionUntruncated: trunc.calls.truncated === 0 && trunc.functions.truncated === 0,
    unsupportedRows: unsupportedRows.length,
    unsupportedByReason,
    unsupportedByKind,
    parseComplete: unsupportedRows.length === 0,
    semantics: 'extractionUntruncated 表示索引上限未触发；unsupported>0 表示存在具名解析缺口，'
      + '两者同时成立时只可声称“未截断+具名缺口”，不可声称组件代码已完整抽取。'
  };

  return {
    scope: scopeId,
    snapshotId: facts.snapshotId,
    roots: rootRows,
    policyLimits: facts.limits,
    tables,
    unsupported: { rows: unsupportedRows.length, byReason: unsupportedByReason, byKind: unsupportedByKind },
    index: {
      counts: idx.counts,
      truncated: idx.truncated,
      truncation: trunc
    },
    entries: {
      total: anchorsInfo.entries.length,
      byKind: anchorsInfo.stats.entryKinds,
      coverageAnchors: anchorsInfo.stats.coverageAnchors,
      bindingByKind,
      nonResolvedSamples: bindingSamples
    },
    extraction
  };
}

function main(argv = []) {
  const args = parseArgs(argv);
  const shards = [];
  for (const scopeId of args.scopes) {
    const snapArg = args.snapshot && args.scopes.length === 1 ? args.snapshot : null;
    shards.push(shardReport(scopeId, snapArg));
  }
  const result = {
    manifestVersion: 'r2-shard-manifest-v1',
    generatedAt: new Date().toISOString(),
    tool: 'tools/autonomy-fact-shards.js',
    shards
  };
  const outFile = args.outFile || path.join(TOOL_DIR, 'out', 'autonomy', 'inventory', 'r2-shard-manifest.json');
  fs.mkdirSync(path.dirname(outFile), { recursive: true });
  fs.writeFileSync(outFile, `${JSON.stringify(result, null, 2)}\n`, 'utf8');
  const brief = shards.map((s) => ({
    scope: s.scope, snapshotId: s.snapshotId.slice(7, 19),
    productionFiles: s.roots.reduce((a, r) => a + (r.productionFiles || 0), 0),
    callsTruncated: s.index.truncation.calls.truncated,
    unsupported: s.unsupported.rows,
    entries: s.entries.total,
    binding: s.entries.bindingByKind
  }));
  process.stdout.write(`${JSON.stringify({ ok: true, out: path.relative(TOOL_DIR, outFile).split(path.sep).join('/'), shards: brief })}\n`);
  return 0;
}

module.exports = { main, shardReport };

if (require.main === module) {
  try { process.exitCode = main(process.argv.slice(2)); }
  catch (e) {
    process.stderr.write(`${JSON.stringify({ ok: false, error: e.message })}\n`);
    process.exitCode = 1;
  }
}
