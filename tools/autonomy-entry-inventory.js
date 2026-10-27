'use strict';

/**
 * tools/autonomy-entry-inventory.js —— E0 入口/绑定只读清点（不建索引、不写 run）。
 *
 * 用途：对固定 facts 快照中的一个或多个 root，逐条列出元数据入口（IDL 方法 / SA / NAPI /
 * OnRemoteRequest），并在**该 root 的函数表**中做名称 + owner 段绑定可行性调查：
 *   candidates = 同 root 内 name === method 的函数，按 qualified 是否含候选 owner 段分组。
 * 输出：JSON（stdout）+ 可选 --out=<file>；所有计数带分母，抽样/截断显式。
 *
 * 这是清点工具，不是裁决器：candidate/owner 只用于判断绑定是否可能唯一，
 * 不产出任何 finding/excluded，也不改变 run。
 *
 * 用法：
 *   node tools/autonomy-entry-inventory.js --scope=<policy> [--root=<repo rel path>]
 *     [--owner=<suffix>] [--interface=<substr>] [--out=<file>] [--max-candidates=<n>]
 *   --root 省略时使用 scope.roots 全部；--root 可重复（逗号分隔）。
 *   --owner 省略时使用 scope.modelMetadata.implOwnerSuffix（若存在）；可逗号分隔多个候选。
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const jsonl = require('../lib/autonomy/jsonl');

const TOOL_DIR = path.resolve(__dirname, '..');
const FACTS_ROOT = path.join(TOOL_DIR, 'out', 'facts');

function fail(message) {
  const e = new Error(message);
  e.code = 'inventory-error';
  throw e;
}

function parseFlags(argv) {
  const flags = {};
  const names = new Set(['scope', 'snapshot', 'root', 'owner', 'interface', 'out', 'max-candidates']);
  for (const arg of argv) {
    if (!arg.startsWith('--') || arg.indexOf('=') < 0) fail(`bad argument: ${arg}`);
    const eq = arg.indexOf('=');
    const key = arg.slice(2, eq);
    if (!names.has(key)) fail(`unknown flag: ${key}`);
    flags[key] = arg.slice(eq + 1);
  }
  return flags;
}

function resolvePath(p) {
  return path.isAbsolute(p) ? p : path.join(TOOL_DIR, p);
}

function resolveFactsDir(snapshot) {
  const raw = String(snapshot || 'latest');
  if (raw === 'latest') {
    const entries = fs.existsSync(FACTS_ROOT)
      ? fs.readdirSync(FACTS_ROOT).filter((n) => /^[0-9a-f]{64}$/.test(n)) : [];
    if (!entries.length) fail('no facts snapshot');
    entries.sort((a, b) => fs.statSync(path.join(FACTS_ROOT, b)).mtimeMs -
      fs.statSync(path.join(FACTS_ROOT, a)).mtimeMs);
    return path.join(FACTS_ROOT, entries[0]);
  }
  const hex = raw.replace(/^sha256:/, '');
  if (!/^[0-9a-f]{64}$/.test(hex)) fail(`bad snapshot id ${raw}`);
  const dir = path.join(FACTS_ROOT, hex);
  if (!fs.existsSync(path.join(dir, 'snapshot.json'))) fail(`snapshot not built: ${hex}`);
  return dir;
}

function sha256Hex(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function loadScope(file) {
  const abs = file ? resolvePath(file) : null;
  if (!abs || !fs.existsSync(abs)) fail(`scope policy not found: ${file}`);
  const doc = JSON.parse(fs.readFileSync(abs, 'utf8'));
  doc.__path = abs;
  return doc;
}

function list(values) {
  if (!values) return [];
  return String(values).split(',').map((v) => v.trim()).filter(Boolean);
}

/** owner 段的可观察形式：`::Owner::`；也接受仅 `Owner` 写法 */
function ownerHits(qualified, owner) {
  if (!owner) return true;
  const q = String(qualified || '');
  return q.includes(`::${owner}::`) || q.includes(`::${owner}<`) || q.endsWith(`::${owner}`);
}

function main(argv) {
  const flags = parseFlags(argv);
  const scope = loadScope(flags.scope);
  const snapshotArg = flags.snapshot || scope.snapshotId || 'latest';
  const factsDir = resolveFactsDir(snapshotArg);
  const snapshotId = JSON.parse(fs.readFileSync(path.join(factsDir, 'snapshot.json'), 'utf8')).snapshotId;
  if (scope.snapshotId && scope.snapshotId !== snapshotId) fail('scope snapshot mismatch');

  const roots = list(flags.root).length ? list(flags.root) : (scope.roots || []).map((r) => r.root);
  if (!roots.length) fail('no roots');
  for (const root of roots) {
    if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_./-]+$/.test(root)) fail(`bad root: ${root}`);
  }
  const owners = list(flags.owner).length ? list(flags.owner)
    : (scope.modelMetadata?.implOwnerSuffix ? [scope.modelMetadata.implOwnerSuffix] : []);
  const maxCandidates = Number(flags['max-candidates'] || 8);
  const interfaceNeedle = flags.interface || null;

  // 只读 functions.jsonl，按 repo needle 预过滤；只为命中 root 的行 JSON.parse。
  const needles = roots.map((r) => `"repo":"${r}"`);
  const byName = new Map();
  const fileRows = new Map();
  const fnRes = jsonl.readJsonl(path.join(factsDir, 'l1', 'functions.jsonl'), { needles });
  if (fnRes.malformed.length) fail(`malformed functions rows: ${fnRes.malformed.length}`);
  let functionsInRoots = 0;
  for (const row of fnRes.rows) {
    const repo = row.locator && row.locator.repo;
    if (!roots.includes(repo)) continue;
    functionsInRoots += 1;
    const name = row.name || '';
    if (!byName.has(name)) byName.set(name, []);
    byName.get(name).push(row);
  }

  const filesRes = jsonl.readJsonl(path.join(factsDir, 'l1', 'files.jsonl'), { needles });
  let filesInRoots = 0;
  for (const row of filesRes.rows) {
    const repo = row.repo || (row.locator && row.locator.repo);
    if (!roots.includes(repo)) continue;
    filesInRoots += 1;
    const rel = String(row.path || '').split(path.sep).join('/');
    if (!fileRows.has(rel)) fileRows.set(rel, row);
  }

  const fileNeedles = roots.map((r) => `"${r}/`);
  const meta = {};
  for (const kind of ['idl', 'sa', 'napi']) {
    const res = jsonl.readJsonl(path.join(factsDir, 'metadata', `${kind}.jsonl`), { needles: fileNeedles });
    meta[kind] = res.rows.filter((row) => roots.some((r) => String(row.sourceFile || '').startsWith(`${r}/`)));
  }

  const entries = [];
  const pushEntry = (entry) => {
    // 接口过滤器只用于 IDL；SA/NAPI/OnRemoteRequest 是 root 级入口，不因接口名过滤而消失。
    if (interfaceNeedle && entry.entryKind === 'idl') {
      const hay = `${entry.interface || ''} ${entry.method || ''}`;
      if (!hay.includes(interfaceNeedle)) return;
    }
    entries.push(entry);
  };
  for (const row of meta.idl) {
    const p = row.payload || {};
    pushEntry({ entryKind: 'idl', interface: p.interface || null, method: p.method || null,
      sourceFile: row.sourceFile || null, sourceLine: row.sourceLine || null,
      metadataRef: row.metadataId || null, paramCount: p.paramCount ?? null });
  }
  for (const row of meta.sa) {
    const p = row.payload || {};
    pushEntry({ entryKind: 'sa', interface: null, method: null, saId: p.saId ?? null,
      process: p.process || null, sourceFile: row.sourceFile || null, sourceLine: row.sourceLine || null,
      metadataRef: row.metadataId || null });
  }
  for (const row of meta.napi) {
    const p = row.payload || {};
    pushEntry({ entryKind: 'napi', interface: null, method: null, module: p.module || null,
      sourceFile: row.sourceFile || null, sourceLine: row.sourceLine || null,
      metadataRef: row.metadataId || null });
  }
  let testNameMatches = 0;
  for (const [name, rows] of byName) {
    if (!/OnRemoteRequest/.test(name)) continue;
    for (const row of rows) {
      // HWTEST_F 宏展开出的测试函数名也含 OnRemoteRequest；只把生产函数算入口，
      // 测试名匹配单独计数，避免把测试当入口（与 lib/autonomy/index.js 同口径）。
      if (row.role !== 'production') { testNameMatches += 1; continue; }
      pushEntry({ entryKind: 'on-remote-request', interface: null, method: name,
        sourceFile: row.sourceRange && row.sourceRange.file, sourceLine: row.startLine,
        metadataRef: null, qualified: row.qualified || null, factRef: row.factId });
    }
  }

  const findings = [];
  const methodHistogram = {};
  let idlTotal = 0;
  for (const entry of entries) {
    if (entry.entryKind !== 'idl' || !entry.method) continue;
    const name = entry.method;
    const rows = byName.get(name) || [];
    const sameName = rows.filter((fn) => fn.name === name);
    const ownerFiltered = sameName.filter((fn) => owners.some((owner) => ownerHits(fn.qualified, owner)));
    const impls = ownerFiltered.filter((fn) => fn.role === 'production');
    idlTotal += 1;
    const record = {
      entryKind: 'idl', interface: entry.interface, method: name,
      sourceFile: entry.sourceFile, sourceLine: entry.sourceLine,
      sameNameFunctions: sameName.length,
      sameNameProduction: sameName.filter((fn) => fn.role === 'production').length,
      owners,
      ownerMatched: ownerFiltered.length,
      ownerMatchedProduction: impls.length,
      binding: impls.length === 1 ? 'resolved' : impls.length > 1 ? 'suspect' : 'unbound',
      candidates: impls.slice(0, maxCandidates).map((fn) => ({
        qualified: fn.qualified || null, file: fn.sourceRange && fn.sourceRange.file,
        startLine: fn.startLine, endLine: fn.endLine, signature: fn.signature || null
      })),
      truncatedCandidates: Math.max(0, impls.length - maxCandidates)
    };
    findings.push(record);
    methodHistogram[record.interface || '?'] = (methodHistogram[record.interface || '?'] || 0) + 1;
  }

  const entryKinds = entries.reduce((m, e) => { m[e.entryKind] = (m[e.entryKind] || 0) + 1; return m; }, {});
  const summary = {
    snapshotId, factsDir: path.relative(TOOL_DIR, factsDir).split(path.sep).join('/'),
    roots, owners: owners.length ? owners : null, maxCandidates,
    interfaceFilter: interfaceNeedle,
    counts: {
      filesInRoots, functionsInRoots,
      metadata: { idl: meta.idl.length, sa: meta.sa.length, napi: meta.napi.length },
      entriesTotal: entries.length,
      entryKinds,
      testFunctionsNamedOnRemoteRequest: testNameMatches,
      idlTotal,
      idlBinding: findings.reduce((m, f) => { m[f.binding] = (m[f.binding] || 0) + 1; return m; }, {}),
      byInterface: methodHistogram
    },
    note: 'entries 只计生产入口：IDL/sa/napi 元数据 + role=production 且名字含 OnRemoteRequest 的函数；接口过滤器只作用于 IDL。testFunctionsNamedOnRemoteRequest 是名字含 OnRemoteRequest 的测试函数数，不计入入口。',
    entries,
    idlBinding: findings
  };
  const body = `${JSON.stringify(summary, null, 2)}\n`;
  if (flags.out) {
    const outAbs = resolvePath(flags.out);
    fs.mkdirSync(path.dirname(outAbs), { recursive: true });
    fs.writeFileSync(outAbs, body, { encoding: 'utf8' });
    process.stdout.write(`${JSON.stringify({ ok: true, out: path.relative(TOOL_DIR, outAbs)
      .split(path.sep).join('/'), sha256: sha256Hex(body), counts: summary.counts })}\n`);
  } else {
    process.stdout.write(body);
  }
}

module.exports = { main };

if (require.main === module) {
  try {
    main(process.argv.slice(2));
  } catch (e) {
    process.stderr.write(`${JSON.stringify({ ok: false, error: e.message })}\n`);
    process.exitCode = 1;
  }
}
