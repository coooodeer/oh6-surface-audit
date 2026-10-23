#!/usr/bin/env node
'use strict';

/**
 * bin/fact-metadata.js —— AG0.2：IDL / SA / permission / NAPI / CES / harness 元数据。
 *
 * 用法：node bin/fact-metadata.js --snapshot=<id|hex>   （省略时取最近一次 snapshot）
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ids = require('../lib/facts/ids');
const io = require('../lib/facts/io');
const scope = require('../lib/facts/scope');
const idl = require('../lib/facts/idl');
const sa = require('../lib/facts/sa');
const permission = require('../lib/facts/permission');
const napi = require('../lib/facts/napi');
const { updateManifest } = require('../lib/facts/manifest');

function parseArgs(argv) {
  const args = { snapshot: null, scopeId: null };
  for (const a of argv) {
    if (a.startsWith('--snapshot=')) args.snapshot = a.slice('--snapshot='.length);
    else if (a.startsWith('--scope=')) args.scopeId = a.slice('--scope='.length);
    else if (a === '--help' || a === '-h') args.help = true;
    else throw new Error(`unknown-arg: ${a}`);
  }
  return args;
}

function resolveSnapshotDir(arg) {
  if (!fs.existsSync(scope.FACTS_ROOT)) throw new Error('no-snapshot: out/facts 不存在，先跑 fact-snapshot');
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

function readWithHash(abs) {
  const buf = fs.readFileSync(abs);
  return { text: buf.toString('utf8'), sha256: crypto.createHash('sha256').update(buf).digest('hex') };
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log('usage: node bin/fact-metadata.js [--snapshot=<id>] [--scope=d4-r1]');
    return 0;
  }
  const dir = resolveSnapshotDir(args.snapshot);
  const snapshot = JSON.parse(fs.readFileSync(path.join(dir, 'snapshot.json'), 'utf8'));
  const snapshotId = snapshot.snapshotId;
  const policy = scope.loadPolicy(args.scopeId || snapshot.scope || 'd4-r1');

  const sources = scope.metadataSources(policy);
  const byKind = { idl: [], sa: [], permission: [], napi: [], ces: [], harness: [] };
  const external = [];
  for (const s of sources) {
    if (s.scope === 'external-authority') external.push(s);
    else byKind[s.kind].push(s);
  }

  const rows = { idl: [], sa: [], permission: [], ces: [], napi: [], harness: [] };
  const unsupported = [];
  const stats = { idlFiles: 0, idlMethods: 0, idlTokenAbsent: 0, saRows: 0, permissionRows: 0, externalRows: 0, cesRows: 0, napiRows: 0 };

  // ---- IDL ----
  for (const s of byKind.idl) {
    const { text, sha256 } = readWithHash(s.abs);
    const parsed = idl.parseIdl(text);
    const methodRows = idl.toRows(parsed, s.rel);
    stats.idlFiles += 1;
    stats.idlMethods += methodRows.length;
    for (const m of methodRows) {
      const locator = { file: s.rel, interface: m.interface, method: m.method, line: m.line };
      rows.idl.push({
        metadataId: ids.metadataIdOf(snapshotId, 'idl', locator),
        kind: 'idl',
        snapshotId,
        sourceFile: s.rel,
        sourceLine: m.line,
        sha256,
        source: 'own',
        producer: 'AG0',
        schemaVersion: '1',
        payload: {
          interface: m.interface,
          package: m.package,
          descriptor: m.interface,
          method: m.method,
          returnType: m.returnType,
          paramCount: m.paramCount,
          params: m.params,
          ipcCode: m.ipcCode,
          oneway: m.oneway,
          token: m.token,
          tokenSource: m.tokenSource
        }
      });
    }
    if (methodRows.length && methodRows.every((m) => m.tokenSource === 'absent')) {
      stats.idlTokenAbsent += methodRows.length;
      unsupported.push({
        id: `U:idl:${s.rel}`,
        kind: 'idl',
        reason: 'token-absent',
        file: s.rel,
        detail: { methods: methodRows.length }
      });
    }
  }

  // ---- SA / CES ----
  for (const s of byKind.sa) {
    const { text, sha256 } = readWithHash(s.abs);
    for (const r of sa.saRows(text, s.rel)) {
      const locator = { file: s.rel, process: r.process, saId: r.saId };
      rows.sa.push({
        metadataId: ids.metadataIdOf(snapshotId, 'sa', locator),
        kind: 'sa',
        snapshotId,
        sourceFile: s.rel,
        sourceLine: r.line,
        sha256,
        source: 'own',
        producer: 'AG0',
        schemaVersion: '1',
        payload: { saId: r.saId, process: r.process, library: r.library, runOnCreate: r.runOnCreate, distributed: r.distributed }
      });
      stats.saRows += 1;
    }
    for (const c of sa.cesRows(text, s.rel)) {
      const locator = { file: s.rel, provider: c.provider, action: c.action };
      rows.ces.push({
        metadataId: ids.metadataIdOf(snapshotId, 'ces', locator),
        kind: 'ces',
        snapshotId,
        sourceFile: s.rel,
        sourceLine: c.line,
        sha256,
        source: 'own',
        producer: 'AG0',
        schemaVersion: '1',
        payload: { action: c.action, provider: c.provider, process: c.process }
      });
      stats.cesRows += 1;
    }
  }

  // ---- permission（root 内接口表 + root 外权威表）----
  for (const s of byKind.permission) {
    const { text, sha256 } = readWithHash(s.abs);
    for (const r of permission.parseInterfaceProcessTable(text, s.rel)) {
      const locator = { file: s.rel, name: r.name };
      rows.permission.push({
        metadataId: ids.metadataIdOf(snapshotId, 'permission', locator),
        kind: 'permission',
        snapshotId,
        sourceFile: s.rel,
        sourceLine: r.line,
        sha256,
        source: 'own',
        producer: 'AG0',
        schemaVersion: '1',
        payload: { name: r.name, table: 'interface-process', processes: r.processes }
      });
      stats.permissionRows += 1;
    }
  }
  for (const s of external) {
    const { text, sha256 } = readWithHash(s.abs);
    for (const r of permission.parsePermissionDefinitions(text, s.rel)) {
      const locator = { file: s.rel, name: r.name };
      rows.permission.push({
        metadataId: ids.metadataIdOf(snapshotId, 'permission', locator),
        kind: 'permission',
        snapshotId,
        sourceFile: s.rel,
        sourceLine: r.line,
        sha256,
        source: 'external-authority',
        producer: 'AG0',
        schemaVersion: '1',
        payload: { name: r.name, table: 'permission-definitions', level: r.level, grantMode: r.grantMode, availableType: r.availableType, since: r.since, deprecated: r.deprecated }
      });
      stats.externalRows += 1;
    }
  }

  // ---- NAPI（代码派生：扫描 5 root 的源文件）----
  const sourceFiles = [];
  for (const root of policy.roots) {
    const abs = path.join(scope.SRC_ROOT, root.root.split('/').join(path.sep));
    if (fs.existsSync(abs)) sourceFiles.push(...scope.listSourceFiles(abs, policy.sourceExtensions));
  }
  for (const abs of sourceFiles) {
    let text;
    try { text = fs.readFileSync(abs, 'utf8'); } catch (_) { continue; }
    if (!text.includes('napi_module_register')) continue;
    const rel = scope.relToSrc(abs);
    const sha256 = crypto.createHash('sha256').update(text, 'utf8').digest('hex');
    for (const r of napi.scanText(text, rel)) {
      const locator = { file: rel, module: r.module, struct: r.struct };
      rows.napi.push({
        metadataId: ids.metadataIdOf(snapshotId, 'napi', locator),
        kind: 'napi',
        snapshotId,
        sourceFile: rel,
        sourceLine: r.line,
        sha256,
        source: 'own',
        producer: 'AG0',
        schemaVersion: '1',
        payload: { module: r.module, struct: r.struct, registration: 'napi_module_register' }
      });
      stats.napiRows += 1;
    }
  }

  // ---- 缺源登记 ----
  if (rows.ces.length === 0) {
    unsupported.push({ id: 'U:ces:source', kind: 'ces', reason: 'source-not-in-scope', file: null, detail: { note: 'CES action 表在 base/notification/common_event_service（root 外）' } });
  }
  unsupported.push({ id: 'U:harness:definition', kind: 'harness', reason: 'definition-pending', file: null, detail: { note: 'root 内无 harness 元数据文件；fuzz/mock 是代码形态，留给 AG1' } });
  for (const s of external) {
    if (!fs.existsSync(s.abs)) unsupported.push({ id: `U:ext:${s.rel}`, kind: 'permission', reason: 'source-not-in-scope', file: s.rel, detail: {} });
  }

  // ---- 写盘 ----
  const metaDir = path.join(dir, 'metadata');
  const written = {};
  for (const kind of Object.keys(rows)) {
    const res = io.writeJsonl(path.join(metaDir, `${kind}.jsonl`), rows[kind]);
    written[kind] = { rows: res.written, duplicates: res.duplicates };
  }
  io.writeJsonl(path.join(metaDir, 'unsupported.jsonl'), unsupported, { key: (r) => r.id });
  written.unsupported = unsupported.length;

  updateManifest(dir, Object.keys(rows).map((k) => `metadata/${k}.jsonl`).concat(['metadata/unsupported.jsonl']));

  console.log(JSON.stringify({
    snapshotId,
    dir: scope.posix(path.relative(scope.TOOL_DIR, dir)),
    stats,
    written,
    externalSources: external.map((e) => e.rel)
  }, null, 2));
  return 0;
}

try {
  process.exitCode = main();
} catch (e) {
  console.error(String(e.message || e));
  process.exitCode = 1;
}
