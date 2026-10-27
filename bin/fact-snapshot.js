#!/usr/bin/env node
'use strict';

/**
 * bin/fact-snapshot.js —— AG0.1：snapshot / build / metadata manifest。
 *
 * 用法：
 *   node bin/fact-snapshot.js --scope=d4-r1
 *   node bin/fact-snapshot.js --scope=d4-r1 --check
 *   node bin/fact-snapshot.js --scope=d4-r1 --prune
 */

const fs = require('fs');
const path = require('path');
const cp = require('child_process');

const ids = require('../lib/facts/ids');
const io = require('../lib/facts/io');
const scope = require('../lib/facts/scope');
const compdb = require('../lib/facts/compdb');

const { rulesVersionFor } = require('../lib/facts/manifest');

function parseArgs(argv) {
  const args = { scopeId: null, check: false, prune: false, snapshot: null };
  for (const a of argv) {
    if (a.startsWith('--scope=')) args.scopeId = a.slice('--scope='.length);
    else if (a === '--check') args.check = true;
    else if (a === '--prune') args.prune = true;
    else if (a.startsWith('--snapshot=')) args.snapshot = a.slice('--snapshot='.length);
    else if (a === '--help' || a === '-h') args.help = true;
    else throw new Error(`unknown-arg: ${a}`);
  }
  return args;
}

function pkgVersion(abs) {
  try { return JSON.parse(fs.readFileSync(abs, 'utf8')).version || null; } catch (_) { return null; }
}

function toolVersions(policy) {
  const clangExe = path.join(scope.SRC_ROOT, 'prebuilts', 'clang', 'ohos', 'windows-x86_64', 'llvm', 'bin', 'clang++.exe');
  let clang = null;
  if (fs.existsSync(clangExe)) {
    const r = cp.spawnSync(clangExe, ['--version'], { encoding: 'utf8', windowsHide: true });
    const m = /clang version (\S+)/.exec(r.stdout || '');
    clang = m ? m[1] : null;
  }
  const nodeMods = path.join(scope.WORKSPACE, 'oh6-framework-want-leak-miner', 'node_modules');
  const versions = {
    node: process.version,
    clang,
    treeSitter: pkgVersion(path.join(nodeMods, 'tree-sitter', 'package.json')),
    treeSitterCpp: pkgVersion(path.join(nodeMods, 'tree-sitter-cpp', 'package.json')),
    treeSitterC: pkgVersion(path.join(nodeMods, 'tree-sitter-c', 'package.json'))
  };
  if (policy.sourceExtensions.includes('.ets')) {
    versions.typescript = pkgVersion(path.join(nodeMods, 'typescript', 'package.json'));
  }
  if (policy.sourceExtensions.includes('.rs')) {
    const probe = require('../lib/facts/rust').probeBinary();
    versions.rustProbe = fs.existsSync(probe) ? require('../lib/facts/ids').sha256File(probe) : null;
  }
  return versions;
}

function computeGenVisibility(genDirs) {
  const referenced = genDirs.size;
  let missing = 0;
  const missingSample = [];
  for (const [dir, refs] of genDirs) {
    const win = compdb.wslToWin(dir);
    if (!fs.existsSync(win)) {
      missing += 1;
      if (missingSample.length < 10) missingSample.push({ dir: dir.replace(/^.*\/OpenHarmony\//, ''), refs });
    }
  }
  missingSample.sort((a, b) => (a.dir < b.dir ? -1 : 1));
  return { referenced, missing, missingSample };
}

/** 计算完整 snapshot（不写盘） */
function buildSnapshot(policy) {
  const roots = policy.roots.map((r) => scope.enumerateRoot(r, policy, ids.sha256Hex));
  const missingRoots = roots.filter((r) => !r.present);
  if (missingRoots.length) {
    const msg = missingRoots.map((r) => r.root).join(', ');
    const err = new Error(`fatal:root-missing: ${msg}`);
    err.code = 2;
    throw err;
  }
  const missingHead = roots.filter((r) => !r.head);
  if (missingHead.length) {
    const err = new Error(`fatal:repo-head-missing: ${missingHead.map((r) => r.root).join(', ')}`);
    err.code = 2;
    throw err;
  }

  const compdbRes = compdb.scanCompdb(policy, scope.SRC_ROOT);
  const genVisibility = computeGenVisibility(compdbRes.genDirs);
  const metaSrc = scope.metadataSources(policy).map((s) => {
    const st = scope.fileStats(s.abs);
    return { kind: s.kind, scope: s.scope, rel: s.rel, sha256: st.sha256, bytes: st.bytes };
  });

  const payload = {
    scope: policy.snapshotScope || 'd4-r1',
    source: roots.map((r) => ({
      root: r.root,
      repo: r.repo,
      head: r.head,
      files: r.files,
      bytes: r.bytes,
      sourceManifestHash: r.sourceManifestHash
    })),
    build: {
      parts: compdbRes.parts.map((p) => ({ part: p.part, present: p.present, sha256: p.sha256 || null, bytes: p.bytes || 0, entries: p.entries || 0 })),
      genVisibility: { referenced: genVisibility.referenced, missing: genVisibility.missing }
    },
    metadata: { sources: metaSrc.map((s) => ({ kind: s.kind, scope: s.scope, rel: s.rel, sha256: s.sha256, bytes: s.bytes })) },
    tools: toolVersions(policy)
  };
  if (policy.sourceExtensions.includes('.ets') || policy.sourceExtensions.includes('.rs')) {
    payload.parseRulesVersion = rulesVersionFor(policy);
  }
  const snapshotId = ids.snapshotIdOf(payload);
  return { payload, snapshotId, roots, compdbRes, genVisibility, metaSrc };
}

function writeSnapshot(snap, policy) {
  const idHex = snap.snapshotId.replace(/^sha256:/, '');
  const dir = path.join(scope.FACTS_ROOT, idHex);
  io.ensureDir(dir);

  const metaCounts = {
    idl: snap.metaSrc.filter((s) => s.kind === 'idl').length,
    sa: snap.metaSrc.filter((s) => s.kind === 'sa').length,
    permission: snap.metaSrc.filter((s) => s.kind === 'permission').length,
    external: snap.metaSrc.filter((s) => s.scope === 'external-authority').length
  };

  const snapshot = {
    snapshotId: snap.snapshotId,
    scope: policy.snapshotScope || 'd4-r1',
    policyVersion: policy.version,
    workingTreeDirty: snap.roots.some((r) => r.dirty),
    roots: snap.roots.map((r) => ({
      root: r.root,
      repo: r.repo,
      part: r.part,
      head: r.head,
      dirty: r.dirty,
      dirtyEntries: r.dirtyEntries,
      files: r.files,
      productionFiles: r.productionFiles,
      bytes: r.bytes,
      sourceManifestHash: r.sourceManifestHash
    })),
    compdb: {
      parts: snap.compdbRes.parts,
      totals: {
        entries: snap.compdbRes.parts.reduce((a, p) => a + (p.entries || 0), 0),
        rootFiles: snap.compdbRes.rootEntries.size
      }
    },
    genVisibility: snap.genVisibility,
    metadata: { counts: metaCounts },
    toolVersions: snap.payload.tools
  };

  const buildManifest = {
    snapshotId: snap.snapshotId,
    parts: snap.compdbRes.parts,
    genVisibility: snap.genVisibility,
    compdbWin: {
      file: 'compdb-win.jsonl',
      rows: snap.compdbRes.rootEntries.size,
      note: '只存投影元数据；完整 command 由 P7 用同一规则从 compdb 重建'
    }
  };

  const metadataManifest = {
    snapshotId: snap.snapshotId,
    sources: snap.metaSrc,
    counts: metaCounts
  };

  const projectionRows = compdb.projectionRows(snap.compdbRes.rootEntries);
  io.writeJsonl(path.join(dir, 'compdb-win.jsonl'), projectionRows, { key: (r) => r.id });

  const artifactRefs = [
    'snapshot.json',
    'build-manifest.json',
    'metadata-manifest.json',
    'compdb-win.jsonl',
    'manifest.json'
  ];
  const manifestId = ids.manifestIdOf(snap.snapshotId, artifactRefs);
  const manifest = {
    manifestId,
    snapshotId: snap.snapshotId,
    factSchemaVersion: '1',
    rulesVersion: rulesVersionFor(policy),
    obligationVersion: null,
    l6IndexVersion: null,
    verificationRunId: null,
    reportVersion: null,
    createdAt: new Date().toISOString(),
    producer: 'AG0',
    artifactRefs
  };

  io.writeJson(path.join(dir, 'snapshot.json'), snapshot);
  io.writeJson(path.join(dir, 'build-manifest.json'), buildManifest);
  io.writeJson(path.join(dir, 'metadata-manifest.json'), metadataManifest);
  io.writeJson(path.join(dir, 'manifest.json'), manifest);

  return { dir, snapshot, buildManifest, metadataManifest, manifest, projectionRows: projectionRows.length };
}

function listSnapshotDirs() {
  if (!fs.existsSync(scope.FACTS_ROOT)) return [];
  return fs.readdirSync(scope.FACTS_ROOT, { withFileTypes: true })
    .filter((d) => d.isDirectory() && /^[0-9a-f]{64}$/.test(d.name))
    .map((d) => ({ name: d.name, abs: path.join(scope.FACTS_ROOT, d.name), mtime: fs.statSync(path.join(scope.FACTS_ROOT, d.name)).mtimeMs }))
    .sort((a, b) => b.mtime - a.mtime);
}

function checkSnapshot(policy, snap, written) {
  const problems = [];
  const dir = written.dir;
  for (const rel of ['snapshot.json', 'build-manifest.json', 'metadata-manifest.json', 'manifest.json', 'compdb-win.jsonl']) {
    if (!fs.existsSync(path.join(dir, rel))) problems.push(`missing-artifact: ${rel}`);
  }
  const onDisk = JSON.parse(fs.readFileSync(path.join(dir, 'snapshot.json'), 'utf8'));
  if (onDisk.snapshotId !== snap.snapshotId) {
    problems.push(`snapshotId-mismatch: disk=${onDisk.snapshotId} computed=${snap.snapshotId}`);
  }
  const build = JSON.parse(fs.readFileSync(path.join(dir, 'build-manifest.json'), 'utf8'));
  for (const part of build.parts || []) {
    if (!part.present) continue;
    const abs = path.join(scope.SRC_ROOT, part.file.split('/').join(path.sep));
    if (!fs.existsSync(abs)) { problems.push(`compdb-missing: ${part.file}`); continue; }
    const sha = ids.sha256File(abs);
    if (sha !== part.sha256) problems.push(`compdb-sha-mismatch: ${part.file}`);
  }
  const meta = JSON.parse(fs.readFileSync(path.join(dir, 'metadata-manifest.json'), 'utf8'));
  for (const s of meta.sources || []) {
    const abs = path.join(scope.SRC_ROOT, s.rel.split('/').join(path.sep));
    if (!fs.existsSync(abs)) { problems.push(`metadata-missing: ${s.rel}`); continue; }
    if (ids.sha256File(abs) !== s.sha256) problems.push(`metadata-sha-mismatch: ${s.rel}`);
  }
  return problems;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help || !args.scopeId) {
    console.log('usage: node bin/fact-snapshot.js --scope=d4-r1 [--check] [--prune]');
    return 0;
  }
  const policy = scope.loadPolicy(args.scopeId);
  const snap = buildSnapshot(policy);
  const written = writeSnapshot(snap, policy);

  if (args.prune) {
    for (const d of listSnapshotDirs().slice(2)) io.removeDir(d.abs);
  }

  const summary = {
    snapshotId: snap.snapshotId,
    dir: scope.posix(path.relative(scope.TOOL_DIR, written.dir)),
    roots: snap.roots.map((r) => ({ root: r.root, head: (r.head || '').slice(0, 9), dirty: r.dirty, dirtyEntries: r.dirtyEntries, files: r.files, production: r.productionFiles })),
    compdb: written.snapshot.compdb.totals,
    genVisibility: snap.genVisibility.referenced + '/' + snap.genVisibility.missing + ' missing',
    metadata: written.snapshot.metadata.counts,
    tools: snap.payload.tools,
    projectionRows: written.projectionRows,
    manifestId: written.manifest.manifestId
  };

  if (args.check) {
    const problems = checkSnapshot(policy, snap, written);
    if (problems.length) {
      console.error(`CHECK-FAIL\n${problems.join('\n')}`);
      console.log(JSON.stringify(summary, null, 2));
      return 1;
    }
    console.log('CHECK-OK');
  }
  console.log(JSON.stringify(summary, null, 2));
  return 0;
}

try {
  process.exitCode = main();
} catch (e) {
  console.error(String(e.message || e));
  process.exitCode = e.code === 2 ? 2 : 1;
}
