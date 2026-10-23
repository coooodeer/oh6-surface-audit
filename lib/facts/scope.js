'use strict';

/**
 * lib/facts/scope.js —— AG0.1 的输入面：scope policy、git 状态、源文件枚举与哈希、metadata 源枚举。
 *
 * 约定（AG0-GOAL-GUIDE §2.2）：
 *   - 所有相对路径用 POSIX 形式（相对 OpenHarmony/）；
 *   - 文件枚举只走 policy.sourceExtensions，跳过 .git/node_modules/third_party/prebuilts/out/build；
 *   - role 由 policy.testPathPattern / testFilePattern 判定。
 */

const fs = require('fs');
const path = require('path');
const cp = require('child_process');
const crypto = require('crypto');

const TOOL_DIR = path.resolve(__dirname, '..', '..');
const WORKSPACE = path.resolve(TOOL_DIR, '..');
const SRC_ROOT = path.join(WORKSPACE, 'OpenHarmony');
const K_DIR = path.join(TOOL_DIR, 'K');
const FACTS_ROOT = path.join(TOOL_DIR, 'out', 'facts');

const SKIP_DIRS = new Set(['.git', 'node_modules', 'third_party', 'prebuilts', 'out', 'build']);

function posix(p) {
  return String(p).split(path.sep).join('/');
}

function relToSrc(abs) {
  return posix(path.relative(SRC_ROOT, abs));
}

function loadPolicy(scopeId) {
  const file = path.join(K_DIR, 'policies', `scope-${scopeId}.json`);
  if (!fs.existsSync(file)) throw new Error(`policy-missing: ${posix(path.relative(TOOL_DIR, file))}`);
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function git(repoAbs, args) {
  const r = cp.spawnSync('git', ['-C', repoAbs, ...args], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, windowsHide: true });
  if (r.status !== 0) return null;
  return r.stdout;
}

function gitState(repoRel) {
  const abs = path.join(SRC_ROOT, repoRel.split('/').join(path.sep));
  if (!fs.existsSync(abs)) return { present: false, head: null, dirty: null, dirtyEntries: null };
  const head = (git(abs, ['rev-parse', 'HEAD']) || '').trim() || null;
  const status = git(abs, ['status', '--porcelain']);
  const lines = status === null ? [] : status.split(/\r?\n/).filter(Boolean);
  return { present: true, head, dirty: lines.length > 0, dirtyEntries: lines.length };
}

/** 递归列出 root 下的源文件（返回绝对路径，排序后稳定） */
function listSourceFiles(rootAbs, exts) {
  const extSet = new Set(exts.map((e) => e.toLowerCase()));
  const out = [];
  const stack = [rootAbs];
  while (stack.length) {
    const dir = stack.pop();
    let ents;
    try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { continue; }
    for (const ent of ents) {
      const abs = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        if (!SKIP_DIRS.has(ent.name)) stack.push(abs);
        continue;
      }
      if (!ent.isFile()) continue;
      if (!extSet.has(path.extname(ent.name).toLowerCase())) continue;
      out.push(abs);
    }
  }
  out.sort((a, b) => (posix(a) < posix(b) ? -1 : 1));
  return out;
}

function isTestPath(rel, policy) {
  if (policy.testPathPattern && new RegExp(policy.testPathPattern, 'i').test(`/${rel}`)) return true;
  if (policy.testFilePattern && new RegExp(policy.testFilePattern, 'i').test(rel)) return true;
  return false;
}

/** 单文件 sha256 + 字节数 + 行数（一遍读，一遍数换行） */
function fileStats(abs) {
  const buf = fs.readFileSync(abs);
  const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
  let lines = 0;
  for (let i = 0; i < buf.length; i += 1) if (buf[i] === 0x0a) lines += 1;
  if (buf.length > 0 && buf[buf.length - 1] !== 0x0a) lines += 1;
  return { sha256, bytes: buf.length, lines };
}

/** 枚举一个 root 的全部源文件（含 sha256/bytes/lines/role），并给出 sourceManifestHash */
function enumerateRoot(rootEntry, policy, sha256Hex) {
  const rootAbs = path.join(SRC_ROOT, rootEntry.root.split('/').join(path.sep));
  if (!fs.existsSync(rootAbs)) return { ...rootEntry, present: false, error: 'root-missing' };
  const files = listSourceFiles(rootAbs, policy.sourceExtensions);
  const rows = [];
  let bytes = 0;
  for (const abs of files) {
    const rel = relToSrc(abs);
    const st = fileStats(abs);
    bytes += st.bytes;
    rows.push({
      rel,
      sha256: st.sha256,
      bytes: st.bytes,
      lines: st.lines,
      role: isTestPath(rel, policy) ? 'test' : 'production'
    });
  }
  const sourceManifestHash = sha256Hex(rows.map((r) => `${r.rel}\u0000${r.sha256}\u0000${r.bytes}`).join('\n'));
  const g = gitState(rootEntry.root);
  return {
    root: rootEntry.root,
    part: rootEntry.part,
    repo: rootEntry.root,
    present: true,
    head: g.head,
    dirty: g.dirty,
    dirtyEntries: g.dirtyEntries,
    files: rows.length,
    productionFiles: rows.filter((r) => r.role === 'production').length,
    bytes,
    sourceManifestHash,
    rows
  };
}

/** 收集 root 下所有文件（不做扩展名过滤），用于 metadata 源枚举 */
function listAllFiles(rootAbs) {
  const out = [];
  const stack = [rootAbs];
  while (stack.length) {
    const dir = stack.pop();
    let ents;
    try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { continue; }
    for (const ent of ents) {
      const abs = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        if (!SKIP_DIRS.has(ent.name)) stack.push(abs);
        continue;
      }
      if (ent.isFile()) out.push(abs);
    }
  }
  out.sort((a, b) => (posix(a) < posix(b) ? -1 : 1));
  return out;
}

/**
 * 枚举 metadata 源（idl / sa / permission / external-authority）。
 * 返回 [{kind, scope, rel, abs, present}]
 */
function metadataSources(policy) {
  const out = [];
  const seen = new Set();
  const push = (kind, scope, abs) => {
    const rel = relToSrc(abs);
    if (seen.has(rel)) return;
    seen.add(rel);
    out.push({ kind, scope, rel, abs, present: true });
  };

  for (const src of policy.metadataSources) {
    if (src.scope === 'code-derived' || src.scope === 'definition-pending') continue;
    if (src.scope === 'external-authority' && src.file) {
      const abs = path.join(SRC_ROOT, src.file.split('/').join(path.sep));
      if (fs.existsSync(abs)) push(src.kind, 'external-authority', abs);
      continue;
    }
    if (src.scope !== 'roots') continue;
    for (const root of policy.roots) {
      const rootAbs = path.join(SRC_ROOT, root.root.split('/').join(path.sep));
      if (!fs.existsSync(rootAbs)) continue;
      for (const abs of listAllFiles(rootAbs)) {
        const rel = relToSrc(abs);
        if (src.kind === 'idl' && /\.idl$/i.test(abs)) push('idl', 'roots', abs);
        else if (src.kind === 'sa' && /(^|\/)sa_profile\//.test(rel) && /\.json$/i.test(abs)) push('sa', 'roots', abs);
        else if (src.kind === 'permission' && /permission/i.test(path.basename(abs)) && /\.json$/i.test(abs)) push('permission', 'roots', abs);
      }
    }
  }
  return out.sort((a, b) => (a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : 0));
}

module.exports = {
  TOOL_DIR, WORKSPACE, SRC_ROOT, K_DIR, FACTS_ROOT, SKIP_DIRS,
  posix, relToSrc, loadPolicy, gitState, listSourceFiles, listAllFiles,
  isTestPath, fileStats, enumerateRoot, metadataSources
};
