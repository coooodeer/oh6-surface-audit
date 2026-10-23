'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const cp = require('child_process');

const WORKSPACE = path.resolve(__dirname, '..', '..');
const SOURCE_ROOT = path.join(WORKSPACE, 'OpenHarmony');
const TOOL_ROOT = path.join(WORKSPACE, 'oh6-vuln-agent');
const OUT_ROOT = path.join(WORKSPACE, 'oh6-surface-audit', 'out');

const C_EXTS = new Set(['.c', '.cc', '.cpp', '.cxx']);
const H_EXTS = new Set(['.h', '.hh', '.hpp', '.hxx']);
const CPP_EXTS = new Set([...C_EXTS, ...H_EXTS]);

const SKIP_DIRS = new Set([
  '.git', '.repo', 'out', 'node_modules', 'third_party', 'prebuilts',
  'test', 'tests', 'unittest', 'fuzztest', 'build', 'buildtools'
]);

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function writeJson(file, obj) {
  ensureDir(path.dirname(file));
  fs.writeFileSync(file, JSON.stringify(obj, null, 2) + '\n', 'utf8');
}

function writeJsonl(file, rows) {
  ensureDir(path.dirname(file));
  fs.writeFileSync(file, rows.map((r) => JSON.stringify(r)).join('\n') + (rows.length ? '\n' : ''), 'utf8');
}

function readJsonl(file) {
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, 'utf8').split(/\r?\n/).filter(Boolean).map((l) => {
    try { return JSON.parse(l); } catch (_) { return null; }
  }).filter(Boolean);
}

function readText(file, cap = 2 * 1024 * 1024) {
  try {
    const st = fs.statSync(file);
    if (st.size > cap) return { text: null, reason: 'file-too-large', size: st.size };
    return { text: fs.readFileSync(file, 'utf8'), reason: null, size: st.size };
  } catch (e) {
    return { text: null, reason: 'read-failed', size: 0, error: String(e.message || e) };
  }
}

/**
 * 递归列文件。rel 为相对 root 的 POSIX 路径。
 * @param {string} root
 * @param {{exts?:Set<string>, skipDirs?:Set<string>, maxFiles?:number}} opts
 */
function walk(root, opts = {}) {
  const exts = opts.exts || null;
  const skip = opts.skipDirs || SKIP_DIRS;
  const out = [];
  const maxFiles = opts.maxFiles || 200000;
  function rec(dir) {
    if (out.length >= maxFiles) return;
    let ents;
    try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { return; }
    ents.sort((a, b) => (a.name < b.name ? -1 : 1));
    for (const ent of ents) {
      if (out.length >= maxFiles) return;
      const abs = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        if (skip.has(ent.name)) continue;
        rec(abs);
        continue;
      }
      if (!ent.isFile()) continue;
      const ext = path.extname(ent.name).toLowerCase();
      if (exts && !exts.has(ext)) continue;
      let size = 0;
      try { size = fs.statSync(abs).size; } catch (_) { continue; }
      out.push({ abs, rel: path.relative(root, abs).split(path.sep).join('/'), size });
    }
  }
  rec(root);
  return out;
}

function git(repoRel, args, opts = {}) {
  const repoAbs = path.join(SOURCE_ROOT, repoRel);
  try {
    return cp.execFileSync('git', ['-C', repoAbs, ...args], {
      encoding: 'utf8',
      maxBuffer: opts.maxBuffer || 64 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe']
    });
  } catch (e) {
    return null;
  }
}

function sha256(s) {
  return crypto.createHash('sha256').update(String(s), 'utf8').digest('hex');
}

function lineOf(text, index) {
  let n = 1;
  for (let i = 0; i < index && i < text.length; i += 1) if (text[i] === '\n') n += 1;
  return n;
}

function posix(p) {
  return String(p).split(path.sep).join('/');
}

module.exports = {
  WORKSPACE, SOURCE_ROOT, TOOL_ROOT, OUT_ROOT,
  C_EXTS, H_EXTS, CPP_EXTS, SKIP_DIRS,
  ensureDir, writeJson, writeJsonl, readJsonl, readText, walk, git, sha256, lineOf, posix
};
