'use strict';
/* 临时探针：AG0 前置工具可用性检查。用完删除。 */
const fs = require('fs');
const path = require('path');

const WORKSPACE = path.resolve(__dirname, '..', '..', '..');
const SRC = path.join(WORKSPACE, 'OpenHarmony');
const ROOTS = [
  'base/account/os_account',
  'foundation/communication/dsoftbus',
  'foundation/communication/ipc',
  'base/notification/eventhandler',
  'base/accesscontrol/sandbox_manager'
];

function log(...a) { console.log(...a); }

// ---------- A. tree-sitter ----------
function probeTreeSitter() {
  const base = path.join(WORKSPACE, 'oh6-framework-want-leak-miner', 'node_modules');
  const out = { module: null, error: null, node: process.version, abi: process.versions.modules };
  try {
    const Parser = require(path.join(base, 'tree-sitter'));
    const Cpp = require(path.join(base, 'tree-sitter-cpp'));
    const p = new Parser();
    p.setLanguage(Cpp);
    const t = p.parse('int f(int a){ return a+1; }');
    out.module = {
      hasError: t.rootNode.hasError,
      rootType: t.rootNode.type,
      childCount: t.rootNode.namedChildCount,
      firstChild: t.rootNode.namedChild(0) && t.rootNode.namedChild(0).type
    };
    out.version = require(path.join(base, 'tree-sitter', 'package.json')).version;
    out.cppVersion = require(path.join(base, 'tree-sitter-cpp', 'package.json')).version;
  } catch (e) {
    out.error = String(e && e.message || e);
  }
  return out;
}

// ---------- B. compdb ----------
// 单行 JSON 数组；用分块扫描提取每个对象的 directory/file/command。
function scanCompdb(file, onEntry) {
  const CHUNK = 1 << 20;
  const fd = fs.openSync(file, 'r');
  const buf = Buffer.alloc(CHUNK);
  let carry = '';
  let entries = 0;
  let bytes = 0;
  try {
    for (;;) {
      const n = fs.readSync(fd, buf, 0, CHUNK, null);
      if (n <= 0) break;
      bytes += n;
      let text = carry + buf.toString('utf8', 0, n);
      // 以对象边界切分：本文件对象内没有裸 '}' 的嵌套（command 内字符串可能含花括号，故用状态机）
      let i = 0;
      let inStr = false;
      let esc = false;
      let depth = 0;
      let start = -1;
      for (; i < text.length; i += 1) {
        const ch = text[i];
        if (inStr) {
          if (esc) { esc = false; continue; }
          if (ch === '\\') { esc = true; continue; }
          if (ch === '"') inStr = false;
          continue;
        }
        if (ch === '"') { inStr = true; continue; }
        if (ch === '{') { if (depth === 0) start = i; depth += 1; continue; }
        if (ch === '}') {
          depth -= 1;
          if (depth === 0 && start >= 0) {
            const objText = text.slice(start, i + 1);
            entries += 1;
            try { onEntry(JSON.parse(objText)); } catch (e) { return { bytes, entries, parseError: String(e.message), at: objText.slice(0, 120) }; }
            start = -1;
          }
          continue;
        }
      }
      carry = start >= 0 ? text.slice(start) : '';
      if (carry.length > 8 * CHUNK) return { bytes, entries, parseError: 'carry-too-large' };
    }
    return { bytes, entries, carryLeft: carry.length };
  } finally {
    fs.closeSync(fd);
  }
}

function probeCompdb() {
  const res = [];
  for (const part of ['account', 'communication', 'notification', 'accesscontrol']) {
    const file = path.join(SRC, 'out', 'rk3568', 'compdb_parts', part, 'compile_commands.json');
    if (!fs.existsSync(file)) { res.push({ part, present: false }); continue; }
    const st = fs.statSync(file);
    const perRoot = new Map(ROOTS.map((r) => [r, 0]));
    const genFiles = new Set();
    const dirs = new Set();
    let sample = null;
    const t0 = Date.now();
    const r = scanCompdb(file, (e) => {
      if (e.directory) dirs.add(e.directory);
      const f = String(e.file || '');
      if (!sample) sample = { directory: e.directory, file: f, cmdHead: String(e.command || '').slice(0, 200) };
      for (const root of ROOTS) {
        if (f.includes(`/OpenHarmony/${root}/`) || f.includes(`OpenHarmony/${root}/`)) perRoot.set(root, perRoot.get(root) + 1);
      }
      if (f.includes('/out/rk3568/gen/')) genFiles.add(f);
    });
    res.push({
      part,
      present: true,
      bytes: st.size,
      dirs: [...dirs],
      ...r,
      ms: Date.now() - t0,
      genFiles: genFiles.size,
      perRoot: Object.fromEntries([...perRoot].filter(([, v]) => v > 0)),
      sample
    });
  }
  return res;
}

// ---------- D/E. 目标树文件与元数据 ----------
const CPP_EXT = new Set(['.c', '.cc', '.cpp', '.cxx', '.h', '.hh', '.hpp', '.hxx']);
function walkStat(rootAbs) {
  const stat = {
    files: 0, bytes: 0, byExt: {}, generated: 0, metadata: { idl: 0, saProfile: 0, moduleJson5: 0, dts: 0, permission: 0, cesJson: 0 },
    skippedDirs: {}
  };
  const skip = new Set(['.git', 'node_modules', 'third_party', 'prebuilts', 'out', 'build']);
  const stack = [rootAbs];
  while (stack.length) {
    const dir = stack.pop();
    let ents;
    try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { continue; }
    for (const ent of ents) {
      const abs = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        if (skip.has(ent.name)) { stat.skippedDirs[ent.name] = (stat.skippedDirs[ent.name] || 0) + 1; continue; }
        stack.push(abs);
        continue;
      }
      if (!ent.isFile()) continue;
      const ext = path.extname(ent.name).toLowerCase();
      if (CPP_EXT.has(ext)) {
        stat.files += 1;
        try { stat.bytes += fs.statSync(abs).size; } catch (_) { /* ignore */ }
        stat.byExt[ext] = (stat.byExt[ext] || 0) + 1;
      } else if (ext === '.idl') stat.metadata.idl += 1;
      else if (ext === '.d.ts' || ext === '.d.ets') stat.metadata.dts += 1;
      else if (ext === '.json5' && ent.name === 'module.json5') stat.metadata.moduleJson5 += 1;
      else if (ext === '.json' && /(^|\/)sa_profile\//.test(abs.split(path.sep).join('/'))) stat.metadata.saProfile += 1;
      else if (ext === '.json' && /permission/i.test(ent.name)) stat.metadata.permission += 1;
    }
  }
  return stat;
}

function probeRoots() {
  const out = [];
  for (const root of ROOTS) {
    const abs = path.join(SRC, root.split('/').join(path.sep));
    const t0 = Date.now();
    const s = walkStat(abs);
    out.push({ root, ms: Date.now() - t0, ...s });
  }
  return out;
}

const mode = process.argv[2] || 'all';
if (mode === 'ts' || mode === 'all') log('A tree-sitter:', JSON.stringify(probeTreeSitter(), null, 2));
if (mode === 'roots' || mode === 'all') log('E roots:', JSON.stringify(probeRoots(), null, 2));
if (mode === 'compdb' || mode === 'all') log('B compdb:', JSON.stringify(probeCompdb(), null, 2));
