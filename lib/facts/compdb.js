'use strict';

/**
 * lib/facts/compdb.js —— compile_commands.json 的流式扫描（Windows 原生，不依赖 WSL）。
 *
 * 事实（预研实测）：
 *   - 单行 JSON 数组，最大 107 MB；必须分块扫描，不能 readFileSync + JSON.parse；
 *   - 每条含 directory/file/command；command 里有被 shell 转义破坏的 -D（见 P3/P7）；
 *   - 路径是 WSL 形式 /mnt/d/...，Windows 侧需要投影成 D:/...。
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { StringDecoder } = require('string_decoder');

const CHUNK = 1 << 20;

/** WSL 路径 → Windows 路径（/mnt/d/a/b → D:/a/b） */
function wslToWin(p) {
  return String(p || '').replace(/^\/mnt\/([a-z])\//, (_, d) => `${d.toUpperCase()}:/`);
}

function compilerOf(command) {
  const first = String(command || '').trim().split(/\s+/)[0] || '';
  return path.posix.basename(first);
}

/**
 * 扫描一个 part。
 * @param {string} fileAbs
 * @param {{rootPrefixes:string[]}} opts rootPrefixes 形如 ['/OpenHarmony/base/account/os_account/']
 */
function scanPart(fileAbs, opts = {}) {
  const stat = fs.statSync(fileAbs);
  const hash = crypto.createHash('sha256');
  const decoder = new StringDecoder('utf8');
  const fd = fs.openSync(fileAbs, 'r');
  const buf = Buffer.alloc(CHUNK);
  const roots = opts.rootPrefixes || [];
  const rootEntries = new Map();
  const genDirs = new Map();
  const keepCommand = opts.keepCommand === true;
  let entries = 0;
  let carry = '';

  const handleEntry = (e) => {
    entries += 1;
    const file = String(e.file || '');
    const command = String(e.command || '');
    // gen 目录引用（全量统计，不限 root）
    const re = /-I(\/mnt\/\S+)/g;
    let m;
    while ((m = re.exec(command)) !== null) {
      if (m[1].includes('/out/rk3568/gen')) genDirs.set(m[1], (genDirs.get(m[1]) || 0) + 1);
    }
    const hit = roots.find((r) => file.includes(r));
    if (!hit) return;
    if (!rootEntries.has(file)) {
      rootEntries.set(file, {
        file,
        directory: String(e.directory || ''),
        ...(keepCommand ? { command } : {}),
        compiler: compilerOf(command),
        commandChars: command.length,
        commandSha256: crypto.createHash('sha256').update(command, 'utf8').digest('hex'),
        variants: 1
      });
    } else {
      rootEntries.get(file).variants += 1;
    }
  };

  try {
    for (;;) {
      const n = fs.readSync(fd, buf, 0, CHUNK, null);
      if (n <= 0) break;
      hash.update(buf.subarray(0, n));
      const text = carry + decoder.write(buf.subarray(0, n));
      let inStr = false;
      let esc = false;
      let depth = 0;
      let start = -1;
      let i = 0;
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
            try { handleEntry(JSON.parse(objText)); } catch (_) { /* 坏对象计入 entries 缺失，由调用方对比 */ }
            start = -1;
          }
          continue;
        }
      }
      carry = start >= 0 ? text.slice(start) : '';
      if (carry.length > 8 * CHUNK) throw new Error(`compdb-carry-overflow: ${fileAbs}`);
    }
  } finally {
    fs.closeSync(fd);
  }

  return {
    file: fileAbs,
    bytes: stat.size,
    sha256: hash.digest('hex'),
    entries,
    rootEntries,
    genDirs,
    complete: carry.length === 0
  };
}

/** 汇总 4 个 part；返回 {parts, rootEntries, genDirs} */
function scanCompdb(policy, srcRoot) {
  const parts = [];
  const allRootEntries = new Map();
  const genDirs = new Map();
  for (const part of policy.compdbParts) {
    const fileAbs = path.join(srcRoot, 'out', 'rk3568', 'compdb_parts', part, 'compile_commands.json');
    if (!fs.existsSync(fileAbs)) {
      parts.push({ part, present: false, file: `out/rk3568/compdb_parts/${part}/compile_commands.json` });
      continue;
    }
    const prefixes = policy.roots.map((r) => `/OpenHarmony/${r.root}/`);
    const res = scanPart(fileAbs, { rootPrefixes: prefixes });
    for (const [k, v] of res.rootEntries) if (!allRootEntries.has(k)) allRootEntries.set(k, { ...v, part });
    for (const [k, v] of res.genDirs) genDirs.set(k, (genDirs.get(k) || 0) + v);
    parts.push({
      part,
      present: true,
      file: `out/rk3568/compdb_parts/${part}/compile_commands.json`,
      bytes: res.bytes,
      sha256: res.sha256,
      entries: res.entries,
      rootFiles: res.rootEntries.size,
      complete: res.complete
    });
  }
  return { parts, rootEntries: allRootEntries, genDirs };
}

/** 生成 compdb-win 投影行（只存元数据，完整 command 由 P7 按需重建） */
function projectionRows(rootEntries) {
  const rows = [];
  for (const [file, v] of rootEntries) {
    rows.push({
      id: file,
      file,
      fileWin: wslToWin(file),
      directory: v.directory,
      directoryWin: wslToWin(v.directory),
      part: v.part,
      compiler: v.compiler,
      commandChars: v.commandChars,
      commandSha256: v.commandSha256,
      variants: v.variants
    });
  }
  rows.sort((a, b) => (a.file < b.file ? -1 : 1));
  return rows;
}

module.exports = { CHUNK, wslToWin, scanPart, scanCompdb, projectionRows };
