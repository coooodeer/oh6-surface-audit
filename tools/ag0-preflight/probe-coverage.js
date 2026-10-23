'use strict';
/* 临时探针：汇总 compdb 覆盖与生成头可见性；并统计 tree-sitter 错误节点分布。用完删除。 */
const fs = require('fs');
const path = require('path');

const WORKSPACE = path.resolve(__dirname, '..', '..', '..');
const SRC = path.join(WORKSPACE, 'OpenHarmony');
const PARTS = ['account', 'communication', 'notification', 'accesscontrol'];
const ROOTS = ['base/account/os_account', 'foundation/communication/dsoftbus', 'foundation/communication/ipc',
  'base/notification/eventhandler', 'base/accesscontrol/sandbox_manager'];

function scanCompdb(file, onEntry) {
  const CHUNK = 1 << 20;
  const fd = fs.openSync(file, 'r');
  const buf = Buffer.alloc(CHUNK);
  let carry = '';
  try {
    for (;;) {
      const n = fs.readSync(fd, buf, 0, CHUNK, null);
      if (n <= 0) break;
      const text = carry + buf.toString('utf8', 0, n);
      let inStr = false; let esc = false; let depth = 0; let start = -1;
      for (let i = 0; i < text.length; i += 1) {
        const ch = text[i];
        if (inStr) { if (esc) { esc = false; continue; } if (ch === '\\') { esc = true; continue; } if (ch === '"') inStr = false; continue; }
        if (ch === '"') { inStr = true; continue; }
        if (ch === '{') { if (depth === 0) start = i; depth += 1; continue; }
        if (ch === '}') { depth -= 1; if (depth === 0 && start >= 0) { onEntry(JSON.parse(text.slice(start, i + 1))); start = -1; } continue; }
      }
      carry = start >= 0 ? text.slice(start) : '';
    }
  } finally { fs.closeSync(fd); }
}

function winPath(p) {
  const m = /^\/mnt\/([a-z])\/(.*)$/.exec(p || '');
  return m ? `${m[1].toUpperCase()}:\\${m[2].replace(/\//g, '\\')}` : p;
}

const useByRoot = new Map(ROOTS.map((r) => [r, new Set()]));
const genDirs = new Map(); // 相对 out/rk3568 的 gen 目录 -> 是否被引用
let totalEntries = 0;
for (const part of PARTS) {
  const file = path.join(SRC, 'out', 'rk3568', 'compdb_parts', part, 'compile_commands.json');
  scanCompdb(file, (e) => {
    totalEntries += 1;
    const f = String(e.file || '');
    const root = ROOTS.find((r) => f.includes(`/OpenHarmony/${r}/`));
    if (root) useByRoot.get(root).add(f);
    const cmd = String(e.command || '');
    const re = /-I(\/mnt\/[^ ]+|\S+)/g;
    let m;
    while ((m = re.exec(cmd)) !== null) {
      const dir = m[1];
      if (dir.includes('/out/rk3568/gen')) genDirs.set(dir, (genDirs.get(dir) || 0) + 1);
    }
  });
}

let genTotal = 0; let genMissing = 0; const missingSample = [];
for (const [dir, count] of genDirs) {
  genTotal += 1;
  const win = winPath(dir);
  if (!fs.existsSync(win)) { genMissing += 1; if (missingSample.length < 5) missingSample.push({ dir: dir.replace(/^.*OpenHarmony\//, ''), refs: count }); }
}

const perRoot = ROOTS.map((root) => ({
  root,
  compdbUniqueFiles: useByRoot.get(root).size
}));

console.log(JSON.stringify({ totalEntries, perRoot, genDirs: genTotal, genDirsMissing: genMissing, missingSample }, null, 2));
