'use strict';
/* 探针：在 Windows 原生 clang 上重跑 30 样本 -fsyntax-only 门，
 * 与之前 WSL 基线（tools/ag0-preflight/batch3-result.json）逐条对比。 */
const fs = require('fs');
const path = require('path');
const cp = require('child_process');

const WORKSPACE = path.resolve(__dirname, '..', '..', '..');
const SRC = path.join(WORKSPACE, 'OpenHarmony');
const CWD = path.join(SRC, 'out', 'rk3568');
const BIN = path.join(SRC, 'prebuilts', 'clang', 'ohos', 'windows-x86_64', 'llvm', 'bin');
const { buildArgs } = require('../../lib/facts/cmdline');

const ROOTS = ['base/account/os_account', 'foundation/communication/dsoftbus', 'foundation/communication/ipc',
  'base/notification/eventhandler', 'base/accesscontrol/sandbox_manager'];
const PARTS = ['account', 'communication', 'notification', 'accesscontrol'];
const TMP = path.join(__dirname, 'winargs');

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

const toWin = (p) => p.replace(/^\/mnt\/([a-z])\//, (_, d) => `${d.toUpperCase()}:/`);
const rewrite = (args) => args.map((a) => (a.startsWith('-I/mnt/') ? `-I${toWin(a.slice(2))}` : (a.startsWith('/mnt/') ? toWin(a) : a)));

function classify(log) {
  if (/file not found/.test(log)) return 'missing-generated-header';
  if (/macro name must be an identifier|macro names must be identifiers/.test(log)) return 'broken-macro';
  if (/unknown type name|undeclared identifier/.test(log)) return 'unknown-identifier';
  if (/error:/.test(log)) return 'compile-error';
  return 'other';
}

function runOne(item) {
  return new Promise((resolve) => {
    const { compiler, args } = buildArgs(item.command);
    const exe = path.posix.basename(compiler) === 'clang' ? path.join(BIN, 'clang.exe') : path.join(BIN, 'clang++.exe');
    const full = [...rewrite(args), '-fsyntax-only', '-ferror-limit=3'];
    const len = full.reduce((a, b) => a + b.length + 3, 0);
    const useRsp = len > 30000;
    let cmdArgs = full;
    if (useRsp) {
      const rsp = path.join(TMP, `a${item.id}.rsp`);
      fs.writeFileSync(rsp, full.map((a) => `"${a.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`).join('\n') + '\n', 'utf8');
      cmdArgs = [`@${rsp}`];
    }
    const t0 = Date.now();
    const child = cp.spawn(exe, cmdArgs, { cwd: CWD });
    let err = '';
    child.stderr.on('data', (d) => { err += d.toString(); });
    child.on('error', (e) => resolve({ id: item.id, exit: -1, ms: Date.now() - t0, category: 'spawn-error', log: String(e.message), useRsp, len }));
    child.on('close', (code) => {
      const log = err.replace(/\u001b\[[0-9;]*m/g, '');
      resolve({ id: item.id, exit: code, ms: Date.now() - t0, category: code === 0 ? 'ok' : classify(log), log, useRsp, len });
    });
  });
}

async function main() {
  const entries = [];
  const seen = new Set();
  for (const part of PARTS) {
    scanCompdb(path.join(SRC, 'out', 'rk3568', 'compdb_parts', part, 'compile_commands.json'), (e) => {
      const f = String(e.file || '');
      const root = ROOTS.find((r) => f.includes(`/OpenHarmony/${r}/`));
      if (!root || !/\.(cpp|cc|c)$/.test(f) || seen.has(f)) return;
      seen.add(f);
      entries.push({ root, file: f, command: e.command });
    });
  }
  const byRoot = new Map(ROOTS.map((r) => [r, []]));
  for (const e of entries) byRoot.get(e.root).push(e);
  const sample = [];
  for (const r of ROOTS) {
    const list = byRoot.get(r).sort((a, b) => (a.file < b.file ? -1 : 1));
    const step = Math.max(1, Math.floor(list.length / 6));
    for (let i = 0; i < list.length && sample.filter((s) => s.root === r).length < 6; i += step) sample.push(list[i]);
  }
  sample.forEach((s, i) => { s.id = i; });

  fs.rmSync(TMP, { recursive: true, force: true });
  fs.mkdirSync(TMP, { recursive: true });
  const t0 = Date.now();
  const results = [];
  const queue = [...sample];
  await Promise.all(Array.from({ length: 8 }, async () => {
    for (;;) {
      const item = queue.shift();
      if (!item) return;
      results.push(await runOne(item));
    }
  }));
  const wall = Date.now() - t0;

  const prev = fs.existsSync(path.join(__dirname, 'batch3-result.json'))
    ? JSON.parse(fs.readFileSync(path.join(__dirname, 'batch3-result.json'), 'utf8')) : [];
  const rows = sample.map((s) => {
    const r = results.find((x) => x.id === s.id);
    const old = prev.find((p) => p.file === s.file.replace(/^.*\/OpenHarmony\//, ''));
    return {
      id: s.id, root: s.root, file: s.file.replace(/^.*\/OpenHarmony\//, ''),
      win: { exit: r.exit, ms: r.ms, category: r.category, viaRsp: r.useRsp, chars: r.len },
      wsl: old ? { exit: old.code, ms: old.ms, category: old.category } : null,
      firstError: (/error: ([^\n]*)/.exec(r.log) || [])[1] || ''
    };
  });
  fs.writeFileSync(path.join(__dirname, 'batch-win.json'), JSON.stringify(rows, null, 2), 'utf8');
  const ok = rows.filter((r) => r.win.exit === 0).length;
  const cats = {};
  for (const r of rows) cats[r.win.category] = (cats[r.win.category] || 0) + 1;
  const sameVerdict = rows.filter((r) => r.wsl && (r.wsl.exit === 0) === (r.win.exit === 0)).length;
  console.log(JSON.stringify({
    samples: rows.length, wallMs: wall,
    winOk: ok, winOkRatio: Number((ok / rows.length).toFixed(4)),
    winAvgMs: Math.round(rows.reduce((a, b) => a + b.win.ms, 0) / rows.length),
    winMaxMs: Math.max(...rows.map((x) => x.win.ms)),
    wslAvgMs: Math.round(rows.reduce((a, b) => a + (b.wsl ? b.wsl.ms : 0), 0) / rows.length),
    viaRsp: rows.filter((r) => r.win.viaRsp).length,
    categories: cats,
    sameVerdictAsWsl: `${sameVerdict}/${rows.filter((r) => r.wsl).length}`,
    disagreements: rows.filter((r) => r.wsl && (r.wsl.exit === 0) !== (r.win.exit === 0))
      .map((r) => ({ file: r.file, wsl: r.wsl.category, win: r.win.category, err: r.firstError.slice(0, 100) }))
  }, null, 2));
  fs.rmSync(TMP, { recursive: true, force: true });
}

main();
