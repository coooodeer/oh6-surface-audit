'use strict';
/* 临时探针：用 NUL 分隔参数文件（避免 rsp 引号语义）批量跑 clang；可选 -ast-dump=json 统计。用完删除。 */
const fs = require('fs');
const path = require('path');
const cp = require('child_process');
const { buildArgs } = require('../../lib/facts/cmdline');

const WORKSPACE = path.resolve(__dirname, '..', '..', '..');
const SRC = path.join(WORKSPACE, 'OpenHarmony');
const TMP = path.join(__dirname, 'args');
const toWsl = (p) => {
  const abs = path.resolve(p);
  const m = /^([A-Za-z]):\\(.*)$/.exec(abs);
  return m ? `/mnt/${m[1].toLowerCase()}/${m[2].replace(/\\/g, '/')}` : abs.replace(/\\/g, '/');
};
const TMP_WSL = toWsl(TMP);
const SRC_WSL = toWsl(SRC);
const WSL_CWD = `${SRC_WSL}/out/rk3568`;
const CLANG = `${SRC_WSL}/prebuilts/clang/ohos/linux-x86_64/llvm/bin/clang++`;
const ROOTS = ['base/account/os_account', 'foundation/communication/dsoftbus', 'foundation/communication/ipc',
  'base/notification/eventhandler', 'base/accesscontrol/sandbox_manager'];
const PARTS = ['account', 'communication', 'notification', 'accesscontrol'];

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

function classify(log) {
  if (/file not found/.test(log)) return 'missing-generated-header';
  if (/macro name must be an identifier|macro names must be identifiers/.test(log)) return 'broken-macro';
  if (/unknown type name|undeclared identifier/.test(log)) return 'unknown-identifier';
  if (/error:/.test(log)) return 'compile-error';
  return 'other';
}

function main() {
  const perRoot = Number(process.argv[2] || 6);
  const par = Number(process.argv[3] || 12);
  const astMode = process.argv.includes('--ast');
  const OUT_WSL = astMode ? '/tmp/ag0ast' : TMP_WSL;
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
    const step = Math.max(1, Math.floor(list.length / perRoot));
    for (let i = 0; i < list.length && sample.filter((s) => s.root === r).length < perRoot; i += step) sample.push(list[i]);
  }
  fs.rmSync(TMP, { recursive: true, force: true });
  fs.mkdirSync(TMP, { recursive: true });
  const runner = ['#!/bin/bash', `cd ${WSL_CWD}`, 'mkdir -p /tmp/ag0ast', `echo -n > ${TMP_WSL}/status.txt`];
  sample.forEach((s, idx) => {
    const { compiler, args } = buildArgs(s.command);
    s.id = idx; s.compiler = compiler; s.kept = args.length;
    fs.writeFileSync(path.join(TMP, `a${idx}.bin`), Buffer.from([...args, '-fsyntax-only', '-ferror-limit=3'].join('\0') + '\0', 'utf8'));
    const extra = astMode ? ' -Xclang -ast-dump=json' : '';
    const exe = compiler.startsWith('/') ? compiler : path.posix.resolve(WSL_CWD, compiler);
    runner.push(`( s=$(date +%s%N); mapfile -d '' -t A < ${TMP_WSL}/a${idx}.bin; ${exe} "\${A[@]}"${extra} >${OUT_WSL}/o${idx}.json 2>${TMP_WSL}/e${idx}.log; c=$?; e=$(date +%s%N); echo "${idx} $c $(( (e-s)/1000000 ))" >> ${TMP_WSL}/status.txt ) &`);
    if ((idx + 1) % par === 0) runner.push('wait');
  });
  runner.push('wait');
  fs.writeFileSync(path.join(TMP, 'run.sh'), runner.join('\n') + '\n', 'utf8');
  const t0 = Date.now();
  const r = cp.spawnSync('wsl.exe', ['-d', 'Ubuntu-22.04', '--', 'bash', `${TMP_WSL}/run.sh`], { encoding: 'utf8', timeout: 3600000 });
  const wall = Date.now() - t0;
  const st = fs.readFileSync(path.join(TMP, 'status.txt'), 'utf8').trim().split(/\r?\n/).map((l) => l.split(' ').map(Number));
  const rows = sample.map((s) => {
    const rec = st.find((x) => x[0] === s.id) || [s.id, -1, 0];
    const log = fs.readFileSync(path.join(TMP, `e${s.id}.log`), 'utf8').replace(/\u001b\[[0-9;]*m/g, '');
    const firstError = (/error: ([^\n]*)/.exec(log) || [])[1] || '';
    const osize = Number((cp.spawnSync('wsl.exe', ['-d', 'Ubuntu-22.04', '--', 'stat', '-c', '%s', `/tmp/ag0ast/o${s.id}.json`], { encoding: 'utf8' }).stdout || '0').trim()) || 0;
    return {
      id: s.id, root: s.root, file: s.file.replace(/^.*\/OpenHarmony\//, ''), code: rec[1], ms: rec[2],
      category: rec[1] === 0 ? 'ok' : classify(log), firstError: firstError.slice(0, 130), astBytes: osize
    };
  });
  fs.writeFileSync(path.join(__dirname, astMode ? 'batch3-ast.json' : 'batch3-result.json'), JSON.stringify(rows, null, 2), 'utf8');
  const cats = {};
  for (const x of rows) cats[x.category] = (cats[x.category] || 0) + 1;
  const ok = rows.filter((x) => x.code === 0);
  console.log(JSON.stringify({
    wallMs: wall, samples: rows.length, ok: ok.length, okRatio: Number((ok.length / rows.length).toFixed(4)),
    avgMs: Math.round(rows.reduce((a, b) => a + b.ms, 0) / rows.length), maxMs: Math.max(...rows.map((x) => x.ms)),
    sumCpuMs: rows.reduce((a, b) => a + b.ms, 0),
    categories: cats,
    astBytesAvg: astMode ? Math.round(ok.reduce((a, b) => a + b.astBytes, 0) / Math.max(1, ok.length)) : null,
    astBytesMax: astMode ? Math.max(0, ...ok.map((x) => x.astBytes)) : null,
    perRoot: ROOTS.map((root) => ({ root, ok: rows.filter((x) => x.root === root && x.code === 0).length, n: rows.filter((x) => x.root === root).length })),
    failures: rows.filter((x) => x.code !== 0).map((x) => ({ file: x.file, category: x.category, firstError: x.firstError }))
  }, null, 2));
}

main();
