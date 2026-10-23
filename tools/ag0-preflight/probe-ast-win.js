'use strict';
/* 探针：Windows 原生 clang 的 -ast-dump=json 体积与耗时（stdout 直接落文件，避免内存爆）。 */
const fs = require('fs');
const path = require('path');
const cp = require('child_process');
const { buildArgs } = require('../../lib/facts/cmdline');

const WORKSPACE = path.resolve(__dirname, '..', '..', '..');
const SRC = path.join(WORKSPACE, 'OpenHarmony');
const CWD = path.join(SRC, 'out', 'rk3568');
const BIN = path.join(SRC, 'prebuilts', 'clang', 'ohos', 'windows-x86_64', 'llvm', 'bin');

const CASES = [
  'base/notification/eventhandler/frameworks/eventhandler/src/event_handler.cpp',
  'foundation/communication/ipc/test/fuzztest/ipc/native/src/core/ipcthreadpool_fuzzer/ipcthreadpool_fuzzer.cpp'
];

function findCommand(absWsl) {
  for (const part of ['account', 'communication', 'notification', 'accesscontrol']) {
    const file = path.join(SRC, 'out', 'rk3568', 'compdb_parts', part, 'compile_commands.json');
    const text = fs.readFileSync(file, 'utf8');
    const at = text.indexOf(`"file": "${absWsl}"`);
    if (at < 0) continue;
    const s = text.lastIndexOf('{"directory"', at);
    const e = text.indexOf('"}', text.indexOf('"_strategy"', at));
    return JSON.parse(text.slice(s, e + 2)).command;
  }
  return null;
}
const toWin = (p) => p.replace(/^\/mnt\/([a-z])\//, (_, d) => `${d.toUpperCase()}:/`);
const rewrite = (args) => args.map((a) => (a.startsWith('-I/mnt/') ? `-I${toWin(a.slice(2))}` : (a.startsWith('/mnt/') ? toWin(a) : a)));

const outFile = path.join(__dirname, 'ast-dump.tmp.json');
const rows = [];
for (const rel of CASES) {
  const command = findCommand(`/mnt/d/oh6.0/OpenHarmony-v6.0-Release/OpenHarmony/${rel}`);
  if (!command) { rows.push({ file: rel, error: 'no-compdb-entry' }); continue; }
  const { compiler, args } = buildArgs(command);
  const exe = path.posix.basename(compiler) === 'clang' ? path.join(BIN, 'clang.exe') : path.join(BIN, 'clang++.exe');
  const full = [...rewrite(args), '-fsyntax-only', '-Xclang', '-ast-dump=json'];
  const rsp = path.join(__dirname, 'ast.rsp');
  const needRsp = full.reduce((a, b) => a + b.length + 3, 0) > 30000;
  if (needRsp) {
    fs.writeFileSync(rsp, full.map((a) => `"${a.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`).join('\n') + '\n', 'utf8');
  }
  const fd = fs.openSync(outFile, 'w');
  const t0 = Date.now();
  const r = cp.spawnSync(exe, needRsp ? [`@${rsp}`] : full, { cwd: CWD, stdio: ['ignore', fd, 'pipe'], encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  const ms = Date.now() - t0;
  fs.closeSync(fd);
  const size = fs.existsSync(outFile) ? fs.statSync(outFile).size : 0;
  const err = (r.stderr || '').replace(/\u001b\[[0-9;]*m/g, '');
  rows.push({ file: rel.split('/').pop(), ms, bytes: size, mb: Math.round(size / 1048576), exit: r.status, viaRsp: needRsp, errors: (err.match(/error:/g) || []).length, errHead: err.split(/\r?\n/).filter((l) => /error:/.test(l)).slice(0, 2) });
  if (fs.existsSync(outFile)) fs.unlinkSync(outFile);
  if (fs.existsSync(rsp)) fs.unlinkSync(rsp);
}
console.log(JSON.stringify(rows, null, 2));
