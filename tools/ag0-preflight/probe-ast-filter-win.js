'use strict';
/* 探针：Windows 原生 clang 的「定向 AST」——-ast-dump-filter 单函数/单类，
 * 用于评估 getType 能否在按需查询里拿到精确类型。 */
const fs = require('fs');
const path = require('path');
const cp = require('child_process');
const { buildArgs } = require('../../lib/facts/cmdline');

const SRC = path.resolve(__dirname, '..', '..', '..', 'OpenHarmony');
const CWD = path.join(SRC, 'out', 'rk3568');
const BIN = path.join(SRC, 'prebuilts', 'clang', 'ohos', 'windows-x86_64', 'llvm', 'bin');

const CASES = [
  { rel: 'base/notification/eventhandler/frameworks/eventhandler/src/event_handler.cpp', filter: 'EventHandler' },
  { rel: 'base/account/os_account/frameworks/osaccount/core/src/os_account.cpp', filter: 'OsAccount' }
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

const outFile = path.join(__dirname, 'ast-filtered.tmp.json');
const rows = [];
for (const { rel, filter } of CASES) {
  const command = findCommand(`/mnt/d/oh6.0/OpenHarmony-v6.0-Release/OpenHarmony/${rel}`);
  if (!command) { rows.push({ file: rel, error: 'no-compdb-entry' }); continue; }
  const { compiler, args } = buildArgs(command);
  const exe = path.posix.basename(compiler) === 'clang' ? path.join(BIN, 'clang.exe') : path.join(BIN, 'clang++.exe');
  const full = [...rewrite(args), '-fsyntax-only', '-Xclang', '-ast-dump=json', '-Xclang', `-ast-dump-filter=${filter}`];
  const fd = fs.openSync(outFile, 'w');
  const t0 = Date.now();
  const r = cp.spawnSync(exe, full, { cwd: CWD, stdio: ['ignore', fd, 'pipe'], encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  const ms = Date.now() - t0;
  fs.closeSync(fd);
  const size = fs.existsSync(outFile) ? fs.statSync(outFile).size : 0;
  const err = (r.stderr || '').replace(/\u001b\[[0-9;]*m/g, '');
  // 检查能否被 JSON.parse 消费（filter 模式是拼接的多个 JSON 对象，不是数组）
  let parseOk = null;
  try { JSON.parse(fs.readFileSync(outFile, 'utf8')); parseOk = 'single-json'; } catch (_) {
    parseOk = 'not-single-json (concatenated objects)';
  }
  rows.push({ file: rel.split('/').pop(), filter, ms, bytes: size, mb: +(size / 1048576).toFixed(1), exit: r.status, parseOk, errors: (err.match(/error:/g) || []).length });
  if (fs.existsSync(outFile)) fs.unlinkSync(outFile);
}
console.log(JSON.stringify(rows, null, 2));
