'use strict';
/* 探针：Windows 原生 clang 的可用性边界——
 * 1) 命令行长度（CreateProcess 上限 32767）与响应文件绕过
 * 2) --target=arm-linux-ohos 下预定义宏是否与 WSL/Linux clang 一致 */
const fs = require('fs');
const path = require('path');
const cp = require('child_process');
const { buildArgs } = require('../../lib/facts/cmdline');

const WORKSPACE = path.resolve(__dirname, '..', '..', '..');
const SRC = path.join(WORKSPACE, 'OpenHarmony');
const CWD = path.join(SRC, 'out', 'rk3568');
const WIN_CLANG = path.join(SRC, 'prebuilts', 'clang', 'ohos', 'windows-x86_64', 'llvm', 'bin', 'clang++.exe');
const WSL_PRE = '/mnt/d/oh6.0/OpenHarmony-v6.0-Release/oh6-surface-audit/tools/ag0-preflight';
const LINUX_CWD = '/mnt/d/oh6.0/OpenHarmony-v6.0-Release/OpenHarmony/out/rk3568';

const CASES = [
  'base/notification/eventhandler/frameworks/eventhandler/src/event_handler.cpp',
  'foundation/communication/dsoftbus/core/bus_center/lnn/lane_hub/lane_manager/src/lnn_lane_link_p2p.c'
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

function writeRsp(file, argv) {
  fs.writeFileSync(file, argv.map((a) => `"${a.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`).join('\n') + '\n', 'utf8');
}

function runWin(argv, { useRsp = false, exe = WIN_CLANG } = {}) {
  const rsp = path.join(__dirname, 'win.rsp');
  const args = useRsp ? [`@${rsp}`] : argv.slice(1);
  if (useRsp) writeRsp(rsp, argv.slice(1));
  const t0 = Date.now();
  const r = cp.spawnSync(exe, args, { cwd: CWD, encoding: 'utf8', maxBuffer: 512 * 1024 * 1024 });
  const err = (r.stderr || '').replace(/\u001b\[[0-9;]*m/g, '');
  return { ms: Date.now() - t0, exit: r.status, spawnError: r.error ? String(r.error.code || r.error.message) : null, stdout: r.stdout || '', errors: (err.match(/error:/g) || []).length, stderrHead: err.split(/\r?\n/).filter(Boolean).slice(0, 3) };
}

function runLinuxMacros(compiler, args) {
  const bin = path.join(__dirname, 'win2.bin');
  fs.writeFileSync(bin, Buffer.from([...args, '-dM', '-E'].join('\0') + '\0', 'utf8'));
  const sh = path.join(__dirname, 'win2.sh');
  const compilerAbs = path.posix.resolve(LINUX_CWD, compiler);
  fs.writeFileSync(sh, ['#!/bin/bash', `cd ${LINUX_CWD}`,
    `mapfile -d '' -t A < ${WSL_PRE}/win2.bin`,
    `${compilerAbs} "\${A[@]}" > ${WSL_PRE}/linux-macros.txt 2>/dev/null; echo exit=$?`].join('\n') + '\n');
  const r = cp.spawnSync('wsl.exe', ['-d', 'Ubuntu-22.04', '--', 'bash', `${WSL_PRE}/win2.sh`], { encoding: 'utf8' });
  const out = fs.existsSync(path.join(__dirname, 'linux-macros.txt')) ? fs.readFileSync(path.join(__dirname, 'linux-macros.txt'), 'utf8') : '';
  return { status: String(r.stdout || '').trim(), macros: out.split('\n').filter((l) => l.startsWith('#define')) };
}

const IGNORE = /^#define (__DATE__|__TIME__|__TIMESTAMP__|__FILE__|__BASE_FILE__|__FILE_NAME__)\b/;
const normalize = (line) => line.replace(/\s+/g, ' ').trim();
const out = [];
for (const rel of CASES) {
  const absWsl = `/mnt/d/oh6.0/OpenHarmony-v6.0-Release/OpenHarmony/${rel}`;
  const command = findCommand(absWsl);
  if (!command) { out.push({ file: rel, error: 'no-compdb-entry' }); continue; }
  const { compiler, args } = buildArgs(command);
  // 与 compdb 一致：C 用 clang.exe，C++ 用 clang++.exe
  const exe = path.posix.basename(compiler) === 'clang'
    ? path.join(SRC, 'prebuilts', 'clang', 'ohos', 'windows-x86_64', 'llvm', 'bin', 'clang.exe')
    : WIN_CLANG;
  // compdb 自带 --target/--sysroot/-march，这里不再追加 target 覆盖
  const winBase = [exe, ...rewrite([...args])];
  const winArgv = [...winBase, '-fsyntax-only'];
  const cmdlineChars = winArgv.slice(1).reduce((a, b) => a + b.length + 3, 0);

  const direct = runWin([...winBase, '-dM', '-E'], { exe });
  const viaRsp = runWin([...winBase, '-dM', '-E'], { useRsp: true, exe });
  const winMacros = (viaRsp.stdout || '').split('\n').filter((l) => l.startsWith('#define'));
  const linux = runLinuxMacros(compiler, args);

  const winSet = new Set(winMacros.map(normalize).filter((l) => !IGNORE.test(l)));
  const linuxSet = new Set(linux.macros.map(normalize).filter((l) => !IGNORE.test(l)));
  const onlyWin = [...winSet].filter((l) => !linuxSet.has(l));
  const onlyLinux = [...linuxSet].filter((l) => !winSet.has(l));

  out.push({
    file: rel.split('/').pop(),
    cmdlineChars,
    direct: { exit: direct.exit, spawnError: direct.spawnError, ms: direct.ms },
    viaRsp: { exit: viaRsp.exit, spawnError: viaRsp.spawnError, ms: viaRsp.ms },
    macrosWin: winSet.size,
    macrosLinux: linuxSet.size,
    same: onlyWin.length === 0 && onlyLinux.length === 0,
    onlyWin: onlyWin.length, onlyLinux: onlyLinux.length,
    onlyWinSample: onlyWin.slice(0, 5),
    onlyLinuxSample: onlyLinux.slice(0, 5)
  });
  fs.writeFileSync(path.join(__dirname, 'win-macros.txt'), viaRsp.stdout || '', 'utf8');
}
for (const f of ['win.rsp', 'win2.bin', 'win2.sh', 'linux-macros.txt', 'win-macros.txt']) {
  const p = path.join(__dirname, f);
  if (fs.existsSync(p)) fs.unlinkSync(p);
}
console.log(JSON.stringify(out, null, 2));
