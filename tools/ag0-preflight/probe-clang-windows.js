'use strict';
/* 探针：Windows 原生 clang 能否替代 WSL clang 做 -fsyntax-only 校核。
 * 对比三种 target 与 Linux clang 基线；同时测耗时。 */
const fs = require('fs');
const path = require('path');
const cp = require('child_process');
const { buildArgs } = require('../../lib/facts/cmdline');

const WORKSPACE = path.resolve(__dirname, '..', '..', '..');
const SRC = path.join(WORKSPACE, 'OpenHarmony');
const CWD = path.join(SRC, 'out', 'rk3568');
const WIN_CLANG = path.join(SRC, 'prebuilts', 'clang', 'ohos', 'windows-x86_64', 'llvm', 'bin', 'clang++.exe');
const LINUX_CLANG = '/mnt/d/oh6.0/OpenHarmony-v6.0-Release/OpenHarmony/prebuilts/clang/ohos/linux-x86_64/llvm/bin/clang++';

const TARGETS = [
  'base/notification/eventhandler/frameworks/eventhandler/src/event_handler.cpp',
  'base/accesscontrol/sandbox_manager/frameworks/inner_api/sandbox_manager/src/sandbox_manager_kit.cpp',
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

function runWin(args) {
  const t0 = Date.now();
  const r = cp.spawnSync(WIN_CLANG, args, { cwd: CWD, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024, timeout: 600000 });
  const err = (r.stderr || '').replace(/\u001b\[[0-9;]*m/g, '');
  return { ms: Date.now() - t0, exit: r.status, errors: (err.match(/error:/g) || []).length, head: err.split(/\r?\n/).filter((l) => /error:/.test(l)).slice(0, 2) };
}

function runLinux(relSrc) {
  const bin = path.join(__dirname, 'winprobe.bin');
  // 用 compdb 自身编译器（C 用 clang）
  const entry = findCommand(`/mnt/d/oh6.0/OpenHarmony-v6.0-Release/OpenHarmony/${relSrc}`);
  const { compiler, args } = buildArgs(entry);
  fs.writeFileSync(bin, Buffer.from([...args, '-fsyntax-only'].join('\0') + '\0', 'utf8'));
  const exe = path.posix.resolve('/mnt/d/oh6.0/OpenHarmony-v6.0-Release/OpenHarmony/out/rk3568', compiler);
  const sh = path.join(__dirname, 'winprobe.sh');
  fs.writeFileSync(sh, `#!/bin/bash\ncd /mnt/d/oh6.0/OpenHarmony-v6.0-Release/OpenHarmony/out/rk3568\n` +
    `s=$(date +%s%N); mapfile -d '' -t A < /mnt/d/oh6.0/OpenHarmony-v6.0-Release/oh6-surface-audit/tools/ag0-preflight/winprobe.bin; ` +
    `${exe} "\${A[@]}" >/dev/null 2>winprobe.err; c=$?; e=$(date +%s%N); echo "$c $(( (e-s)/1000000 ))"\n`);
  const t0 = Date.now();
  const r = cp.spawnSync('wsl.exe', ['-d', 'Ubuntu-22.04', '--', 'bash', '/mnt/d/oh6.0/OpenHarmony-v6.0-Release/oh6-surface-audit/tools/ag0-preflight/winprobe.sh'], { encoding: 'utf8', timeout: 600000 });
  const err = fs.existsSync(path.join(__dirname, 'winprobe.err')) ? fs.readFileSync(path.join(__dirname, 'winprobe.err'), 'utf8') : '';
  return { wallMs: Date.now() - t0, parsed: String(r.stdout || '').trim(), errors: (err.match(/error:/g) || []).length, head: err.split(/\r?\n/).filter((l) => /error:/.test(l)).slice(0, 2) };
}

const out = [];
for (const rel of TARGETS) {
  const absWsl = `/mnt/d/oh6.0/OpenHarmony-v6.0-Release/OpenHarmony/${rel}`;
  const command = findCommand(absWsl);
  if (!command) { out.push({ file: rel, error: 'no-compdb-entry' }); continue; }
  const { compiler, args } = buildArgs(command);
  const winArgs = rewrite([...args, '-fsyntax-only']);
  const isC = rel.endsWith('.c');
  const rec = { file: rel.split('/').pop(), compiler: path.posix.basename(compiler), winDefault: runWin(winArgs) };
  if (isC) rec.winDefault = runWin([...rewrite([...args]), '-fsyntax-only', '-x', 'c']);
  rec.winArm = runWin([...winArgs, '--target=arm-linux-ohos']);
  rec.winLinux = runWin([...winArgs, '--target=x86_64-unknown-linux-gnu']);
  rec.linux = runLinux(rel);
  out.push(rec);
}
console.log(JSON.stringify(out, null, 2));
