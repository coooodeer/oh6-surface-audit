'use strict';

/**
 * lib/facts/clang.js —— AG0.3/P7 的 clang 有界校核。
 *
 * 两种模式：
 *   native（默认）：Windows 预编译 clang，路径 /mnt/d → D:/ 投影，cwd=out/rk3568。
 *                  便宜（实测 ~0.5 s/文件），但属"语法/宏指纹"：宿主二进制 + 路径改写，
 *                  不能当作目标构建等价证明。
 *   wsl：          Debian(WSL2) 里的 OHOS Linux clang，路径保持 /mnt/d，无改写。
 *                  是目标语义（同一二进制、同一 sysroot），但经 9p 读头文件极慢：
 *                  实测同一 TU 16.2 s vs 0.48 s（约 33×）。因此只用于「有争议的少数文件」，
 *                  绝不做批量默认。
 *
 * 纪律（AGENT-ARCHITECTURE-GUIDE §4.3）：
 *   - 不做过度参数清理：只删 -c / -o / -MF 等产物参数，保留 target/sysroot/宏/ABI/异常模式；
 *   - 命令行超 32k 仍走 @rsp（wsl 模式下 rsp 路径要转成 /mnt/d/... 给 Linux clang）。
 */

const fs = require('fs');
const path = require('path');
const cp = require('child_process');
const crypto = require('crypto');

const scope = require('./scope');
const compdb = require('./compdb');
const { buildArgs } = require('./cmdline');

const RSP_DIR = path.join(scope.TOOL_DIR, 'runtime', 'clang-rsp');
const CWD = path.join(scope.SRC_ROOT, 'out', 'rk3568');
const BIN = path.join(scope.SRC_ROOT, 'prebuilts', 'clang', 'ohos', 'windows-x86_64', 'llvm', 'bin');
const LINUX_BIN = path.join(scope.SRC_ROOT, 'prebuilts', 'clang', 'ohos', 'linux-x86_64', 'llvm', 'bin');
const WSL_DISTRO = process.env.OH6_WSL_DISTRO || 'debian';

/** Windows 绝对路径 → WSL 路径（D:\x → /mnt/d/x） */
function toWslPath(p) {
  const abs = path.resolve(p).replace(/\\/g, '/');
  const m = /^([A-Za-z]):\/(.*)$/.exec(abs);
  return m ? `/mnt/${m[1].toLowerCase()}/${m[2]}` : abs;
}

/** rsp 文件名：按完整 rel 做 sha256，避免同前缀文件互相覆盖 */
function rspName(rel) {
  return `${crypto.createHash('sha256').update(rel).digest('hex').slice(0, 24)}.rsp`;
}

function exeFor(compiler) {
  return path.posix.basename(compiler) === 'clang' ? path.join(BIN, 'clang.exe') : path.join(BIN, 'clang++.exe');
}

/** WSL 里的 clang 可执行路径（Linux 形式） */
function linuxExeFor(compiler) {
  const name = path.posix.basename(compiler) === 'clang' ? 'clang' : 'clang++';
  return `${toWslPath(LINUX_BIN)}/${name}`;
}

function rewritePaths(args) {
  return args.map((a) => (a.startsWith('-I/mnt/') ? `-I${compdb.wslToWin(a.slice(2))}`
    : (a.startsWith('/mnt/') ? compdb.wslToWin(a) : a)));
}

/**
 * compdb command → clang 调用。
 * @param {object} entry compdb 条目（需含 command）
 * @param {{mode?:'native'|'wsl', distro?:string}} [opts]
 */
function buildInvocation(entry, opts = {}) {
  const mode = opts.mode === 'wsl' ? 'wsl' : 'native';
  const distro = opts.distro || WSL_DISTRO;
  // faithful：保留 --target/--sysroot/-D/-I/-std/-fno-exceptions 等全部语义开关
  const { compiler, args } = buildArgs(String(entry.command || ''), { faithful: true });
  const name = path.posix.basename(compiler);
  if (mode === 'wsl') {
    const full = [...args, '-fsyntax-only', '-ferror-limit=5'];
    const chars = full.reduce((a, b) => a + b.length + 3, 0);
    return { mode, exe: linuxExeFor(compiler), compiler: name, args: full, chars, useRsp: chars > 30000, distro };
  }
  const full = [...rewritePaths(args), '-fsyntax-only', '-ferror-limit=5'];
  const chars = full.reduce((a, b) => a + b.length + 3, 0);
  return { mode, exe: exeFor(compiler), compiler: name, args: full, chars, useRsp: chars > 30000, distro };
}

function writeRsp(file, args) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, args.map((a) => `"${a.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`).join('\n') + '\n', 'utf8');
}

/** stderr + exit code → 状态分类 */
function classify(status, stderr) {
  const log = String(stderr || '');
  if (status === 0) return 'ok';
  if (/no such file or directory|file not found/i.test(log)) return 'missing-header';
  if (/error:/i.test(log)) return 'compile-error';
  return 'compile-error';
}

function firstErrors(stderr, limit = 3) {
  return String(stderr || '')
    .split(/\r?\n/)
    .filter((l) => /error:/i.test(l))
    .slice(0, limit)
    .map((l) => l.replace(/\u001b\[[0-9;]*m/g, '').trim().slice(0, 220));
}

/** 组装实际 spawn 的 (cmd, argv)；rsp 路径在 wsl 模式下转成 Linux 路径 */
function spawnSpec(inv, rspFile) {
  let args = inv.args;
  let rspPath = null;
  if (inv.useRsp && rspFile) {
    rspPath = rspFile;
    writeRsp(rspPath, inv.args);
    args = [`@${inv.mode === 'wsl' ? toWslPath(rspPath) : rspPath}`];
  }
  if (inv.mode === 'wsl') {
    return { cmd: 'wsl.exe', argv: ['-d', inv.distro, '--exec', inv.exe, ...args], rspPath };
  }
  return { cmd: inv.exe, argv: args, rspPath };
}

/**
 * 同步跑一个文件。
 * @param {{file:string, rel:string}} target
 * @param {object} entry compdb 条目
 * @param {{mode?:'native'|'wsl', timeoutMs?:number, run?:Function, rspFile?:string}} opts
 *        run(cmd, argv, cwd) 可注入（测试用）
 */
function checkOne(target, entry, opts = {}) {
  const inv = buildInvocation(entry, opts);
  const timeoutMs = opts.timeoutMs || 120000;
  const run = opts.run || ((cmd, argv, cwd) => cp.spawnSync(cmd, argv, { cwd, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, timeout: timeoutMs, windowsHide: true }));
  const spec = spawnSpec(inv, opts.rspFile || (inv.useRsp ? path.join(RSP_DIR, rspName(target.rel)) : null));
  try {
    const t0 = Date.now();
    const r = run(spec.cmd, spec.argv, CWD);
    const ms = Date.now() - t0;
    if (r.error) {
      const code = r.error.code || 'error';
      return { file: target.rel, status: code === 'ETIMEDOUT' ? 'timeout' : 'skipped', exitCode: null, ms, mode: inv.mode, viaRsp: inv.useRsp, chars: inv.chars, compiler: inv.compiler, errors: [String(code)] };
    }
    const status = classify(r.status, r.stderr);
    return { file: target.rel, status, exitCode: r.status, ms, mode: inv.mode, viaRsp: inv.useRsp, chars: inv.chars, compiler: inv.compiler, errors: firstErrors(r.stderr) };
  } finally {
    if (spec.rspPath) { try { fs.unlinkSync(spec.rspPath); } catch (_) { /* ignore */ } }
    try { fs.rmdirSync(RSP_DIR); } catch (_) { /* 非空或不存在都无妨 */ }
    try { fs.rmdirSync(path.dirname(RSP_DIR)); } catch (_) { /* 同上 */ }
  }
}

/** 异步跑一个文件（并发池用） */
function checkOneAsync(target, entry, opts = {}) {
  const inv = buildInvocation(entry, opts);
  const timeoutMs = opts.timeoutMs || 120000;
  const spec = spawnSpec(inv, inv.useRsp ? path.join(RSP_DIR, rspName(target.rel)) : null);
  return new Promise((resolve) => {
    const cleanup = () => {
      if (spec.rspPath) { try { fs.unlinkSync(spec.rspPath); } catch (_) { /* ignore */ } }
      try { fs.rmdirSync(RSP_DIR); } catch (_) { /* ignore */ }
      try { fs.rmdirSync(path.dirname(RSP_DIR)); } catch (_) { /* ignore */ }
    };
    const t0 = Date.now();
    let killed = false;
    const child = cp.spawn(spec.cmd, spec.argv, { cwd: CWD, windowsHide: true });
    let stderr = '';
    const timer = setTimeout(() => { killed = true; try { child.kill(); } catch (_) { /* ignore */ } }, timeoutMs);
    child.stderr.on('data', (d) => {
      stderr += d.toString();
      if (stderr.length > (1 << 20)) stderr = stderr.slice(-(1 << 20));
    });
    child.on('error', (e) => {
      clearTimeout(timer);
      cleanup();
      resolve({ file: target.rel, status: 'skipped', exitCode: null, ms: Date.now() - t0, mode: inv.mode, viaRsp: inv.useRsp, chars: inv.chars, compiler: inv.compiler, errors: [String(e.code || e.message)] });
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      cleanup();
      const status = killed ? 'timeout' : classify(code, stderr);
      resolve({
        file: target.rel,
        status,
        exitCode: code,
        ms: Date.now() - t0,
        mode: inv.mode,
        viaRsp: inv.useRsp,
        chars: inv.chars,
        compiler: inv.compiler,
        errors: status === 'ok' ? [] : firstErrors(stderr)
      });
    });
  });
}

/** 从 compdb 取 root 内条目（保留 command，供 clang 用） */
function loadEntries(policy) {
  const map = new Map();
  for (const part of policy.compdbParts) {
    const file = path.join(scope.SRC_ROOT, 'out', 'rk3568', 'compdb_parts', part, 'compile_commands.json');
    if (!fs.existsSync(file)) continue;
    const prefixes = policy.roots.map((r) => `/OpenHarmony/${r.root}/`);
    const res = compdb.scanPart(file, { rootPrefixes: prefixes, keepCommand: true });
    for (const [k, v] of res.rootEntries) if (!map.has(k)) map.set(k, v);
  }
  return map;
}

/** 确定性抽样：按路径排序后等步长取 n 个 */
function sampleTargets(relsIn, n) {
  const rels = [...relsIn].sort();
  if (!n || n >= rels.length) return rels;
  const step = Math.max(1, Math.floor(rels.length / n));
  const out = [];
  for (let i = 0; i < rels.length && out.length < n; i += step) out.push(rels[i]);
  return out;
}

module.exports = {
  classify, buildInvocation, checkOne, checkOneAsync, loadEntries, sampleTargets,
  rewritePaths, writeRsp, exeFor, linuxExeFor, rspName, toWslPath,
  CWD, RSP_DIR, BIN, LINUX_BIN, WSL_DISTRO
};
