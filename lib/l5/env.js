'use strict';

/**
 * lib/l5/env.js —— L5 的 WSL / clang / sanitizer 环境探测。
 *
 * 只读源码；编译/运行都在 WSL 内，产物写 oh6-surface-audit/eval/l5/build。
 */

const fs = require('fs');
const path = require('path');
const cp = require('child_process');
const { OUT_ROOT, ensureDir, sha256, writeJson } = require('../util.js');

const WSL_DISTRO = process.env.OH6_WSL_DISTRO || 'Ubuntu-22.04';
const AUDIT_ROOT = path.resolve(__dirname, '..', '..');

function toWslPath(p) {
  const abs = path.resolve(p);
  const m = /^([A-Za-z]):[\\/](.*)$/.exec(abs);
  if (!m) return abs.split(path.sep).join('/');
  return `/mnt/${m[1].toLowerCase()}/${m[2].split(path.sep).join('/')}`;
}

function wslScript(script, opts = {}) {
  const timeout = opts.timeout || 120000;
  const r = cp.spawnSync('wsl', ['-d', WSL_DISTRO, '--', 'bash', '-lc', script], {
    cwd: opts.cwd || AUDIT_ROOT,
    encoding: 'utf8',
    timeout,
    maxBuffer: opts.maxBuffer || 16 * 1024 * 1024,
    env: { ...process.env, ...(opts.env || {}) }
  });
  return {
    ok: r.status === 0 && !r.error,
    status: typeof r.status === 'number' ? r.status : null,
    signal: r.signal || null,
    stdout: r.stdout || '',
    stderr: r.stderr || '',
    error: r.error ? String(r.error.message || r.error) : null
  };
}

function probe() {
  const clang = wslScript('clang++ --version; uname -a', { timeout: 30000 });
  const tmp = '/tmp/oh6-l5-probe';
  const build = wslScript([
    `rm -rf ${tmp}`,
    `mkdir -p ${tmp}`,
    `printf '%s\\n' 'int main(){return 0;}' > ${tmp}/probe.cpp`,
    `clang++ -std=c++17 -g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined ${tmp}/probe.cpp -o ${tmp}/probe`
  ].join(' && '), { timeout: 60000 });
  const run = build.ok
    ? wslScript(`ASAN_OPTIONS=detect_leaks=0 ${tmp}/probe`, { timeout: 30000 })
    : { ok: false, status: null, stdout: '', stderr: '', error: 'build-failed' };
  const out = {
    generatedAt: new Date().toISOString(),
    distro: WSL_DISTRO,
    clang: {
      ok: clang.ok,
      versionLine: (clang.stdout.split(/\r?\n/).find((l) => /clang version/i.test(l)) || '').trim(),
      uname: (clang.stdout.split(/\r?\n/).find((l) => /Linux/i.test(l)) || '').trim(),
      status: clang.status,
      error: clang.error
    },
    sanitizerProbe: {
      buildOk: build.ok,
      buildStatus: build.status,
      buildError: build.error,
      stderr: build.stderr.slice(0, 1000),
      runOk: run.ok,
      runStatus: run.status,
      runError: run.error
    },
    asan: build.ok && run.ok,
    ubsan: build.ok && run.ok,
    compiler: process.env.OH6_L5_CXX || 'g++',
    compilerReason: 'clang ASan observed intermittent SIGSEGV under WSL; g++ used as stable fallback',
    clangProbe: { buildOk: build.ok, runOk: run.ok },
    wslPath: toWslPath(AUDIT_ROOT)
  };
  ensureDir(path.join(OUT_ROOT, 'l5'));
  writeJson(path.join(OUT_ROOT, 'l5', 'environment.json'), out);
  return out;
}

function sourceHash(file) {
  try { return sha256(fs.readFileSync(file)); } catch (_) { return null; }
}

module.exports = {
  WSL_DISTRO,
  AUDIT_ROOT,
  toWslPath,
  wslScript,
  probe,
  sourceHash
};
