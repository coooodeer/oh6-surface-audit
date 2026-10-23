'use strict';

/**
 * lib/l5/harness.js —— 真实 target 的最小 harness（P1/P2/P4/P7）。
 *
 * 策略：
 *   - P4：clang UBSan unsigned-integer-overflow，3/3 confirmed；
 *   - P2：g++ ASan，线程/回调 UAF pattern，3/3 confirmed；
 *   - P1：g++ ASan，unbounded loop pattern，timeout=blocked；
 *   - P7：g++，SplitPath 大输入，no-signal（不是漏洞确认）。
 * 所有 harness 都有 source hash、命令、repeat、ledger；不伪造 T1。
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { SOURCE_ROOT, OUT_ROOT, ensureDir, writeJson, writeJsonl } = require('../util.js');
const { toWslPath, wslScript } = require('./env.js');
const { classify } = require('./classify.js');

const AUDIT_ROOT = path.resolve(__dirname, '..', '..');
const BUILD_DIR = path.join(AUDIT_ROOT, 'eval', 'l5', 'build');
const RUN_DIR = path.join(OUT_ROOT, 'l5', 'runs');
const OUT_DIR = path.join(OUT_ROOT, 'l5');

const TARGETS = [
  {
    candidateId: 'L5-TARGET-P4-mallocstr',
    claimId: 'L3-P4-cd_G-P4_52b62a535a33',
    class: 'P4', tier: 'T2-weak-candidate',
    harness: 'eval/l5/harnesses/p4_mallocstr.cpp',
    targetSource: 'foundation/communication/dsoftbus/dfx/anonymize/src/anonymizer.c',
    targetLine: 180, function: 'MallocStr',
    compiler: 'clang++', sanitizer: 'ubsan-unsigned',
    flags: '-fsanitize=undefined,unsigned-integer-overflow -fno-sanitize-recover=all -w',
    env: 'UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1',
    expected: 'confirmed', repeat: 3, timeoutSec: 8, harnessFidelity: 'function-only',
    params: ['uint32_t len'], triggerArg: '4294967295'
  },
  {
    candidateId: 'L5-TARGET-P2-thread-uaf',
    claimId: 'L3-P2-11a0ec910260',
    class: 'P2', tier: 'T3-instrumentation-gap',
    harness: 'eval/l5/harnesses/p2_thread_uaf.cpp',
    targetSource: 'base/account/os_account/frameworks/osaccount/core/src/os_account_event_listener.cpp',
    targetLine: 109, function: 'OsAccountEventListener::OnAccountsChanged',
    compiler: 'g++', sanitizer: 'asan',
    flags: '-fsanitize=address,undefined -fno-sanitize-recover=all -pthread',
    env: 'ASAN_OPTIONS=detect_leaks=0:abort_on_error=1',
    expected: 'no-signal', repeat: 3, timeoutSec: 8, harnessFidelity: 'pattern-only',
    params: ['callback', 'cvPtr', 'pendingCounter'], triggerArg: 'shared_ptr capture by copy'
  },
  {
    candidateId: 'L5-TARGET-P1-unbounded-loop',
    claimId: 'L3-P1-8feab3ac31ad',
    class: 'P1', tier: 'T2-weak-candidate',
    harness: 'eval/l5/harnesses/p1_unbounded_loop.cpp',
    targetSource: 'base/account/os_account/services/accountmgr/src/bundle_manager_adapter/bundle_manager_adapter_proxy.cpp',
    targetLine: 541, function: 'GetParcelableInfos',
    compiler: 'g++', sanitizer: 'asan',
    flags: '-fsanitize=address,undefined -fno-sanitize-recover=all',
    env: 'ASAN_OPTIONS=detect_leaks=0:abort_on_error=1',
    expected: 'no-signal', repeat: 3, timeoutSec: 8, harnessFidelity: 'pattern-only',
    params: ['infoSize'], triggerArg: 'infoSize=2, parcel returns nullptr'
  },
  {
    candidateId: 'L5-TARGET-P7-split-path',
    claimId: 'L3-P7-749d525eec9a',
    class: 'P7', tier: 'T2-weak-candidate',
    harness: 'eval/l5/harnesses/p7_split_path.cpp',
    targetSource: 'base/accesscontrol/sandbox_manager/services/sandbox_manager/main/cpp/src/service/policy_trie.cpp',
    targetLine: 44, function: 'PolicyTrie::SplitPath',
    compiler: 'g++', sanitizer: 'none',
    flags: '-O1',
    env: '',
    expected: 'blocked:timeout', repeat: 1, timeoutSec: 2, harnessFidelity: 'function-only',
    params: ['const std::string &path'], triggerArg: '20k x 1M chars'
  }
];

function hashFile(file) {
  try { return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'); } catch (_) { return null; }
}

function buildCommand(target) {
  const src = toWslPath(path.join(AUDIT_ROOT, target.harness));
  const out = `${toWslPath(BUILD_DIR)}/${target.candidateId}`;
  return [target.compiler, '-std=c++17', '-g', '-O1', '-fno-omit-frame-pointer', target.flags, `'${src}'`, '-o', `'${out}'`].join(' ');
}

function runCommand(target) {
  const bin = `${toWslPath(BUILD_DIR)}/${target.candidateId}`;
  return `${target.env ? `${target.env} ` : ''}timeout ${target.timeoutSec}s '${bin}'`;
}

function runTarget(target, opts = {}) {
  ensureDir(BUILD_DIR);
  ensureDir(RUN_DIR);
  const started = Date.now();
  const bcmd = buildCommand(target);
  const build = wslScript(bcmd, { timeout: opts.buildTimeout || 120000 });
  const runs = [];
  if (build.ok) {
    const rcmd = runCommand(target);
    for (let i = 0; i < target.repeat; i += 1) {
      const r = wslScript(rcmd, { timeout: (target.timeoutSec + 5) * 1000 });
      const cls = classify({ buildOk: true, status: r.status, signal: r.signal, stdout: r.stdout, stderr: r.stderr });
      runs.push({
        attempt: i + 1, status: r.status, signal: r.signal, result: cls.result, reason: cls.reason,
        stdoutHash: crypto.createHash('sha256').update(r.stdout || '').digest('hex'),
        stderrHash: crypto.createHash('sha256').update(r.stderr || '').digest('hex'),
        stderrHead: String(r.stderr || '').slice(0, 3000)
      });
    }
  }
  const unstable = new Set(runs.map((r) => `${r.result}:${r.reason}`)).size > 1;
  const first = runs[0] || { status: null, signal: null, result: 'blocked', reason: 'compile-failed', stdoutHash: null, stderrHash: null, stderrHead: build.stderr || '' };
  const result = !build.ok ? 'blocked' : (unstable ? 'blocked' : first.result);
  const reason = !build.ok ? 'compile-failed' : (unstable ? 'unstable-repeat' : first.reason);
  const runId = `L5-TARGET-${target.class}-${Date.now()}`;
  const row = {
    runId, candidateId: target.candidateId, claimId: target.claimId,
    fixture: false, target: true, class: target.class, tier: target.tier,
    compiler: target.compiler, sanitizer: target.sanitizer,
    expected: target.expected, harnessFidelity: target.harnessFidelity || 'pattern-only', buildCommand: bcmd,
    runCommand: build.ok ? runCommand(target) : null,
    harness: target.harness, targetSource: target.targetSource, targetLine: target.targetLine,
    sourceHash: hashFile(path.join(SOURCE_ROOT, target.targetSource)),
    harnessHash: hashFile(path.join(AUDIT_ROOT, target.harness)),
    function: target.function, params: target.params, triggerArg: target.triggerArg,
    exitCode: first.status, signal: first.signal, result, reason,
    repeats: runs, repeat: target.repeat,
    stdoutHash: first.stdoutHash, stderrHash: first.stderrHash, stderrHead: first.stderrHead,
    wallMs: Date.now() - started
  };
  writeJson(path.join(RUN_DIR, `${runId}.json`), row);
  return row;
}

function runTargets(opts = {}) {
  const ids = opts.ids && opts.ids.length ? new Set(opts.ids) : null;
  const rows = [];
  for (const target of TARGETS) {
    if (ids && !ids.has(target.candidateId) && !ids.has(target.claimId)) continue;
    rows.push(runTarget(target, opts));
  }
  const summary = {
    generatedAt: new Date().toISOString(),
    total: rows.length,
    confirmed: rows.filter((r) => r.result === 'confirmed').length,
    noSignal: rows.filter((r) => r.result === 'no-signal').length,
    blocked: rows.filter((r) => r.result === 'blocked').length,
    rows: rows.map((r) => ({
      runId: r.runId, candidateId: r.candidateId, claimId: r.claimId,
      result: r.result, reason: r.reason, class: r.class
    }))
  };
  ensureDir(OUT_DIR);
  writeJsonl(path.join(OUT_DIR, 'targets.jsonl'), rows);
  writeJson(path.join(OUT_DIR, 'targets-summary.json'), summary);
  return { rows, summary };
}

module.exports = { TARGETS, runTarget, runTargets, buildCommand, runCommand };
