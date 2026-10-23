'use strict';

/**
 * lib/l5/classify.js —— 把 build/run 结果映射为 L5 四态。
 *
 * confirmed 必须看到 sanitizer/UB/SEGV 证据；status=0 只能叫 no-signal。
 * no-signal 不是 safe，不能用于 T4/refuted。
 */

function sanitizerHit(text) {
  const s = String(text || '');
  return /AddressSanitizer|LeakSanitizer|UndefinedBehaviorSanitizer|runtime error:|heap-use-after-free|heap-buffer-overflow|stack-buffer-overflow|global-buffer-overflow|SEGV|SIGSEGV|SIGABRT/i.test(s);
}

function classify(input = {}) {
  const buildOk = input.buildOk !== false;
  const status = typeof input.status === 'number' ? input.status : null;
  const signal = input.signal || null;
  const stdout = input.stdout || '';
  const stderr = input.stderr || '';
  const text = `${stdout}\n${stderr}`;
  if (!buildOk) {
    return { result: 'blocked', reason: 'compile-failed', signal, status };
  }
  if (sanitizerHit(text) || signal === 'SIGSEGV' || signal === 'SIGABRT') {
    return { result: 'confirmed', reason: 'sanitizer-signal', signal, status };
  }
  if (status === 124) {
    return { result: 'blocked', reason: 'timeout', signal, status };
  }
  if (status === 0) {
    return { result: 'no-signal', reason: 'clean-exit', signal, status };
  }
  return { result: 'blocked', reason: `run-failed:status-${status == null ? 'null' : status}`, signal, status };
}

module.exports = { sanitizerHit, classify };
