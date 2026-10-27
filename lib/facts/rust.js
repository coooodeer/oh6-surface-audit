'use strict';

/**
 * lib/facts/rust.js —— R3 非 C/C++ 有限形态：Rust 事实提取（基于 tools/rust-ast-probe 受限语法行）。
 *
 * 仅支持探针已判形的有限形态：function/method、execute!() 目标、`?` 调用、尾调用、
 * IpcCode enum/派发行（ipc-call 记为调用事实）；其余语法（execute-unresolved、
 * ipc-unresolved、unsupported-macro）逐条进 unsupported.jsonl，不生成调用/入口事实。
 * 探针行格式：file\tkind\tname\tline\tendLine\tctx\targc（TSV）。
 */

const path = require('path');
const crypto = require('crypto');
const cp = require('child_process');
const ids = require('./ids');

function probeBinary() {
  if (process.env.OH6_RUST_PROBE) return process.env.OH6_RUST_PROBE;
  return path.join(__dirname, '..', '..', 'out', 'autonomy', 'rust-ast-probe-target', 'debug',
    process.platform === 'win32' ? 'oh6-rust-ast-probe.exe' : 'oh6-rust-ast-probe');
}

const CALL_KINDS = new Set(['try-call', 'tail-call', 'execute-call', 'ipc-call']);

function signatureOf(srcLines, startLine, endLine) {
  const slice = srcLines.slice(startLine - 1, endLine).join(' ');
  const brace = slice.indexOf('{');
  return (brace >= 0 ? slice.slice(0, brace) : slice).replace(/\s+/g, ' ').trim().slice(0, 400);
}

function extract({ file, snapshotId, text, sha256, bytes, lines, buckets, unsupported }) {
  const base = { snapshotId, role: file.role, producer: 'AG0', schemaVersion: '1' };
  const qualityBase = { parse: 'full', resolution: 'syntax-only', errorNodes: 0 };
  const fileLocator = { repo: file.repo, file: file.rel };
  const pushFile = (quality) => buckets.files.push({ ...base, factId: ids.factIdOf(snapshotId, 'file', fileLocator),
    kind: 'file', locator: fileLocator, sourceRange: { file: file.rel, startLine: 1, endLine: lines || 1 },
    quality, path: file.rel, repo: file.repo, bytes, lines, sha256, language: 'rust' });

  const binary = probeBinary();
  if (!binary || !require('fs').existsSync(binary)) {
    pushFile({ parse: 'failed', resolution: 'unknown', errorNodes: 0 });
    unsupported.push({ id: `U:rust-probe-missing:${file.rel}`, kind: 'file', reason: 'probe-missing',
      file: file.rel, detail: { binary: binary || null } });
    buckets.quality.push({ id: `Q:${file.rel}`, file: file.rel, repo: file.repo, role: file.role,
      language: 'rust', parse: 'failed', errorNodes: 0, bytes, lines,
      counts: { functions: 0, calls: 0 }, macroFunctions: 0, cfgCoverageAvg: null, dfgCoverageAvg: null,
      cfgUnsupportedEdges: 0, astCallExpressions: null, astFunctionDefinitions: null });
    return;
  }

  const result = cp.spawnSync(binary, [file.abs], { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
  if (result.status !== 0) {
    pushFile({ parse: 'failed', resolution: 'unknown', errorNodes: 0 });
    unsupported.push({ id: `U:rust-parse:${file.rel}`, kind: 'file', reason: 'parse-failed',
      file: file.rel, detail: { error: (result.stderr || '').trim().slice(0, 500) || `exit-${result.status}` } });
    buckets.quality.push({ id: `Q:${file.rel}`, file: file.rel, repo: file.repo, role: file.role,
      language: 'rust', parse: 'failed', errorNodes: 0, bytes, lines,
      counts: { functions: 0, calls: 0 }, macroFunctions: 0, cfgCoverageAvg: null, dfgCoverageAvg: null,
      cfgUnsupportedEdges: 0, astCallExpressions: null, astFunctionDefinitions: null });
    return;
  }

  const rows = [];
  const srcRoot = path.join(__dirname, '..', '..', '..', 'OpenHarmony');
  for (const line of result.stdout.split('\n')) {
    if (!line.trim()) continue;
    const [absolute, kind, name, rowLine, endLine, ctx, argc] = line.trimEnd().split('\t');
    const rel = path.relative(srcRoot, absolute).split(path.sep).join('/');
    if (rel !== file.rel) throw new Error(`rust-probe-row-file-mismatch: ${line}`);
    rows.push({ kind, name, line: Number(rowLine), endLine: Number(endLine) || 0,
      ctx: ctx || '', argc: Number(argc) || 0 });
  }

  pushFile(qualityBase);
  const srcLines = text.split(/\r?\n/);
  const counts = { functions: 0, calls: 0 };
  const fnByQualified = new Map();
  const occurrence = new Map();

  for (const row of rows.filter((r) => r.kind === 'function' || r.kind === 'method')) {
    const qualified = row.ctx ? `${row.ctx}::${row.name}` : row.name;
    const startLine = row.line;
    const endLine = row.endLine >= startLine ? row.endLine : startLine;
    const locator = { repo: file.repo, file: file.rel, startLine, name: qualified };
    const factId = ids.factIdOf(snapshotId, 'function', locator);
    buckets.functions.push({ ...base, factId, kind: 'function', locator,
      sourceRange: { file: file.rel, startLine, endLine }, quality: qualityBase,
      name: row.name, owner: row.ctx, qualified,
      signature: signatureOf(srcLines, startLine, endLine),
      startLine, endLine,
      bodyHash: crypto.createHash('sha256').update(srcLines.slice(startLine - 1, endLine).join('\n')).digest('hex'),
      argc: row.argc, isTest: file.role === 'test', language: 'rust' });
    fnByQualified.set(qualified, factId);
    counts.functions += 1;
  }

  for (const row of rows.filter((r) => CALL_KINDS.has(r.kind))) {
    let callerQualified = row.ctx;
    let calleeText;
    const arrow = row.name.indexOf('->');
    if (row.kind === 'ipc-call') {
      if (arrow < 0) continue;
      calleeText = row.name.slice(arrow + 2);
    } else {
      if (arrow < 0) continue;
      callerQualified = row.name.slice(0, arrow);
      calleeText = row.name.slice(arrow + 2);
    }
    const caller = fnByQualified.get(callerQualified);
    if (!caller) {
      unsupported.push({ id: `U:rust-call-caller:${file.rel}:${row.line}`, kind: 'call',
        reason: 'caller-function-unresolved', file: file.rel, detail: { row } });
      continue;
    }
    const key = `${row.kind}|${callerQualified}|${calleeText}|${row.line}`;
    const seen = occurrence.get(key) || 0;
    occurrence.set(key, seen + 1);
    const locator = { repo: file.repo, file: file.rel, line: row.line, caller: callerQualified,
      callee: calleeText, kind: row.kind, occurrence: seen };
    const factId = ids.factIdOf(snapshotId, 'call', locator);
    buckets.calls.push({ ...base, factId, kind: 'call', locator,
      sourceRange: { file: file.rel, startLine: row.line, endLine: row.line },
      quality: qualityBase, caller, callerName: callerQualified,
      calleeName: calleeText.split('::').pop(), calleePath: calleeText, callee: null,
      line: row.line, column: 0, argc: row.argc, edgeKind: row.kind });
    counts.calls += 1;
  }

  buckets.quality.push({ id: `Q:${file.rel}`, file: file.rel, repo: file.repo, role: file.role,
    language: 'rust', parse: 'full', errorNodes: 0, bytes, lines,
    counts, macroFunctions: 0, cfgCoverageAvg: null, dfgCoverageAvg: null,
    cfgUnsupportedEdges: 0, astCallExpressions: null, astFunctionDefinitions: null });

  for (const row of rows.filter((r) => ['execute-unresolved', 'ipc-unresolved', 'unsupported-macro'].includes(r.kind))) {
    unsupported.push({ id: `U:rust-${row.kind}:${file.rel}:${row.line}`, kind: 'file',
      reason: row.kind, file: file.rel, detail: { row } });
  }
}

module.exports = { extract, probeBinary };
