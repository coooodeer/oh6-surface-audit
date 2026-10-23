'use strict';

/**
 * lib/prover.js —— 义务执行器（行级/块级）。
 * 与 bin/spec-prover.js 的试点逻辑同源；batch 与后续 claim 管线共用这里。
 * 义务字段使用 **正则字符串**（调用方负责把 literal 转 regex）。
 */

function lineOf(text, index) {
  let n = 1;
  for (let i = 0; i < index && i < text.length; i += 1) if (text[i] === '\n') n += 1;
  return n;
}

function matchBrace(text, openIdx) {
  let depth = 0;
  for (let i = openIdx; i < text.length; i += 1) {
    const c = text[i];
    if (c === '"' || c === "'") {
      const q = c; i += 1;
      while (i < text.length) {
        if (text[i] === '\\') { i += 2; continue; }
        if (text[i] === q) break;
        i += 1;
      }
      continue;
    }
    if (c === '/' && text[i + 1] === '/') { while (i < text.length && text[i] !== '\n') i += 1; continue; }
    if (c === '/' && text[i + 1] === '*') { i += 2; while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) i += 1; i += 1; continue; }
    if (c === '{') depth += 1;
    else if (c === '}') { depth -= 1; if (depth === 0) return i; }
  }
  return -1;
}

function findFunction(text, name) {
  const esc = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`${esc}\\s*\\(`, 'g');
  let m;
  while ((m = re.exec(text)) !== null) {
    let i = text.indexOf('(', m.index);
    let depth = 0;
    for (; i < text.length; i += 1) {
      if (text[i] === '(') depth += 1;
      else if (text[i] === ')') { depth -= 1; if (depth === 0) { i += 1; break; } }
    }
    let k = i;
    while (k < text.length && /\s/.test(text[k])) k += 1;
    while (k < text.length && text[k] !== ';' && text[k] !== '{') k += 1;
    if (text[k] !== '{') continue;
    const close = matchBrace(text, k);
    if (close < 0) continue;
    return { name, startLine: lineOf(text, m.index), openLine: lineOf(text, k), endLine: lineOf(text, close), body: text.slice(k, close + 1), openIdx: k, closeIdx: close };
  }
  return null;
}

function findLine(lines, regex, from = 0) {
  for (let i = from; i < lines.length; i += 1) if (regex.test(lines[i])) return i;
  return -1;
}
function findMatchOnLine(line, regex) {
  const m = new RegExp(regex.source, regex.flags.replace('g', '')).exec(line);
  return m ? m.index : -1;
}
function blockAfter(lines, guardIdx) {
  let open = -1;
  for (let i = guardIdx; i < Math.min(lines.length, guardIdx + 4); i += 1) {
    const p = lines[i].indexOf('{');
    if (p >= 0) { open = { line: i, col: p }; break; }
  }
  if (!open) return null;
  const text = lines.slice(open.line).join('\n');
  const close = matchBrace(text, open.col);
  if (close < 0) return null;
  const block = text.slice(0, close + 1);
  const endLine = open.line + block.split('\n').length - 1;
  return { start: open.line, end: endLine, text: block };
}

function evalObligation(o, ctx) {
  const { lines, fn } = ctx;
  const base = fn.openLine - 1;
  const ev = {};
  const guardIdx = o.guard ? findLine(lines, new RegExp(o.guard)) : -1;
  const sinkRegex = o.sink || o.mutation;
  const sinkIdx = sinkRegex ? findLine(lines, new RegExp(sinkRegex)) : -1;

  if (o.kind === 'guard-before-sink') {
    if (guardIdx < 0) return { id: o.id, kind: o.kind, text: o.text, status: 'disproven', reason: 'guard-missing', evidence: {} };
    if (sinkIdx < 0) return { id: o.id, kind: o.kind, text: o.text, status: 'unproven', reason: 'sink-not-found', evidence: { guardLine: base + guardIdx + 1 } };
    const sameLine = guardIdx === sinkIdx;
    const guardPos = sameLine ? findMatchOnLine(lines[guardIdx], new RegExp(o.guard)) : 0;
    const sinkPos = sameLine ? findMatchOnLine(lines[sinkIdx], new RegExp(o.sink)) : 0;
    ev.guardLine = base + guardIdx + 1;
    ev.sinkLine = base + sinkIdx + 1;
    if (guardIdx > sinkIdx || (sameLine && guardPos >= sinkPos)) return { id: o.id, kind: o.kind, text: o.text, status: 'disproven', reason: 'guard-after-sink', evidence: ev };
    if (o.requireExit) {
      const block = blockAfter(lines, guardIdx);
      if (!block || !/(return|throw|continue|break|goto)\b/.test(block.text)) return { id: o.id, kind: o.kind, text: o.text, status: 'disproven', reason: 'guard-without-exit', evidence: ev };
      ev.exitLine = base + block.start + 1;
    }
    return { id: o.id, kind: o.kind, text: o.text, status: 'proven', reason: 'guard-before-sink', evidence: ev };
  }

  if (o.kind === 'guard-branch-exits') {
    if (guardIdx < 0) return { id: o.id, kind: o.kind, text: o.text, status: 'disproven', reason: 'guard-missing', evidence: {} };
    const block = blockAfter(lines, guardIdx);
    ev.guardLine = base + guardIdx + 1;
    if (!block) return { id: o.id, kind: o.kind, text: o.text, status: 'disproven', reason: 'no-guard-block', evidence: ev };
    ev.blockStart = base + block.start + 1;
    ev.blockEnd = base + block.end + 1;
    if (!new RegExp(o.exit).test(block.text)) return { id: o.id, kind: o.kind, text: o.text, status: 'disproven', reason: 'exit-missing', evidence: ev };
    return { id: o.id, kind: o.kind, text: o.text, status: 'proven', reason: 'guard-exits', evidence: ev };
  }

  if (o.kind === 'lock-acquire-before-sink') {
    const acqIdx = findLine(lines, new RegExp(o.acquire));
    if (acqIdx < 0) return { id: o.id, kind: o.kind, text: o.text, status: 'disproven', reason: 'acquire-missing', evidence: {} };
    if (sinkIdx < 0) return { id: o.id, kind: o.kind, text: o.text, status: 'unproven', reason: 'sink-not-found', evidence: { acquireLine: base + acqIdx + 1 } };
    ev.acquireLine = base + acqIdx + 1;
    ev.sinkLine = base + sinkIdx + 1;
    if (acqIdx > sinkIdx) return { id: o.id, kind: o.kind, text: o.text, status: 'disproven', reason: 'acquire-after-sink', evidence: ev };
    return { id: o.id, kind: o.kind, text: o.text, status: 'proven', reason: 'acquire-before-sink', evidence: ev };
  }

  if (o.kind === 'lock-release-on-return') {
    const acqIdx = findLine(lines, new RegExp(o.acquire));
    if (acqIdx < 0) return { id: o.id, kind: o.kind, text: o.text, status: 'disproven', reason: 'acquire-missing', evidence: {} };
    let failBlock = null;
    for (let i = Math.max(0, acqIdx - 3); i <= acqIdx; i += 1) {
      if (/\bif\s*\(/.test(lines[i]) && /Require|lock|Lock/.test(lines[i])) { failBlock = blockAfter(lines, i); break; }
    }
    const failRange = failBlock ? [failBlock.start, failBlock.end] : null;
    const releases = [];
    for (let i = acqIdx + 1; i < lines.length; i += 1) if (new RegExp(o.release).test(lines[i])) releases.push(i);
    const missing = [];
    for (let i = acqIdx + 1; i < lines.length; i += 1) {
      if (!/\breturn\b/.test(lines[i])) continue;
      if (failRange && i >= failRange[0] && i <= failRange[1]) continue;
      if (!releases.some((r) => r < i)) missing.push(base + i + 1);
    }
    ev.acquireLine = base + acqIdx + 1;
    ev.releaseLines = releases.map((i) => base + i + 1);
    if (missing.length) return { id: o.id, kind: o.kind, text: o.text, status: 'disproven', reason: 'return-without-release', evidence: { ...ev, missing } };
    return { id: o.id, kind: o.kind, text: o.text, status: 'proven', reason: 'release-before-each-return', evidence: ev };
  }

  if (o.kind === 'existence-check-before-mutation') {
    const exIdx = findLine(lines, new RegExp(o.existence));
    const mutIdx = findLine(lines, new RegExp(o.mutation));
    if (exIdx < 0) return { id: o.id, kind: o.kind, text: o.text, status: 'disproven', reason: 'existence-check-missing', evidence: {} };
    if (mutIdx < 0) return { id: o.id, kind: o.kind, text: o.text, status: 'unproven', reason: 'mutation-not-found', evidence: { existenceLine: base + exIdx + 1 } };
    const notFoundIdx = o.notFound ? findLine(lines, new RegExp(o.notFound), exIdx) : -1;
    ev.existenceLine = base + exIdx + 1;
    ev.mutationLine = base + mutIdx + 1;
    if (exIdx > mutIdx) return { id: o.id, kind: o.kind, text: o.text, status: 'disproven', reason: 'existence-check-after-mutation', evidence: ev };
    if (notFoundIdx < 0) return { id: o.id, kind: o.kind, text: o.text, status: 'disproven', reason: 'not-found-return-missing', evidence: ev };
    ev.notFoundLine = base + notFoundIdx + 1;
    return { id: o.id, kind: o.kind, text: o.text, status: 'proven', reason: 'existence-then-mutate', evidence: ev };
  }

  return { id: o.id, kind: o.kind, text: o.text, status: 'unproven', reason: 'unsupported-obligation-kind', evidence: {} };
}

function proveSpec(entry, text) {
  const fn = findFunction(text, entry.functionName);
  if (!fn) return { specId: entry.specId, ok: false, error: 'function-not-found', verdict: 'UNPROVEN', obligations: [] };
  const ctx = { lines: fn.body.split(/\r?\n/), fn };
  const obs = entry.obligations.map((o) => evalObligation(o, ctx));
  const disproven = obs.filter((o) => o.status === 'disproven');
  const unproven = obs.filter((o) => o.status === 'unproven');
  const verdict = disproven.length ? 'VIOLATION' : (unproven.length ? 'UNPROVEN' : 'SATISFIED');
  return {
    specId: entry.specId,
    seedId: entry.seedId,
    title: entry.title,
    repo: entry.repo,
    file: entry.file,
    function: entry.functionName,
    functionRange: { start: fn.startLine, end: fn.endLine },
    verdict,
    disproven: disproven.map((o) => ({ id: o.id, reason: o.reason, evidence: o.evidence })),
    unproven: unproven.map((o) => ({ id: o.id, reason: o.reason, evidence: o.evidence })),
    obligations: obs
  };
}

module.exports = { findFunction, evalObligation, proveSpec, blockAfter, matchBrace, lineOf };
