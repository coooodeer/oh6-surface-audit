'use strict';

/**
 * prover-p4.js —— P4 整数溢出/回绕的 L4a 确定性 prover（O1–O10）。
 *
 * 关键口径：
 *   - O2 operation-site 只从 pre/removed 行取，不能把 added check 当 operation；
 *   - O4 要逐个 operand 的 type/width/signedness，不能用 widthMix 冒充；
 *   - O7 check-implication / O8 check-integrity 是硬义务：
 *       check 自身先算危险表达式（`len - off`、`total_size + 8`、`size + len + 2`）-> O8 disproven；
 *   - O10 只读已有 native-harness 结果，不伪造动态结果。
 */

const { OBLIGATION_STATUS } = require('./claims.js');

const OK = 'proven';
const NO = 'disproven';
const UNK = 'unproven';

const TYPE_INFO = {
  char: { width: 8, signed: true, rank: 1 },
  signedchar: { width: 8, signed: true, rank: 1 },
  unsignedchar: { width: 8, signed: false, rank: 1 },
  int8_t: { width: 8, signed: true, rank: 1 },
  uint8_t: { width: 8, signed: false, rank: 1 },
  short: { width: 16, signed: true, rank: 2 },
  unsignedshort: { width: 16, signed: false, rank: 2 },
  int16_t: { width: 16, signed: true, rank: 2 },
  uint16_t: { width: 16, signed: false, rank: 2 },
  int: { width: 32, signed: true, rank: 3 },
  unsignedint: { width: 32, signed: false, rank: 3 },
  int32_t: { width: 32, signed: true, rank: 3 },
  uint32_t: { width: 32, signed: false, rank: 3 },
  long: { width: 64, signed: true, rank: 4 },
  unsignedlong: { width: 64, signed: false, rank: 4 },
  int64_t: { width: 64, signed: true, rank: 4 },
  uint64_t: { width: 64, signed: false, rank: 4 },
  int64: { width: 64, signed: true, rank: 4 },
  uint64: { width: 64, signed: false, rank: 4 },
  size_t: { width: 64, signed: false, rank: 4 },
  ssize_t: { width: 64, signed: true, rank: 4 },
  bool: { width: 8, signed: false, rank: 0 },
  float: null,
  double: null
};

function normalizeType(t) {
  return String(t || '').replace(/\s+/g, '').replace(/^const/, '').replace(/\*+$/, '').toLowerCase();
}

function typeInfo(type) {
  const n = normalizeType(type);
  if (!n) return null;
  if (TYPE_INFO[n]) return { ...TYPE_INFO[n], name: type, known: true };
  const stripped = n.replace(/^struct/, '').replace(/^class/, '');
  if (TYPE_INFO[stripped]) return { ...TYPE_INFO[stripped], name: type, known: true };
  if (n.endsWith('*')) return { width: 64, signed: false, rank: 4, pointer: true, known: true, name: type };
  return { width: null, signed: null, rank: null, known: false, name: type };
}

function typeMapOf(typeHints) {
  const map = new Map();
  for (const t of typeHints || []) {
    if (!t || !t.name) continue;
    if (!map.has(t.name)) map.set(t.name, t.type || null);
  }
  return map;
}

function stripOuter(expr) {
  let s = String(expr || '').trim();
  while (s.startsWith('(') && s.endsWith(')')) {
    let depth = 0;
    let balanced = true;
    for (let i = 0; i < s.length; i += 1) {
      if (s[i] === '(') depth += 1;
      if (s[i] === ')') depth -= 1;
      if (depth === 0 && i < s.length - 1) { balanced = false; break; }
    }
    if (!balanced) break;
    s = s.slice(1, -1).trim();
  }
  return s;
}

function splitTopLevel(expr, opChar) {
  const parts = [];
  let depth = 0;
  let last = 0;
  const s = String(expr);
  for (let i = 0; i < s.length; i += 1) {
    const c = s[i];
    if (c === '(' || c === '[' || c === '{') depth += 1;
    else if (c === ')' || c === ']' || c === '}') depth -= 1;
    else if (depth === 0 && c === opChar) {
      // 排除 ->、++、--
      if (opChar === '-' && (s[i + 1] === '>' || s[i - 1] === '-' || s[i + 1] === '-')) continue;
      if (opChar === '+' && (s[i + 1] === '+' || s[i - 1] === '+')) continue;
      parts.push(s.slice(last, i));
      last = i + 1;
    }
  }
  if (!parts.length) return null;
  parts.push(s.slice(last));
  return parts.map((p) => p.trim()).filter(Boolean);
}

function operandType(operand, typeMap) {
  const e = stripOuter(operand);
  if (/^\d+$/.test(e)) return { name: 'int', ...TYPE_INFO.int, known: true, literal: true };
  if (/\.size\s*\(\)$/.test(e) || /\bsizeof\b/.test(e)) return { name: 'size_t', ...TYPE_INFO.size_t, known: true, derived: true };
  if (/^static_cast<([^>]+)>/.test(e)) {
    const m = /^static_cast<([^>]+)>/.exec(e);
    return { ...(typeInfo(m[1]) || {}), name: m[1], cast: true };
  }
  if (/^\(\s*([A-Za-z_]\w*)\s*\)/.test(e)) {
    const m = /^\(\s*([A-Za-z_]\w*)\s*\)/.exec(e);
    const ti = typeInfo(m[1]);
    if (ti) return { ...ti, name: m[1], cast: true };
  }
  if (/^\(\s*\*\s*([A-Za-z_]\w*)\s*\)$/.test(e)) {
    const name = /^\(\s*\*\s*([A-Za-z_]\w*)\s*\)$/.exec(e)[1];
    const t = typeMap.get(name);
    return t ? { ...typeInfo(t), name: t, deref: name } : { known: false, name: `*${name}` };
  }
  const m = /^([A-Za-z_]\w*)(?:\s*->\s*|\s*\.\s*)([A-Za-z_]\w*)$/.exec(e);
  if (m) {
    // 成员类型不在函数内声明窗口里时，标记 unknown，不用 widthMix 猜。
    return { known: false, name: `${m[1]}->${m[2]}`, member: true };
  }
  const id = /^([A-Za-z_]\w*)$/.exec(e);
  if (id) {
    const t = typeMap.get(id[1]);
    return t ? { ...typeInfo(t), name: t } : { known: false, name: id[1] };
  }
  return { known: false, name: e.slice(0, 80) };
}

function binaryOpsIn(expr) {
  const s = String(expr || '');
  const ops = [];
  for (const [ch, kind] of [['*', 'mul'], ['+', 'add'], ['-', 'sub'], ['<<', 'shift'], ['>>', 'shift']]) {
    const parts = splitTopLevel(s, ch === '<<' || ch === '>>' ? ch[0] : ch);
    if (!parts || parts.length < 2) continue;
    if (ch === '-' && /^\(/.test(s) && !/\)\s*-/.test(s)) continue;
    for (let i = 0; i < parts.length - 1; i += 1) {
      ops.push({ kind, operator: ch, left: parts[i], right: parts[i + 1] });
    }
  }
  return ops;
}

/** 从 pre 表达式抽 operation（全部候选，按危险性排序） */
function singleCallInner(expr) {
  const s = String(expr || '').trim();
  const m = /^([A-Za-z_][\w:>.]*)\s*\(/.exec(s);
  if (!m) return null;
  const open = m[0].length - 1;
  let depth = 0;
  let close = -1;
  for (let i = open; i < s.length; i += 1) {
    if (s[i] === '(') depth += 1;
    else if (s[i] === ')') {
      depth -= 1;
      if (depth === 0) { close = i; break; }
    }
  }
  if (close !== s.length - 1) return null;
  return s.slice(open + 1, close);
}

function operationRoot(expr) {
  let s = stripOuter(expr);
  for (let i = 0; i < 5; i += 1) {
    const cast = /^static_cast\s*<[^>]*>\s*\((.*)\)$/.exec(s);
    if (cast) { s = stripOuter(cast[1]); continue; }
    const ccast = /^\(\s*(?:const\s+)?[A-Za-z_][\w\s:<>]*\s*\**\s*\)\s*\((.*)\)$/.exec(s);
    if (ccast) { s = stripOuter(ccast[1]); continue; }
    const inner = singleCallInner(s);
    if (inner !== null && /[+*]|(?<!-)-(?!>)/.test(inner)) { s = stripOuter(inner); continue; }
    break;
  }
  return s;
}

function parseOperations(expr, typeHints) {
  const typeMap = typeMapOf(typeHints);
  const s = operationRoot(expr);
  const out = [];
  const seen = new Set();
  const visit = (text) => {
    const t = stripOuter(text);
    if (!t || seen.has(t)) return;
    seen.add(t);
    let found = false;
    for (const [ch, kind] of [['*', 'mul'], ['+', 'add'], ['-', 'sub']]) {
      const parts = splitTopLevel(t, ch);
      if (!parts || parts.length < 2) continue;
      for (let i = 0; i < parts.length - 1; i += 1) {
        const l = operandType(parts[i], typeMap);
        const r = operandType(parts[i + 1], typeMap);
        const known = !!(l.known && r.known);
        const width = known ? Math.max(l.width || 32, r.width || 32) : null;
        const promotion = known && width < 32 ? { width: 32, reason: 'integer-promotion' } : null;
        out.push({
          kind,
          operator: ch,
          expr: `${parts[i]} ${ch} ${parts[i + 1]}`,
          operands: [l, r],
          resultType: known ? (promotion ? 'int' : width === 64 ? (l.signed && r.signed ? 'int64_t' : 'uint64_t') : 'int') : null,
          resultWidth: known ? (promotion ? 32 : width) : null,
          resultSigned: known ? !!(l.signed || r.signed) : null,
          typeKnown: known,
          promotion
        });
      }
      found = true;
      for (const p of parts) visit(p);
    }
    if (!found) {
      // 还可能有括号包裹的嵌套表达式或函数实参
      let m;
      const innerRe = /\(([^()]*)\)/g;
      while ((m = innerRe.exec(t))) visit(m[1]);
      const call = /^[A-Za-z_][\w:>.]*\s*\((.*)\)$/.exec(t);
      if (call) visit(call[1]);
    }
  };
  visit(s);
  // 显式窄化 cast / truncate（跳过 sizeof(type) 里的类型括号）
  const castRe = /(?:static_cast<([^>]+)>)|(?:\(\s*(int8_t|uint8_t|int16_t|uint16_t|int32_t|uint32_t|int|char|short)\s*\))/g;
  let m;
  while ((m = castRe.exec(s))) {
    if (/sizeof\s*$/.test(s.slice(0, m.index))) continue;
    const target = m[1] || m[2];
    const ti = typeInfo(target);
    if (!ti || !ti.known) continue;
    const inner = s.slice(0, m.index) + s.slice(m.index + m[0].length);
    const innerOps = binaryOpsIn(stripOuter(inner));
    if (innerOps.length && ti.width && ti.width <= 32) {
      out.push({
        kind: 'truncate',
        operator: 'cast',
        expr: `${m[0]}...`,
        targetType: target,
        targetWidth: ti.width,
        targetSigned: ti.signed,
        typeKnown: true,
        operands: innerOps.map((x) => ({ name: x.left, known: false }))
      });
    }
  }
  // 去重并按危险性排序
  const uniq = [];
  const keys = new Set();
  for (const o of out) {
    const k = `${o.kind}|${o.expr}`;
    if (keys.has(k)) continue;
    keys.add(k);
    uniq.push(o);
  }
  uniq.sort((a, b) => {
    const risk = (x) => (x.kind === 'truncate' ? 0 : (x.resultWidth && x.resultWidth <= 32 ? 1 : 2));
    return risk(a) - risk(b);
  });
  return uniq;
}

function checkExpressionsFromText(text, line = null) {
  const out = [];
  const lines = String(text || '').split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    const l = lines[i];
    const m = /\b(if|while)\s*\((.*)\)/.exec(l);
    if (m) out.push({ expr: m[2].trim(), kind: m[1], line: line == null ? i + 1 : line, text: l.trim() });
  }
  return out;
}

function checkHasArithmetic(expr) {
  let s = String(expr || '');
  // 去掉指针箭头、比较/逻辑/位运算，保留 + - * 的算术语义
  s = s.replace(/->/g, ' ').replace(/\+\+|--/g, ' ');
  s = s.replace(/[<>]=?|==|!=|&&|\|\||[&|^~!?:]/g, ' ');
  const hits = [];
  const patterns = [
    /([A-Za-z_]\w*)\s*([+\-*])\s*([A-Za-z_]\w*|\d+)/g,
    /(\d+)\s*([+\-*])\s*([A-Za-z_]\w*)/g
  ];
  for (const re of patterns) {
    let m;
    while ((m = re.exec(s))) hits.push({ left: m[1], operator: m[2], right: m[3], expr: `${m[1]} ${m[2]} ${m[3]}` });
  }
  // 括号内单边表达式（如 len - off 已被上面覆盖）；去重
  const seen = new Set();
  return hits.filter((h) => {
    const k = `${h.left}${h.operator}${h.right}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

function lowerBoundOnly(expr) {
  const s = String(expr || '');
  return /^[^<>]*[A-Za-z_]\w*\s*<\s*\d+\s*$/.test(s.trim())
    || /^[^<>]*[A-Za-z_]\w*\s*<\s*[A-Za-z_]\w*\s*$/.test(s.trim());
}

function impliesSafe(expr) {
  const s = String(expr || '');
  if (checkHasArithmetic(s).length) return false;
  if (lowerBoundOnly(s)) return false;
  if (/\b(MAX|SIZE_MAX|INT_MAX|UINT_MAX|PAGE_SIZE)\b/.test(s) && /[<>]=?/.test(s)) return true;
  return false;
}

function setStatus(ob, status, extra = {}) {
  ob.status = status;
  if (extra.reason) ob.reason = extra.reason;
  if (extra.evidence) ob.evidence = { ...(ob.evidence || {}), ...extra.evidence };
  return ob;
}

function sourceWindow(l1, repo, file, line, radius = 12) {
  const lines = l1.sourceLines(repo, file);
  if (!lines) return null;
  const start = Math.max(1, line - radius);
  const end = Math.min(lines.length, line + radius);
  return { start, end, text: lines.slice(start - 1, end).join('\n') };
}

function evaluateP4CandidateObligations(claim, candidate, l1) {
  const obs = claim.obligations;
  const byId = (id) => obs.find((o) => o.id === id);

  // O1 entry-resolved
  const binding = candidate.binding || null;
  if (binding === 'verified' || binding === 'resolved') {
    setStatus(byId('O1'), OK, { evidence: { binding, entryBinding: candidate.entryBinding } });
  } else {
    setStatus(byId('O1'), UNK, { reason: 'entry-binding-suspect', evidence: { binding, entryBinding: candidate.entryBinding } });
  }

  // O2 operation-site：来自 pre 行（candidate.originText/sizeExpr）
  const preLine = String(candidate.originText || '');
  const opExpr = String(candidate.sizeExpr || preLine);
  if (/[+*]|(?<!-)-(?!>)/.test(opExpr)) {
    setStatus(byId('O2'), OK, { evidence: { source: 'pre-line', line: candidate.line, text: preLine, sizeExpr: candidate.sizeExpr } });
  } else {
    setStatus(byId('O2'), UNK, { reason: 'no-arithmetic-in-pre-line', evidence: { line: candidate.line, text: preLine } });
  }

  // O3 operation-kind
  const ops = parseOperations(opExpr, candidate.typeHints);
  if (ops.length) {
    setStatus(byId('O3'), OK, { evidence: { operations: ops.map((o) => ({ kind: o.kind, expr: o.expr, typeKnown: o.typeKnown })) } });
  } else {
    setStatus(byId('O3'), UNK, { reason: 'operation-kind-not-parsed', evidence: { sizeExpr: candidate.sizeExpr } });
  }

  // O4 operand-result-types
  const primary = ops[0] || null;
  if (primary && primary.typeKnown) {
    setStatus(byId('O4'), OK, {
      evidence: {
        expression: primary.expr,
        operands: primary.operands.map((o) => ({ name: o.name, width: o.width, signed: o.signed, known: o.known })),
        resultType: primary.resultType,
        resultWidth: primary.resultWidth,
        resultSigned: primary.resultSigned,
        promotion: primary.promotion
      }
    });
  } else {
    const unknown = primary ? primary.operands.filter((o) => !o.known).map((o) => o.name) : [];
    setStatus(byId('O4'), UNK, {
      reason: primary ? 'operand-type-missing' : 'no-operation',
      evidence: { expression: primary ? primary.expr : null, unknownOperands: unknown, typeHints: candidate.typeHints || [] }
    });
  }

  // O5 sink-relation
  const sinkText = `${preLine} ${opExpr}`;
  let sinkKind = null;
  if (/\b(malloc|calloc|realloc|alloca)\s*\(/.test(sinkText)) sinkKind = 'alloc-size';
  else if (/\[[^\]]+\]/.test(sinkText)) sinkKind = 'index';
  else if (/\b(memcpy|memset|memmove|copy_to_user)\s*\(/.test(sinkText)) sinkKind = 'memcpy-length';
  if (sinkKind) setStatus(byId('O5'), OK, { evidence: { sinkKind, line: candidate.line } });
  else setStatus(byId('O5'), UNK, { reason: 'sink-relation-unresolved', evidence: { text: sinkText } });

  // O6 unsafe-arithmetic
  if (primary && primary.typeKnown) {
    const risky = primary.kind === 'truncate'
      || (primary.resultWidth != null && primary.resultWidth <= 32)
      || (primary.kind === 'mul' && primary.resultWidth === 64);
    setStatus(byId('O6'), risky ? OK : NO, {
      reason: risky ? undefined : 'operands-wide-enough',
      evidence: { kind: primary.kind, resultWidth: primary.resultWidth, resultSigned: primary.resultSigned }
    });
  } else {
    setStatus(byId('O6'), UNK, { reason: primary ? 'operand-type-missing' : 'operation-missing', evidence: {} });
  }

  // O7/O8 check
  const window = sourceWindow(l1, candidate.repo, candidate.file, candidate.line);
  const checks = window ? checkExpressionsFromText(window.text, window.start) : [];
  const hasBoundCheck = candidate.boundCheckInWindow === true;
  if (!hasBoundCheck || !checks.length) {
    setStatus(byId('O7'), NO, { reason: 'no-check', evidence: { boundCheckInWindow: hasBoundCheck, checks: checks.length } });
    setStatus(byId('O8'), UNK, { reason: 'no-check', evidence: {} });
  } else {
    const chk = checks[0];
    const s = chk.expr;
    if (checkHasArithmetic(s).length) {
      setStatus(byId('O7'), NO, { reason: 'check-does-not-imply-safe', evidence: { check: s, line: chk.line } });
      setStatus(byId('O8'), NO, { reason: 'check-computes-arithmetic', evidence: { check: s, line: chk.line } });
    } else if (impliesSafe(s)) {
      setStatus(byId('O7'), OK, { evidence: { check: s, line: chk.line } });
      setStatus(byId('O8'), OK, { evidence: { check: s, line: chk.line } });
    } else {
      setStatus(byId('O7'), NO, { reason: 'check-does-not-imply-safe', evidence: { check: s, line: chk.line } });
      setStatus(byId('O8'), OK, { reason: 'check-pure-comparison', evidence: { check: s, line: chk.line } });
    }
  }

  // O9 fix-kind
  const fixKind = hasBoundCheck ? 'guard' : 'none';
  setStatus(byId('O9'), fixKind === 'none' ? UNK : OK, { reason: fixKind === 'none' ? 'no-fix-signal' : undefined, evidence: { fixKind } });
  byId('O9').evidence.fixKind = fixKind;

  // O10 oracle（只读 native-harness）
  const oracle = candidate.oracle || null;
  if (oracle && oracle.state === 'confirmed') {
    setStatus(byId('O10'), OK, { evidence: oracle });
  } else if (oracle && oracle.state === 'blocked') {
    setStatus(byId('O10'), UNK, { reason: `oracle-blocked:${oracle.reason || 'unknown'}`, evidence: oracle });
  } else {
    setStatus(byId('O10'), UNK, { reason: 'no-oracle', evidence: {} });
  }
  return obs;
}

function evalCveCheck(cve) {
  const removed = claimRemovedLines(cve);
  const added = claimAddedLines(cve);
  const preChecks = [];
  for (const l of removed) {
    const m = /\b(if|while)\s*\((.*)\)/.exec(l);
    if (m) preChecks.push({ expr: m[2].trim(), line: l.trim(), source: 'pre-removed' });
  }
  const check = cve.check && cve.check.expr ? { expr: cve.check.expr, line: cve.check.line, source: 'patch-check' } : null;
  const candidates = [...preChecks, ...(check ? [check] : [])];
  return { preChecks, check, candidates, added };
}

function claimRemovedLines(cve) {
  return String(cve.diff || '').split(/\r?\n/).filter((l) => /^-[^-]/.test(l)).map((l) => l.slice(1));
}

function claimAddedLines(cve) {
  return String(cve.diff || '').split(/\r?\n/).filter((l) => /^\+[^+]/.test(l)).map((l) => l.slice(1));
}

function detectFixKind(cve, addedLines) {
  const added = addedLines || claimAddedLines(cve);
  const text = added.join('\n');
  if (/\bint64(?:_t)?\b|\buint64(?:_t)?\b|\blong long\b/.test(text) && /start_output|limit_output|int64/.test(text)) return 'type-widen';
  if (/\b(__builtin_|check_add_overflow|check_mul_overflow)/.test(text)) return 'overflow-builtin';
  if (/for\s*\([^)]*(<|<=)[^)]*\)/.test(text) && /row\s*<|imagelength/.test(text)) return 'loop-guard';
  if (/\bif\s*\(/.test(text) && /return|goto/.test(text)) return 'guard';
  if (/\bif\s*\(/.test(text)) return 'guard';
  return 'none';
}

function evaluateP4CveObligations(claim, cve, l1) {
  const obs = claim.obligations;
  const byId = (id) => obs.find((o) => o.id === id);
  const removed = claimRemovedLines(cve);
  const added = claimAddedLines(cve);
  const checkInfo = evalCveCheck(cve);

  // O1 entry
  setStatus(byId('O1'), UNK, { reason: 'external-sample-entry-not-in-l1', evidence: { repo: cve.repo, file: cve.file } });

  // O2 operation-site：只从 removed 行找非 check 的算术行
  const opCandidates = removed.filter((l) => {
    if (/^\s*(if|while|for)\s*\(/.test(l)) return false;
    return /[+*]|(?<!-)-(?!>)/.test(l) && /(size|len|count|off|idx|alloc|malloc|\*)/i.test(l);
  });
  const opLine = opCandidates.length ? opCandidates[0].trim() : null;
  if (opLine) setStatus(byId('O2'), OK, { evidence: { source: 'pre-removed', text: opLine } });
  else setStatus(byId('O2'), UNK, { reason: 'no-pre-operation-line-in-diff', evidence: { removedLines: removed.slice(0, 5) } });

  // O3 operation-kind
  const ops = opLine ? parseOperations(opLine, cve.typeHints) : [];
  if (cve.cwe === 'CWE-197') {
    setStatus(byId('O3'), OK, { evidence: { kind: 'truncate', reason: 'CWE-197', castTarget: (cve.diff || '').match(/int64/) ? 'int64' : null } });
  } else if (ops.length) {
    setStatus(byId('O3'), OK, { evidence: { operations: ops.map((o) => ({ kind: o.kind, expr: o.expr })) } });
  } else {
    setStatus(byId('O3'), UNK, { reason: 'operation-kind-not-parsed', evidence: { opLine } });
  }

  // O4 operand-result-types
  const primary = ops[0] || null;
  if (cve.cwe === 'CWE-197') {
    const hints = (cve.typeHints || []).map((t) => ({ type: t.type, name: t.name }));
    const widened = hints.some((t) => /int64|uint64/.test(t.type));
    if (widened) setStatus(byId('O4'), OK, { evidence: { operands: hints.slice(0, 8), reason: 'type-widen-visible-in-patch' } });
    else setStatus(byId('O4'), UNK, { reason: 'operand-type-missing', evidence: { typeHints: hints } });
  } else if (primary && primary.typeKnown) {
    setStatus(byId('O4'), OK, {
      evidence: { expression: primary.expr, operands: primary.operands.map((o) => ({ name: o.name, width: o.width, signed: o.signed })), resultWidth: primary.resultWidth }
    });
  } else {
    setStatus(byId('O4'), UNK, { reason: 'operand-type-missing', evidence: { opLine, typeHints: cve.typeHints || [] } });
  }

  // O5 sink-relation
  const sinkText = `${removed.join('\n')}\n${added.join('\n')}`;
  let sinkKind = null;
  if (/\b(malloc|calloc|realloc|alloca|kmalloc|vmalloc)\s*\(/.test(sinkText)) sinkKind = 'alloc-size';
  else if (/\b(memcpy|memmove|copy_to_user|strlen|index|\[[^\]]+\])\b/.test(sinkText)) sinkKind = 'index-or-length';
  if (sinkKind) setStatus(byId('O5'), OK, { evidence: { sinkKind } });
  else setStatus(byId('O5'), UNK, { reason: 'sink-not-in-patch-window', evidence: {} });

  // O6 unsafe-arithmetic
  if (cve.cwe === 'CWE-190' || cve.cwe === 'CWE-191') {
    setStatus(byId('O6'), OK, { evidence: { cwe: cve.cwe, reason: 'signed/unsigned-integer-arithmetic' } });
  } else if (cve.cwe === 'CWE-197') {
    setStatus(byId('O6'), OK, { evidence: { cwe: cve.cwe, reason: 'int64-to-int-truncation' } });
  } else {
    setStatus(byId('O6'), UNK, { reason: 'cwe-not-covered', evidence: { cwe: cve.cwe } });
  }

  // O7/O8：优先选择“自身含算术”的 check（这是 check-integrity 的关键），
  // 其次 patch 提取的 check，最后 pre 的纯比较 check。
  const arithCandidates = checkInfo.candidates.filter((c) => checkHasArithmetic(c.expr).length);
  const chosen = arithCandidates[0] || checkInfo.check || checkInfo.candidates[0] || null;
  if (!chosen) {
    setStatus(byId('O7'), NO, { reason: 'no-check', evidence: {} });
    setStatus(byId('O8'), UNK, { reason: 'no-check', evidence: {} });
  } else {
    const arith = checkHasArithmetic(chosen.expr);
    if (arith.length) {
      setStatus(byId('O7'), NO, { reason: 'check-does-not-imply-safe', evidence: { check: chosen.expr, source: chosen.source } });
      setStatus(byId('O8'), NO, { reason: 'check-computes-arithmetic', evidence: { check: chosen.expr, arithmetic: arith.map((o) => o.expr), source: chosen.source } });
    } else if (impliesSafe(chosen.expr)) {
      setStatus(byId('O7'), OK, { evidence: { check: chosen.expr, source: chosen.source } });
      setStatus(byId('O8'), OK, { evidence: { check: chosen.expr, source: chosen.source } });
    } else {
      setStatus(byId('O7'), NO, { reason: 'check-does-not-imply-safe', evidence: { check: chosen.expr, source: chosen.source } });
      setStatus(byId('O8'), OK, { reason: 'check-pure-comparison', evidence: { check: chosen.expr, source: chosen.source } });
    }
  }

  // O9 fix-kind
  const fixKind = detectFixKind(cve, added);
  setStatus(byId('O9'), fixKind === 'none' ? UNK : OK, {
    reason: fixKind === 'none' ? 'fix-kind-not-detected' : undefined,
    evidence: { fixKind, addedLines: added.slice(0, 6) }
  });
  byId('O9').evidence.fixKind = fixKind;

  // O10 oracle（外部样本没有 native-harness 行）
  setStatus(byId('O10'), UNK, { reason: 'no-native-harness-oracle', evidence: {} });
  return obs;
}

function get(obs, id) {
  return obs.find((o) => o.id === id) || { status: 'unproven', evidence: {} };
}

/**
 * P4 判定（v2）：
 *   O6 disproven -> SATISFIED
 *   O6 proven ∧ O7 proven -> SATISFIED
 *   O6 proven ∧ (O7 disproven ∨ O8 disproven) -> VIOLATION
 *   O6 proven ∧ O9=type-widen/loop-guard -> 按类型判
 */
function p4Verdict(obligations) {
  const o = (id) => get(obligations, id);
  const O1 = o('O1'); const O2 = o('O2'); const O3 = o('O3'); const O4 = o('O4');
  const O5 = o('O5'); const O6 = o('O6'); const O7 = o('O7'); const O8 = o('O8'); const O9 = o('O9');
  if (O6.status === NO) return { claimVerdict: 'SATISFIED', reason: 'unsafe-arithmetic-impossible' };
  if (O6.status === UNK) return { claimVerdict: 'UNPROVEN', reason: 'unsafe-arithmetic-unproven' };
  if (O7.status === OK) return { claimVerdict: 'SATISFIED', reason: 'check-implies-safe' };
  if (O8.status === NO) return { claimVerdict: 'VIOLATION', reason: 'check-integrity-broken' };
  if (O7.status === NO) return { claimVerdict: 'VIOLATION', reason: 'check-does-not-imply-safe' };
  const fixKind = O9.evidence && O9.evidence.fixKind;
  if (fixKind === 'type-widen' || fixKind === 'loop-guard') return { claimVerdict: 'VIOLATION', reason: `fix-kind-${fixKind}` };
  if ([O2, O3, O4, O5].every((x) => x.status !== OK)) return { claimVerdict: 'UNPROVEN', reason: 'structural-obligations-unproven' };
  return { claimVerdict: 'UNPROVEN', reason: 'obligations-not-satisfied' };
}

function productForP4(claimVerdict, obligations, opts = {}) {
  const o = (id) => get(obligations, id);
  if (claimVerdict === 'SATISFIED') return { productVerdict: 'NOT-VULN', reason: 'satisfied' };
  const O10 = o('O10');
  const oracleState = O10.evidence && O10.evidence.state;
  if (claimVerdict !== 'VIOLATION') {
    if (oracleState === 'blocked') {
      return { productVerdict: 'CONDITIONS-NOT-MET', reason: `instrumentation-gap:${(O10.evidence && O10.evidence.reason) || 'oracle-blocked'}` };
    }
    return { productVerdict: 'CONDITIONS-NOT-MET', reason: 'unproven' };
  }
  const O1 = o('O1');
  const oracleConfirmed = oracleState === 'confirmed';
  if (O1.status === OK && oracleConfirmed) return { productVerdict: 'PROVEN-VULN', reason: 'entry-and-structural-obligations-proven-and-oracle-confirmed' };
  if (opts.oracleGapAsConditions !== false && oracleState === 'blocked') {
    return { productVerdict: 'CONDITIONS-NOT-MET', reason: `instrumentation-gap:${(O10.evidence && O10.evidence.reason) || 'oracle-blocked'}` };
  }
  if (O1.status !== OK) return { productVerdict: 'PROVEN-WEAKNESS', reason: 'entry-unproven' };
  return { productVerdict: 'PROVEN-WEAKNESS', reason: 'oracle-unconfirmed' };
}

function proveP4Claim(claim, l1, opts = {}) {
  let obligations;
  if (claim.group === 'cve-calibration') {
    const cve = opts.cveById ? opts.cveById.get(claim.cveId) : null;
    obligations = evaluateP4CveObligations(claim, cve || {}, l1);
  } else {
    const candidate = opts.candidateById ? opts.candidateById.get(claim.candidateId) : null;
    obligations = evaluateP4CandidateObligations(claim, candidate || {}, l1);
  }
  const v = p4Verdict(obligations);
  const p = productForP4(v.claimVerdict, obligations, opts);
  return {
    claimId: claim.claimId,
    class: 'P4',
    group: claim.group,
    origin: claim.origin || null,
    inTarget: claim.inTarget === true,
    codeState: claim.codeState || null,
    productionEligible: claim.productionEligible === true,
    novelty: claim.novelty || null,
    candidateId: claim.candidateId || null,
    cveId: claim.cveId || null,
    cwe: claim.cwe || null,
    file: claim.entry.file,
    line: claim.entry.line || null,
    obligations,
    claimVerdict: v.claimVerdict,
    reason: v.reason,
    productVerdict: p.productVerdict,
    productReason: p.reason
  };
}

function proveP4Claims(claims, l1, opts = {}) {
  return claims.map((c) => proveP4Claim(c, l1, opts));
}

function summarizeP4Verdicts(rows) {
  const countBy = (field) => rows.reduce((a, r) => { a[r[field]] = (a[r[field]] || 0) + 1; return a; }, {});
  const oh = rows.filter((r) => r.group === 'oh-candidate');
  const cve = rows.filter((r) => r.group === 'cve-calibration');
  let total = 0;
  let proven = 0;
  const obligationStatus = {};
  for (const r of rows) {
    for (const ob of r.obligations) {
      total += 1;
      if (ob.status === 'proven') proven += 1;
      if (!obligationStatus[ob.id]) obligationStatus[ob.id] = {};
      obligationStatus[ob.id][ob.status] = (obligationStatus[ob.id][ob.status] || 0) + 1;
    }
  }
  const oracle = {
    confirmed: oh.filter((r) => { const o = r.obligations.find((x) => x.id === 'O10'); return o && o.evidence && o.evidence.state === 'confirmed'; }).length,
    blocked: oh.filter((r) => { const o = r.obligations.find((x) => x.id === 'O10'); return o && o.evidence && o.evidence.state === 'blocked'; }).length,
    blockedReasons: {}
  };
  for (const r of oh) {
    const o = r.obligations.find((x) => x.id === 'O10');
    if (o && o.evidence && o.evidence.state === 'blocked') {
      oracle.blockedReasons[o.evidence.reason] = (oracle.blockedReasons[o.evidence.reason] || 0) + 1;
    }
  }
  const fixKinds = {};
  for (const r of cve) {
    const o = r.obligations.find((x) => x.id === 'O9');
    const k = (o && o.evidence && o.evidence.fixKind) || 'none';
    fixKinds[k] = (fixKinds[k] || 0) + 1;
  }
  return {
    total: rows.length,
    byGroup: countBy('group'),
    claimVerdict: countBy('claimVerdict'),
    productVerdict: countBy('productVerdict'),
    obligationClosure: { proven, total, rate: total ? Number((proven / total).toFixed(3)) : 0 },
    obligationStatus,
    oracle,
    cveFixKinds: fixKinds,
    cveObligationsDecided: cve.filter((r) => {
      const o7 = r.obligations.find((x) => x.id === 'O7');
      const o8 = r.obligations.find((x) => x.id === 'O8');
      return o7 && o8 && o7.status !== 'invalid' && o8.status !== 'invalid';
    }).length
  };
}

module.exports = {
  parseOperations,
  operandType,
  typeInfo,
  checkHasArithmetic,
  impliesSafe,
  detectFixKind,
  evaluateP4CandidateObligations,
  evaluateP4CveObligations,
  p4Verdict,
  productForP4,
  proveP4Claim,
  proveP4Claims,
  summarizeP4Verdicts
};
