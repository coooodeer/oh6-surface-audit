'use strict';

/**
 * common.js —— P1/P2/P7/P8 静态发现链路的共享底座。
 *
 * 只做“确定性静态事实”：
 *   - D4 五仓与源码路径解析（P1/P2/P7 的 origin.file 相对部件根，P8 的 file 已含部件根）；
 *   - functions.jsonl 的函数区间查询；
 *   - 源码行窗口、条件守卫、支配关系、死分支、同变量检查；
 *   - 统一 O1–O10 义务骨架与 tier 口径。
 *
 * 本模块不做漏洞判定；判定在 prover-p*.js。
 */

const fs = require('fs');
const path = require('path');
const {
  WORKSPACE, SOURCE_ROOT, TOOL_ROOT, OUT_ROOT,
  ensureDir, readJsonl, writeJsonl, writeJson, sha256, posix
} = require('../util');
const origin = require('../candidate-origin');

const D4_ROOTS = Object.freeze([
  'base/account/os_account',
  'foundation/communication/dsoftbus',
  'foundation/communication/ipc',
  'base/notification/eventhandler',
  'base/accesscontrol/sandbox_manager'
]);

const CLASSES = Object.freeze(['P1', 'P2', 'P7', 'P8']);

const TIERS = Object.freeze({
  T1: 'T1-confirmed',
  T2: 'T2-weak-candidate',
  T2_STATIC: 'T2-static-confirmed',
  T2_FACT: 'T2-fact-needs-validation',
  T3: 'T3-instrumentation-gap',
  T4: 'T4-negative',
  T5: 'T5-not-applicable'
});

const T2_TIERS = Object.freeze([TIERS.T2, TIERS.T2_STATIC, TIERS.T2_FACT]);
function isT2Tier(tier) {
  return T2_TIERS.includes(tier) || String(tier || '').startsWith('T2');
}

/** 兼容旧产物：旧 T2 一律视为 fact 已确认的 static T2。 */
function normalizeTier(tier) {
  return tier === TIERS.T2 ? TIERS.T2_STATIC : tier;
}

const OBLIGATION_KINDS = Object.freeze({
  O1: 'entry-resolved',
  O2: 'source',
  O3: 'sink',
  O4: 'class-fact',
  O5: 'guard-check',
  O6: 'check-coverage',
  O7: 'path',
  O8: 'entry-coverage',
  O9: 'impact-static',
  O10: 'oracle'
});

const D4 = Object.freeze({
  P1_SEED: { repo: 'foundation/communication/ipc', file: 'interfaces/innerkits/cj/src/message_sequence_impl.cpp', line: 1195 },
  P2_SEED: { repo: 'base/notification/eventhandler', file: 'frameworks/eventhandler/src/event_queue_ffrt.cpp', line: 76 }
});

function isD4(root) {
  const s = String(root || '');
  return D4_ROOTS.some((r) => s === r || s.startsWith(`${r}/`));
}

function componentOf(root) {
  const s = String(root || '');
  for (const r of D4_ROOTS) {
    if (s === r || s.startsWith(`${r}/`)) return r;
  }
  return null;
}

/** 把 origin.file 归一成“部件根 + 仓内相对路径”；P8 的 file 已经含部件根。 */
function sourceRelPath(root, file) {
  const f = posix(String(file || ''));
  const r = posix(String(root || ''));
  if (r && (f === r || f.startsWith(`${r}/`))) return f;
  return `${r}/${f}`;
}

const SOURCE_CACHE = new Map();

function readSource(relPath, cap = 4 * 1024 * 1024) {
  const rel = posix(relPath);
  if (SOURCE_CACHE.has(rel)) return SOURCE_CACHE.get(rel);
  let text = null;
  try {
    const abs = path.join(SOURCE_ROOT, rel);
    const st = fs.statSync(abs);
    if (st.size <= cap) text = fs.readFileSync(abs, 'utf8');
  } catch (_) {
    text = null;
  }
  SOURCE_CACHE.set(rel, text);
  return text;
}

function clearSourceCache() {
  SOURCE_CACHE.clear();
}

function linesOf(text) {
  return String(text == null ? '' : text).split(/\r?\n/);
}

function sliceLines(lines, startLine, endLine) {
  const a = Math.max(1, Number(startLine) || 1);
  const b = Math.max(a, Number(endLine) || a);
  return lines.slice(a - 1, b);
}

function lineWindow(lines, line, radius = 40) {
  const idx = Math.max(1, Math.min(lines.length, Number(line) || 1));
  const a = Math.max(1, idx - radius);
  const b = Math.min(lines.length, idx + radius);
  return { startLine: a, endLine: b, lines: lines.slice(a - 1, b) };
}

// ---------------------------------------------------------------- functions

let FN_INDEX = null;

function functionsIndex() {
  if (FN_INDEX) return FN_INDEX;
  const rows = readJsonl(path.join(TOOL_ROOT, 'index', 'functions.jsonl')).filter((r) => r && r.root && r.file);
  const byRepoFile = new Map();
  const byFile = new Map();
  for (const r of rows) {
    const k = `${r.root}\u0000${r.file}`;
    if (!byRepoFile.has(k)) byRepoFile.set(k, []);
    byRepoFile.get(k).push(r);
    if (!byFile.has(r.file)) byFile.set(r.file, new Set());
    byFile.get(r.file).add(r.root);
  }
  for (const list of byRepoFile.values()) list.sort((a, b) => a.startLine - b.startLine);
  FN_INDEX = { rows, byRepoFile, byFile };
  return FN_INDEX;
}

function rootsForFile(file) {
  return [...(functionsIndex().byFile.get(posix(file)) || [])];
}

function d4RootsForFile(file) {
  return rootsForFile(file).filter(isD4);
}

function enclosingFunction(root, file, line) {
  const list = functionsIndex().byRepoFile.get(`${root}\u0000${posix(file)}`);
  if (!list) return null;
  let best = null;
  const n = Number(line) || 0;
  for (const f of list) {
    if (f.startLine > n) break;
    if (n <= f.endLine && (!best || f.endLine - f.startLine < best.endLine - best.startLine)) best = f;
  }
  return best;
}

function functionBody(root, file, range, pad = 0) {
  const text = readSource(sourceRelPath(root, file));
  if (text == null) return { text: null, lines: [], startLine: range ? range.startLine : 1, endLine: range ? range.endLine : 0, reason: 'source-missing' };
  const lines = linesOf(text);
  const a = Math.max(1, (range ? range.startLine : 1) - pad);
  const b = Math.min(lines.length, (range ? range.endLine : lines.length) + pad);
  return { text: lines.slice(a - 1, b).join('\n'), lines: lines.slice(a - 1, b), startLine: a, endLine: b, reason: null };
}

// ---------------------------------------------------------------- text/guards

function escapeRe(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function stripLine(line) {
  let s = String(line || '');
  s = s.replace(/\/\/.*$/, '');
  s = s.replace(/\/\*.*?\*\//g, ' ');
  return s;
}

function isCommentLine(line) {
  return /^\s*(\/\/|\/\*|\*)/.test(String(line || ''));
}

function mentions(text, name) {
  const n = String(name || '').trim();
  if (!n) return false;
  if (n === 'this') return /\bthis\b/.test(text);
  return new RegExp(`(^|[^A-Za-z0-9_])${escapeRe(n)}([^A-Za-z0-9_]|$)`).test(String(text || ''));
}

function mentionsAny(text, names) {
  return (names || []).some((n) => mentions(text, n));
}

/** 取 if/while/for/switch 后第一个括号内的文本（忽略字符串里的括号）。 */
function parenContent(line, fromIdx) {
  const s = String(line || '');
  let i = s.indexOf('(', fromIdx);
  if (i < 0) return '';
  let depth = 0;
  let inStr = null;
  for (let j = i; j < s.length; j += 1) {
    const c = s[j];
    if (inStr) {
      if (c === '\\') { j += 1; continue; }
      if (c === inStr) inStr = null;
      continue;
    }
    if (c === '"' || c === "'") { inStr = c; continue; }
    if (c === '(') depth += 1;
    else if (c === ')') {
      depth -= 1;
      if (depth === 0) return s.slice(i + 1, j);
    }
  }
  return s.slice(i + 1);
}

/** 从 startIdx 开始找块结束行（按花括号深度）；没有花括号返回 startIdx。 */
function blockEnd(lines, startIdx, maxLook = 200) {
  const first = String(lines[startIdx] || '');
  let depth = 0;
  let seen = false;
  const limit = Math.min(lines.length, startIdx + maxLook);
  for (let i = startIdx; i < limit; i += 1) {
    const s = stripLine(lines[i]);
    for (const ch of s) {
      if (ch === '{') { depth += 1; seen = true; }
      else if (ch === '}') depth -= 1;
    }
    if (seen && depth <= 0) return i;
  }
  return seen ? Math.min(lines.length - 1, startIdx + maxLook) : startIdx;
}

function findExit(lines, fromIdx, toIdx) {
  const end = Math.min(lines.length - 1, toIdx);
  for (let i = Math.max(0, fromIdx); i <= end; i += 1) {
    const s = stripLine(lines[i]);
    if (/\b(return|throw|goto|break|continue)\b/.test(s)) return i;
  }
  return -1;
}

function isDeadCondition(cond) {
  const t = String(cond || '').replace(/\s+/g, '');
  return t === 'false' || t === '0' || t === 'FALSE';
}

function firstBraceLine(lines, startIdx, maxLook = 3) {
  for (let i = startIdx; i <= Math.min(lines.length - 1, startIdx + maxLook); i += 1) {
    if (String(lines[i] || '').includes('{')) return i;
  }
  return -1;
}

/**
 * 守卫分析：围绕 sinkIndex 找其前面的 if / 宏 / switch 守卫。
 *
 * “覆盖 sink”有两种正形态：
 *   1) early-exit：`if (bad) { return; } ... sink`  —— exit 在 sink 前；
 *   2) guarded-sink：`if (Check(x)) { sink }`       —— sink 在守卫块内。
 * 只看“有 check”不算覆盖：dead branch / 检查后 sink / 检查错变量都单独留痕。
 */
function analyzeGuards(lines, opts = {}) {
  const targetVars = opts.targetVars || [];
  const sinkIndex = Number.isInteger(opts.sinkIndex) ? opts.sinkIndex : lines.length;
  const from = Math.max(0, Number.isInteger(opts.from) ? opts.from : 0);
  const to = Math.min(lines.length, Number.isInteger(opts.to) ? opts.to : sinkIndex + 80);
  const guards = [];
  const deadRanges = [];
  for (let i = from; i < to; i += 1) {
    if (isCommentLine(lines[i])) continue;
    const s = stripLine(lines[i]);
    if (!s.trim()) continue;
    const underDead = deadRanges.some(([a, b]) => i > a && i <= b);
    const m = /\b(if|while|switch)\s*\(/.exec(s);
    if (m) {
      if (m[1] === 'while') continue; // while 是循环，不是写入守卫
      const cond = parenContent(s, m.index + m[0].length - 1);
      const open = i;
      const hasBrace = s.slice(s.indexOf('(', m.index)).includes('{');
      let close = open;
      let exitLine = -1;
      if (hasBrace) {
        close = blockEnd(lines, open);
        exitLine = findExit(lines, open, close);
      } else {
        // 单行守卫：`if (x > MAX) return false;`
        const inline = stripLine(lines[i]).slice(stripLine(lines[i]).indexOf(')') + 1);
        if (/\b(return|throw|goto|break|continue)\b/.test(inline)) exitLine = i;
        else {
          const nxt = i + 1;
          if (nxt < lines.length && /\b(return|throw|goto|break|continue)\b/.test(stripLine(lines[nxt]))) exitLine = nxt;
        }
      }
      const dead = isDeadCondition(cond);
      if (dead) deadRanges.push([i, close]);
      const guard = {
        index: i,
        line: i + 1,
        kind: m[1] === 'switch' ? 'switch' : 'if',
        condition: cond,
        hasBrace,
        blockEnd: close + 1,
        exitLine: exitLine >= 0 ? exitLine + 1 : null,
        exitIndex: exitLine,
        dead,
        deadAncestor: underDead,
        targetMention: mentionsAny(cond, targetVars),
        text: String(lines[i]).trim()
      };
      guard.sinkInsideBlock = i <= sinkIndex && sinkIndex <= close;
      guard.exitBeforeSink = exitLine >= 0 && exitLine < sinkIndex;
      guard.coversSink = !guard.dead && !guard.deadAncestor && guard.targetMention && (guard.sinkInsideBlock || guard.exitBeforeSink);
      guards.push(guard);
      continue;
    }
    // 宏式校验：RETURN_IF_xxx(var, ...) / CHECK_xxx(var) / Verify/Check/IsValid 调用
    const macro = /\b([A-Z][A-Z0-9_]{2,}|Check[A-Za-z0-9_]+|Verify[A-Za-z0-9_]+|IsValid[A-Za-z0-9_]+|Is[A-Z][A-Za-z0-9_]+)\s*\(/.exec(s);
    if (macro && !/^\s*(?:case|default)\b/.test(s)) {
      const macroExits = /^(RETURN_IF|CHECK_|ASSERT_)/.test(macro[1]);
      const guard = {
        index: i,
        line: i + 1,
        kind: 'call',
        condition: macro[1],
        hasBrace: false,
        blockEnd: i + 1,
        exitLine: macroExits ? i + 1 : null,
        exitIndex: macroExits ? i : null,
        dead: false,
        deadAncestor: underDead,
        targetMention: mentionsAny(s, targetVars),
        text: String(lines[i]).trim()
      };
      guard.sinkInsideBlock = false;
      guard.exitBeforeSink = macroExits && i < sinkIndex;
      guard.coversSink = !guard.dead && !guard.deadAncestor && guard.targetMention && guard.exitBeforeSink;
      guards.push(guard);
    }
  }
  const before = guards.filter((g) => g.index <= sinkIndex);
  const dom = before.filter((g) => g.exitBeforeSink || g.sinkInsideBlock);
  const same = dom.filter((g) => g.targetMention && !g.dead);
  const after = guards.filter((g) => g.index > sinkIndex);
  const dead = guards.filter((g) => g.dead);
  const wrong = dom.filter((g) => !g.targetMention);
  const covering = guards.filter((g) => g.coversSink);
  return {
    guards,
    before,
    after,
    dominating: dom,
    covering,
    sameVariableDominating: same,
    wrongVariableDominating: wrong,
    deadBranch: dead,
    anyGuardBefore: before.length > 0,
    hasDominating: dom.length > 0,
    hasSameVariableDominating: same.length > 0,
    hasCovering: covering.length > 0,
    checkAfterSink: after.length > 0,
    onlyCheckAfterSink: after.length > 0 && !covering.length
  };
}

/** switch/case 分派：sink 前 12 行内出现 switch(...) 且中间有 case 常量，视为结构性守卫。 */
function switchCaseGuard(lines, sinkIndex) {
  const from = Math.max(0, sinkIndex - 12);
  let switchLine = -1;
  let caseLine = -1;
  for (let i = sinkIndex - 1; i >= from; i -= 1) {
    const s = stripLine(lines[i]);
    if (/^\s*(case\b|default\s*:)/.test(s)) {
      if (caseLine < 0) caseLine = i;
      continue;
    }
    if (/\bswitch\s*\(/.test(s)) { switchLine = i; break; }
  }
  if (switchLine < 0 || caseLine < 0) return null;
  const cond = parenContent(stripLine(lines[switchLine]), stripLine(lines[switchLine]).indexOf('('));
  return { switchLine: switchLine + 1, caseLine: caseLine + 1, condition: cond, text: String(lines[caseLine]).trim() };
}

function hasLifecycleOp(text) {
  return /\bdelete\s+[A-Za-z_]|\bdelete\s*\[|\bfree\s*\(|\.Reset\s*\(|->Reset\s*\(|\bRelease\s*\(|->Release\s*\(|\bDestroy\w*\s*\(|RemoveDeathRecipient|\.erase\s*\(|\.clear\s*\(|\bfclose\s*\(|\bclose\s*\(/.test(String(text || ''));
}

function hasLifetimeAnchor(text) {
  return /lock_guard|unique_lock|shared_ptr|weak_ptr|sptr<|AutoLock|\.join\s*\(|\bjoin\s*\(|wait\s*\(|\.wait|condvar|refcount|AddRef|IncStrong|std::move\s*\(/.test(String(text || ''));
}

function hasValidationCall(text) {
  return /\b(Check|Verify|Validate|IsValid|RETURN_IF|CHECK_|ASSERT_|EXPECT_)[A-Za-z0-9_]*\s*\(/.test(String(text || ''));
}

// ---------------------------------------------------------------- sampling

/** 按 key 轮转抽样，保证跨 root/文件分散，而不是同一文件凑数。 */
function stratifiedSample(items, count, keyFn, idFn) {
  const groups = new Map();
  for (const it of items) {
    const k = keyFn(it);
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(it);
  }
  const keys = [...groups.keys()].sort();
  for (const k of keys) {
    groups.get(k).sort((a, b) => String(idFn ? idFn(a) : JSON.stringify(a)).localeCompare(String(idFn ? idFn(b) : JSON.stringify(b))));
  }
  const out = [];
  let round = 0;
  while (out.length < count) {
    let added = false;
    for (const k of keys) {
      const list = groups.get(k);
      if (round < list.length) {
        out.push(list[round]);
        added = true;
        if (out.length >= count) break;
      }
    }
    if (!added) break;
    round += 1;
  }
  return out;
}

// ---------------------------------------------------------------- obligations / claims

function obligation(id, status, evidence = {}, reason = null) {
  return {
    id,
    kind: OBLIGATION_KINDS[id] || 'unknown',
    status,
    evidence,
    ...(reason ? { reason } : {})
  };
}

function obligationById(obligations, id) {
  return (obligations || []).find((o) => o.id === id) || { id, status: 'unproven', evidence: {} };
}

function provenanceOf(record) {
  return origin.classify(record);
}

function claimId(cls, unitId) {
  return `L3-${cls}-${sha256(`${cls}\u0000${unitId}`).slice(0, 12)}`;
}

function tierOfProduct(productVerdict, factValidation = 'confirmed') {
  if (productVerdict === 'PROVEN-VULN') return TIERS.T1;
  if (productVerdict === 'PROVEN-WEAKNESS') return factValidation === 'needs-validation' ? TIERS.T2_FACT : TIERS.T2_STATIC;
  if (productVerdict === 'CONDITIONS-NOT-MET' || productVerdict === 'UNPROVEN') return TIERS.T3;
  if (productVerdict === 'NOT-VULN') return TIERS.T4;
  if (productVerdict === 'NOT-APPLICABLE') return TIERS.T5;
  return TIERS.T3;
}

/**
 * 统一 verdict 映射（§4.5）：
 *   O1/O2/O3 disproven -> NOT-APPLICABLE
 *   O5/O6 proven       -> SATISFIED
 *   O5/O6 disproven    -> VIOLATION
 *   其余              -> UNPROVEN
 * O10 永不参与：固定 unproven，因此 t1Eligible=false，永不出 PROVEN-VULN。
 */
function claimVerdictFor(obligations, opts = {}) {
  const o = (id) => obligationById(obligations, id);
  const structural = opts.structural || ['O1', 'O2', 'O3'];
  for (const id of structural) {
    if (o(id).status === 'disproven') {
      return { claimVerdict: 'NOT-APPLICABLE', reason: `${id}-disproven:${opts.notApplicableReason || 'structural-fact-absent'}` };
    }
  }
  const guardIds = opts.guardIds || ['O5', 'O6'];
  const gates = guardIds.map(o);
  if (gates.every((g) => g.status === 'proven')) {
    return { claimVerdict: 'SATISFIED', reason: opts.satisfiedReason || 'guard-covers-sink' };
  }
  if (gates.some((g) => g.status === 'disproven')) {
    return { claimVerdict: 'VIOLATION', reason: opts.violationReason || 'guard-missing-or-not-covering' };
  }
  for (const id of (opts.gapIds || ['O4', 'O7', 'O8'])) {
    if (o(id).status !== 'proven') {
      return { claimVerdict: 'UNPROVEN', reason: `${id}-unproven:${o(id).reason || 'missing-data'}` };
    }
  }
  return { claimVerdict: 'UNPROVEN', reason: opts.unprovenReason || 'data-missing' };
}

function productFor(claimVerdict, opts = {}) {
  if (claimVerdict === 'SATISFIED') return { productVerdict: 'NOT-VULN', reason: opts.satisfiedReason || 'guard-covers-sink' };
  if (claimVerdict === 'NOT-APPLICABLE') return { productVerdict: 'NOT-APPLICABLE', reason: opts.notApplicableReason || 'structural-fact-absent' };
  if (claimVerdict === 'VIOLATION') return { productVerdict: 'PROVEN-WEAKNESS', reason: opts.violationReason || 'static-violation-no-dynamic-oracle' };
  return { productVerdict: 'CONDITIONS-NOT-MET', reason: opts.unprovenReason || 'missing-data' };
}

// ---------------------------------------------------------------- files

function writeUtf8(file, text) {
  ensureDir(path.dirname(file));
  fs.writeFileSync(file, text, 'utf8');
}

function readJsonlSafe(file) {
  if (!fs.existsSync(file)) return [];
  return readJsonl(file);
}

function outputPath(...parts) {
  return path.join(OUT_ROOT, 'p1p2p7p8', ...parts);
}

module.exports = {
  D4_ROOTS, CLASSES, TIERS, T2_TIERS, isT2Tier, normalizeTier, OBLIGATION_KINDS, D4,
  isD4, componentOf, sourceRelPath, readSource, clearSourceCache, linesOf, sliceLines, lineWindow,
  functionsIndex, rootsForFile, d4RootsForFile, enclosingFunction, functionBody,
  escapeRe, stripLine, isCommentLine, mentions, mentionsAny, parenContent, blockEnd, findExit,
  analyzeGuards, switchCaseGuard, hasLifecycleOp, hasLifetimeAnchor, hasValidationCall,
  stratifiedSample, obligation, obligationById, provenanceOf, claimId, tierOfProduct,
  claimVerdictFor, productFor, writeUtf8, readJsonlSafe, outputPath,
  OUT_ROOT, SOURCE_ROOT, TOOL_ROOT, WORKSPACE, ensureDir, writeJson, writeJsonl, readJsonl, sha256
};
