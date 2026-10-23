'use strict';

/**
 * facts-p1.js —— P1 数据适配：parcel-read → alloc/memcpy/loop 的静态窗口事实。
 *
 * 不重造 G-P1，只把窗口从 40 行有界放宽到 80 行，并把“有没有 check”拆成：
 *   - check 是否支配 sink（early-exit / guarded-sink）；
 *   - check 是否检查同一变量；
 *   - check 是否在 sink 之后；
 *   - check 是否在死分支。
 *
 * 输出仍是候选级事实；T2/T4 由 prover-p1.js 判。
 */

const path = require('path');
const {
  D4_ROOTS, isD4, componentOf, readSource, sourceRelPath,
  linesOf, enclosingFunction, functionBody, analyzeGuards, switchCaseGuard,
  stripLine, isCommentLine, mentions, mentionsAny, parenContent,
  stratifiedSample, provenanceOf, sha256, readJsonlSafe, TOOL_ROOT
} = require('./common');

const WINDOW = 80;

const SINK_PATTERNS = [
  { kind: 'alloc', re: /\b(malloc|calloc|realloc|alloca)\s*\(/ },
  { kind: 'alloc', re: /\bnew\s+[A-Za-z_][A-Za-z0-9_:<>]*\s*\[/ },
  { kind: 'alloc', re: /\.(resize|reserve)\s*\(/ },
  { kind: 'memcpy', re: /\b(memcpy|memmove|memcpy_s|memmove_s)\s*\(/ },
  { kind: 'memcpy', re: /\bCopyData\s*\(/ },
  { kind: 'loop', re: /\b(for|while)\s*\(/ }
];

function readValueVars(read) {
  const vars = new Set();
  if (read && read.var) vars.add(String(read.var));
  const text = String((read && read.text) || '');
  // ReadUint32(io, (uint32_t *)size) 的“被读出值”是 *size，不是返回值变量。
  const cast = /\(\s*(?:const\s+)?(?:u?int(?:8|16|32|64)_t|size_t|uintptr_t|long|int|unsigned\s+int)\s*\*+\s*\)\s*([A-Za-z_][A-Za-z0-9_]*)/.exec(text);
  if (cast) vars.add(cast[1]);
  const addr = /&\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)/.exec(text);
  if (addr) vars.add(addr[1]);
  // ReadBuffer(size) 之类：输入参数本身也是 P1 的“长度”来源。
  const open = text.indexOf('(');
  if (open >= 0) {
    const args = parenContent(text, open);
    for (const a of args.split(',')) {
      const id = a.trim().match(/^[A-Za-z_][A-Za-z0-9_]*$/);
      if (id && !['this', 'true', 'false'].includes(id[0])) vars.add(id[0]);
    }
  }
  return [...vars].filter(Boolean);
}

/** 只把真正的上/下界比较或长度校验当成 P1 的 bound check；null 检查不算。 */
function boundLike(condition, macroName) {
  const c = String(condition || '');
  if (/nullptr|null\b|NULL|!\s*[A-Za-z_][A-Za-z0-9_]*\s*$/.test(c)) return false;
  if (/[<>]=?|<=|>=|==\s*0\b|!=\s*0\b/.test(c)) return true;
  if (/MAX|LIMIT|CAP|SIZE|BOUND|RANGE/.test(c)) return true;
  if (/\b(?:Check|Validate|Verify)[A-Za-z0-9_]*(?:Length|Size|Bound|Range|Cap)\b/.test(`${c} ${macroName || ''}`)) return true;
  return false;
}

/**
 * P1 只认“上界/容量”检查：`len <= 0`、`len > 0` 只是下界，不能证明 malloc(len) 有界。
 */
function upperBoundLike(condition, macroName) {
  const c = String(condition || '');
  const m = String(macroName || '');
  if (/nullptr|null\b|NULL/.test(c)) return false;
  if (/\b(?:Check|Validate|Verify)[A-Za-z0-9_]*(?:Length|Size|Bound|Range|Cap)\b/.test(`${c} ${m}`)) return true;
  if (/MAX|LIMIT|CAP|SIZE|BOUND|RANGE/.test(c)) return true;
  if (/(?:>|>=)\s*(?!0\b)(?:\([^)]*\)\s*)*(?:[0-9]+|[A-Za-z_][A-Za-z0-9_:]*)/.test(c)) return true;
  if (/(?:<=|<)\s*[0-9]{2,}/.test(c)) return true;
  return false;
}

function findSinks(lines, readIdx, vars, maxWindow = WINDOW, lineOffset = 0) {
  const out = [];
  const end = Math.min(lines.length, readIdx + maxWindow + 1);
  for (let i = readIdx + 1; i < end; i += 1) {
    if (isCommentLine(lines[i])) continue;
    const s = stripLine(lines[i]);
    if (!s.trim()) continue;
    for (const p of SINK_PATTERNS) {
      const m = p.re.exec(s);
      if (!m) continue;
      let arg = '';
      if (p.kind === 'alloc' || p.kind === 'memcpy') {
        arg = parenContent(s, m.index + m[0].length - 1);
      } else if (p.kind === 'loop') {
        arg = parenContent(s, s.indexOf('('));
      }
      const hay = `${arg} ${s}`;
      if (!mentionsAny(hay, vars)) continue;
      if (p.kind === 'loop' && !mentionsAny(arg, vars)) continue;
      out.push({
        kind: p.kind,
        callee: (m[1] || m[0]).replace(/\s*\($/, '').trim(),
        line: lineOffset + i + 1,
        sizeExpr: (arg || s).trim().slice(0, 300),
        text: s.trim().slice(0, 300)
      });
      break;
    }
    if (out.length) break;
  }
  return out;
}

function boundGuards(lines, sinkIdx, vars) {
  const g = analyzeGuards(lines, { targetVars: vars, sinkIndex: sinkIdx, from: 0 });
  const guards = g.guards.map((x) => ({
    line: x.line, kind: x.kind, condition: x.condition, targetMention: x.targetMention,
    coversSink: Boolean(x.coversSink), dead: x.dead, deadAncestor: Boolean(x.deadAncestor), exitLine: x.exitLine,
    boundLike: boundLike(x.condition, x.kind === 'call' ? x.condition : ''),
    upperBound: upperBoundLike(x.condition, x.kind === 'call' ? x.condition : '')
  }));
  const bound = guards.filter((x) => x.upperBound && x.line - 1 < sinkIdx);
  const covering = bound.filter((x) => x.coversSink && !x.dead);
  return {
    present: bound.length > 0,
    covering: covering.length > 0,
    sameVariable: covering.some((x) => x.targetMention),
    wrongVariable: bound.some((x) => !x.targetMention),
    afterSink: guards.some((x) => x.upperBound && x.line - 1 > sinkIdx),
    deadBranch: bound.some((x) => x.dead || x.deadAncestor),
    guards,
    switchGuard: null,
    details: g
  };
}

/**
 * 分析一个 parcel-read 单元。
 * @returns {object|null}
 */
function analyzeReadUnit({ root, file, read, fn, lines, window = WINDOW, entry = null }) {
  if (!fn || !lines || !lines.length) return null;
  const body = lines.slice(fn.startLine - 1, fn.endLine);
  const readIdx = read.line - fn.startLine;
  if (readIdx < 0 || readIdx >= body.length) return null;
  const vars = readValueVars(read);
  const sinks = findSinks(body, readIdx, vars, window, fn.startLine - 1);
  if (!sinks.length) return null;
  const sink = sinks[0];
  const sinkIdx = sink.line - fn.startLine;
  const checks = boundGuards(body, sinkIdx, vars);
  const bodyText = body.slice(readIdx, Math.min(body.length, sinkIdx + 1)).join('\n');
  const analysis = {
    window,
    readIndex: readIdx,
    sinkIndex: sinkIdx,
    distance: sink.line - read.line,
    vars,
    bodyText,
    checks: {
      present: checks.present,
      covering: checks.covering,
      sameVariable: checks.sameVariable,
      wrongVariable: checks.wrongVariable,
      afterSink: checks.afterSink,
      deadBranch: checks.deadBranch,
      guards: checks.guards,
      switchGuard: checks.switchGuard
    },
    bounded: checks.covering && !checks.deadBranch,
    sizeArithmetic: /\*|\+|-|<<|>>/.test(sink.sizeExpr),
    sinkKind: sink.kind
  };
  const unitId = `P1U-${sha256(`${root}\u0000${file}\u0000${read.line}\u0000${sink.line}`).slice(0, 12)}`;
  const record = {
    candidateId: `cd_P1_${sha256(`${root}\u0000${file}\u0000${read.line}\u0000${read.var}`).slice(0, 12)}`,
    class: 'P1',
    generator: 'G-P1+window80',
    unitId,
    originKind: 'target',
    inTarget: true,
    codeState: 'current-head',
    constructed: false,
    componentRoot: root,
    file,
    line: read.line,
    source: {
      kind: read.kind,
      api: read.api,
      var: read.var,
      vars,
      file,
      line: read.line,
      text: String(read.text || '').trim().slice(0, 300)
    },
    origin: {
      file,
      line: read.line,
      kind: read.kind,
      api: read.api,
      var: read.var,
      text: String(read.text || '').trim().slice(0, 300)
    },
    signal: {
      readApi: read.api,
      readVar: read.var,
      useSink: {
        callee: sink.callee,
        kind: sink.kind,
        line: sink.line,
        sizeExpr: sink.sizeExpr
      },
      sinkKinds: [`${sink.callee}:${sink.kind}`],
      windowLines: window,
      boundCheckInWindow: checks.present,
      boundCheckBasis: 'source-window',
      entryBinding: (entry && entry.bindingScope === 'path-scoped') ? 'path-scoped-entry' : 'module-inherited-entry',
      lifecycleEvidence: null
    },
    sink: {
      kind: sink.kind,
      callee: sink.callee,
      file,
      line: sink.line,
      sizeExpr: sink.sizeExpr,
      text: sink.text
    },
    window: {
      radius: window,
      fileVisible: true,
      function: { name: fn.name, owner: fn.owner || null, startLine: fn.startLine, endLine: fn.endLine }
    },
    boundCheck: {
      present: analysis.checks.present,
      covering: analysis.checks.covering,
      sameVariable: analysis.checks.sameVariable,
      wrongVariable: analysis.checks.wrongVariable,
      afterSink: analysis.checks.afterSink,
      deadBranch: analysis.checks.deadBranch,
      basis: 'source-window',
      guards: analysis.checks.guards,
      switchGuard: analysis.checks.switchGuard
    },
    analysis,
    entry: entry || { id: null, kind: null, repo: root, file: null, line: null, bindingScope: 'unknown' },
    evidenceRefs: [
      `index/parcel-reads.jsonl#${file}:${read.line}`,
      `index/alloc-sites.jsonl#${file}:${sink.line}`,
      `OpenHarmony/${root}/${file}#L${sink.line}`
    ],
    provenance: null
  };
  record.provenance = provenanceOf(record);
  return record;
}

let P1_ENTRY_INDEX = null;

function loadEntriesByRoot() {
  if (P1_ENTRY_INDEX) return P1_ENTRY_INDEX;
  const entries = readJsonlSafe(path.join(TOOL_ROOT, 'result', 'latest', 'contracts', 'entries.jsonl'));
  const byRoot = new Map();
  for (const e of entries) {
    const f = e && e.origin && e.origin.file ? String(e.origin.file) : '';
    if (!f) continue;
    for (const root of D4_ROOTS) {
      if (f.startsWith(`${root}/`)) {
        if (!byRoot.has(root)) byRoot.set(root, []);
        byRoot.get(root).push(e);
        break;
      }
    }
  }
  for (const list of byRoot.values()) {
    list.sort((a, b) => {
      const rank = (k) => (k === 'napi' ? 0 : k === 'ipc-remote' ? 1 : k === 'socket' ? 2 : 3);
      return rank(a.kind || a.entryKind) - rank(b.kind || b.entryKind) || String(a.id).localeCompare(String(b.id));
    });
  }
  P1_ENTRY_INDEX = byRoot;
  return byRoot;
}

function entryForRoot(root) {
  const list = loadEntriesByRoot().get(root) || [];
  const e = list[0];
  if (!e) return { id: null, kind: null, repo: root, file: null, line: null, bindingScope: 'unknown' };
  return {
    id: e.id,
    kind: e.kind || e.entryKind || null,
    repo: root,
    file: e.origin.file,
    line: e.origin.line || null,
    bindingScope: 'module-inherited',
    basis: 'component-root-entry'
  };
}

function existingSeed(candidates) {
  return (candidates || []).find((c) => c && c.patternClass === 'P1') || null;
}

/**
 * 构建 P1 真实 D4 候选。
 * @param {{candidates?:Array, parcels?:Array, allocs?:Array, maxUnits?:number}} opts
 */
function buildP1Facts(opts = {}) {
  const parcels = opts.parcels || readJsonlSafe(path.join(TOOL_ROOT, 'index', 'parcel-reads.jsonl'));
  const allocs = opts.allocs || readJsonlSafe(path.join(TOOL_ROOT, 'index', 'alloc-sites.jsonl'));
  const seed = existingSeed(opts.candidates);
  const functions = require('./common').functionsIndex();
  const seen = new Set();
  const units = [];
  const parcelByFile = new Map();
  for (const p of parcels) {
    if (!p || !p.file) continue;
    if (!parcelByFile.has(p.file)) parcelByFile.set(p.file, []);
    parcelByFile.get(p.file).push(p);
  }
  const allocFiles = new Set(allocs.map((a) => a && a.file).filter(Boolean));
  const fileCandidates = [...parcelByFile.keys()].filter((f) => allocFiles.has(f));
  for (const file of fileCandidates) {
    const roots = require('./common').d4RootsForFile(file);
    if (!roots.length) continue;
    const text = readSource(sourceRelPath(roots[0], file));
    if (text == null) continue;
    const lines = linesOf(text);
    for (const read of parcelByFile.get(file)) {
      for (const root of roots) {
        if (!isD4(root)) continue;
        if (seen.has(`${root}\u0000${file}\u0000${read.line}\u0000${read.var}`)) continue;
        const fn = enclosingFunction(root, file, read.line);
        if (!fn) continue;
        const entry = entryForRoot(root);
        const rec = analyzeReadUnit({ root, file, read, fn, lines, entry });
        if (!rec) continue;
        seen.add(`${root}\u0000${file}\u0000${read.line}\u0000${read.var}`);
        units.push(rec);
      }
    }
  }
  // seed 保留原 candidateId，但用新窗口/源码事实重算。
  if (seed) {
    const root = seed.componentRoot;
    const fullFile = sourceRelPath(root, seed.origin.file);
    const file = fullFile.startsWith(`${root}/`) ? fullFile.slice(root.length + 1) : fullFile;
    const line = seed.origin.line;
    const fn = enclosingFunction(root, file, line);
    const text = readSource(fullFile);
    if (fn && text != null) {
      const read = { ...seed.origin, file, line };
      const rec = analyzeReadUnit({
        root, file, read, fn, lines: linesOf(text),
        entry: {
          id: seed.entryId,
          kind: (seed.entryIds && seed.entryIds.length) ? 'napi' : null,
          repo: root,
          file,
          line,
          bindingScope: seed.signal && seed.signal.entryBinding === 'module-inherited-entry' ? 'module-inherited' : 'path-scoped'
        }
      });
      if (rec) {
        rec.candidateId = seed.candidateId;
        rec.generator = 'G-P1';
        rec.isSeed = true;
        rec.originCandidate = {
          candidateId: seed.candidateId,
          entryId: seed.entryId,
          signal: seed.signal,
          binding: seed.binding
        };
        rec.boundCheck.originalSignal = {
          boundCheckInWindow: seed.signal && seed.signal.boundCheckInWindow,
          windowLines: seed.signal && seed.signal.windowLines,
          useSink: seed.signal && seed.signal.useSink
        };
        const idx = units.findIndex((u) => u.componentRoot === root && u.file === file && u.line === line);
        if (idx >= 0) units[idx] = rec;
        else units.unshift(rec);
      }
    }
  }
  // 同一 root cause 多行只算一个 unit：按 component/file/sinkLine 去重，保留 seed 优先。
  units.sort((a, b) => (b.isSeed ? 1 : 0) - (a.isSeed ? 1 : 0)
    || a.componentRoot.localeCompare(b.componentRoot)
    || a.file.localeCompare(b.file)
    || a.line - b.line);
  const seenSink = new Set();
  const deduped = [];
  for (const u of units) {
    const k = `${u.componentRoot}\u0000${u.file}\u0000${u.sink.line}`;
    if (seenSink.has(k)) continue;
    seenSink.add(k);
    deduped.push(u);
  }
  units.length = 0;
  units.push(...deduped);
  const realUnits = units.length;
  const bounded = units.filter((u) => u.analysis.bounded).length;
  const unbounded = units.filter((u) => !u.analysis.bounded && !u.analysis.checks.afterSink && !u.analysis.checks.wrongVariable).length;
  const byRoot = units.reduce((a, u) => { a[u.componentRoot] = (a[u.componentRoot] || 0) + 1; return a; }, {});
  return {
    units,
    summary: {
      class: 'P1',
      windowLines: WINDOW,
      realD4Candidates: realUnits,
      seedPresent: Boolean(seed),
      bounded,
      unbounded,
      checkAfterSink: units.filter((u) => u.analysis.checks.afterSink).length,
      wrongVariableCheck: units.filter((u) => u.analysis.checks.wrongVariable).length,
      byRoot,
      candidateRecallGap: realUnits < 8,
      recallNote: realUnits < 8 ? 'real D4 P1 units < 8; fixtures fill the calibration set; no synthetic target candidates' : null
    }
  };
}

module.exports = {
  WINDOW, SINK_PATTERNS, readValueVars, boundLike, upperBoundLike, findSinks, analyzeReadUnit, buildP1Facts,
  loadEntriesByRoot, entryForRoot
};
