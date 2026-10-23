'use strict';

/**
 * facts-p7.js —— P7（拒绝服务）数据适配。
 *
 * 复用 G-P7 候选的 dosClass / dosGate / amplification static-proxy，
 * 再用源码窗口独立核对“上界/限流”证据（不把窗口内出现 length() 当成限流）。
 *
 * 纪律：
 *   - amplification.basis 固定 static-proxy，不写实测比率；
 *   - module-inherited 的 cross-app-impact 只算模块级线索，不算真实跨应用；
 *   - T4 必须有 literal cap / limiter / 明确非攻击者可控。
 */

const path = require('path');
const {
  D4_ROOTS, isD4, readSource, sourceRelPath, linesOf, enclosingFunction, lineWindow,
  stripLine, isCommentLine, hasValidationCall, stratifiedSample, provenanceOf, sha256,
  readJsonlSafe, TOOL_ROOT
} = require('./common');

const DOS_CLASSES = Object.freeze(['unbounded-loop', 'unbounded-alloc', 'blocking-hold', 'amplification']);
const WINDOW = 60;

function sourceWindowAt(root, file, line, radius = WINDOW) {
  const text = readSource(sourceRelPath(root, file));
  if (text == null) return { lines: [], startLine: 0, text: '', reason: 'source-missing' };
  const lines = linesOf(text);
  const w = lineWindow(lines, line, radius);
  return { lines: w.lines, startLine: w.startLine, endLine: w.endLine, text: w.lines.join('\n'), reason: null };
}

function capEvidence(windowText, signal, dosClass) {
  const text = String(windowText || '');
  const literalCaps = [];
  const re = /\b([A-Z][A-Z0-9_]*(?:MAX|LIMIT|CAP|SIZE|BOUND)[A-Z0-9_]*|MAX_[A-Z0-9_]+|[A-Z0-9_]+_MAX)\b/g;
  let m;
  while ((m = re.exec(text))) literalCaps.push(m[1]);
  const comparisons = [];
  for (const line of text.split(/\r?\n/)) {
    const s = stripLine(line);
    if (!s) continue;
    if (/<=?\s*[A-Z0-9_]{3,}/.test(s) || />=?\s*[A-Z0-9_]{3,}/.test(s)) comparisons.push(s.trim().slice(0, 180));
  }
  const limiter = /\b(RateLimit|Throttle|CheckLimit|TryAcquire|Acquire.*Limit|max[A-Z]\w*Size|MAX_[A-Z_]+|Limit\s*\()/.test(text);
  const boundedByInput = /\.length\(\)|\.size\(\)|\.count\(\)|\bcount\b|\blen\b/.test(String((signal && signal.conditionText) || ''));
  const fixedCap = literalCaps.length > 0 || limiter;
  const t4 = fixedCap || (
    signal && signal.boundedInWindow === true
    && dosClass === 'unbounded-loop'
    && !(signal.containerOpsInside > 0)
    && !(signal.allocCallsInside > 0)
    && !(signal.nestedLoops > 0)
  );
  return {
    literalCaps: [...new Set(literalCaps)].slice(0, 8),
    comparisons: comparisons.slice(0, 6),
    limiter,
    boundedByInput,
    fixedCap,
    t4,
    basis: fixedCap ? 'literal-or-limiter' : (t4 ? 'bounded-by-input-length' : 'none')
  };
}

function criteriaOf(signal) {
  const gate = (signal && signal.dosGate) || {};
  const detail = gate.criteriaDetail || {};
  const amps = signal && signal.amplification ? signal.amplification : null;
  const cross = detail['cross-app-impact'] || {};
  const persistence = detail.persistence || {};
  const amplification = detail.amplification || {};
  return {
    raw: gate.criteria || [],
    amplification: {
      met: Boolean(amplification.met),
      computable: amplification.computable !== false,
      basis: 'static-proxy',
      ratio: amps ? amps.ratio : null,
      note: '静态代理，不是实测放大比'
    },
    persistence: {
      met: Boolean(persistence.met),
      machineCheckable: Boolean(persistence.machineCheckable),
      basis: 'not-machine-checkable'
    },
    crossAppImpact: {
      met: Boolean(cross.met),
      checked: Boolean(cross.checked),
      basis: cross.basis || null,
      moduleInherited: (cross.basis || '') === 'module-inherited-entry',
      caveat: cross.caveat || null
    },
    anyMet: Boolean(amplification.met || persistence.met || cross.met)
  };
}

function analyzeP7Candidate(c, opts = {}) {
  const root = c.componentRoot;
  const file = c.origin.file;
  const line = c.origin.line;
  const dosClass = (c.signal && c.signal.dosClass) || null;
  const win = sourceWindowAt(root, file, line, opts.window || WINDOW);
  const cap = capEvidence(win.text, c.signal, dosClass);
  const criteria = criteriaOf(c.signal);
  const entryBinding = (c.signal && c.signal.entryBinding) || (c.binding && c.binding.status) || 'unknown';
  const pathScoped = entryBinding === 'path-scoped' || entryBinding === 'contract-entry';
  const unitId = `P7U-${sha256(`${c.candidateId}`).slice(0, 12)}`;
  const record = {
    candidateId: c.candidateId,
    class: 'P7',
    generator: 'G-P7',
    unitId,
    origin: 'target',
    inTarget: true,
    codeState: 'current-head',
    constructed: false,
    componentRoot: root,
    file,
    line,
    dosClass,
    source: {
      kind: (c.signal && c.signal.sourceKind) || (c.origin && c.origin.kind) || null,
      file,
      line,
      text: (c.origin && c.origin.text) || null,
      attackerControlled: Boolean((c.signal && c.signal.sizeTokens && c.signal.sizeTokens.length) || cap.boundedByInput),
      sizeTokens: (c.signal && c.signal.sizeTokens) || []
    },
    signal: {
      dosClass,
      dosGate: (c.signal && c.signal.dosGate) || null,
      sourceKind: (c.signal && c.signal.sourceKind) || null,
      sizeTokens: (c.signal && c.signal.sizeTokens) || [],
      boundedInWindow: Boolean(c.signal && c.signal.boundedInWindow),
      amplification: c.signal && c.signal.amplification ? { ...c.signal.amplification, basis: 'static-proxy' } : null,
      entryBinding: (c.signal && c.signal.entryBinding) || null,
      attackerPositionBasis: (c.signal && c.signal.attackerPositionBasis) || null
    },
    structure: {
      loopKind: c.signal && c.signal.loopKind,
      conditionText: c.signal && c.signal.conditionText,
      bodyLines: c.signal && c.signal.bodyLines,
      nestedLoops: c.signal && c.signal.nestedLoops,
      containerOpsInside: c.signal && c.signal.containerOpsInside,
      allocCallsInside: c.signal && c.signal.allocCallsInside,
      allocKind: c.signal && c.signal.allocKind,
      holdKind: c.signal && c.signal.holdKind,
      sizeArgText: c.signal && c.signal.sizeArgText,
      boundedInWindow: c.signal && c.signal.boundedInWindow
    },
    bound: {
      sourceWindow: { startLine: win.startLine, endLine: win.endLine, visible: win.reason == null },
      ...cap
    },
    amplification: {
      numerator: c.signal && c.signal.amplification ? c.signal.amplification.numerator : null,
      denominator: c.signal && c.signal.amplification ? c.signal.amplification.denominator : null,
      ratio: c.signal && c.signal.amplification ? c.signal.amplification.ratio : null,
      basis: 'static-proxy',
      note: '静态代理，不是实测放大比；报告不得写成 10× 实测'
    },
    criteria,
    entry: {
      id: c.entryId || null,
      kind: (c.entryIds && c.entryIds.length) ? 'ipc-entry' : null,
      repo: root,
      file: (c.binding && c.binding.entryIds && c.binding.entryIds[0]) || null,
      line: line,
      bindingScope: pathScoped ? 'path-scoped' : 'module-inherited',
      bindingStatus: (c.binding && c.binding.status) || 'unknown'
    },
    verdictHint: null,
    evidenceRefs: [`result/latest/candidates.jsonl#${c.candidateId}`, `OpenHarmony/${root}/${file}#L${line}`],
    provenance: null
  };
  record.provenance = provenanceOf(record);
  return record;
}

function buildP7Facts(opts = {}) {
  const candidates = (opts.candidates || []).filter((c) => c && c.patternClass === 'P7'
    && isD4(c.componentRoot));
  const units = candidates.map((c) => analyzeP7Candidate(c, opts));
  const byClass = {};
  const byRoot = {};
  for (const u of units) {
    byClass[u.dosClass] = (byClass[u.dosClass] || 0) + 1;
    byRoot[u.componentRoot] = (byRoot[u.componentRoot] || 0) + 1;
  }
  return {
    units,
    summary: {
      class: 'P7',
      realD4Candidates: units.length,
      byDosClass: byClass,
      byRoot,
      amplificationCandidates: units.filter((u) => u.dosClass === 'amplification').length,
      recallNote: (byClass.amplification || 0) < 6
        ? 'D4 amplification 候选不足 6；amplification claims 由 fixture 补齐，fixture 不进入 D4 统计'
        : null
    }
  };
}

/**
 * 分层抽样：每类 6 条，尽量跨 root/文件；amplification 不足时由 fixture 补。
 */
function selectP7Claims(units, perClass = 6) {
  const selected = [];
  for (const cls of DOS_CLASSES) {
    const list = units.filter((u) => u.dosClass === cls);
    const sample = stratifiedSample(list, perClass, (u) => `${u.componentRoot}`, (u) => u.candidateId);
    selected.push(...sample);
  }
  return selected;
}

module.exports = {
  DOS_CLASSES, WINDOW, sourceWindowAt, capEvidence, criteriaOf, analyzeP7Candidate, buildP7Facts, selectP7Claims
};
