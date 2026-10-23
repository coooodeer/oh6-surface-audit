'use strict';

/**
 * facts-p8.js —— P8（逻辑漏洞）数据适配：state write / return / lifecycle + invariant 适用性。
 *
 * 两种已有 pattern（INV-PAT-STATE-GUARD / INV-PAT-RETURN-CONTRACT）来自
 * oh6-vuln-agent/spec/invariants.yaml；第三种 INV-PAT-LIFECYCLE 由本目标补在
 * lib/p1p2p7p8/invariants.js（authority 指向 history-invariants 的 lifetime-guard-added 42 条）。
 *
 * 纪律：函数内“没有校验调用”只是候选信号；必须证明 invariant 适用 + 写点 + 守卫覆盖，
 * 否则只能 T3，不能硬套 T2。
 */

const {
  isD4, readSource, sourceRelPath, linesOf, stripLine, isCommentLine,
  analyzeGuards, switchCaseGuard, hasValidationCall, hasLifecycleOp, mentions,
  stratifiedSample, provenanceOf, sha256
} = require('./common');
const { INVARIANTS } = require('./invariants');

const P8_PATTERNS = Object.freeze({
  STATE_GUARD: 'INV-PAT-STATE-GUARD',
  RETURN_CONTRACT: 'INV-PAT-RETURN-CONTRACT',
  LIFECYCLE: 'INV-PAT-LIFECYCLE'
});

const PATTERN_AUTHORITY = Object.freeze({
  'INV-PAT-STATE-GUARD': 'oh6-vuln-agent/spec/invariants.yaml#INV-PAT-STATE-GUARD / propositionsByCode:P-STATE-MACHINE-LEGAL / history state-guard-added (7)',
  'INV-PAT-RETURN-CONTRACT': 'oh6-vuln-agent/spec/invariants.yaml#INV-PAT-RETURN-CONTRACT / propositionsByCode:P-STATE-MACHINE-LEGAL / history return paths',
  'INV-PAT-LIFECYCLE': 'lib/p1p2p7p8/invariants.js#INV-PAT-LIFECYCLE / history lifetime-guard-added (42) / P2 lifecycle anchor semantics'
});

function resolveFile(root, file) {
  return String(file).startsWith(`${root}/`) ? String(file).slice(root.length + 1) : String(file);
}

function bodyOf(c, root) {
  const fn = c.origin.function;
  if (!fn || !fn.startLine) return { lines: [], startLine: 0, endLine: 0, reason: 'function-range-missing' };
  const text = readSource(sourceRelPath(root, c.origin.file));
  if (text == null) return { lines: [], startLine: 0, endLine: 0, reason: 'source-missing' };
  const lines = linesOf(text);
  return {
    lines: lines.slice(fn.startLine - 1, fn.endLine),
    startLine: fn.startLine,
    endLine: fn.endLine,
    name: fn.name,
    reason: null
  };
}

function stateVarOf(text) {
  const s = String(text || '');
  const m = /^\s*(?:this->)?([A-Za-z_][A-Za-z0-9_]*(?:_|\.)?[A-Za-z0-9_]*)\s*(?:=|\+\+|--)/.exec(s);
  if (m) return m[1];
  const m2 = /(?:this->|\.)([A-Za-z_][A-Za-z0-9_]*)\s*=/.exec(s);
  return m2 ? m2[1] : null;
}

function lifecycleOpOf(bodyText) {
  const lines = String(bodyText || '').split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    if (isCommentLine(lines[i])) continue;
    if (hasLifecycleOp(lines[i])) return { line: i + 1, text: stripLine(lines[i]).trim().slice(0, 200) };
  }
  return null;
}

function patternFor(c) {
  const id = c.signal && c.signal.invariantPattern && c.signal.invariantPattern.id;
  if (id) return id;
  if (c.signal && c.signal.invariantContractRef) return c.signal.invariantContractRef;
  return null;
}

function analyzeP8Candidate(c, opts = {}) {
  const root = c.componentRoot;
  const body = bodyOf(c, root);
  const lines = body.lines;
  let writeLine = c.origin.line - body.startLine;
  if (writeLine < 0 || writeLine >= lines.length) writeLine = 0;
  let writeText = lines[writeLine] || '';
  const pattern = patternFor(c);
  let stateVar = stateVarOf(writeText);
  // origin 有时指向 if/return 行；把 sink 下移到同一状态变量的真实写点。
  if (stateVar && pattern === P8_PATTERNS.STATE_GUARD) {
    const re = new RegExp(`(?:^|[^=!<>])\\b${stateVar.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*=(?!=)`);
    for (let i = writeLine; i < Math.min(lines.length, writeLine + 8); i += 1) {
      if (re.test(stripLine(lines[i]))) { writeLine = i; writeText = lines[i]; break; }
    }
  }
  const targetVars = stateVar ? [stateVar] : [];
  const guards = lines.length
    ? analyzeGuards(lines, { targetVars, sinkIndex: writeLine, from: 0 })
    : { guards: [], before: [], after: [], covering: [], sameVariableDominating: [], wrongVariableDominating: [], deadBranch: [], anyGuardBefore: false, hasCovering: false, hasSameVariableDominating: false, checkAfterSink: false };
  const switchGuard = lines.length ? switchCaseGuard(lines, writeLine) : null;
  const fullFunctionVisible = body.reason == null && lines.length > 0;
  const around = lines.slice(Math.max(0, writeLine - 3), Math.min(lines.length, writeLine + 4)).join('\n');
  const validationCalls = hasValidationCall(body.lines.join('\n'));
  let invariantApplicable = false;
  let applicabilityReason = null;
  if (pattern === P8_PATTERNS.STATE_GUARD || pattern === P8_PATTERNS.LIFECYCLE) {
    invariantApplicable = lines.length >= 2;
    applicabilityReason = invariantApplicable ? 'state-or-lifecycle-write-in-visible-function' : 'function-too-small';
  } else if (pattern === P8_PATTERNS.RETURN_CONTRACT) {
    // 纯空桩（函数体只有 return ERR_OK）没有内部状态，invariant 不适用。
    const meaningful = lines.filter((l) => {
      const s = stripLine(l).trim();
      return s && !/^[{}]+$/.test(s) && !/^return\s+(?:ERR_OK|0|true)\s*;/.test(s);
    });
    invariantApplicable = meaningful.length > 0 || lines.length > 2;
    applicabilityReason = invariantApplicable ? 'function-has-internal-state-or-error-path' : 'stub-without-internal-state';
  }
  if (pattern === P8_PATTERNS.LIFECYCLE) {
    const op = lifecycleOpOf(body.lines.join('\n'));
    invariantApplicable = Boolean(op);
    applicabilityReason = op ? 'lifetime-operation-in-function' : 'no-lifetime-operation';
  }
  let covering = (guards.covering || []).filter((g) => g.targetMention && !g.dead && !g.deadAncestor);
  let sameCovering = covering.filter((g) => g.targetMention);
  if (pattern === P8_PATTERNS.RETURN_CONTRACT && !stateVar) {
    // return-contract 没有单一状态变量：任何“检查失败即退出”的守卫都覆盖该 return。
    sameCovering = (guards.guards || []).filter((g) => g.exitBeforeSink && !g.dead && !g.deadAncestor
      && /Check|Verify|Is[A-Z]|[<>]=?|==|!=|empty\s*\(|nullptr|NULL/.test(g.condition));
    covering = sameCovering;
  }
  const switchCoversState = Boolean(switchGuard && pattern === P8_PATTERNS.STATE_GUARD);
  const covered = sameCovering.length > 0 || switchCoversState;
  const after = (guards.after || []).filter((g) => g.targetMention);
  const wrong = (guards.wrongVariableDominating || []).filter((g) => !g.targetMention);
  const dead = (guards.deadBranch || []).filter((g) => g.targetMention);
  let guardStatus;
  let guardReason = null;
  if (!invariantApplicable) {
    guardStatus = 'proven';
    guardReason = 'invariant-not-applicable';
  } else if (covered) {
    guardStatus = 'proven';
  } else if (after.length) {
    guardStatus = 'disproven';
    guardReason = 'check-after-write';
  } else if (wrong.length) {
    guardStatus = 'disproven';
    guardReason = 'wrong-state-check';
  } else if (dead.length) {
    guardStatus = 'disproven';
    guardReason = 'check-in-dead-branch';
  } else if (fullFunctionVisible) {
    guardStatus = 'disproven';
    guardReason = 'no-guard-before-write';
  } else {
    guardStatus = 'unproven';
    guardReason = 'function-window-missing';
  }
  const unitId = `P8U-${sha256(`${c.candidateId}`).slice(0, 12)}`;
  const record = {
    candidateId: c.candidateId,
    class: 'P8',
    generator: 'G-P8',
    unitId,
    origin: 'target',
    inTarget: true,
    codeState: 'current-head',
    constructed: false,
    componentRoot: root,
    file: c.origin.file,
    line: c.origin.line,
    invariant: {
      pattern,
      authority: PATTERN_AUTHORITY[pattern] || 'unproven-pattern',
      applicable: invariantApplicable,
      applicabilityReason
    },
    signal: {
      stateWriteKinds: [c.origin.kind],
      functionHasNoValidationLikeCall: Boolean(c.signal && c.signal.functionHasNoValidationLikeCall),
      checksInFunction: 0,
      invariantPattern: {
        id: pattern,
        text: (INVARIANTS[pattern] || {}).text || null,
        authority: PATTERN_AUTHORITY[pattern] || null
      },
      invariantContractRef: pattern,
      entryBinding: (c.signal && c.signal.entryBinding) || null
    },
    source: {
      kind: c.origin.kind,
      file: c.origin.file,
      line: c.origin.line,
      text: String(writeText).trim().slice(0, 300),
      stateVar,
      function: { name: body.name || (c.origin.function && c.origin.function.name), startLine: body.startLine, endLine: body.endLine }
    },
    sink: {
      kind: c.origin.kind,
      file: c.origin.file,
      line: c.origin.line,
      stateVar,
      lifecycleOp: pattern === P8_PATTERNS.LIFECYCLE ? lifecycleOpOf(body.lines.join('\n')) : null
    },
    analysis: {
      fullFunctionVisible,
      validationLikeCallInFunction: validationCalls,
      generatorSaysNoValidationCall: Boolean(c.signal && c.signal.functionHasNoValidationCall),
      guards: (guards.guards || []).map((g) => ({
        line: g.line, kind: g.kind, condition: g.condition, targetMention: g.targetMention,
        coversSink: Boolean(g.coversSink), dead: Boolean(g.dead), deadAncestor: Boolean(g.deadAncestor)
      })).slice(0, 8),
      switchGuard,
      covering: sameCovering.map((g) => ({ line: g.line, condition: g.condition })),
      after: after.map((g) => ({ line: g.line, condition: g.condition })),
      wrong: wrong.map((g) => ({ line: g.line, condition: g.condition })),
      dead: dead.map((g) => ({ line: g.line, condition: g.condition })),
      guardStatus,
      guardReason
    },
    entry: {
      id: c.entryId || null,
      kind: (c.entryIds && c.entryIds.length) ? 'ipc-entry' : null,
      repo: root,
      file: c.origin.file,
      line: c.origin.line,
      bindingScope: (c.signal && c.signal.entryBinding === 'module-inherited-entry') ? 'module-inherited' : 'path-scoped',
      bindingStatus: (c.binding && c.binding.status) || 'unknown'
    },
    evidenceRefs: [`result/latest/candidates.jsonl#${c.candidateId}`, `OpenHarmony/${root}/${c.origin.file}#L${c.origin.line}`],
    provenance: null
  };
  record.provenance = provenanceOf(record);
  return record;
}

function buildP8Facts(opts = {}) {
  const candidates = (opts.candidates || []).filter((c) => c && c.patternClass === 'P8' && isD4(c.componentRoot));
  const units = candidates.map((c) => analyzeP8Candidate(c, opts));
  // 第三种 pattern：从“函数含 lifetime operation”的 P8 候选里重标 INV-PAT-LIFECYCLE。
  const lifeCandidates = candidates.filter((c) => {
    const body = bodyOf(c, c.componentRoot);
    return body.lines.length && lifecycleOpOf(body.lines.join('\n'));
  });
  const lifePick = stratifiedSample(lifeCandidates, opts.lifecycleCount || 12, (c) => c.componentRoot, (c) => c.candidateId);
  const lifeIds = new Set(lifePick.map((c) => c.candidateId));
  for (const c of lifePick) {
    const u = makeLifecycleUnit(c);
    if (u) units.push(u);
  }
  const byPattern = {};
  const byRoot = {};
  for (const u of units) {
    byPattern[u.invariant.pattern] = (byPattern[u.invariant.pattern] || 0) + 1;
    byRoot[u.componentRoot] = (byRoot[u.componentRoot] || 0) + 1;
  }
  return {
    units,
    lifecycleCandidateIds: [...lifeIds],
    summary: {
      class: 'P8',
      realD4Candidates: candidates.length,
      byPattern,
      byRoot,
      patterns: Object.values(P8_PATTERNS),
      thirdPattern: P8_PATTERNS.LIFECYCLE,
      recordsWithLifetimeOp: lifeCandidates.length,
      recallNote: null
    }
  };
}

/** 把一个含 lifetime operation 的 P8 候选重标成 INV-PAT-LIFECYCLE。 */
function makeLifecycleUnit(c) {
  const root = c.componentRoot;
  const body = bodyOf(c, root);
  if (!body.lines.length) return null;
  const op = lifecycleOpOf(body.lines.join('\n'));
  if (!op) return null;
  const opIdx = op.line - 1;
  const varMatch = /\b(?:delete|free|Release|Reset|erase|clear)\s*[( ]\s*(?:this->)?([A-Za-z_][A-Za-z0-9_]*)/.exec(op.text);
  const targetVars = varMatch ? [varMatch[1]] : [];
  const guards = analyzeGuards(body.lines, { targetVars, sinkIndex: opIdx, from: 0 });
  const covering = (guards.covering || []).filter((g) => g.targetMention && !g.dead && !g.deadAncestor);
  const fullVisible = body.reason == null;
  let guardStatus;
  let guardReason = null;
  if (covering.length) guardStatus = 'proven';
  else if (fullVisible) { guardStatus = 'disproven'; guardReason = 'no-lifetime-guard-before-operation'; }
  else { guardStatus = 'unproven'; guardReason = 'function-window-missing'; }
  const unitId = `P8U-${sha256(`${c.candidateId}\u0000LIFECYCLE`).slice(0, 12)}`;
  const record = {
    candidateId: c.candidateId,
    class: 'P8',
    generator: 'G-P8+lifecycle',
    unitId,
    origin: 'target',
    inTarget: true,
    codeState: 'current-head',
    constructed: false,
    componentRoot: root,
    file: c.origin.file,
    line: body.startLine + opIdx,
    invariant: {
      pattern: P8_PATTERNS.LIFECYCLE,
      authority: PATTERN_AUTHORITY[P8_PATTERNS.LIFECYCLE],
      applicable: true,
      applicabilityReason: 'lifetime-operation-in-function'
    },
    signal: {
      stateWriteKinds: [c.origin.kind],
      functionHasNoValidationLikeCall: Boolean(c.signal && c.signal.functionHasNoValidationLikeCall),
      checksInFunction: 0,
      invariantPattern: {
        id: P8_PATTERNS.LIFECYCLE,
        text: INVARIANTS[P8_PATTERNS.LIFECYCLE].text,
        authority: PATTERN_AUTHORITY[P8_PATTERNS.LIFECYCLE]
      },
      invariantContractRef: P8_PATTERNS.LIFECYCLE,
      entryBinding: (c.signal && c.signal.entryBinding) || null
    },
    source: {
      kind: 'lifetime-op',
      file: c.origin.file,
      line: body.startLine + opIdx,
      text: op.text,
      stateVar: targetVars[0] || null,
      function: { name: body.name || (c.origin.function && c.origin.function.name), startLine: body.startLine, endLine: body.endLine }
    },
    sink: { kind: 'lifetime-op', file: c.origin.file, line: body.startLine + opIdx, stateVar: targetVars[0] || null, lifecycleOp: op },
    analysis: {
      fullFunctionVisible: fullVisible,
      validationLikeCallInFunction: hasValidationCall(body.lines.join('\n')),
      generatorSaysNoValidationCall: Boolean(c.signal && c.signal.functionHasNoValidationCall),
      guards: (guards.guards || []).map((g) => ({
        line: g.line, kind: g.kind, condition: g.condition, targetMention: g.targetMention,
        coversSink: Boolean(g.coversSink), dead: Boolean(g.dead), deadAncestor: Boolean(g.deadAncestor)
      })).slice(0, 8),
      switchGuard: null,
      covering: covering.map((g) => ({ line: g.line, condition: g.condition })),
      after: (guards.after || []).filter((g) => g.targetMention).map((g) => ({ line: g.line, condition: g.condition })),
      wrong: (guards.wrongVariableDominating || []).map((g) => ({ line: g.line, condition: g.condition })),
      dead: (guards.deadBranch || []).map((g) => ({ line: g.line, condition: g.condition })),
      guardStatus,
      guardReason
    },
    entry: {
      id: c.entryId || null,
      kind: (c.entryIds && c.entryIds.length) ? 'ipc-entry' : null,
      repo: root,
      file: c.origin.file,
      line: c.origin.line,
      bindingScope: (c.signal && c.signal.entryBinding === 'module-inherited-entry') ? 'module-inherited' : 'path-scoped',
      bindingStatus: (c.binding && c.binding.status) || 'unknown'
    },
    evidenceRefs: [`result/latest/candidates.jsonl#${c.candidateId}`, `OpenHarmony/${root}/${c.origin.file}#L${body.startLine + opIdx}`],
    provenance: null
  };
  record.provenance = provenanceOf(record);
  return record;
}

/** 24 claims：8 STATE-GUARD + 8 RETURN-CONTRACT + 8 LIFECYCLE（不足时回退到现有 pattern）。 */
function selectP8Claims(units, perPattern = 8) {
  const selected = [];
  const lifecycleUnits = units.filter((u) => u.invariant.pattern === P8_PATTERNS.LIFECYCLE);
  const lifeIds = new Set(lifecycleUnits.map((u) => u.candidateId));
  const state = units.filter((u) => u.invariant.pattern === P8_PATTERNS.STATE_GUARD && !lifeIds.has(u.candidateId));
  const ret = units.filter((u) => u.invariant.pattern === P8_PATTERNS.RETURN_CONTRACT && !lifeIds.has(u.candidateId));
  selected.push(...stratifiedSample(state, perPattern, (u) => u.componentRoot, (u) => u.candidateId));
  selected.push(...stratifiedSample(ret, perPattern, (u) => u.componentRoot, (u) => u.candidateId));
  selected.push(...stratifiedSample(lifecycleUnits, perPattern, (u) => u.componentRoot, (u) => u.candidateId));
  // 不足 24 时用剩余候选补齐（仍保持 >=3 种 pattern）。
  if (selected.length < perPattern * 3) {
    const rest = stratifiedSample(units.filter((u) => !selected.includes(u)), perPattern * 3 - selected.length,
      (u) => u.componentRoot, (u) => u.candidateId);
    selected.push(...rest);
  }
  return selected.slice(0, perPattern * 3);
}

module.exports = {
  P8_PATTERNS, PATTERN_AUTHORITY, resolveFile, stateVarOf, lifecycleOpOf, analyzeP8Candidate, buildP8Facts, selectP8Claims
};
