'use strict';

/**
 * lib/autonomy/retrieval.js —— ContextPacket（P5）。
 *
 * 一块上下文只含"能回查的事实"：入口身份、绑定候选、函数窗口（≤80 行）、guards、直接调用、metadata。
 * 不含推断、不含自由文本摘要；token 用 `ceil(chars/4)` 估算（不引第三方 tokenizer）。
 */

const ids = require('./ids');
const state = require('./state');

const MAX_WINDOW_LINES = 80;
const MAX_GUARDS = 20;
const MAX_CALLS = 60;

function estimateTokens(chars) {
  return Math.ceil(chars / 4);
}

/**
 * @param {{facts:object, scope:object, task:object, anchor:object, binding:object, contextId?:string}} o
 */
function buildContext(o) {
  const { facts, task, anchor, binding } = o;
  const limits = (o.scope && o.scope.limits) || {};
  const maxWindow = Math.min(limits.maxWindowLines || MAX_WINDOW_LINES, MAX_WINDOW_LINES);

  let windowRec = null;
  let truncated = false;
  const omittedRefs = [];
  const fn = binding && binding.bound ? binding.bound : null;

  if (fn) {
    const file = fn.sourceRange && fn.sourceRange.file;
    const start = fn.startLine;
    const end = fn.endLine;
    if (file) {
      const win = facts.sourceWindow(file, start, end, { maxLines: maxWindow });
      windowRec = {
        file: win.file,
        startLine: win.startLine,
        endLine: win.endLine,
        lines: win.lines,
        sha256: win.sha256
      };
      if (win.truncated) truncated = true;
      if (win.endLine < end) omittedRefs.push(`${file}:${win.endLine + 1}-${end}`);
    }
  } else {
    truncated = true;
    omittedRefs.push(`binding:${binding ? binding.binding : 'unknown'}`);
  }

  const functionName = fn ? (fn.qualified || fn.name) : null;
  const guards = functionName
    ? facts.guardsOf(functionName, { limit: MAX_GUARDS }).map((g) => ({
      line: g.line,
      guardKind: g.guardKind,
      variables: (g.variables || []).slice(0, 8),
      dominates: !!g.dominates,
      factRef: g.factId
    }))
    : [];
  const calls = functionName
    ? [...new Set(facts.callsOf(functionName, { limit: 400 }).map((c) => c.calleeName))].sort().slice(0, MAX_CALLS)
    : [];

  const metadata = {
    entryKind: anchor ? anchor.kind : null,
    interface: anchor ? anchor.interface || null : null,
    method: anchor ? anchor.method || null : null,
    saId: anchor ? (anchor.saId === undefined ? null : anchor.saId) : null,
    module: anchor ? anchor.module || null : null,
    file: anchor ? anchor.file || null : null,
    line: anchor ? anchor.line || null : null,
    metadataRef: anchor ? anchor.metadataRef || null : null,
    implOwnerSuffix: binding ? binding.implOwnerSuffix : null
  };

  const semantic = {
    taskId: task.taskId,
    entryRef: anchor ? anchor.entityId : null,
    binding: binding ? binding.binding : 'unbound',
    window: windowRec,
    guards,
    calls,
    metadata
  };
  const contextId = ids.contextId('context', semantic);

  const serializable = {
    contextId,
    taskId: task.taskId,
    entryRef: anchor ? anchor.entityId : null,
    binding: semantic.binding,
    window: windowRec,
    guards,
    calls,
    metadata,
    estimatedInputTokens: 0,
    truncated,
    omittedRefs: ids.uniqueSorted(omittedRefs),
    sufficiency: computeSufficiency({ binding, windowRec, truncated, guards, calls })
  };
  serializable.estimatedInputTokens = estimateTokens(Buffer.byteLength(JSON.stringify(serializable), 'utf8'));
  return serializable;
}

function computeSufficiency({ binding, windowRec, truncated, guards, calls }) {
  if (!binding || binding.binding === 'unbound') return 'insufficient';
  if (!windowRec) return 'insufficient';
  if (truncated) return 'partial';
  if (!calls.length) return 'partial';
  if (!guards.length) return 'partial';
  return 'sufficient';
}

function contextRecord(context, manifestId) {
  return state.makeRecord({
    recordId: context.contextId,
    recordType: 'context',
    manifestId,
    producer: state.PRODUCERS.assessment,
    dependencyRefs: [context.entryRef, context.taskId].filter(Boolean),
    payload: context
  });
}

/** 渲染成模型可读的最小提示（只含事实，不含结论） */
function renderForModel(context) {
  const lines = [];
  lines.push(`ENTRY ${context.entryRef} kind=${context.metadata.entryKind} method=${context.metadata.method}`);
  lines.push(`BINDING ${context.binding}`);
  if (context.window) {
    lines.push(`WINDOW ${context.window.file}:${context.window.startLine}-${context.window.endLine}`);
  }
  if (context.guards.length) {
    lines.push('GUARDS ' + context.guards.map((g) => `${g.guardKind}@${g.line}(${(g.variables || []).join(',')})`).join(' '));
  }
  if (context.calls.length) lines.push(`CALLS ${context.calls.join(', ')}`);
  lines.push(`SUFFICIENCY ${context.sufficiency} truncated=${context.truncated}`);
  return lines.join('\n');
}

module.exports = { buildContext, contextRecord, renderForModel, estimateTokens, computeSufficiency, MAX_WINDOW_LINES };
