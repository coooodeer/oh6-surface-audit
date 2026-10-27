'use strict';

/**
 * lib/autonomy/tools.js —— 工具注册表 + dispatcher（P2）。
 *
 * 每个工具都返回 §5.5 ToolResult 的 **payload**（不含封套），由 dispatcher 统一：
 *   schema 校验 → 能力/作用域检查 → 预算预留 → 超时（30 s）→ 结果 ≤256 KiB
 *   → 归档 evidence/<EVID>.json（含内容哈希）→ 写 tool-ledger.jsonl。
 *
 * 6 个可用工具：getScopeOverview / searchEntities / inspectEntry / inspectRelation / getEvidence / inspectAuthorization。
 * 5 个未实现工具注册为 `unsupported` 并给具名 reason（**不得**返回空结果冒充实现）。
 */

const fs = require('fs');
const path = require('path');

const ids = require('./ids');
const jsonl = require('./jsonl');
const state = require('./state');
const delegation = require('./delegation');
const vertical = require('./vertical');
const knowledgeLib = require('./knowledge');
const permissionArgument = require('./permission-argument');
const staticProof = require('./static-proof');
const ipcVerdict = require('./ipc-verdict');
const platform = require('./platform');

const TOOL_VERSION = '1';
const DEFAULT_MAX_BYTES = 262144;
const DEFAULT_TIMEOUT_MS = 30000;

function fail(code, message, extra) {
  const e = new Error(message);
  e.code = code;
  if (extra) Object.assign(e, extra);
  return e;
}

/** 预算：工具调用与模型请求共用一个账本 */
function createBudget(policy = {}) {
  const p = { ...policy };
  return {
    policy: p,
    toolCalls: 0,
    modelRequests: 0,
    inputTokens: 0,
    outputTokens: 0,
    startedAt: Date.now(),
    perTaskToolCalls: new Map(),
    perTaskModelRequests: new Map(),
    reserveTool(taskId) {
      if (p.maxToolCalls > 0 && this.toolCalls >= p.maxToolCalls) {
        throw fail('budget-exhausted', `budget: maxToolCalls ${p.maxToolCalls} reached`);
      }
      if (p.maxTaskToolCalls > 0) {
        const n = this.perTaskToolCalls.get(taskId) || 0;
        if (n >= p.maxTaskToolCalls) {
          throw fail('budget-exhausted', `budget: maxTaskToolCalls ${p.maxTaskToolCalls} reached for ${taskId}`);
        }
      }
      this.toolCalls += 1;
      if (taskId) this.perTaskToolCalls.set(taskId, (this.perTaskToolCalls.get(taskId) || 0) + 1);
    },
    reserveModel(taskId, maxInputTokensEstimate) {
      if (p.maxModelRequests > 0 && this.modelRequests >= p.maxModelRequests) {
        throw fail('budget-exhausted', `budget: maxModelRequests ${p.maxModelRequests} reached`);
      }
      if (p.maxTaskModelRequests > 0) {
        const n = this.perTaskModelRequests.get(taskId) || 0;
        if (n >= p.maxTaskModelRequests) {
          throw fail('budget-exhausted', `budget: maxTaskModelRequests ${p.maxTaskModelRequests} reached for ${taskId}`);
        }
      }
      if (p.maxInputTokens > 0 && maxInputTokensEstimate && this.inputTokens + maxInputTokensEstimate > p.maxInputTokens) {
        throw fail('budget-exhausted', 'budget: maxInputTokens would be exceeded');
      }
      this.modelRequests += 1;
      if (taskId) this.perTaskModelRequests.set(taskId, (this.perTaskModelRequests.get(taskId) || 0) + 1);
      return { requestIndex: this.modelRequests };
    },
    settleModel({ inputTokens, outputTokens }) {
      this.inputTokens += Number(inputTokens || 0);
      this.outputTokens += Number(outputTokens || 0);
    },
    wallSeconds() {
      return (Date.now() - this.startedAt) / 1000;
    },
    exceededWall() {
      return p.maxWallSeconds > 0 && this.wallSeconds() > p.maxWallSeconds;
    }
  };
}

const UNSUPPORTED = Object.freeze({
  collectEvidence: 'runtime-witness-not-implemented: MVP 不做设备/host 证据收集',
  inspectLifetime: 'lifetime-model-not-implemented: MVP 不做生命周期分析',
  traceValue: 'dataflow-model-not-implemented: MVP 不做跨函数值追踪',
  checkSource: 'source-build-not-implemented: MVP 不做源码构建/编译校验'
});

/** 词表匹配分档：strong = 授权判定；weak = 仅身份获取/宽泛子串 */
const STRONG_CHECK_CALLEES = Object.freeze([
  'VerifyAccessToken', 'CheckSystemApp', 'IsSystemApp', 'VerifyPermission',
  'CheckCallingPermission', 'IsSystemAppOrNative', 'CheckPermission', 'IsFileManagerCalling'
]);
const WEAK_CHECK_CALLEES = Object.freeze(['AccessToken', 'Permission', 'GetCallingTokenID', 'GetCallingUid']);

function checkTier(calleeName, vocabulary) {
  const name = String(calleeName || '');
  const strong = (vocabulary && vocabulary.strong) || STRONG_CHECK_CALLEES;
  const weak = (vocabulary && vocabulary.weak) || WEAK_CHECK_CALLEES;
  if (strong.some((v) => name.includes(v))) return 'strong';
  if (weak.some((v) => name.includes(v))) return 'weak';
  return null;
}

function emptyAnswer(status, text) {
  return { status, text, basis: 'derived', assurance: 'bounded-analysis' };
}

function basePayload(tool, questionId, inputManifestId) {
  return {
    resultId: null,
    tool,
    toolVersion: TOOL_VERSION,
    status: 'ok',
    questionId: questionId || null,
    inputManifestId,
    answer: emptyAnswer('unknown', ''),
    assumptions: [],
    evidenceRefs: [],
    counterEvidenceRefs: [],
    sourceWindows: [],
    completeness: { scope: '', enumeration: 'complete', unresolvedRefs: [], truncated: false, nextCursor: null },
    missingRefs: [],
    nextActions: [],
    requiresInterpretation: false,
    usage: { wallMs: 0, bytesRead: 0, cacheHit: false }
  };
}

/** EVID 只由**语义字段**派生：不含 usage/nextActions（否则重跑会换 ID，破坏确定性） */
function evidenceIdOf(payload) {
  return ids.evidenceId('tool-result', {
    tool: payload.tool,
    toolVersion: payload.toolVersion,
    status: payload.status,
    questionId: payload.questionId,
    inputManifestId: payload.inputManifestId,
    answer: payload.answer,
    completeness: { scope: payload.completeness.scope, enumeration: payload.completeness.enumeration },
    evidenceRefs: payload.evidenceRefs,
    counterEvidenceRefs: payload.counterEvidenceRefs,
    sourceWindows: payload.sourceWindows,
    missingReasons: payload.missingRefs.length ? 'has-missing' : 'none'
  });
}

function withTimeout(promise, ms, toolName) {
  if (!(ms > 0)) return promise;
  let timer = null;
  return Promise.race([
    promise.finally(() => { if (timer) clearTimeout(timer); }),
    new Promise((_, reject) => {
      timer = setTimeout(() => {
        const e = new Error(`tools: ${toolName} timed out after ${ms} ms`);
        e.code = 'timeout';
        reject(e);
      }, ms);
      if (timer.unref) timer.unref();
    })
  ]);
}

// ---------------------------------------------------------------------------
// 工具实现
// ---------------------------------------------------------------------------

const TOOLS = {
  inspectStaticContract: {
    version: TOOL_VERSION,
    status: 'available',
    args: { entryRef: { type: 'string', required: true, minLength: 3 } },
    description: 'Return a bounded local static verdict for one verified entry',
    run(ctx, args) {
      const payload = basePayload('inspectStaticContract', ctx.questionId, ctx.facts.inputManifestId);
      payload.completeness.scope = 'entry:' + args.entryRef + ':static-contract';
      const anchor = ctx.anchors?.get(args.entryRef);
      const binding = anchor && ctx.resolveBinding(args.entryRef);
      let hit = false;
      // 1.0.20 双命题路径：契约差异 + 具体主体经实际门禁的安全裁决。
      const proof = ctx.ipcCodeVerdict
        ? ipcVerdict.analyze(ctx.facts, anchor, binding, ctx.ipcCodeVerdict)
        : ctx.securityVerdict
        ? staticProof.analyzeSecurity(ctx.facts, anchor, binding, ctx.knowledge, ctx.comparison,
          { policy: ctx.securityPolicy, cache: ctx.proofCache, includeCandidateContext: true,
            requireSaMethod: ctx.requireSaMethod,
            onCacheHit: (key) => { hit = true; ctx.onProofCacheHit?.(key); } })
        : staticProof.analyze(ctx.facts, anchor, binding, ctx.knowledge, ctx.comparison,
          { includeNewFamilies: true, includeCandidateContext: true, cache: ctx.proofCache,
            onCacheHit: (key) => { hit = true; ctx.onProofCacheHit?.(key); } });
      payload.observations = proof;
      // 旧语义：question 是契约命题（finding=契约被反驳）；新语义：question 是安全命题
      // （finding=主体可达成立，excluded=命题被反驳）。
      payload.answer = ctx.securityVerdict
        ? emptyAnswer(proof.status === 'finding' ? 'supported' :
          proof.status === 'excluded' ? 'refuted' : 'unknown',
        proof.security?.family || proof.security?.reason || proof.reason)
        : emptyAnswer(proof.status === 'finding' ? 'refuted' :
          proof.status === 'excluded' ? 'supported' : 'unknown', proof.family || proof.reason);
      payload.evidenceRefs = ids.uniqueSorted([proof.normRef, proof.reviewRef,
        proof.delegateRef, proof.checkRef, proof.operationCallRef, proof.operationRef,
        proof.saMethod?.profileRef, proof.saMethod?.serviceFactRef,
        proof.saRegistration?.profileRef, proof.saRegistration?.serviceFactRef].filter(Boolean));
      payload.completeness.enumeration = proof.status === 'insufficient' ? 'partial' : 'complete';
      payload.completeness.unresolvedRefs = proof.status === 'insufficient' ? [args.entryRef] : [];
      payload.assumptions = [proof.limitation || 'Bounded local source and published norm only.'];
      payload.nextActions = proof.status === 'insufficient' ? ['inspect-source-and-contract'] : [];
      payload.usage.cacheHit = hit;
      return payload;
    }
  },
  inspectPermissionArgument: {
    version: TOOL_VERSION,
    status: 'available',
    args: { entryRef: { type: 'string', required: true, minLength: 3 } },
    description: 'Compare one exact delegated CheckPermission argument with a sourced document permission; not an authorization verdict',
    run(ctx, args) {
      const payload = basePayload('inspectPermissionArgument', ctx.questionId, ctx.facts.inputManifestId);
      payload.completeness.scope = `entry:${args.entryRef}:permission-argument`;
      const anchor = ctx.anchors?.get(args.entryRef);
      const binding = anchor && ctx.resolveBinding(args.entryRef);
      const result = permissionArgument.compare(ctx.facts, anchor, binding, ctx.knowledge);
      payload.observations = result;
      payload.answer = emptyAnswer(result.status === 'insufficient' ? 'unknown' : result.status,
        result.reason || `literal permission argument ${result.observedPermission} vs document ${result.expectedPermission}`);
      payload.evidenceRefs = result.checkRef
        ? [result.delegateRef, result.checkRef, result.normRef, result.headerRef].sort() : [];
      payload.completeness.enumeration = result.status === 'insufficient' ? 'partial' : 'complete';
      payload.completeness.unresolvedRefs = result.status === 'insufficient' ? [args.entryRef] : [];
      payload.assumptions = ['Literal single-call comparison only; no async applicability, object, path, or runtime proof.'];
      payload.nextActions = result.status === 'insufficient' ? ['inspect-permission-argument'] :
        (result.status === 'refuted' ? ['independent-norm-review', 'inspect-exceptions'] : []);
      return payload;
    }
  },
  getApplicableNorms: {
    version: TOOL_VERSION,
    status: 'available',
    args: { entryRef: { type: 'string', required: true, minLength: 3 } },
    description: '限定 sandbox_manager 文档原文的权限规范候选与适用性；不自动批准',
    run(ctx, args) {
      const payload = basePayload('getApplicableNorms', ctx.questionId, ctx.facts.inputManifestId);
      payload.completeness.scope = `entry:${args.entryRef}:knowledge`;
      if (!ctx.scope || ctx.scope.scopeId !== 'sandbox_manager-pilot') {
        payload.status = 'unsupported';
        payload.errorCode = 'knowledge-scope-unsupported';
        payload.answer = emptyAnswer('unknown', 'no fixed document set for this scope');
        return payload;
      }
      const entry = ctx.anchors && ctx.anchors.get(args.entryRef);
      if (!entry) {
        payload.answer = emptyAnswer('unknown', 'entry not in scoped discovery index');
        payload.completeness.enumeration = 'partial';
        payload.completeness.unresolvedRefs = [args.entryRef];
        return payload;
      }
      const knowledge = ctx.knowledge || (ctx.knowledgeSuite ? ctx.knowledgeSuite.byMethod.get(entry.method) : null);
      if (!knowledge && ctx.knowledgeSuite) {
        payload.answer = emptyAnswer('unknown', 'no published norm applies to this IDL method');
        payload.observations = { norm: null, applicability: { status: 'not-applicable' } };
        payload.completeness.enumeration = 'complete';
        return payload;
      }
      const selected = knowledge || knowledgeLib.loadAuthorization(ctx.facts);
      const delegationName = { SetPolicyAsync: 'SetPolicy', UnSetPolicyAsync: 'UnSetPolicy' }[entry.method] || null;
      const applicability = knowledgeLib.applicability(selected, entry.method, delegationName);
      payload.answer = emptyAnswer('unknown', `norm is ${selected.norm.state}; applicability=${applicability.status}`);
      payload.observations = { norm: selected.norm, knowledgeVersion: selected.knowledgeVersion, applicability };
      payload.evidenceRefs = [selected.norm.header.factRef];
      payload.completeness.enumeration = 'complete';
      payload.requiresInterpretation = applicability.status === 'unknown';
      payload.nextActions = applicability.status === 'unknown' ? ['review-norm-applicability'] : [];
      return payload;
    }
  },
  getScopeOverview: {
    version: TOOL_VERSION,
    status: 'available',
    args: { scopeId: { type: 'string', required: true, minLength: 1 } },
    description: '该 scope 的入口数、函数数、覆盖缺口',
    run(ctx, args) {
      const idx = ctx.facts.index();
      const entries = ctx.entries ? [...ctx.entries.values()] : [];
      const byKind = {};
      for (const e of entries) byKind[e.kind] = (byKind[e.kind] || 0) + 1;
      const payload = basePayload('getScopeOverview', ctx.questionId, ctx.facts.inputManifestId);
      const coverage = ctx.facts.coverage();
      payload.answer = {
        status: 'supported',
        text: `${args.scopeId}: ${idx.counts.functions} functions, ${idx.counts.calls} calls, ${entries.length} entry candidates`,
        basis: 'derived',
        assurance: 'bounded-analysis'
      };
      payload.completeness.scope = `scope:${args.scopeId}`;
      payload.completeness.enumeration = (idx.truncated.functions || idx.truncated.calls) ? 'partial' : 'complete';
      payload.completeness.truncated = payload.completeness.enumeration === 'partial';
      payload.observations = {
        scopeId: args.scopeId,
        snapshotId: ctx.facts.snapshotId,
        roots: idx.roots,
        functions: idx.counts.functions,
        calls: idx.counts.calls,
        guards: idx.counts.guards,
        sinks: idx.counts.sinks,
        files: idx.counts.files,
        metadata: { idl: idx.counts.idl, sa: idx.counts.sa, napi: idx.counts.napi },
        entryCandidates: byKind,
        coverageMetrics: coverage.map((c) => ({ metric: c.metric, value: c.value })),
        indexTruncated: idx.truncated
      };
      return payload;
    }
  },

  searchEntities: {
    version: TOOL_VERSION,
    status: 'available',
    args: { query: { type: 'string', required: true, minLength: 2 }, limit: { type: 'integer', required: false, minimum: 1, maximum: 100 } },
    description: '在 functions/symbols 上做名称召回，返回候选 + 依据',
    run(ctx, args) {
      const limit = args.limit || 20;
      const hits = ctx.facts.searchByName(args.query, { limit });
      const payload = basePayload('searchEntities', ctx.questionId, ctx.facts.inputManifestId);
      payload.answer = hits.length
        ? { status: 'supported', text: `${hits.length} candidate(s) for "${args.query}"`, basis: 'derived', assurance: 'bounded-analysis' }
        : { status: 'refuted', text: `no in-scope function name contains "${args.query}"`, basis: 'derived', assurance: 'bounded-analysis' };
      payload.completeness.scope = 'functions:in-scope';
      payload.completeness.enumeration = hits.length >= limit ? 'partial' : 'complete';
      payload.items = hits.map((fn) => ({
        name: fn.name,
        qualified: fn.qualified || null,
        file: fn.sourceRange && fn.sourceRange.file,
        startLine: fn.startLine,
        factRef: fn.factId,
        resolution: (fn.quality && fn.quality.resolution) || null
      }));
      payload.evidenceRefs = hits.map((fn) => fn.factId).filter(Boolean);
      return payload;
    }
  },

  inspectEntry: {
    version: TOOL_VERSION,
    status: 'available',
    args: { entryRef: { type: 'string', required: true, minLength: 3 } },
    description: '入口候选 → 绑定状态 resolved/suspect/unbound',
    run(ctx, args) {
      const binding = ctx.resolveBinding(args.entryRef);
      const payload = basePayload('inspectEntry', ctx.questionId, ctx.facts.inputManifestId);
      payload.answer = {
        status: binding.binding === 'resolved' ? 'supported' : (binding.binding === 'suspect' ? 'unknown' : 'unknown'),
        text: binding.note,
        basis: 'derived',
        assurance: 'bounded-analysis'
      };
      payload.completeness.scope = `entry:${args.entryRef}`;
      payload.completeness.enumeration = 'complete';
      payload.observations = {
        entryRef: args.entryRef,
        entry: binding.entry || null,
        binding: binding.binding,
        candidates: binding.candidates,
        implOwnerSuffix: binding.implOwnerSuffix,
        searchSpace: binding.searchSpace
      };
      payload.evidenceRefs = binding.candidates.map((c) => c.factRef).filter(Boolean);
      payload.requiresInterpretation = binding.binding !== 'resolved';
      return payload;
    }
  },

  inspectRelation: {
    version: TOOL_VERSION,
    status: 'available',
    args: {
      ref: { type: 'string', required: true, minLength: 3 },
      relation: { type: 'string', required: true, enum: ['calls', 'callers', 'registers'] },
      limit: { type: 'integer', required: false, minimum: 1, maximum: 500 }
    },
    description: 'calls/callers/registers 邻接，带 resolution',
    run(ctx, args) {
      const limit = args.limit || 200;
      const payload = basePayload('inspectRelation', ctx.questionId, ctx.facts.inputManifestId);
      if (args.relation === 'registers') {
        const binding = ctx.resolveBinding(args.ref);
        payload.answer = {
          status: binding.binding === 'resolved' ? 'supported' : 'unknown',
          text: `registers: ${binding.candidates.length} candidate(s), binding=${binding.binding}`,
          basis: 'derived',
          assurance: 'bounded-analysis'
        };
        payload.observations = { ref: args.ref, relation: 'registers', binding: binding.binding, candidates: binding.candidates };
        payload.completeness.scope = `entry:${args.ref}`;
        payload.evidenceRefs = binding.candidates.map((c) => c.factRef).filter(Boolean);
        return payload;
      }
      const target = ctx.resolveFunctionRef(args.ref);
      if (!target) {
        payload.status = 'error';
        payload.errorCode = 'unresolved-ref';
        payload.answer = { status: 'unknown', text: `cannot resolve function ref ${args.ref}`, basis: 'derived', assurance: 'bounded-analysis' };
        payload.completeness.scope = `ref:${args.ref}`;
        payload.completeness.enumeration = 'partial';
        payload.completeness.unresolvedRefs = [args.ref];
        return payload;
      }
      const rows = args.relation === 'callers'
        ? ctx.facts.callersOf(target.qualified || target.name, { limit })
        : ctx.facts.callsOf(target.qualified || target.name, { limit });
      const edges = rows.map((r) => ({
        relation: 'calls',
        callerName: r.callerName,
        calleeName: r.calleeName,
        callee: r.callee || null,
        line: r.line,
        factRef: r.factId,
        resolution: (r.quality && r.quality.resolution) || 'name-only'
      }));
      payload.answer = {
        status: rows.length ? 'supported' : 'refuted',
        text: rows.length
          ? `${edges.length} ${args.relation} edge(s) for ${target.qualified || target.name}`
          : `no ${args.relation} edge for ${target.qualified || target.name}`,
        basis: 'derived',
        assurance: 'bounded-analysis'
      };
      payload.completeness.scope = `function:${target.qualified || target.name}`;
      payload.completeness.enumeration = rows.length >= limit ? 'partial' : 'complete';
      payload.observations = { ref: args.ref, relation: args.relation, function: target.qualified || target.name, edges };
      payload.evidenceRefs = rows.map((r) => r.factId).filter(Boolean);
      if (rows.length >= limit) payload.completeness.truncated = true;
      return payload;
    }
  },

  getEvidence: {
    version: TOOL_VERSION,
    status: 'available',
    args: {
      file: { type: 'string', required: false },
      line: { type: 'integer', required: false, minimum: 1 },
      count: { type: 'integer', required: false, minimum: 1, maximum: 200 },
      resultRef: { type: 'string', required: false }
    },
    description: '返回源码窗口 + 哈希校验（file,line）或回查已归档工具结果（resultRef）',
    run(ctx, args) {
      const payload = basePayload('getEvidence', ctx.questionId, ctx.facts.inputManifestId);
      if (args.resultRef) {
        const archived = ctx.loadEvidence(args.resultRef);
        payload.answer = archived
          ? { status: 'supported', text: `archived result ${args.resultRef} found and hash-verified`, basis: 'observed', assurance: 'bounded-analysis' }
          : { status: 'unknown', text: `archived result ${args.resultRef} not found`, basis: 'observed', assurance: 'bounded-analysis' };
        payload.completeness.scope = `evidence:${args.resultRef}`;
        payload.completeness.enumeration = archived ? 'complete' : 'partial';
        if (!archived) {
          payload.status = 'error';
          payload.errorCode = 'result-ref-missing';
          payload.completeness.unresolvedRefs = [args.resultRef];
        }
        payload.observations = archived ? { resultRef: args.resultRef, sha256: archived.sha256 } : null;
        return payload;
      }
      if (!args.file) throw fail('invalid-args', 'getEvidence: either file+line or resultRef required');
      const line = args.line || 1;
      const count = args.count || 12;
      const half = Math.floor(count / 2);
      const startLine = Math.max(1, line - half);
      const endLine = startLine + count - 1;
      const verify = ctx.facts.verifyFile(args.file);
      if (!verify.ok) {
        payload.status = 'error';
        payload.errorCode = verify.reason === 'stale-input' ? 'stale-input' : verify.reason;
        payload.answer = {
          status: 'unknown',
          text: `refusing to cite ${args.file}: ${verify.reason}`,
          basis: 'observed',
          assurance: 'observation'
        };
        payload.completeness.scope = `file:${args.file}`;
        payload.completeness.enumeration = 'partial';
        payload.completeness.unresolvedRefs = [args.file];
        payload.assumptions = [`expected sha256 ${verify.expected || 'n/a'}, actual ${verify.actual || 'n/a'}`];
        return payload;
      }
      if (args.line === undefined) throw fail('invalid-args', 'getEvidence: line required when file is given');
      const win = ctx.facts.sourceWindow(args.file, startLine, endLine, { maxLines: count });
      payload.answer = {
        status: 'supported',
        text: `source window ${win.file}:${win.startLine}-${win.endLine} (sha256 verified)`,
        basis: 'observed',
        assurance: 'bounded-analysis'
      };
      payload.completeness.scope = `file:${args.file}`;
      payload.completeness.enumeration = win.truncated ? 'partial' : 'complete';
      payload.completeness.truncated = win.truncated;
      payload.sourceWindows = [{ file: win.file, startLine: win.startLine, endLine: win.endLine, sha256: win.sha256 }];
      payload.observations = { file: win.file, startLine: win.startLine, endLine: win.endLine, totalLines: win.totalLines, text: win.text };
      payload.usage.bytesRead = Buffer.byteLength(win.text, 'utf8');
      payload.evidenceRefs = verify.record && verify.record.factId ? [verify.record.factId] : [];
      return payload;
    }
  },

  inspectOperationCandidate: {
    version: TOOL_VERSION,
    status: 'available',
    args: { entryRef: { type: 'string', required: true, minLength: 3 } },
    description: '经源码限定的 PolicyInfoManager 操作候选；name-only 边仍为 suspect',
    run(ctx, args) {
      const payload = basePayload('inspectOperationCandidate', ctx.questionId, ctx.facts.inputManifestId);
      const binding = ctx.resolveBinding(args.entryRef);
      payload.completeness.scope = `entry:${args.entryRef}:operation-candidate`;
      if (binding.binding !== 'resolved' || !binding.bound) {
        payload.answer = emptyAnswer('unknown', `binding=${binding.binding}; operation unavailable`);
        payload.completeness.enumeration = 'partial';
        payload.completeness.unresolvedRefs = [args.entryRef];
        return payload;
      }
      const result = vertical.inspectOperationCandidates(ctx.facts, binding.bound);
      payload.answer = emptyAnswer('unknown', result.candidates.length === 1
        ? 'one source-qualified operation candidate; target remains suspect'
        : 'no unique source-qualified operation candidate');
      payload.observations = { entryRef: args.entryRef, ...result };
      payload.evidenceRefs = ids.uniqueSorted(result.candidates.flatMap((item) => [item.callRef, item.targetRef]));
      payload.completeness.enumeration = result.truncated ? 'partial' : 'complete';
      payload.completeness.truncated = result.truncated;
      payload.assumptions = ['Source-qualified name-only calls are not globally resolved targets.'];
      payload.nextActions = ['resolve-operation-call-target'];
      return payload;
    }
  },

  inspectDelegation: {
    version: TOOL_VERSION,
    status: 'available',
    args: { entryRef: { type: 'string', required: true, minLength: 3 } },
    description: '已绑定实现的一跳精确调用边及被调函数中的校验调用；不证明检查有效',
    run(ctx, args) {
      const payload = basePayload('inspectDelegation', ctx.questionId, ctx.facts.inputManifestId);
      const binding = ctx.resolveBinding(args.entryRef);
      payload.completeness.scope = `entry:${args.entryRef}:one-hop`;
      if (binding.binding !== 'resolved' || !binding.bound) {
        payload.answer = emptyAnswer('unknown', `binding=${binding.binding}; delegation unavailable`);
        payload.completeness.enumeration = 'partial';
        payload.completeness.unresolvedRefs = [args.entryRef];
        return payload;
      }
      const source = binding.bound.sourceRange && binding.bound.sourceRange.file;
      if (!source || !ctx.facts.verifyFile(source).ok) {
        payload.answer = emptyAnswer('unknown', 'bound source is stale or unavailable');
        payload.errorCode = 'stale-input';
        payload.completeness.enumeration = 'partial';
        payload.completeness.unresolvedRefs = [args.entryRef];
        return payload;
      }
      const result = delegation.inspect(ctx.facts, binding.bound, ctx.scope && ctx.scope.checkVocabulary, 8);
      payload.answer = emptyAnswer('unknown', result.delegates.some((d) => d.status === 'check-observed')
        ? 'one-hop callee contains a check call; object, order, and failure path remain unproven'
        : 'no decisive one-hop authorization evidence');
      payload.observations = { entryRef: args.entryRef, ...result };
      payload.evidenceRefs = result.evidenceRefs;
      payload.completeness.enumeration = result.partial ? 'partial' : 'complete';
      payload.completeness.truncated = result.partial;
      payload.assumptions = ['Only exact resolved one-hop edges; a check call does not prove authorization.'];
      payload.nextActions = result.delegates.some((d) => d.status === 'check-observed')
        ? ['inspect-check-condition-and-object'] : ['inspect-upstream-and-unresolved-calls'];
      return payload;
    }
  },

  inspectAuthorization: {
    version: TOOL_VERSION,
    status: 'available',
    args: { entryRef: { type: 'string', required: true, minLength: 3 }, entryBodyRef: { type: 'string', required: false } },
    description: '按 scope.checkVocabulary 在绑定实现体的直接调用里找校验调用；supported/refuted/insufficient',
    run(ctx, args) {
      const payload = basePayload('inspectAuthorization', ctx.questionId, ctx.facts.inputManifestId);
      const vocabulary = ctx.scope && ctx.scope.checkVocabulary ? ctx.scope.checkVocabulary : {};
      const binding = ctx.resolveBinding(args.entryRef, { entryBodyRef: args.entryBodyRef });
      payload.completeness.scope = `entry:${args.entryRef}`;
      if (binding.binding !== 'resolved') {
        payload.answer = {
          status: 'unknown',
          text: `cannot inspect authorization: binding=${binding.binding} (${binding.note})`,
          basis: 'derived',
          assurance: 'bounded-analysis'
        };
        payload.completeness.enumeration = 'partial';
        payload.completeness.unresolvedRefs = [args.entryRef];
        payload.observations = { entryRef: args.entryRef, binding: binding.binding, candidates: binding.candidates, matches: [] };
        return payload;
      }
      const target = binding.bound;
      const calls = ctx.facts.callsOf(target.qualified || target.name, { limit: 400 });
      const matches = [];
      for (const c of calls) {
        const tier = checkTier(c.calleeName, vocabulary);
        if (!tier) continue;
        matches.push({ calleeName: c.calleeName, tier, line: c.line, factRef: c.factId });
      }
      const strong = matches.filter((m) => m.tier === 'strong');
      const weak = matches.filter((m) => m.tier === 'weak');
      if (strong.length) {
        payload.answer = {
          status: 'supported',
          text: `${strong.length} strong check call(s) in ${target.qualified || target.name}`,
          basis: 'observed',
          assurance: 'bounded-analysis'
        };
      } else if (weak.length) {
        payload.answer = {
          status: 'unknown',
          text: `only weak identity call(s) (${weak.map((m) => m.calleeName).join(',')}) in ${target.qualified || target.name}; no authorization decision call`,
          basis: 'observed',
          assurance: 'bounded-analysis'
        };
        payload.errorCode = 'check-call-weak-only';
      } else {
        payload.answer = {
          status: 'refuted',
          text: `no check-vocabulary callee among ${calls.length} direct call(s) of ${target.qualified || target.name}`,
          basis: 'observed',
          assurance: 'bounded-analysis'
        };
      }
      payload.assumptions = [
        '只看函数体内的**直接调用**名；宏、包装、基类与上游调用不在观察范围内',
        '命中只说明有校验调用，不说明校验对象与敏感操作一致'
      ];
      payload.completeness.enumeration = calls.length >= 400 ? 'partial' : 'complete';
      payload.observations = {
        entryRef: args.entryRef,
        binding: binding.binding,
        function: { name: target.name, qualified: target.qualified, file: target.sourceRange && target.sourceRange.file, startLine: target.startLine },
        callees: [...new Set(calls.map((c) => c.calleeName))].sort(),
        matches,
        strongTier: strong.length,
        weakTier: weak.length,
        weakOnly: strong.length === 0 && weak.length > 0,
        vocabulary: { strong: (vocabulary.strong || STRONG_CHECK_CALLEES), weak: (vocabulary.weak || WEAK_CHECK_CALLEES) }
      };
      payload.evidenceRefs = matches.map((m) => m.factRef).filter(Boolean);
      payload.usage.bytesRead = 0;
      return payload;
    }
  }
};

function unsupportedTool(name, reason) {
  return {
    version: TOOL_VERSION,
    status: 'unsupported',
    args: {},
    description: reason,
    run(ctx) {
      const payload = basePayload(name, ctx.questionId, ctx.facts ? ctx.facts.inputManifestId : 'AM-0000000000000000');
      payload.status = 'unsupported';
      payload.errorCode = 'tool-unsupported';
      payload.answer = { status: 'unknown', text: `unsupported: ${reason}`, basis: 'derived', assurance: 'observation' };
      payload.completeness.scope = `tool:${name}`;
      payload.requiresInterpretation = false;
      return payload;
    }
  };
}

/**
 * 工具在**没有 run 上下文**时也要能用（§6/P2 的验收就是直接调 tools.run）：
 * anchors / resolveBinding / resolveFunctionRef / loadEvidence 缺失则就地补默认实现
 * （discovery 会复用 facts 的作用域索引，成本低）。
 */
function ensureAnchors(ctx) {
  if (!ctx.facts || !ctx.scope) return ctx;
  if (!ctx.anchors) {
    const discovery = require('./discovery');
    const info = discovery.buildAnchors(ctx.facts, ctx.scope);
    ctx.anchors = info.anchors;
    ctx.entries = info.anchors;
    if (!ctx.resolveBinding) ctx.resolveBinding = (ref) => discovery.resolveBinding(ref, ctx);
    if (!ctx.resolveFunctionRef) ctx.resolveFunctionRef = (ref) => discovery.resolveFunctionRef(ref, ctx);
  }
  if (!ctx.loadEvidence && ctx.store) ctx.loadEvidence = (ref) => loadEvidenceFromDir(ctx.store.dir, ref);
  return ctx;
}

for (const [name, reason] of Object.entries(UNSUPPORTED)) {
  TOOLS[name] = unsupportedTool(name, reason);
}

const UNSUPPORTED_REASONS = UNSUPPORTED;

function listTools() {
  return Object.keys(TOOLS).sort().map((name) => ({
    name,
    version: TOOLS[name].version,
    status: TOOLS[name].status,
    description: TOOLS[name].description,
    args: TOOLS[name].args,
    ...(TOOLS[name].status === 'unsupported' ? { reason: UNSUPPORTED_REASONS[name] } : {})
  }));
}

function validateArgs(tool, args) {
  const spec = tool.args || {};
  const errors = [];
  for (const [key, def] of Object.entries(spec)) {
    const v = args ? args[key] : undefined;
    if (v === undefined || v === null) {
      if (def.required) errors.push(`missing required arg: ${key}`);
      continue;
    }
    const types = Array.isArray(def.type) ? def.type : [def.type];
    const okType = types.some((t) => {
      if (t === 'string') return typeof v === 'string';
      if (t === 'integer') return Number.isInteger(v);
      if (t === 'number') return typeof v === 'number';
      if (t === 'boolean') return typeof v === 'boolean';
      if (t === 'array') return Array.isArray(v);
      if (t === 'object') return v && typeof v === 'object' && !Array.isArray(v);
      return false;
    });
    if (!okType) { errors.push(`arg ${key}: expected ${types.join('|')}`); continue; }
    if (def.minLength !== undefined && typeof v === 'string' && v.length < def.minLength) errors.push(`arg ${key}: shorter than ${def.minLength}`);
    if (def.minimum !== undefined && typeof v === 'number' && v < def.minimum) errors.push(`arg ${key}: below ${def.minimum}`);
    if (def.maximum !== undefined && typeof v === 'number' && v > def.maximum) errors.push(`arg ${key}: above ${def.maximum}`);
    if (def.enum && !def.enum.includes(v)) errors.push(`arg ${key}: not in ${def.enum.join('|')}`);
  }
  for (const key of Object.keys(args || {})) {
    if (!Object.prototype.hasOwnProperty.call(spec, key)) errors.push(`unexpected arg: ${key}`);
  }
  if (errors.length) throw fail('invalid-args', `tools: ${errors.join('; ')}`, { errors });
  return args;
}

function capPayload(payload, maxBytes) {
  const size = () => Buffer.byteLength(JSON.stringify(payload), 'utf8');
  if (size() <= maxBytes) return payload;
  payload.completeness.truncated = true;
  payload.completeness.enumeration = 'partial';
  if (payload.observations && typeof payload.observations === 'object') {
    if (typeof payload.observations.text === 'string' && payload.observations.text.length > 8000) {
      payload.observations.text = `${payload.observations.text.slice(0, 8000)}\n…[truncated]`;
    }
    for (const k of Object.keys(payload.observations)) {
      const v = payload.observations[k];
      if (Array.isArray(v) && v.length > 20) {
        payload.observations[k] = v.slice(0, 20);
        payload.completeness.nextCursor = `observations.${k}:20`;
      }
    }
  }
  for (const k of ['items', 'evidenceRefs', 'assumptions', 'nextActions']) {
    if (Array.isArray(payload[k]) && payload[k].length > 50) {
      payload[k] = payload[k].slice(0, 50);
      payload.completeness.nextCursor = payload.completeness.nextCursor || k;
    }
  }
  if (size() > maxBytes) {
    payload.observations = { truncatedReason: `payload exceeded ${maxBytes} bytes` };
  }
  return payload;
}

/**
 * dispatcher。
 * @param {string} toolName
 * @param {object} args
 * @param {{facts:object, scope:object, store?:object, questionId?:string, taskId?:string,
 *          budget?:object, entries?:Map, maxBytes?:number, timeoutMs?:number,
 *          resolveBinding?:function, resolveFunctionRef?:function, loadEvidence?:function}} ctx
 */
async function run(toolName, args, ctx = {}) {
  platform.requireWindowsNative();
  const started = Date.now();
  const tool = TOOLS[toolName];
  const maxBytes = ctx.maxBytes || DEFAULT_MAX_BYTES;
  const timeoutMs = ctx.timeoutMs || DEFAULT_TIMEOUT_MS;

  const missing = [];
  let payload;
  if (!tool) {
    payload = basePayload(String(toolName), ctx.questionId, ctx.facts ? ctx.facts.inputManifestId : 'AM-0000000000000000');
    payload.status = 'error';
    payload.errorCode = 'unknown-tool';
    payload.answer = emptyAnswer('unknown', `unknown tool: ${toolName}`);
    payload.completeness.scope = `tool:${toolName}`;
    payload.completeness.enumeration = 'partial';
  } else {
    try {
      if (tool.status === 'unsupported') {
        validateArgs(tool, args);
      } else {
        validateArgs(tool, args);
        if (ctx.budget) ctx.budget.reserveTool(ctx.taskId);
      }
      const richCtx = ensureAnchors({ ...ctx, questionId: ctx.questionId || null });
      payload = await withTimeout(Promise.resolve(tool.run(richCtx, args || {})), timeoutMs, toolName);
      if (tool.status === 'unsupported') {
        payload.status = 'unsupported';
        missing.push('tool-unsupported');
      }
    } catch (e) {
      payload = payload || basePayload(String(toolName), ctx.questionId, ctx.facts ? ctx.facts.inputManifestId : 'AM-0000000000000000');
      if (e.code === 'timeout') {
        payload.status = 'cancelled';
        payload.errorCode = 'timeout';
        payload.answer = emptyAnswer('unknown', `cancelled: ${toolName} timed out after ${timeoutMs} ms`);
      } else if (e.code === 'invalid-args') {
        payload.status = 'error';
        payload.errorCode = 'invalid-args';
        payload.answer = emptyAnswer('unknown', `invalid args: ${e.message}`);
      } else if (e.code === 'budget-exhausted') {
        payload.status = 'cancelled';
        payload.errorCode = 'budget-exhausted';
        payload.answer = emptyAnswer('unknown', `cancelled: ${e.message}`);
        missing.push('budget-exhausted');
      } else {
        payload.status = 'error';
        payload.errorCode = e.code || 'tool-error';
        payload.answer = emptyAnswer('unknown', `tool error: ${e.message}`);
      }
      payload.completeness.scope = payload.completeness.scope || `tool:${toolName}`;
      payload.completeness.enumeration = 'partial';
    }
  }

  payload.usage = { wallMs: Math.max(0, Date.now() - started), bytesRead: payload.usage ? payload.usage.bytesRead : 0,
    cacheHit: !!payload.usage?.cacheHit };
  capPayload(payload, maxBytes);

  // missing（工具级具名缺口）
  if (missing.length && ctx.questionId && ctx.buildMissingRef) {
    payload.missingRefs = ids.uniqueSorted(missing.map((code) => ctx.buildMissingRef(code)));
  }

  payload.resultId = evidenceIdOf(payload);

  if (ctx.store) {
    const record = state.makeRecord({
      recordId: payload.resultId,
      recordType: 'tool-result',
      manifestId: ctx.store.manifestId,
      producer: state.PRODUCERS.tools,
      dependencyRefs: [...payload.evidenceRefs, ...payload.sourceWindows.map((w) => w.file)],
      payload
    });
    const archived = ctx.store.archiveEvidence(record);
    ctx.store.appendToolLedger({
      at: state.nowIso(),
      taskId: ctx.taskId || null,
      questionId: ctx.questionId || null,
      tool: payload.tool,
      resultId: payload.resultId,
      status: payload.status,
      errorCode: payload.errorCode || null,
      wallMs: payload.usage.wallMs,
      bytesRead: payload.usage.bytesRead,
      archivedSha256: archived.sha256
    });
    // 非可枚举：不污染 ToolResult 记录的 JSON 形状（schema additionalProperties=false）
    Object.defineProperty(record, 'evidenceFile', {
      value: path.relative(ctx.store.dir, archived.file).split(path.sep).join('/'),
      enumerable: false
    });
    return record;
  }
  return state.makeRecord({
    recordId: payload.resultId,
    recordType: 'tool-result',
    manifestId: (ctx.facts ? ctx.facts.inputManifestId : 'AM-0000000000000000'),
    producer: state.PRODUCERS.tools,
    dependencyRefs: payload.evidenceRefs,
    payload
  });
}

function loadEvidenceFromDir(dir, resultId) {
  const file = path.join(dir, 'evidence', `${String(resultId).replace(':', '-')}.json`);
  if (!fs.existsSync(file)) return null;
  const record = JSON.parse(fs.readFileSync(file, 'utf8'));
  const sha256 = require('crypto').createHash('sha256').update(fs.readFileSync(file)).digest('hex');
  return { record, sha256, file };
}

module.exports = {
  TOOLS,
  UNSUPPORTED,
  listTools,
  validateArgs,
  run,
  withTimeout,
  createBudget,
  checkTier,
  evidenceIdOf,
  capPayload,
  loadEvidenceFromDir,
  STRONG_CHECK_CALLEES,
  WEAK_CHECK_CALLEES,
  DEFAULT_MAX_BYTES,
  DEFAULT_TIMEOUT_MS
};
