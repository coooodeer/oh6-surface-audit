'use strict';

const ids = require('./ids');
const knowledgeLib = require('./knowledge');
const summaries = require('./summaries');

const DELEGATES = Object.freeze({ SetPolicyAsync: 'SetPolicy', UnSetPolicyAsync: 'UnSetPolicy' });

function sourceQualifiedOperation(facts, index, callee, window, call) {
  if (call.callee || call.quality?.resolution !== 'name-only' ||
      call.line <= callee.startLine || call.line > callee.endLine) return null;
  const line = window.text.split('\n')[call.line - callee.startLine];
  const invocation = /^\s*(?:return\s+|[A-Za-z_]\w*\s*=\s*)PolicyInfoManager::GetInstance\(\)\.([A-Za-z_]\w*)\s*\(/.exec(line || '');
  if (!invocation || invocation[1] !== call.calleeName) return null;
  const prefix = callee.qualified?.split('SandboxManagerService::')[0];
  if (!prefix || !callee.qualified.startsWith(`${prefix}SandboxManagerService::`)) return null;
  const qualified = `${prefix}PolicyInfoManager::${call.calleeName}`;
  // shortcut: rejected downstream matches collapse to no candidate; distinguish stale and ambiguous targets before treating them as actionable.
  const matches = index.functions.filter((fn) => fn.qualified === qualified &&
    fn.argc === call.argc && fn.role === 'production');
  if (matches.length !== 1) return null;
  const target = matches[0];
  const verified = target.sourceRange?.file && facts.verifyFile(target.sourceRange.file);
  if (!verified?.ok) return null;
  return { status: 'suspect', callRef: call.factId, targetRef: target.factId,
    source: { file: window.file, line: call.line, sha256: window.sha256 },
    target: { file: target.sourceRange.file, line: target.startLine, sha256: verified.actual },
    reason: 'source-qualified-name-only' };
}

function selectEvidence(facts, bound, delegateName = 'SetPolicy') {
  const entryFile = bound.sourceRange && bound.sourceRange.file;
  const entryVerified = entryFile && facts.verifyFile(entryFile);
  if (!entryVerified || !entryVerified.ok) return { status: 'insufficient', reason: 'stale-input' };
  const entryWindow = facts.sourceWindow(entryFile, bound.startLine, bound.endLine, { maxLines: 80 });
  if (entryWindow.truncated || entryWindow.sha256 !== entryVerified.actual) {
    return { status: 'insufficient', reason: 'entry-source-truncated-or-stale' };
  }
  const index = facts.index();
  const calls = facts.callsOf(bound.qualified || bound.name, { limit: 101 });
  const edges = delegateName === null ? [] : calls.filter((edge) => edge.calleeName === delegateName && edge.callee &&
    edge.quality && edge.quality.resolution === 'exact');
  if (index.truncated.calls || calls.length >= 101 || (delegateName !== null && edges.length !== 1)) {
    return { status: 'insufficient', reason: 'delegation-ambiguous-or-truncated' };
  }
  const callee = delegateName === null ? bound : index.functions.find((fn) => fn.factId === edges[0].callee);
  if (!callee || (delegateName !== null && callee.name !== delegateName)) {
    return { status: 'insufficient', reason: 'delegation-target-unresolved' };
  }
  const file = callee.sourceRange && callee.sourceRange.file;
  const verified = file && facts.verifyFile(file);
  if (!verified || !verified.ok) return { status: 'insufficient', reason: 'stale-input' };
  const window = facts.sourceWindow(file, callee.startLine, callee.endLine, { maxLines: 80 });
  if (window.truncated || window.sha256 !== verified.actual) {
    return { status: 'insufficient', reason: 'source-truncated-or-stale' };
  }
  const downstream = facts.callsOf(callee.qualified || callee.name, { limit: 101 });
  const checks = downstream.filter((c) => c.calleeName === 'CheckPermission' && c.callee &&
    c.quality && c.quality.resolution === 'exact');
  const operations = downstream.filter((c) => c.line > callee.startLine && c.line <= callee.endLine &&
    (delegateName === null ? sourceQualifiedOperation(facts, index, callee, window, c) !== null
      : c.calleeName === delegateName));
  const parsers = downstream.filter((c) => c.calleeName === 'Unmarshalling' && c.line > callee.startLine);
  const operationCandidates = operations.map((c) => sourceQualifiedOperation(facts, index, callee, window, c))
    .filter(Boolean);
  return {
    status: 'observed', edgeRef: edges[0]?.factId || null, calleeRef: callee.factId,
    entry: { file: entryFile, startLine: bound.startLine, endLine: bound.endLine,
      sha256: entryVerified.actual, text: entryWindow.text },
    callee: { file, startLine: callee.startLine, endLine: callee.endLine, sha256: verified.actual },
    checkRefs: checks.map((c) => c.factId).sort(),
    checkCallsites: downstream.filter((c) => c.calleeName === 'CheckPermission')
      .map((c) => ({ ref: c.factId, resolution: c.quality?.resolution || 'unknown' })),
    operationCallsites: operations.map((c) => ({ ref: c.factId, line: c.line, resolution: c.quality.resolution })),
    operationCandidates,
    parserCallsites: parsers.map((c) => ({ ref: c.factId, line: c.line, resolution: c.quality.resolution })),
    parserTypeHint: /PolicyVecRawData\s*&\s*policyRawData/.test(window.text) &&
      /policyRawData\.Unmarshalling\s*\(/.test(window.text),
    parseQuality: edges[0]?.quality.parse || null,
    unresolvedCalls: downstream.filter((c) => !c.callee).length,
    truncated: downstream.length >= 101,
    text: window.text
  };
}

function inspectOperationCandidates(facts, bound) {
  if (DELEGATES[bound?.name]) {
    const delegated = selectEvidence(facts, bound, DELEGATES[bound.name]);
    return delegated.status === 'observed' && !delegated.truncated
      ? { status: 'observed', candidates: delegated.operationCandidates, truncated: false }
      : { status: 'insufficient', reason: delegated.reason || 'delegation-incomplete', candidates: [], truncated: true };
  }
  const file = bound?.sourceRange?.file;
  const verified = file && facts.verifyFile(file);
  if (!verified?.ok) return { status: 'insufficient', reason: 'stale-input', candidates: [], truncated: true };
  const window = facts.sourceWindow(file, bound.startLine, bound.endLine, { maxLines: 80 });
  if (window.truncated || window.sha256 !== verified.actual) {
    return { status: 'insufficient', reason: 'source-truncated-or-stale', candidates: [], truncated: true };
  }
  const index = facts.index();
  const calls = facts.callsOf(bound.qualified || bound.name, { limit: 101 });
  if (index.truncated.calls || calls.length >= 101) {
    return { status: 'insufficient', reason: 'calls-truncated', candidates: [], truncated: true };
  }
  return { status: 'observed', truncated: false, candidates: calls
    .map((call) => sourceQualifiedOperation(facts, index, bound, window, call)).filter(Boolean) };
}

function validatePlan(parsed, task, contextId, entryRef) {
  if (!parsed || parsed.taskId !== task.taskId || parsed.contextId !== contextId ||
      !parsed.action || parsed.action.type !== 'callTool' ||
      parsed.action.tool !== 'inspectDelegation' ||
      !parsed.action.arguments || parsed.action.arguments.entryRef !== entryRef ||
      Object.keys(parsed.action.arguments).length !== 1) return { ok: false, reason: 'invalid-or-stale-action' };
  return { ok: true, action: { type: 'callTool', tool: 'inspectDelegation', arguments: { entryRef } } };
}

function validateFollowup(parsed, task, contextId, options) {
  if (!parsed || parsed.taskId !== task.taskId || parsed.taskRevision !== task.revision ||
      parsed.contextId !== contextId || !parsed.action ||
      !options.some((action) => ids.canonicalJson(action) === ids.canonicalJson(parsed.action))) {
    return { ok: false, reason: 'invalid-or-stale-followup' };
  }
  return { ok: true, action: parsed.action };
}

function gateInterpretation(call, allowedRefs, evidence, applicability) {
  if (!call || call.status !== 'ok' || !call.parsed) return { status: 'insufficient', reason: call ? call.reason : 'no-response' };
  const p = call.parsed;
  if (!['supported', 'refuted', 'insufficient', 'conflict'].includes(p.decision) ||
      !Array.isArray(p.evidenceRefs) || p.evidenceRefs.some((ref) => !allowedRefs.has(ref))) {
    return { status: 'insufficient', reason: 'invalid-model-evidence' };
  }
  if (!evidence.checkRefs.length && p.decision === 'supported') {
    return { status: 'insufficient', reason: 'unsupported-positive' };
  }
  if (evidence.checkRefs.length && p.decision === 'refuted') {
    return { status: 'conflict', reason: 'model-contradicts-observed-check', evidenceRefs: p.evidenceRefs };
  }
  return {
    status: 'insufficient', reason: applicability.status === 'unknown'
      ? 'norm-applicability-unapproved' : 'operation-target-or-path-unproven',
    modelOpinion: p.decision, evidenceRefs: p.evidenceRefs,
    rationale: String(p.rationale || '').slice(0, 400)
  };
}

async function analyze({ facts, anchor, binding, task, store, gateway, pushResult, knowledge, summaryCache,
  followupQuestionId, enableFollowup = false, twoRoundFollowup = false }) {
  if (!anchor || anchor.kind !== 'idl' || !DELEGATES[anchor.method]) return null;
  const delegateName = DELEGATES[anchor.method];
  const entryRef = anchor.entityId;
  const result = { taskId: task.taskId, entryRef, status: 'insufficient', reason: null, mode: gateway.mode };
  if (binding.binding !== 'resolved' || !binding.bound) {
    result.reason = 'binding-unbound';
    return result;
  }
  knowledge = knowledge || knowledgeLib.loadAuthorization(facts);
  store.writeJson('vertical-knowledge.json', knowledge);
  const normResult = await pushResult('getApplicableNorms', { entryRef });
  if (normResult.payload.status !== 'ok') {
    result.reason = normResult.payload.errorCode || 'norm-tool-unavailable';
    return result;
  }
  const local = selectEvidence(facts, binding.bound, delegateName);
  result.knowledgeVersion = knowledge.knowledgeVersion;
  result.normRef = knowledge.norm.normId;
  if (local.status !== 'observed') {
    result.reason = local.reason;
    return result;
  }
  const applicability = knowledgeLib.applicability(knowledge, anchor.method, delegateName);
  result.applicability = applicability;
  const cache = summaryCache || new Map();
  const first = summaries.resolve(cache, local, knowledge.knowledgeVersion, facts.snapshotId);
  result.summaryRef = first.summaryId;
  const contextId = ids.contextId('vertical-plan', {
    taskId: task.taskId, entryRef, knowledgeVersion: knowledge.knowledgeVersion, edgeRef: local.edgeRef
  });
  result.planContextId = contextId;
  let plan = { ok: true, action: { type: 'callTool', tool: 'inspectDelegation', arguments: { entryRef } }, source: 'deterministic-off' };
  if (gateway.mode !== 'off') {
    const call = await gateway.invoke({ purpose: 'vertical-plan', taskId: task.taskId, contextId,
      maxTokens: 1600, messages: [
        { role: 'system', content: 'Return only JSON: {"taskId":"...","contextId":"...","action":{"type":"callTool","tool":"inspectDelegation","arguments":{"entryRef":"..."}}}. The only permitted next tool is inspectDelegation; do not invent evidence.' },
        { role: 'user', content: JSON.stringify({ taskId: task.taskId, contextId, entryRef,
          directCall: local.edgeRef, norm: { state: knowledge.norm.state, source: knowledge.norm.source },
          question: `Does the delegated ${delegateName} implementation check the caller before its policy-changing callsite?` }) }
      ] });
    plan = call.status === 'ok'
      ? validatePlan(call.parsed, task, contextId, entryRef)
      : { ok: false, reason: call.reason || 'model-plan-unavailable' };
    plan.modelCallRef = call.callId;
  }
  store.appendEvent({ kind: 'vertical-action', taskId: task.taskId,
    detail: { status: plan.ok ? 'accepted' : 'rejected', tool: plan.ok ? plan.action.tool : null,
      reason: plan.reason || null, modelCallRef: plan.modelCallRef || null } });
  result.plan = plan;
  if (!plan.ok) { result.reason = plan.reason; return result; }
  const delegated = await pushResult('inspectDelegation', { entryRef });
  if (delegated.payload.status !== 'ok' || delegated.payload.completeness.enumeration !== 'complete') {
    result.reason = 'delegation-incomplete';
    return result;
  }
  const evidence = await pushResult('getEvidence', {
    file: local.callee.file, line: local.callee.startLine,
    count: Math.min(80, local.callee.endLine - local.callee.startLine + 1)
  });
  if (evidence.payload.status !== 'ok') { result.reason = 'stale-input'; return result; }
  const reused = summaries.resolve(cache, local, knowledge.knowledgeVersion, facts.snapshotId);
  result.summaryReuse = { firstHit: first.cacheHit, contextHit: reused.cacheHit,
    fingerprint: reused.fingerprint };
  store.writeJson('vertical-summary.json', reused);
  if (enableFollowup && twoRoundFollowup) {
    result.followups = [];
    let previous = null;
    const executed = new Set();
    for (let round = 1; round <= 2; round += 1) {
      const missing = [
        ...(!['supported', 'refuted'].includes(result.permissionArgument?.status)
          ? ['permission-argument-unresolved'] : []),
        'operation-target-unproven'
      ];
      const options = [{ type: 'callTool', tool: 'inspectPermissionArgument', arguments: { entryRef } }];
      if (local.operationCandidates.length === 1) {
        const target = local.operationCandidates[0].target;
        options.push({ type: 'callTool', tool: 'getEvidence',
          arguments: { file: target.file, line: target.line, count: 12 } });
      }
      const allowed = options.filter((item) => !executed.has(item.tool) &&
        (item.tool !== 'inspectPermissionArgument' || missing.includes('permission-argument-unresolved')));
      if (!allowed.length) { result.followupStopReason = 'no-new-action'; break; }
      const followupContextId = ids.contextId('vertical-followup-replan', {
        taskId: task.taskId, taskRevision: task.revision, entryRef,
        sourceSha256: local.callee.sha256, round, previous, missing, options: allowed
      });
      let followup = { ok: true, action: allowed[0], source: 'deterministic-off' };
      if (gateway.mode !== 'off') {
        const call = await gateway.invoke({ purpose: 'vertical-followup-replan', taskId: task.taskId,
          contextId: followupContextId, maxTokens: 1200, messages: [
            { role: 'system', content: 'Return only JSON with taskId, taskRevision, contextId and exactly one action from allowedActions. Do not invent tools, paths, or evidence. A suspect target remains unproven after reading its source.' },
            { role: 'user', content: JSON.stringify({ taskId: task.taskId, taskRevision: task.revision,
              contextId: followupContextId, round, previous, missing, allowedActions: allowed }) }
          ] });
        followup = call.status === 'ok' ? validateFollowup(call.parsed, task, followupContextId, allowed)
          : { ok: false, reason: call.reason || 'model-followup-unavailable' };
        followup.modelCallRef = call.callId;
      }
      Object.assign(followup, { round, contextId: followupContextId, taskRevision: task.revision,
        previous, missing, allowedActions: allowed });
      store.appendEvent({ kind: 'vertical-action', taskId: task.taskId,
        detail: { status: followup.ok ? 'accepted' : 'rejected', step: `followup-${round}`,
          tool: followup.ok ? followup.action.tool : null,
          reason: followup.reason || null, modelCallRef: followup.modelCallRef || null } });
      result.followups.push(followup);
      if (!followup.ok) { result.followupStopReason = followup.reason; break; }
      const next = await pushResult(followup.action.tool, followup.action.arguments,
        followup.action.tool === 'inspectPermissionArgument' ? followupQuestionId : null);
      followup.toolResultId = next.recordId;
      executed.add(followup.action.tool);
      if (followup.action.tool === 'inspectPermissionArgument') {
        result.permissionArgument = { ...next.payload.observations, toolResultId: next.recordId };
      }
      const { usage, ...semanticPayload } = next.payload;
      previous = { tool: followup.action.tool, toolResultId: next.recordId,
        status: next.payload.status, payloadSha256: ids.sha256Hex(ids.canonicalJson(semanticPayload)) };
      if (next.payload.status !== 'ok') { result.followupStopReason = 'tool-failed'; break; }
    }
    if (!result.followupStopReason) result.followupStopReason = 'round-limit';
  } else if (enableFollowup) {
    const options = [{ type: 'callTool', tool: 'inspectPermissionArgument', arguments: { entryRef } }];
    if (local.operationCandidates.length === 1) {
      const target = local.operationCandidates[0].target;
      options.push({ type: 'callTool', tool: 'getEvidence',
        arguments: { file: target.file, line: target.line, count: 12 } });
    }
    const followupContextId = ids.contextId('vertical-followup-plan', {
      taskId: task.taskId, taskRevision: task.revision, entryRef,
      sourceSha256: local.callee.sha256, options
    });
    let followup = { ok: true, action: options[0], source: 'deterministic-off' };
    if (gateway.mode !== 'off') {
      const call = await gateway.invoke({ purpose: 'vertical-followup-plan', taskId: task.taskId,
        contextId: followupContextId, maxTokens: 1200, messages: [
          { role: 'system', content: 'Return only JSON with taskId, taskRevision, contextId and one exact action from allowedActions. Do not invent a tool, path or evidence. The target is a suspect source-qualified candidate, not a proven call edge.' },
          { role: 'user', content: JSON.stringify({ taskId: task.taskId, taskRevision: task.revision,
            contextId: followupContextId, allowedActions: options,
            missing: ['permission-argument-unresolved', 'operation-target-unproven'],
            operationCandidates: local.operationCandidates }) }
        ] });
      followup = call.status === 'ok' ? validateFollowup(call.parsed, task, followupContextId, options)
        : { ok: false, reason: call.reason || 'model-followup-unavailable' };
      followup.modelCallRef = call.callId;
    }
    followup.contextId = followupContextId;
    followup.taskRevision = task.revision;
    store.appendEvent({ kind: 'vertical-action', taskId: task.taskId,
      detail: { status: followup.ok ? 'accepted' : 'rejected', step: 'followup',
        tool: followup.ok ? followup.action.tool : null,
        reason: followup.reason || null, modelCallRef: followup.modelCallRef || null } });
    if (followup.ok) {
      const next = await pushResult(followup.action.tool, followup.action.arguments,
        followup.action.tool === 'inspectPermissionArgument' ? followupQuestionId : null);
      followup.toolResultId = next.recordId;
      if (followup.action.tool === 'inspectPermissionArgument') {
        result.permissionArgument = { ...next.payload.observations, toolResultId: next.recordId };
      }
    }
    result.followup = followup;
  }
  const refs = [local.edgeRef, local.calleeRef, ...local.checkRefs,
    ...local.operationCallsites.map((c) => c.ref), knowledge.norm.normId, normResult.recordId,
    ...(result.followup?.toolResultId ? [result.followup.toolResultId] : []),
    ...(result.followups || []).map((item) => item.toolResultId).filter(Boolean)];
  result.evidenceRefs = [...new Set(refs)].sort();
  result.operationCallsites = local.operationCallsites;
  result.operationCandidates = local.operationCandidates;
  result.parserCallsites = local.parserCallsites;
  result.parserTypeHint = local.parserTypeHint;
  result.checkRefs = local.checkRefs;
  result.completeness = { parseQuality: local.parseQuality, unresolvedCalls: local.unresolvedCalls,
    truncated: local.truncated, operationTargetResolved: local.operationCallsites.length > 0 &&
      local.operationCallsites.every((c) => c.resolution === 'exact') };
  result.contextId = ids.contextId('vertical-interpret', {
    taskId: task.taskId, knowledgeVersion: knowledge.knowledgeVersion,
    entrySha256: local.entry.sha256, sourceSha256: local.callee.sha256, evidenceRefs: result.evidenceRefs
  });
  store.writeJson('vertical-context.json', {
    contextId: result.contextId, taskId: task.taskId, entrySource: local.entry,
    source: local.callee, sourceText: local.text, norm: knowledge.norm, applicability,
    summary: reused,
    ...(enableFollowup ? (twoRoundFollowup ? { followups: result.followups,
      followupStopReason: result.followupStopReason } : { followup: result.followup }) : {}),
    operationCandidates: local.operationCandidates,
    evidenceRefs: result.evidenceRefs, limitation: 'Caller-to-IPC dispatch and operation target remain unproven.'
  });
  if (gateway.mode === 'off') {
    result.reason = 'model-interpretation-disabled';
  } else {
    const call = await gateway.invoke({ purpose: 'vertical-interpret', taskId: task.taskId,
      contextId: result.contextId, maxTokens: 4096, messages: [
        { role: 'system', content: 'You are reviewing a bounded source excerpt. Return only JSON with decision supported|refuted|insufficient|conflict, evidenceRefs (subset of allowed IDs), and a short rationale. A visible check call does not prove authorization. A proposed norm is unapproved; an accepted Builder norm is a sourced static precondition, not human verification. Do not claim device behavior or exploitability.' },
        { role: 'user', content: JSON.stringify({ proposition: `The delegated ${delegateName} method contains a calling-token check before its policy-changing callsite, as a bounded local observation only.`,
          applicability, norm: knowledge.norm, entrySource: local.entry.text, calleeSource: local.text, checkRefs: local.checkRefs,
          operationCallsites: local.operationCallsites, allowedRefs: result.evidenceRefs,
          limits: result.completeness }) }
      ] });
    result.modelCallRef = call.callId;
    result.interpretation = gateInterpretation(call, new Set(result.evidenceRefs), local, applicability);
    result.reason = result.interpretation.reason;
  }
  result.status = 'observation';
  result.verification = { status: 'blocked', entryFaithfulness: 'unknown',
    reason: 'no-approved-isolated-runner-or-device-witness' };
  return result;
}

module.exports = { analyze, selectEvidence, inspectOperationCandidates, validatePlan, validateFollowup, gateInterpretation };
