'use strict';

const knowledgeLib = require('./knowledge');
const vertical = require('./vertical');

function guardBeforeOperation(text, startLine, checkLine, operationLine) {
  const lines = text.split(/\r?\n/);
  const index = checkLine - startLine;
  if (index < 0 || operationLine <= checkLine || operationLine - startLine >= lines.length) return false;
  const depthAt = (line) => lines.slice(0, line).reduce((depth, textLine) => {
    const code = textLine.replace(/"(?:\\.|[^"\\])*"/g, '""').replace(/\/\/.*$/, '');
    for (const char of code) {
      if (char === '{') depth += 1;
      if (char === '}') depth -= 1;
    }
    return depth;
  }, 0);
  if (depthAt(index) !== 1 || depthAt(operationLine - startLine) !== 1) return false;
  if (!/^\s*if\s*\(\s*!\s*CheckPermission\s*\(\s*callingTokenId\s*,\s*[A-Z][A-Z0-9_]*\s*\)\s*\)\s*\{\s*$/.test(lines[index])) return false;
  if (!/^\s*return\s+PERMISSION_DENIED\s*;\s*$/.test(lines[index + 1] || '') ||
      !/^\s*\}\s*$/.test(lines[index + 2] || '')) return false;
  const before = lines.slice(0, index).join('\n');
  const after = lines.slice(index + 3, operationLine - startLine).join('\n');
  return /IPCSkeleton::GetCallingTokenID\s*\(\s*\)/.test(before) &&
    !/\b(?:goto|co_return|try|catch)\b|#\s*(?:if|else|endif|define)/.test(before + after);
}

function analyze(facts, anchor, binding, knowledge, permissionArgument, options = {}) {
  const unknown = (reason, operation, candidateSignal) => ({ status: 'insufficient', reason,
    ...(options.includeCandidateContext && operation ? {
      operationRef: operation.targetRef, operationCallRef: operation.callRef,
      ...(candidateSignal ? { candidateSignal } : {})
    } : {}) });
  if (anchor?.kind !== 'idl' || binding?.binding !== 'resolved' || !binding.bound ||
      knowledge?.norm?.state !== 'accepted' || knowledge.norm.authority !== 'builder-llm-review') {
    return unknown('entry-or-builder-norm-unresolved');
  }
  const delegate = { SetPolicyAsync: 'SetPolicy', UnSetPolicyAsync: 'UnSetPolicy' }[anchor.method] || null;
  if ((!options.includeNewFamilies && !delegate) ||
      knowledgeLib.applicability(knowledge, anchor.method, delegate).status !== 'applicable') {
    return unknown('norm-applicability-unknown');
  }
  const local = vertical.selectEvidence(facts, binding.bound, delegate);
  if (local.status !== 'observed' || local.truncated ||
      local.operationCallsites.length !== 1 ||
      local.operationCandidates.length !== 1 || local.operationCandidates[0].status !== 'suspect') {
    return unknown('call-chain-or-operation-ambiguous');
  }
  const operation = local.operationCandidates[0];
  const base = {
    verificationStatus: 'static-only', assurance: 'bounded-analysis',
    normRef: knowledge.norm.normId, reviewRef: knowledge.norm.reviewRef,
    delegateRef: local.calleeRef, operationRef: operation.targetRef,
    operationCallRef: operation.callRef,
    expectedPermission: knowledge.norm.permission,
    limitation: 'Scoped source-qualified call and complete local check enumeration only; documented permission contract, not exploitability or general safety.'
  };
  if (options.includeNewFamilies && local.checkRefs.length === 0 && local.checkCallsites.length === 0 &&
      !/\bCheckPermission\s*\(/.test(local.text)) {
    return { ...base, status: 'finding', family: 'missing-permission-check',
      proposition: 'The service enforces the Builder-approved documented permission at this IDL entry',
      observedPermission: 'none (CheckPermission)',
      limitation: `${base.limitation} Other caller gates, if present, are not classified as absent authorization.` };
  }
  if (local.checkRefs.length !== 1) return unknown('permission-check-ambiguous', operation,
    local.checkRefs.length === 0 && local.checkCallsites.length === 0 ? 'no-resolved-check' : null);
  const check = facts.index().calls.find((c) => c.factId === local.checkRefs[0]);
  if (!check || check.caller !== local.calleeRef || check.line >= operation.source.line) {
    return unknown('guard-dominance-unproven', operation);
  }
  const guarded = guardBeforeOperation(local.text, local.callee.startLine, check.line, operation.source.line);
  if (options.includeNewFamilies && !guarded) {
    const checkLine = local.text.split(/\r?\n/)[check.line - local.callee.startLine] || '';
    if (!/^\s*if\s*\(\s*!\s*CheckPermission\s*\(/.test(checkLine)) {
      return unknown('guard-shape-unsupported', operation);
    }
    return { ...base, status: 'finding', family: 'guard-non-dominating', checkRef: check.factId,
      proposition: 'The documented permission check protects the scoped operation by a local early return',
      observedPermission: permissionArgument?.observedPermission || 'unresolved',
      limitation: `${base.limitation} Local guard shape does not establish global control-flow dominance.` };
  }
  if (!guarded) return unknown('guard-dominance-unproven', operation);
  const comparison = permissionArgument || {};
  if (!['supported', 'refuted'].includes(comparison.status) ||
      comparison.checkRef !== check.factId || comparison.normRef !== knowledge.norm.normId) {
    return unknown('permission-argument-unresolved', operation);
  }
  if (!options.includeNewFamilies) {
    return {
      status: comparison.status === 'refuted' ? 'finding' : 'excluded',
      proposition: 'The service enforces the Builder-approved documented permission at this IDL entry',
      verificationStatus: 'static-only', assurance: 'bounded-analysis',
      normRef: knowledge.norm.normId, reviewRef: knowledge.norm.reviewRef,
      delegateRef: local.calleeRef, checkRef: check.factId,
      operationRef: operation.targetRef, operationCallRef: operation.callRef,
      observedPermission: comparison.observedPermission,
      expectedPermission: comparison.expectedPermission,
      limitation: 'Scoped source-qualified call and straight-line guard only; contract mismatch, not exploitability or general safety.'
    };
  }
  return {
    ...base, family: comparison.status === 'refuted' ? 'permission-mismatch' : 'compliant-excluded',
    status: comparison.status === 'refuted' ? 'finding' : 'excluded',
    proposition: 'The service enforces the Builder-approved documented permission at this IDL entry',
    checkRef: check.factId,
    observedPermission: comparison.observedPermission,
    expectedPermission: comparison.expectedPermission
  };
}

module.exports = { analyze, guardBeforeOperation };
