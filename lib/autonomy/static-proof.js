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

function analyze(facts, anchor, binding, knowledge, permissionArgument) {
  const unknown = (reason) => ({ status: 'insufficient', reason });
  if (anchor?.kind !== 'idl' || binding?.binding !== 'resolved' || !binding.bound ||
      knowledge?.norm?.state !== 'accepted' || knowledge.norm.authority !== 'builder-llm-review') {
    return unknown('entry-or-builder-norm-unresolved');
  }
  const delegate = { SetPolicyAsync: 'SetPolicy', UnSetPolicyAsync: 'UnSetPolicy' }[anchor.method];
  if (!delegate || knowledgeLib.applicability(knowledge, anchor.method, delegate).status !== 'applicable') {
    return unknown('norm-applicability-unknown');
  }
  const local = vertical.selectEvidence(facts, binding.bound, delegate);
  if (local.status !== 'observed' || local.truncated ||
      local.checkRefs.length !== 1 || local.operationCallsites.length !== 1 ||
      local.operationCandidates.length !== 1 || local.operationCandidates[0].status !== 'suspect') {
    return unknown('call-chain-or-operation-ambiguous');
  }
  const operation = local.operationCandidates[0];
  const check = facts.index().calls.find((c) => c.factId === local.checkRefs[0]);
  if (!check || check.caller !== local.calleeRef ||
      !guardBeforeOperation(local.text, local.callee.startLine, check.line, operation.source.line)) {
    return unknown('guard-dominance-unproven');
  }
  const comparison = permissionArgument || {};
  if (!['supported', 'refuted'].includes(comparison.status) ||
      comparison.checkRef !== check.factId || comparison.normRef !== knowledge.norm.normId) {
    return unknown('permission-argument-unresolved');
  }
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

module.exports = { analyze, guardBeforeOperation };
