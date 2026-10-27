'use strict';

const knowledgeLib = require('./knowledge');
const vertical = require('./vertical');
const gatesLib = require('./gates');

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
  const cacheKey = options.cache && JSON.stringify({ calleeRef: local.calleeRef,
    calleeSha256: local.callee.sha256, checkRefs: local.checkRefs,
    operationCallRef: operation.callRef, normRef: knowledge.norm.normId,
    reviewRef: knowledge.norm.reviewRef, comparison: permissionArgument && {
      status: permissionArgument.status, checkRef: permissionArgument.checkRef,
      observedPermission: permissionArgument.observedPermission,
      expectedPermission: permissionArgument.expectedPermission, normRef: permissionArgument.normRef,
      headerRef: permissionArgument.headerRef } });
  if (cacheKey && options.cache.has(cacheKey)) {
    options.onCacheHit?.(cacheKey);
    return options.cache.get(cacheKey);
  }
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
  const result = {
    ...base, family: comparison.status === 'refuted' ? 'permission-mismatch' : 'compliant-excluded',
    status: comparison.status === 'refuted' ? 'finding' : 'excluded',
    proposition: 'The service enforces the Builder-approved documented permission at this IDL entry',
    checkRef: check.factId,
    observedPermission: comparison.observedPermission,
    expectedPermission: comparison.expectedPermission
  };
  if (cacheKey) options.cache.set(cacheKey, result);
  return result;
}

module.exports = { analyze, analyzeSecurity, arbitrateSecurity, guardBeforeOperation };

// ---------------------------------------------------------------------------
// §24.28 阶段 B2：双命题裁决（1.0.20-security-verdict）。
// 旧 analyze 的契约命题语义保持原样，仅供 ≤1.0.19 的旧 run 复算；
// 新语义下 contractDeviation 只描述差异，安全 finding 必须由具体主体 +
// 实际门禁 + 拒绝路径 + 合格策略锚点共同成立。
// ---------------------------------------------------------------------------

const fs = require('node:fs');
const path = require('node:path');

function permissionResolver(facts, headerFile, headerSha256) {
  const verified = facts.verifyFile(headerFile);
  if (!verified.ok || verified.actual !== headerSha256) return null;
  const text = fs.readFileSync(path.join(facts.sourceRoot, ...headerFile.split('/')), 'utf8');
  const table = new Map();
  for (const row of text.split(/\r?\n/)) {
    // 支持 `const std::string SYMBOL = "..."`（pilot）与 `const char SYMBOL[] = "..."`（os_account）。
    const decl = /^\s*const\s+[\w: ]+?\s+([A-Z][A-Z0-9_]*)\s*(?:\[\s*\])?\s*=\s*"([^"]+)"\s*;\s*$/.exec(row);
    if (decl) table.set(decl[1], decl[2]);
  }
  return (symbol) => (table.has(symbol) ? table.get(symbol) : null);
}

function subjectDescription(subject) {
  const holds = subject.holdsPermissions.length ? subject.holdsPermissions.join(', ') : 'no anchored permission';
  const lacks = subject.lacksPermissions.length ? subject.lacksPermissions.join(', ') : 'none';
  const identity = [
    subject.nativeToken ? `nativeToken=${subject.nativeToken}` : null,
    subject.uid ? `uid=${subject.uid}` : null
  ].filter(Boolean).join(', ');
  return `${subject.kind}: holds [${holds}]; lacks [${lacks}]${identity ? `; ${identity}` : ''}`;
}

function gateSummary(gate) {
  return { kind: gate.kind, line: gate.line,
    ...(gate.permission ? { permission: gate.permission } : {}),
    ...(gate.nativeProcess ? { nativeProcess: gate.nativeProcess } : {}),
    ...(gate.uidSymbol ? { uidSymbol: gate.uidSymbol } : {}),
    subjectVariable: gate.subjectVariable,
    blocksOperation: gate.blocksOperation };
}

/**
 * 双命题静态裁决。
 * @param {object} options { policy, cache, onCacheHit }，policy 来自 lib/autonomy/policy.load
 * @returns 契约差异 + 安全裁决 + 门禁清单的合并证明记录；status ∈
 *          finding | excluded | candidate | insufficient。
 */
function analyzeSecurity(facts, anchor, binding, knowledge, comparison, options = {}) {
  const unknown = (reason, extra = {}) => ({ status: 'insufficient', reason, verificationStatus: null,
    normRef: knowledge?.norm?.normId || null, reviewRef: knowledge?.norm?.reviewRef || null, ...extra });
  if (anchor?.kind !== 'idl' || binding?.binding !== 'resolved' || !binding.bound ||
      knowledge?.norm?.state !== 'accepted' || knowledge.norm.authority !== 'builder-llm-review') {
    return unknown('entry-or-builder-norm-unresolved');
  }
  if (options.requireSaMethod && (anchor.saId !== facts.scope?.saMethodBinding?.saId ||
      anchor.saRegistration?.status !== 'resolved' ||
      anchor.saRegistration.serviceFactRef !== binding.bound.factId)) {
    return unknown('sa-method-binding-unresolved', { saStatus: anchor.saRegistration?.status || 'missing' });
  }
  const delegate = { SetPolicyAsync: 'SetPolicy', UnSetPolicyAsync: 'UnSetPolicy' }[anchor.method] || null;
  if (knowledgeLib.applicability(knowledge, anchor.method, delegate).status !== 'applicable') {
    return unknown('norm-applicability-unknown');
  }
  const local = vertical.selectEvidence(facts, binding.bound, delegate);
  if (local.status !== 'observed' || local.truncated ||
      local.operationCallsites.length !== 1 ||
      local.operationCandidates.length !== 1 || local.operationCandidates[0].status !== 'suspect') {
    return unknown('call-chain-or-operation-ambiguous');
  }
  const operation = local.operationCandidates[0];
  const policy = options.policy || null;

  const cacheKey = options.cache && JSON.stringify({ calleeRef: local.calleeRef,
    saProfileRef: options.requireSaMethod ? anchor.saRegistration.profileRef : null,
    calleeSha256: local.callee.sha256, operationCallRef: operation.callRef,
    normRef: knowledge.norm.normId, reviewRef: knowledge.norm.reviewRef,
    policyFingerprint: policy ? require('./policy').fingerprint(policy) : null,
    comparison: comparison && { status: comparison.status, checkRef: comparison.checkRef,
      observedPermission: comparison.observedPermission } });
  if (cacheKey && options.cache.has(cacheKey)) {
    options.onCacheHit?.(cacheKey);
    return options.cache.get(cacheKey);
  }

  const expectedPermission = knowledge.norm.permission;
  const resolvePermission = permissionResolver(facts, knowledge.norm.header.file, knowledge.norm.header.sha256);
  const calleeFn = facts.index().functions.find((fn) => fn.factId === local.calleeRef) || binding.bound;
  const gateVocab = (facts.scope && facts.scope.gateVocabulary) || {};
  const enumerated = gatesLib.enumerate(facts, local.callee, { text: local.text }, {
    operationLine: operation.source.line,
    resolvePermissionConstant: resolvePermission,
    gateTokens: gateVocab.gateTokens,
    identityTokens: gateVocab.identityTokens,
    conditionLinesOnly: Boolean(gateVocab.gateTokens || gateVocab.identityTokens),
    gateVocabulary: gateVocab,
    resolvePermissionHelper: (helperName, line) =>
      gatesLib.resolvePermissionHelper(facts, calleeFn, helperName, line)
  });
  const { gates, unanalyzable } = enumerated;

  // ---- 契约命题：声明与实现的差异（不构成安全结论）。
  let contract;
  if (comparison && comparison.status === 'refuted') {
    contract = { status: 'deviation', family: 'permission-mismatch',
      expectedPermission, observedPermission: comparison.observedPermission };
  } else if (comparison && comparison.status === 'supported') {
    contract = { status: 'none', family: 'compliant',
      expectedPermission, observedPermission: comparison.observedPermission };
  } else {
    const noCheckCalls = local.checkRefs.length === 0 && local.checkCallsites.length === 0 &&
      !/\bCheckPermission\s*\(/.test(local.text);
    const identityGate = gates.find((gate) => gate.kind === 'native-token-match' || gate.kind === 'uid-match');
    if (!noCheckCalls) contract = { status: 'unknown', family: null,
      expectedPermission, observedPermission: null, reason: comparison?.reason || 'permission-check-ambiguous' };
    else if (identityGate) contract = { status: 'deviation', family: 'alternate-identity-gate',
      expectedPermission, observedPermission: identityGate.kind === 'native-token-match'
        ? `native-token(${identityGate.helperName})` : `uid(${identityGate.uidSymbol})` };
    else contract = { status: 'deviation', family: 'missing-permission-check',
      expectedPermission, observedPermission: 'none' };
  }

  const base = {
    verificationStatus: 'static-only', assurance: 'bounded-analysis',
    normRef: knowledge.norm.normId, reviewRef: knowledge.norm.reviewRef,
    delegateRef: local.calleeRef, operationRef: operation.targetRef,
    operationCallRef: operation.callRef,
    ...(options.requireSaMethod ? { saMethod: anchor.saRegistration } : {}),
    expectedPermission, observedPermission: contract.observedPermission,
    limitation: 'Scoped source-qualified operation path and recognized gate shapes only; subject reachability is bounded to the enumerated local gates, not global control flow, aliases, or build variants.'
  };

  // ---- 安全命题：具体主体能否经实际门禁到达操作。
  const security = { status: 'insufficient', family: null, reason: null };
  if (unanalyzable.length) {
    // 取最具体的已知限制作为具名原因（组合 > 未知形状 > 未识别身份条件）。
    security.reason = ['combined-gate-unsupported', 'gate-shape-unsupported', 'unrecognized-caller-guard']
      .find((code) => unanalyzable.some((item) => item.reasonCode === code)) || unanalyzable[0].reasonCode;
  } else {
    const blocking = gates.filter((gate) => gate.blocksOperation === true);
    const callerPermGates = blocking.filter((gate) =>
      gate.kind === 'permission-check' && gate.subjectScope === 'caller' && !gate.unresolved);
    const anchorCheck = policy && expectedPermission
      ? require('./policy').anchorQualifies(policy, expectedPermission)
      : { qualified: false, cap: 'candidate', reason: 'policy-anchor-unavailable' };

    const evaluate = (subject) => gatesLib.evaluateSubject(blocking, subject);
    const docSubject = {
      kind: 'normal-application', holdsPermissions: [expectedPermission],
      lacksPermissions: callerPermGates.map((gate) => gate.permission)
        .filter((permission) => permission && permission !== expectedPermission),
      nativeToken: 'other', uid: 'app'
    };
    const lackingSubject = {
      kind: 'normal-application', holdsPermissions: [],
      lacksPermissions: [expectedPermission], nativeToken: 'other', uid: 'app'
    };

    if (blocking.length) {
      const docEval = evaluate(docSubject);
      const lackingEval = evaluate(lackingSubject);
      if (docEval.status === 'unknown' || lackingEval.status === 'unknown') {
        security.reason = (docEval.status === 'unknown' ? docEval : lackingEval).reason;
      } else if (lackingEval.status === 'rejected') {
        // 缺少门禁所要求凭据的主体被拒绝：仅就该限定主体与路径排除。
        if (docEval.status === 'rejected') {
          // 文档所述主体（仅持 expectedPermission）被实际门禁拒绝（错配/身份门家族）。
          security.status = 'excluded';
          security.family = 'scoped-gate-rejection';
          security.subject = { ...docSubject, description: subjectDescription(docSubject) };
          security.rejectingGates = docEval.rejectingGates.map(gateSummary);
          security.note = 'excluded is scoped to this subject and path; not whole-entry safety';
        } else {
          // 合规：不持文档所述权限的主体被唯一门禁拒绝。
          security.status = 'excluded';
          security.family = 'scoped-gate-rejection';
          security.subject = { ...lackingSubject, description: subjectDescription(lackingSubject) };
          security.rejectingGates = lackingEval.rejectingGates.map(gateSummary);
          security.note = 'excluded is scoped to this subject and path; not whole-entry safety';
        }
        security.proposition = `Subject ${security.subject.description} can complete the scoped operation via this entry`;
        // 门禁比文档要求更弱（不同且主体可获得的权限）时，构造越权主体。
        const weaker = callerPermGates.find((gate) => gate.permission && gate.permission !== expectedPermission &&
          policy && require('./policy').subjectCanHold(policy, gate.permission).status === 'yes');
        if (weaker) {
          const passSubject = {
            kind: 'normal-application', holdsPermissions: [weaker.permission],
            lacksPermissions: [expectedPermission], nativeToken: 'other', uid: 'app'
          };
          const passEval = evaluate(passSubject);
          if (passEval.status === 'passes') {
            security.status = anchorCheck.qualified ? 'finding' : 'candidate';
            security.family = 'gate-permission-weakened';
            security.subject = { ...passSubject, description: subjectDescription(passSubject) };
            security.rejectingGates = [];
            security.proposition = `Subject ${security.subject.description} can complete the scoped operation via this entry`;
            if (!anchorCheck.qualified) security.reason = anchorCheck.reason || 'policy-anchor-doc-only';
            else security.anchor = { qualified: true, basis: anchorCheck.basis };
          } else if (passEval.status === 'unknown') security.reason = passEval.reason;
        }
      } else {
        // 门禁未拒绝缺权主体：不早退或检查了非调用方主体，主体可到达操作。
        const unconstrained = blocking.some((gate) => gate.kind === 'permission-check' && gate.subjectScope === 'non-caller');
        security.status = anchorCheck.qualified ? 'finding' : 'candidate';
        security.family = unconstrained ? 'gate-subject-mismatch' : 'gate-non-blocking';
        security.subject = { ...lackingSubject, description: subjectDescription(lackingSubject) };
        security.rejectingGates = [];
        security.proposition = `Subject ${security.subject.description} can complete the scoped operation via this entry`;
        if (!anchorCheck.qualified) security.reason = anchorCheck.reason || 'policy-anchor-doc-only';
        else security.anchor = { qualified: true, basis: anchorCheck.basis };
      }
    } else {
      // unanalyzable 为空时，含调用方身份的未识别 if 条件都已进入 unanalyzable；
      // 这里只剩三种情况：门禁未解析、已识别门禁未阻断、或完全无可识别门禁。
      const unresolvedGate = gates.find((gate) => gate.unresolved);
      if (unresolvedGate) {
        security.reason = unresolvedGate.unresolved;
      } else if (gates.length > 0) {
        // 门禁已识别但未阻断操作（拒绝分支不早退或不支配）：缺权主体可到达操作。
        const unconstrained = gates.some((gate) => gate.kind === 'permission-check' && gate.subjectScope === 'non-caller');
        security.status = anchorCheck.qualified ? 'finding' : 'candidate';
        security.family = unconstrained ? 'gate-subject-mismatch' : 'gate-non-blocking';
        security.subject = { ...lackingSubject, description: subjectDescription(lackingSubject) };
        security.rejectingGates = [];
        security.proposition = `Subject ${security.subject.description} can complete the scoped operation via this entry`;
        if (!anchorCheck.qualified) security.reason = anchorCheck.reason || 'policy-anchor-doc-only';
        else security.anchor = { qualified: true, basis: anchorCheck.basis };
      } else {
        security.status = anchorCheck.qualified ? 'finding' : 'candidate';
        security.family = 'no-analyzable-gate';
        security.subject = { ...lackingSubject, description: subjectDescription(lackingSubject) };
        security.rejectingGates = [];
        security.proposition = `Subject ${security.subject.description} can complete the scoped operation via this entry`;
        if (!anchorCheck.qualified) security.reason = anchorCheck.reason || 'policy-anchor-doc-only';
        else security.anchor = { qualified: true, basis: anchorCheck.basis };
      }
    }
  }

  const status = security.status === 'finding' ? 'finding' :
    security.status === 'excluded' ? 'excluded' :
      security.status === 'candidate' ? 'candidate' : 'insufficient';
  const result = {
    ...base, status,
    contract,
    security: {
      status: security.status, family: security.family, reason: security.reason || null,
      ...(security.subject ? { subject: security.subject } : {}),
      ...(security.proposition ? { proposition: security.proposition } : {}),
      ...(security.rejectingGates ? { rejectingGates: security.rejectingGates } : {}),
      ...(security.anchor ? { anchor: security.anchor } : {}),
      ...(security.note ? { note: security.note } : {})
    },
    gates: gates.map(gateSummary),
    unanalyzable,
    limitation: status === 'excluded'
      ? `${base.limitation} Excluded refutes only the scoped subject-and-path proposition, not whole-entry safety.`
      : base.limitation
  };
  if (cacheKey) options.cache.set(cacheKey, result);
  return result;
}

/**
 * 模型复核仲裁（阶段 B3）：模型只能提供反例或确认缺口，不能升级结论。
 * excluded + 经证据门接受的 refuted/conflict → 降为 candidate；
 * finding + 经证据门接受的 supported/conflict（模型主张门禁阻断/相左）→ 降为 candidate；
 * 其余不改等级。
 */
function arbitrateSecurity(proof, modelCheck) {
  const refuted = modelCheck?.gate === 'accepted' && modelCheck.decision === 'refuted';
  const opposed = refuted || (modelCheck?.gate === 'accepted' && modelCheck.decision === 'conflict');
  const upheld = modelCheck?.gate === 'accepted' && modelCheck.decision === 'supported';
  if (proof?.status === 'excluded' && opposed) {
    return { status: 'candidate', reasonCode: 'prover-model-conflict',
      subject: proof.security?.subject || null,
      rationale: `Scoped exclusion refuted by model counterexample: ${modelCheck.rationale || 'no rationale'}`,
      modelCallRef: modelCheck.modelCallRef || null };
  }
  if (proof?.status === 'finding' && (upheld || modelCheck?.decision === 'conflict')) {
    return { status: 'candidate', reasonCode: 'prover-model-conflict',
      subject: proof.security?.subject || null,
      rationale: `Static finding contradicted by model review (${modelCheck.decision}): ${modelCheck.rationale || 'no rationale'}`,
      modelCallRef: modelCheck.modelCallRef || null };
  }
  if (proof?.status === 'insufficient' && modelCheck?.gate === 'accepted' &&
      modelCheck.decision === 'refuted') {
    // 经证据门接受的模型反例（引用本任务证据、同一入口命题）把未闭合命题降为 candidate；
    // 模型不能升级，只登记具名疑点。
    return { status: 'candidate', reasonCode: 'model-supported-suspect',
      subject: proof.security?.subject || null,
      rationale: `Model counterexample supports the suspect path: ${modelCheck.rationale || 'no rationale'}`,
      modelCallRef: modelCheck.modelCallRef || null };
  }
  return { status: proof?.status || 'insufficient', reasonCode: proof?.security?.reason || proof?.reason || null,
    subject: proof?.security?.subject || null,
    rationale: proof?.security?.proposition || proof?.reason || null, modelCallRef: null };
}
