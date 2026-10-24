'use strict';

/** Bounded assessment from tool evidence and optional model review. */

const ids = require('./ids');
const state = require('./state');

const DECISIONS = Object.freeze(['supported', 'refuted', 'insufficient', 'conflict']);

const FORBIDDEN_TOKENS = Object.freeze(['device-verified', 'runtime-verified', 'exploitable']);

const DOMINANCE_REASON = 'dominance-unproven';

function questionByKind(questions, kind) {
  return (questions || []).find((q) => q.kind === kind) || null;
}

function toolResultByTool(results, tool) {
  return (results || []).find((r) => r.payload && r.payload.tool === tool) || null;
}

/** 从工具结果里取答案状态（统一成 question status 词表） */
function answerStatusOf(record) {
  if (!record || !record.payload) return 'unknown';
  const st = record.payload.answer ? record.payload.answer.status : 'unknown';
  if (st === 'supported') return 'supported';
  if (st === 'refuted') return 'refuted';
  return 'insufficient';
}

/**
 * off 裁决：纯函数、无时间、无随机。
 * @param {{task:object, questions:Array, results:Array, binding:object, missingRefs:Map}} o
 * @returns {{updates:Array, assessments:Array, extraMissing:Array}}
 */
function adjudicateOff(o) {
  const { task, questions, results, binding } = o;
  const updates = [];
  const assessments = [];
  const extraMissing = [];
  const entryRef = task.anchorRefs[0];

  const bindingQ = questionByKind(questions, 'binding');
  const checkQ = questionByKind(questions, 'check-presence');
  const domQ = questionByKind(questions, 'dominance');

  const inspectEntry = toolResultByTool(results, 'inspectEntry');
  const inspectAuth = toolResultByTool(results, 'inspectAuthorization');
  const inspectDelegation = o.experiment ? toolResultByTool(results, 'inspectDelegation') : null;
  const inspectOperation = o.experiment === 'static-scan'
    ? toolResultByTool(results, 'inspectOperationCandidate') : null;
  const inspectRel = toolResultByTool(results, 'inspectRelation');
  const evidence = toolResultByTool(results, 'getEvidence');

  // ---- Q-binding
  const bindingStatus = (() => {
    if (inspectEntry && inspectEntry.payload.observations) {
      const b = inspectEntry.payload.observations.binding;
      if (b === 'resolved') return { status: 'supported', reason: null };
      if (b === 'suspect') return { status: 'insufficient', reason: 'binding-ambiguous' };
      return { status: 'insufficient', reason: reasonForUnbound(binding, task) };
    }
    if (binding && binding.binding === 'resolved') return { status: 'supported', reason: null };
    return { status: 'insufficient', reason: reasonForUnbound(binding, task) };
  })();

  const bindingMissing = [];
  if (bindingStatus.reason) {
    const miss = state.buildMissing({
      questionId: bindingQ.questionId,
      reasonCode: bindingStatus.reason,
      targetRefs: [entryRef],
      blocking: true,
      nextActions: ['inspect-entry-binding', 'inspect-relation:registers']
    });
    bindingMissing.push(miss.missingId);
    extraMissing.push(miss);
  }

  updates.push({
    questionId: bindingQ.questionId,
    status: bindingStatus.status,
    basis: 'derived',
    assurance: 'bounded-analysis',
    evidenceRefs: inspectEntry ? [inspectEntry.recordId] : [],
    missingRefs: bindingMissing
  });

  assessments.push(makeAssessment({
    task,
    question: bindingQ,
    entryRef,
    snapshotId: o.snapshotId,
    decision: bindingStatus.status,
    basis: 'derived',
    assurance: 'bounded-analysis',
    evidenceRefs: inspectEntry ? [inspectEntry.recordId] : [],
    missingRefs: bindingMissing,
    contextId: o.contextId || null,
    modelCallRef: null,
    rationale: bindingStatus.status === 'supported'
      ? `唯一实现体 ${(binding && binding.bound && (binding.bound.qualified || binding.bound.name)) || 'impl'}`
      : `绑定未收敛：${bindingStatus.reason}`
  }));

  // ---- Q-check
  let checkStatus;
  let checkMissing = [];
  let checkRationale;
  if (bindingStatus.status === 'supported') {
    const auth = answerStatusOf(inspectAuth);
    if (auth === 'supported') {
      checkStatus = 'supported';
      const strong = inspectAuth.payload.observations ? inspectAuth.payload.observations.strongTier : 0;
      checkRationale = `函数体内有 ${inspectAuth.payload.observations.matches.length} 个校验调用（strong=${strong}）`;
    } else if (auth === 'refuted') {
      checkStatus = 'refuted';
      checkRationale = '函数体内直接调用中未出现词表内的校验调用名';
      if (inspectDelegation) {
        const observation = inspectDelegation.payload.observations;
        const hasCheck = observation && observation.delegates &&
          observation.delegates.some((d) => d.status === 'check-observed');
        const incomplete = inspectDelegation.payload.status !== 'ok' ||
          inspectDelegation.payload.completeness.enumeration !== 'complete';
        if (hasCheck || incomplete) {
          const reasonCode = hasCheck ? 'delegated-check-unproven' : 'delegation-incomplete';
          const miss = state.buildMissing({
            questionId: checkQ.questionId,
            reasonCode,
            targetRefs: [entryRef],
            blocking: true,
            nextActions: ['inspect-check-condition-and-object']
          });
          checkMissing.push(miss.missingId);
          extraMissing.push(miss);
          checkRationale += hasCheck
            ? '；精确一跳被调函数中有校验调用，其有效性仍待证'
            : '；一跳证据未闭合';
        }
      }
    } else {
      checkStatus = 'insufficient';
      const code = inspectAuth ? inspectAuth.payload.errorCode : null;
      checkRationale = code === 'check-call-weak-only'
        ? '函数体只有身份获取（weak）调用，没有可判定的授权校验调用'
        : (code === 'budget-exhausted'
          ? '预算在取到校验调用证据之前耗尽'
          : '校验调用工具未能给出可判定答案');
      const reason = code === 'check-call-weak-only'
        ? 'check-call-weak-only'
        : (code === 'budget-exhausted' ? 'budget-exhausted' : 'tool-unsupported');
      const miss = state.buildMissing({
        questionId: checkQ.questionId,
        reasonCode: reason,
        targetRefs: [entryRef],
        blocking: reason !== 'check-call-weak-only',
        nextActions: ['inspect-relation:callers', 'inspect-authorization-path']
      });
      checkMissing.push(miss.missingId);
      extraMissing.push(miss);
    }
  } else {
    checkStatus = 'insufficient';
    checkRationale = '绑定未成功，无法观察实现体';
  }
  updates.push({
    questionId: checkQ.questionId,
    status: checkStatus,
    basis: 'observed',
    assurance: 'bounded-analysis',
    evidenceRefs: [inspectAuth, inspectDelegation].filter(Boolean).map((r) => r.recordId),
    missingRefs: checkMissing
  });
  assessments.push(makeAssessment({
    task,
    question: checkQ,
    entryRef,
    snapshotId: o.snapshotId,
    decision: checkStatus,
    basis: 'observed',
    assurance: 'bounded-analysis',
    evidenceRefs: [inspectAuth, inspectDelegation].filter(Boolean).map((r) => r.recordId),
    counterEvidenceRefs: inspectDelegation ? [inspectDelegation.recordId] : [],
    missingRefs: checkMissing,
    contextId: o.contextId || null,
    modelCallRef: null,
    rationale: checkRationale
  }));

  // ---- Q-dominance（恒 insufficient）
  const domMiss = state.buildMissing({
    questionId: domQ.questionId,
    reasonCode: DOMINANCE_REASON,
    targetRefs: [entryRef],
    blocking: true,
    nextActions: ['inspect-authorization-path', 'inspect-control-flow']
  });
  extraMissing.push(domMiss);
  const operationCandidate = inspectOperation?.payload.observations?.candidates?.length === 1
    ? inspectOperation.payload.observations.candidates[0] : null;
  const operationMiss = o.experiment && task.origin === 'entry-scan' && !task.operationRef
    ? state.buildMissing({
      questionId: domQ.questionId,
      reasonCode: operationCandidate ? 'operation-target-unproven' : 'operation-unbound',
      targetRefs: operationCandidate
        ? [entryRef, operationCandidate.callRef, operationCandidate.targetRef] : [entryRef],
      blocking: true,
      nextActions: [operationCandidate ? 'resolve-operation-call-target' : 'bind-protected-operation']
    }) : null;
  if (operationMiss) extraMissing.push(operationMiss);
  const domMissingRefs = [domMiss.missingId, ...(operationMiss ? [operationMiss.missingId] : [])];
  updates.push({
    questionId: domQ.questionId,
    status: 'insufficient',
    basis: 'derived',
    assurance: 'bounded-analysis',
    evidenceRefs: [inspectRel, evidence, inspectOperation].filter(Boolean).map((r) => r.recordId),
    missingRefs: domMissingRefs
  });
  assessments.push(makeAssessment({
    task,
    question: domQ,
    entryRef,
    snapshotId: o.snapshotId,
    decision: 'insufficient',
    basis: 'derived',
    assurance: 'bounded-analysis',
    evidenceRefs: [inspectRel, evidence, inspectOperation].filter(Boolean).map((r) => r.recordId),
    missingRefs: domMissingRefs,
    contextId: o.contextId || null,
    modelCallRef: null,
    rationale: 'MVP 不实现支配关系与对象一致性分析，因此恒为 insufficient'
  }));

  return { updates, assessments, extraMissing };
}

function reasonForUnbound(binding, task) {
  if (!binding) return 'binding-unbound';
  if (binding.entry && binding.entry.kind === 'sa') return 'binding-metadata-only';
  if (binding.note && /no method body|registration has no bound method body/.test(binding.note)) return 'binding-metadata-only';
  return 'binding-unbound';
}

function makeAssessment(o) {
  const semantic = {
    taskId: o.task.taskId,
    questionId: o.question.questionId,
    decision: o.decision,
    evidenceRefs: ids.uniqueSorted(o.evidenceRefs || []),
    missingRefs: ids.uniqueSorted(o.missingRefs || [])
  };
  const payload = {
    assessmentId: ids.assessmentId('assessment', semantic),
    taskId: o.task.taskId,
    questionId: o.question.questionId,
    proposition: o.question.proposition,
    scope: { entryRefs: [o.entryRef], snapshotId: o.snapshotId },
    decision: o.decision,
    basis: o.basis,
    assurance: o.assurance,
    evidenceRefs: ids.uniqueSorted(o.evidenceRefs || []),
    counterEvidenceRefs: ids.uniqueSorted(o.counterEvidenceRefs || []),
    assumptions: o.assumptions || [],
    missingRefs: ids.uniqueSorted(o.missingRefs || []),
    contextId: o.contextId || null,
    modelCallRef: o.modelCallRef || null,
    rationale: String(o.rationale || '').slice(0, 400)
  };
  return payload;
}

function arbitrateStaticContract(proof, modelCheck) {
  const refuted = modelCheck?.gate === 'accepted' && modelCheck.decision === 'refuted';
  const opposed = refuted || (modelCheck?.gate === 'accepted' && modelCheck.decision === 'conflict');
  if (proof?.status === 'excluded' && opposed) return {
    decision: 'conflict', reasonCode: 'prover-model-conflict',
    rationale: `Static proof excluded; model counterexample: ${modelCheck.rationale || 'no rationale'}`,
    modelCallRef: modelCheck.modelCallRef || null
  };
  if (proof?.status === 'insufficient' && proof.operationRef &&
      (proof.candidateSignal === 'no-resolved-check' || refuted)) return {
    decision: 'insufficient', reasonCode: 'static-contract-suspect',
    rationale: refuted ? `Model counterexample: ${modelCheck.rationale || 'no rationale'}` : proof.reason,
    modelCallRef: refuted ? modelCheck.modelCallRef || null : null
  };
  return { decision: proof?.status === 'finding' ? 'refuted' :
    proof?.status === 'excluded' ? 'supported' : 'insufficient', reasonCode: null,
  rationale: proof?.family || proof?.reason || 'No applicable published norm.', modelCallRef: null };
}

/**
 * live 裁决：模型只给"check-presence"意见，程序门强制收敛。
 * @returns {{decision:string, basis:string, assurance:string, evidenceRefs:Array, missingRefs:Array,
 *            modelCallRef:string|null, rationale:string, gate:string, raw:object|null, extraMissing:Array}}
 */
async function adjudicateLiveCheck(o) {
  const { gateway, task, question, context, allowedRefs } = o;
  const messages = [
    {
      role: 'system',
      content: o.purpose === 'static-contract-review' ? [
        '你是静态契约审计复核者。仅依据给定事实与已发布规范判断局部静态契约是否成立；复杂控制流可以提出有理由的反例。',
        '只输出 JSON：{"decision":"supported|refuted|insufficient|conflict","rationale":"<=2 句","evidenceRefs":["EVID:..."]}。',
        '不得声称设备行为、可利用性或整体安全。'
      ].join('\n') : [
        '你是静态审计的判定器。只能依据给定的、可回查的证据回答。',
        '**只输出一个 JSON 对象**，不要输出推理过程、不要输出 JSON 之外的任何文字。',
        '输出：{"decision":"supported|refuted|insufficient|conflict","rationale":"<=2 句","evidenceRefs":["EVID:..."]}',
        '不得声称设备验证、运行时验证或可利用性。'
      ].join('\n')
    },
    {
      role: 'user',
      content: [
        `命题：${question.proposition}`,
        '上下文（只含事实）：',
        o.contextText || '',
        `允许引用的证据 ID：${[...allowedRefs].sort().join(', ') || '(none)'}`
      ].join('\n')
    }
  ];
  const res = await gateway.invoke({
    purpose: o.purpose || 'check-presence',
    taskId: task.taskId,
    contextId: context ? context.contextId : null,
    messages,
    maxTokens: o.maxTokens || 512
  });
  const extraMissing = [];
  const gateFail = (code, detail, modelCallRef) => {
    const miss = state.buildMissing({
      questionId: question.questionId,
      reasonCode: 'model-output-invalid',
      targetRefs: [task.anchorRefs[0]],
      blocking: true,
      nextActions: ['inspect-model-call', code]
    });
    extraMissing.push(miss);
    return {
      decision: 'insufficient',
      basis: 'llm',
      assurance: 'model-assessment',
      evidenceRefs: [],
      missingRefs: [miss.missingId],
      modelCallRef: modelCallRef || null,
      rationale: `程序证据门拒绝模型输出：${code}${detail ? ` (${String(detail).slice(0, 120)})` : ''}`,
      gate: `rejected:${code}`,
      raw: null,
      extraMissing
    };
  };
  if (!res || res.status !== 'ok' || !res.parsed) {
    return gateFail(res && res.reason ? res.reason : 'no-output', res && res.detail, res ? res.callId : null);
  }
  const out = res.parsed;
  if (!DECISIONS.includes(out.decision)) return gateFail('decision-not-in-enum', out.decision, res.callId);
  const refs = Array.isArray(out.evidenceRefs) ? out.evidenceRefs : [];
  const badRefs = refs.filter((r) => !allowedRefs.has(r));
  if (badRefs.length) return gateFail('unresolvable-evidence-ref', badRefs.join(','), res.callId);
  const blob = JSON.stringify(out);
  const hit = FORBIDDEN_TOKENS.find((t) => blob.includes(t));
  if (hit) return gateFail('forbidden-token', hit, res.callId);
  // 旧 check-presence 意见不作为静态契约的正向证明。
  let decision = out.decision;
  let gate = 'accepted';
  if (decision === 'supported' && o.purpose !== 'static-contract-review') {
    decision = 'insufficient';
    gate = 'downgraded:no-runtime-witness';
  }
  return {
    decision,
    basis: 'llm',
    assurance: 'model-assessment',
    evidenceRefs: ids.uniqueSorted(refs),
    missingRefs: [],
    modelCallRef: res.callId,
    rationale: String(out.rationale || '').slice(0, 400),
    gate,
    raw: out,
    extraMissing
  };
}

module.exports = {
  DECISIONS,
  FORBIDDEN_TOKENS,
  DOMINANCE_REASON,
  adjudicateOff,
  adjudicateLiveCheck,
  makeAssessment,
  arbitrateStaticContract,
  answerStatusOf,
  questionByKind,
  toolResultByTool,
  reasonForUnbound
};
