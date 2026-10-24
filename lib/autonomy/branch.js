'use strict';

const ids = require('./ids');
const state = require('./state');

function proposeInputBoundary(vertical, parent, facts) {
  if (!vertical || vertical.status !== 'observation' ||
      vertical.parserTypeHint !== true ||
      vertical.parserCallsites?.length !== 1 ||
      vertical.parserCallsites[0].resolution === 'exact') return null;
  const target = facts.index().functions.filter((fn) =>
    fn.qualified?.endsWith('::PolicyVecRawData::Unmarshalling'));
  if (target.length !== 1) return null;
  const callsite = vertical.parserCallsites[0];
  const taskId = ids.taskId('input-boundary-branch', { parent: parent.taskId, callsite: callsite.ref });
  const proposition = state.TASK_QUESTION_TEXT['input-boundary-local'];
  const questionId = ids.questionId('question', { taskId, kind: 'input-boundary-local', proposition });
  return {
    task: { taskId, origin: 'analysis-branch', anchorRefs: parent.anchorRefs,
      question: proposition, state: 'queued', questionRefs: [questionId], missingRefs: [], revision: 1 },
    question: { questionId, taskId, kind: 'input-boundary-local', proposition, polarity: 'forall',
      status: 'unknown', basis: 'derived', assurance: 'bounded-analysis', evidenceRefs: [], missingRefs: [] },
    parentTaskId: parent.taskId, view: 'input-boundary', callsite,
    candidate: { factRef: target[0].factId, file: target[0].sourceRange.file,
      startLine: target[0].startLine, endLine: target[0].endLine, binding: 'type-hint-only' }
  };
}

function proposeOperationView(proof, parent, facts) {
  if (proof?.status !== 'insufficient' || !proof.operationRef || !proof.operationCallRef) return null;
  const target = facts.index().functions.filter((fn) => fn.factId === proof.operationRef);
  if (target.length !== 1 || !target[0].sourceRange?.file ||
      !facts.verifyFile(target[0].sourceRange.file).ok) return null;
  const taskId = ids.taskId('operation-view-branch', {
    parent: parent.taskId, callsite: proof.operationCallRef });
  const proposition = state.TASK_QUESTION_TEXT['operation-local'];
  const questionId = ids.questionId('question', { taskId, kind: 'operation-local', proposition });
  return {
    task: { taskId, origin: 'analysis-branch', anchorRefs: parent.anchorRefs,
      question: proposition, state: 'queued', questionRefs: [questionId], missingRefs: [], revision: 1 },
    question: { questionId, taskId, kind: 'operation-local', proposition, polarity: 'forall',
      status: 'unknown', basis: 'derived', assurance: 'bounded-analysis', evidenceRefs: [], missingRefs: [] },
    parentTaskId: parent.taskId, view: 'operation-target', callsite: { ref: proof.operationCallRef },
    candidate: { factRef: target[0].factId, file: target[0].sourceRange.file,
      startLine: target[0].startLine, endLine: target[0].endLine, binding: 'exact-target' }
  };
}

module.exports = { proposeInputBoundary, proposeOperationView };
