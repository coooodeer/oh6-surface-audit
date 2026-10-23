'use strict';

class VerificationPlanError extends Error {
  constructor(message) {
    super(message);
    this.code = 'invalid-verification-plan';
  }
}

function validatePlan(plan, store) {
  const required = ['planId', 'taskId', 'questionIds', 'hypothesis', 'runnerId',
    'targetEnvironment', 'buildVariantId', 'sourceRefs', 'harnessRef', 'inputRefs',
    'controls', 'expectedSignals', 'successCriteria', 'resourceLimits',
    'requiredCapabilities', 'approvalRef', 'snapshotId', 'limitations'];
  if (!plan || typeof plan !== 'object' || required.some((key) => !(key in plan)) ||
      Object.keys(plan).some((key) => !required.includes(key)) ||
      !/^PLAN:[0-9a-f]{16}$/.test(plan.planId) ||
      !/^TASK:[0-9a-f]{16}$/.test(plan.taskId) ||
      plan.snapshotId !== store.run.payload.snapshotId ||
      !['host-isolated', 'target-build', 'device-isolated'].includes(plan.runnerId) ||
      plan.approvalRef !== null || plan.harnessRef !== null ||
      !Array.isArray(plan.questionIds) || !plan.questionIds.length ||
      !Array.isArray(plan.sourceRefs) || !plan.sourceRefs.length ||
      !Array.isArray(plan.inputRefs) || !Array.isArray(plan.controls) ||
      !Array.isArray(plan.expectedSignals) || !plan.expectedSignals.length ||
      !Array.isArray(plan.requiredCapabilities) || !plan.requiredCapabilities.length ||
      typeof plan.hypothesis !== 'string' || !plan.hypothesis.trim() ||
      typeof plan.limitations !== 'string' || !plan.limitations.trim() ||
      !plan.resourceLimits || !Number.isInteger(plan.resourceLimits.timeoutMs) ||
      plan.resourceLimits.timeoutMs < 1 || plan.resourceLimits.timeoutMs > 60000 ||
      !plan.successCriteria || !['blocked', 'no-signal', 'observed'].includes(plan.successCriteria.noSignal)) {
    throw new VerificationPlanError('verification-plan-invalid-or-unapproved');
  }
  const tasks = store.readRecords('task').rows;
  const questions = store.readRecords('question').rows;
  if (!tasks.some((row) => row.recordId === plan.taskId) ||
      plan.questionIds.some((id) => !questions.some((row) => row.recordId === id && row.payload.taskId === plan.taskId))) {
    throw new VerificationPlanError('verification-plan-task-or-question-unbound');
  }
  return { status: 'blocked', reason: 'no-approved-isolated-runner-or-harness',
    entryFaithfulness: 'unknown', executedCommands: [] };
}

module.exports = { validatePlan, VerificationPlanError };
