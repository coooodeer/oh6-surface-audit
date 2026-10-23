'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { evaluate } = require('../tools/autonomy-holdout-eval');

const runId = 'RUN:aaaaaaaaaaaaaaaa';
function fixture(counts) {
  const cases = [];
  const tasks = [];
  const questions = [];
  const assessments = [];
  for (const [verdict, count] of Object.entries(counts)) {
    for (let i = 0; i < count; i += 1) {
      const id = verdict + '-' + i;
      cases.push({ labelId: 'LABEL:' + id, questionId: 'Q:' + id, runId,
        familyId: 'family-' + id, source: 'production', annotator: 'reviewer',
        annotatedAt: '2026-10-22T00:00:00Z', entryRef: 'ENT:' + id,
        questionKind: 'authorization-effect', humanVerdict: verdict });
      tasks.push({ payload: { taskId: 'TASK:' + id, anchorRefs: ['ENT:' + id] } });
      questions.push({ payload: { questionId: 'Q:' + id, taskId: 'TASK:' + id, kind: 'authorization-effect' } });
      assessments.push({ payload: { questionId: 'Q:' + id, decision: verdict } });
    }
  }
  return { labels: { status: 'frozen', frozenAt: '2026-10-22T00:00:00Z',
    independentReviewer: 'reviewer', labels: cases }, run: { runId, tasks, questions, assessments } };
}

test('pending labels never produce effect metrics', () => {
  const result = evaluate({ status: 'pending', labels: [] }, { runId });
  assert.equal(result.status, 'insufficient-sample');
  assert.deepEqual(result.shortfall, { supported: 20, refuted: 20, insufficient: 10 });
  assert.equal(result.candidatePrecision, null);
  assert.equal(result.judgmentAccuracy, null);
});

test('repeated runs report one substantive question rather than two holdout cases', () => {
  const data = fixture({ insufficient: 1 });
  const replay = { ...data.run, runId: 'RUN:bbbbbbbbbbbbbbbb' };
  const result = evaluate({ status: 'pending', labels: [] }, [data.run, replay]);
  assert.deepEqual(result.runCoverage, { substantiveRecords: 2, distinctQuestions: 1,
    decisionCounts: { supported: 0, refuted: 0, insufficient: 2, conflict: 0 } });
  assert.deepEqual(result.localCoverage['authorization-effect'].decisiveRate,
    { numerator: 0, denominator: 1 });
  assert.equal(result.discoveryRecall, null);
});

test('local diagnostic deduplicates question IDs and flags inconsistent reruns without calling it accuracy', () => {
  const data = fixture({ supported: 1, refuted: 1, insufficient: 1 });
  data.run.questions[0].payload.kind = 'check-presence';
  const replay = { ...data.run, runId: 'RUN:bbbbbbbbbbbbbbbb',
    assessments: data.run.assessments.map((row) => ({ payload: { ...row.payload } })) };
  replay.assessments[0].payload.decision = 'refuted';
  const result = evaluate({ status: 'pending', labels: [] }, [data.run, replay]);
  assert.deepEqual(result.localCoverage['check-presence'], { distinctQuestions: 1,
    supported: 0, refuted: 0, insufficient: 0, conflict: 0, unstable: 1,
    decisiveRate: { numerator: 0, denominator: 1 } });
  assert.equal(result.judgmentAccuracy, null);
  assert.equal(result.releaseGate, 'not-evaluated');
});

test('frozen insufficient labels and mismatches cannot masquerade as results', () => {
  const data = fixture({ supported: 1, refuted: 1, insufficient: 1 });
  assert.equal(evaluate(data.labels, data.run).status, 'insufficient-sample');
  data.labels.labels[0].entryRef = 'ENT:wrong';
  assert.throws(() => evaluate(data.labels, data.run), /label-run-mismatch/);
  data.labels.labels[0].entryRef = 'ENT:supported-0';
  data.labels.labels[1].questionId = data.labels.labels[0].questionId;
  assert.throws(() => evaluate(data.labels, data.run), /invalid-or-duplicate-label/);
  data.labels.labels[1].questionId = 'Q:refuted-0';
  data.labels.labels[1].questionKind = 'dominance';
  assert.throws(() => evaluate(data.labels, data.run), /invalid-or-duplicate-label/);
});

test('minimum labels only permit partial judgment metrics, not release metrics', () => {
  const data = fixture({ supported: 20, refuted: 20, insufficient: 10 });
  data.run.assessments[0].payload.decision = 'refuted';
  data.run.assessments[49].payload.decision = 'supported';
  data.run.assessments[48].payload.decision = 'conflict';
  const result = evaluate(data.labels, data.run);
  assert.equal(result.status, 'partial-judgment-only');
  assert.deepEqual(result.judgmentAccuracy, { correct: 39, total: 40 });
  assert.deepEqual(result.falseCertaintyRate, { falseCertain: 1, total: 10 });
  assert.equal(result.discoveryRecall, null);
  assert.equal(result.releaseGate, 'not-evaluated');
});

test('different checked runs can contribute distinct semantic labels', () => {
  const first = fixture({ supported: 10, refuted: 10, insufficient: 5 });
  const second = fixture({ supported: 10, refuted: 10, insufficient: 5 });
  second.run.runId = 'RUN:bbbbbbbbbbbbbbbb';
  for (const item of second.labels.labels) {
    item.runId = second.run.runId;
    item.labelId += '-second';
    item.questionId += '-second';
    item.entryRef += '-second';
  }
  for (const task of second.run.tasks) {
    task.payload.taskId += '-second';
    task.payload.anchorRefs[0] += '-second';
  }
  for (const question of second.run.questions) {
    question.payload.questionId += '-second';
    question.payload.taskId += '-second';
  }
  for (const assessment of second.run.assessments) assessment.payload.questionId += '-second';
  const labels = { ...first.labels, labels: [...first.labels.labels, ...second.labels.labels] };
  assert.equal(evaluate(labels, [first.run, second.run]).status, 'partial-judgment-only');
  labels.labels[25].questionId = 'Q:supported-0';
  assert.throws(() => evaluate(labels, [first.run, second.run]), /invalid-or-duplicate-label/);
  assert.throws(() => evaluate(labels, [first.run, first.run]), /duplicate-run/);
});
