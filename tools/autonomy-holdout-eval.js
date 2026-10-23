'use strict';

// Evaluator-only process: labels are never passed to the Agent or written to a run.
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { RunStore, TOOL_DIR } = require('../lib/autonomy/store');
const { readJsonl } = require('../lib/autonomy/jsonl');

const MINIMUM = Object.freeze({ supported: 20, refuted: 20, insufficient: 10 });
const VERDICTS = new Set(['supported', 'refuted', 'insufficient']);
const DECISIONS = new Set([...VERDICTS, 'conflict']);

function evaluate(labels, inputRuns) {
  const runs = Array.isArray(inputRuns) ? inputRuns : [inputRuns];
  const byRun = new Map(runs.map((run) => [run.runId, {
    questions: new Map((run.questions || []).map((q) => [q.payload.questionId, q.payload])),
    assessments: new Map((run.assessments || []).map((a) => [a.payload.questionId, a.payload])),
    tasks: new Map((run.tasks || []).map((t) => [t.payload.taskId, t.payload]))
  }]));
  if (byRun.size !== runs.length) throw new Error('duplicate-run');
  const questionIds = new Set();
  const decisionCounts = { supported: 0, refuted: 0, insufficient: 0, conflict: 0 };
  const localQuestions = new Map();
  let substantiveRecords = 0;
  for (const records of byRun.values()) {
    for (const [questionId, q] of records.questions) {
      const decision = records.assessments.get(questionId)?.decision;
      if (DECISIONS.has(decision)) {
        if (!localQuestions.has(questionId)) localQuestions.set(questionId, { kind: q.kind, decisions: new Set() });
        const item = localQuestions.get(questionId);
        if (item.kind !== q.kind) throw new Error('question-kind-drift');
        item.decisions.add(decision);
      }
      if (q.kind !== 'authorization-effect') continue;
      substantiveRecords += 1;
      questionIds.add(questionId);
      if (DECISIONS.has(decision)) decisionCounts[decision] += 1;
    }
  }
  const localCoverage = {};
  for (const { kind, decisions } of localQuestions.values()) {
    const row = localCoverage[kind] ||= { distinctQuestions: 0, supported: 0, refuted: 0,
      insufficient: 0, conflict: 0, unstable: 0 };
    row.distinctQuestions += 1;
    if (decisions.size === 1) row[[...decisions][0]] += 1;
    else row.unstable += 1;
  }
  for (const row of Object.values(localCoverage)) row.decisiveRate = {
    numerator: row.supported + row.refuted, denominator: row.distinctQuestions
  };
  const cases = labels.labels;
  if (!Array.isArray(cases) || !['pending', 'frozen'].includes(labels.status)) {
    throw new Error('invalid-label-set');
  }
  const counts = { supported: 0, refuted: 0, insufficient: 0 };
  for (const item of cases) {
    if (!VERDICTS.has(item.humanVerdict)) throw new Error('invalid-human-verdict');
    counts[item.humanVerdict] += 1;
  }
  const shortfall = Object.fromEntries(Object.entries(MINIMUM)
    .map(([kind, min]) => [kind, Math.max(0, min - counts[kind])]));
  const base = {
    status: 'insufficient-sample', runIds: runs.map((run) => run.runId), labelStatus: labels.status,
    counts, minimum: MINIMUM, shortfall,
    runCoverage: { substantiveRecords, distinctQuestions: questionIds.size, decisionCounts },
    localCoverage,
    judgmentAccuracy: null, falseCertaintyRate: null,
    candidatePrecision: null, discoveryRecall: null,
    aBcdComparison: null, releaseGate: 'not-evaluated'
  };
  if (labels.status === 'pending' && cases.length === 0) return base;
  if (labels.status !== 'frozen' || !labels.frozenAt || !labels.independentReviewer) {
    throw new Error('labels-not-independently-frozen');
  }

  const seenLabels = new Set();
  const seenQuestions = new Set();
  for (const item of cases) {
    const records = byRun.get(item.runId);
    if (!item.labelId || !item.questionId || !item.familyId || !item.source ||
        !item.annotator || !item.annotatedAt || item.questionKind !== 'authorization-effect' ||
        !records || seenLabels.has(item.labelId) || seenQuestions.has(item.questionId)) {
      throw new Error('invalid-or-duplicate-label');
    }
    seenLabels.add(item.labelId);
    seenQuestions.add(item.questionId);
    const q = records.questions.get(item.questionId);
    const a = records.assessments.get(item.questionId);
    const task = q && records.tasks.get(q.taskId);
    if (!q || !a || !task || q.kind !== item.questionKind ||
        !task.anchorRefs.includes(item.entryRef) || !DECISIONS.has(a.decision)) {
      throw new Error('label-run-mismatch');
    }
  }
  if (Object.values(shortfall).some(Boolean)) return base;

  const sufficient = cases.filter((item) => item.humanVerdict !== 'insufficient');
  const unknown = cases.filter((item) => item.humanVerdict === 'insufficient');
  const predicted = (item) => byRun.get(item.runId).assessments.get(item.questionId).decision;
  return {
    ...base, status: 'partial-judgment-only',
    judgmentAccuracy: {
      correct: sufficient.filter((item) => predicted(item) === item.humanVerdict).length,
      total: sufficient.length
    },
    falseCertaintyRate: {
      falseCertain: unknown.filter((item) => ['supported', 'refuted'].includes(predicted(item))).length,
      total: unknown.length
    }
  };
}

function main(argv) {
  const options = { runs: [] };
  for (const arg of argv) {
    const match = /^--(run|labels)=(.+)$/.exec(arg);
    if (!match) throw new Error('invalid-argument: ' + arg);
    if (match[1] === 'run') options.runs.push(match[2]);
    else if (options.labels) throw new Error('duplicate-labels-option');
    else options.labels = match[2];
  }
  if (!options.runs.length) throw new Error('--run required');
  const runs = options.runs.map((runArg) => {
    const dir = RunStore.resolve(runArg);
    const checked = spawnSync(process.execPath, [path.join(TOOL_DIR, 'bin/autonomy.js'),
      'check', '--run=' + dir], { encoding: 'utf8', timeout: 120000, windowsHide: true });
    if (checked.error || checked.status !== 0) throw new Error('run-check-failed: ' + (checked.error || checked.stderr));
    const read = (name) => readJsonl(path.join(dir, name + '.jsonl')).rows;
    return {
      runId: JSON.parse(fs.readFileSync(path.join(dir, 'run.json'), 'utf8')).recordId,
      tasks: read('tasks'), questions: read('questions'), assessments: read('assessments')
    };
  });
  const labelsFile = path.resolve(options.labels || path.join(TOOL_DIR, 'eval/autonomy/labels.json'));
  const result = evaluate(JSON.parse(fs.readFileSync(labelsFile, 'utf8')), runs);
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  return result;
}

if (require.main === module) {
  try { main(process.argv.slice(2)); } catch (error) {
    process.stderr.write(error.message + '\n');
    process.exitCode = 3;
  }
}

module.exports = { evaluate, main };
