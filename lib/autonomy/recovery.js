'use strict';

const fs = require('node:fs');
const path = require('node:path');
const jsonl = require('./jsonl');
const ids = require('./ids');
const state = require('./state');
const { sha256File, TOOL_DIR } = require('./store');

function implementationFingerprint() {
  const modules = path.join(TOOL_DIR, 'lib', 'autonomy');
  const schemas = path.join(TOOL_DIR, 'K', 'schemas');
  const files = [path.join(TOOL_DIR, 'bin', 'autonomy.js'),
    ...fs.readdirSync(modules).filter((name) => name.endsWith('.js')).map((name) => path.join(modules, name)),
    ...fs.readdirSync(schemas).filter((name) => name.startsWith('autonomy-') && name.endsWith('.json'))
      .map((name) => path.join(schemas, name))];
  return ids.sha256Hex(ids.canonicalJson(files.sort().map((file) => ({
    file: path.relative(TOOL_DIR, file).split(path.sep).join('/'), sha256: sha256File(file)
  }))));
}

function reconcileModelLedger(rows) {
  const calls = new Map();
  for (const row of rows) {
    if (!/^CALL:[0-9a-f]{16}$/.test(String(row.callId || ''))) throw new Error('invalid-model-ledger-call');
    const current = calls.get(row.callId) || { callId: row.callId, reserved: false, final: null };
    if (row.status === 'reserved') {
      if (current.reserved || current.final) throw new Error('duplicate-model-intent');
      current.reserved = true; current.requestSha256 = row.requestSha256;
    } else {
      if (current.final) throw new Error('duplicate-model-result');
      current.final = { status: row.status, reason: row.reason || null };
    }
    calls.set(row.callId, current);
  }
  const pending = [...calls.values()].filter((call) => call.reserved && !call.final).map((call) => call.callId);
  const legacyWithoutIntent = [...calls.values()].filter((call) => !call.reserved && call.final).map((call) => call.callId);
  return { pending, legacyWithoutIntent, finished: calls.size - pending.length,
    outcome: pending.length ? 'remote-outcome-unknown' : 'no-pending-request',
    nextAction: pending.length ? 'manual-provider-reconciliation' : null, autoResend: false };
}

function reconcileToolEvents(events) {
  const intents = new Map();
  for (const ev of events) {
    if (ev.kind === 'tool-intent') {
      if (!ev.taskId || !ev.detail || typeof ev.detail.tool !== 'string' ||
          !/^[0-9a-f]{64}$/.test(ev.detail.argumentsSha256 || '') || intents.has(ev.actionId)) {
        throw new Error('tool-intent-invalid');
      }
      intents.set(ev.actionId, { actionId: ev.actionId, taskId: ev.taskId,
        tool: ev.detail.tool, resultId: null });
    } else if (ev.kind === 'tool-completed') {
      const intent = ev.detail && intents.get(ev.detail.intentId);
      if (!intent || intent.taskId !== ev.taskId || intent.resultId ||
          !/^EVID:[0-9a-f]{16}$/.test(ev.detail.resultId || '')) {
        throw new Error('tool-completion-unbound');
      }
      intent.resultId = ev.detail.resultId;
    }
  }
  const all = [...intents.values()];
  return { pendingTools: all.filter((item) => !item.resultId),
    completedTools: all.filter((item) => item.resultId) };
}

function prepareFirstToolIntent(store, fingerprint) {
  const manifest = store.readJson('manifest.json');
  if (store.run.payload.mode !== 'off' || manifest.toolTraceVersion !== '1' ||
      !fingerprint || manifest.resumeFingerprint !== fingerprint || store.readCheckpoint()) {
    throw new Error('resume-first-tool-ineligible');
  }
  const read = (name) => {
    const rows = jsonl.readJsonl(store.file(name), { strict: true });
    if (rows.tailPartial) throw new Error('resume-tail-partial:' + name);
    return rows.rows;
  };
  const events = read('events.jsonl');
  const last = events.at(-1);
  const started = events.filter((ev) => ev.kind === 'task-started');
  const trace = reconcileToolEvents(events);
  const allowed = new Set(['run-created', 'task-admitted', 'task-started', 'tool-intent']);
  if (!last || events.some((ev, i) => ev.seq !== i + 1 || ev.runId !== store.runId ||
        !allowed.has(ev.kind) || ev.actionId !== 'ACT:' +
        ids.sha256Hex(ids.canonicalJson({ runId: store.runId, seq: ev.seq,
          kind: ev.kind, taskId: ev.taskId })).slice(0, 16)) ||
      started.length !== 1 || last.kind !== 'tool-intent' ||
      trace.pendingTools.length !== 1 || trace.completedTools.length ||
      last.actionId !== trace.pendingTools[0].actionId || last.taskId !== started[0].taskId ||
      last.detail.tool !== 'inspectEntry') throw new Error('resume-not-at-first-tool-intent');
  const records = {};
  for (const [key, name] of Object.entries({ task: 'tasks.jsonl', question: 'questions.jsonl',
    missing: 'missing.jsonl', assessment: 'assessments.jsonl', context: 'contexts.jsonl' })) records[key] = read(name);
  const task = records.task.find((row) => row.recordId === last.taskId);
  const question = records.question.find((row) => row.recordId === last.detail.questionId);
  const created = events[0].detail;
  if (records.task.length !== 1 || !task || task.payload.state !== 'queued' ||
      !question || question.payload.taskId !== task.recordId || question.payload.kind !== 'binding' ||
      last.detail.argumentsSha256 !== ids.sha256Hex(ids.canonicalJson({ entryRef: task.payload.anchorRefs[0] })) ||
      records.missing.length || records.assessment.length || records.context.length ||
      events[1].kind !== 'task-admitted' || events[1].taskId !== task.recordId ||
      events[2].kind !== 'task-started' || events[2].taskId !== task.recordId ||
      created.mode !== 'off' || !['vertical-v1', 'vertical-v2'].includes(created.experiment) ||
      created.scopeId !== store.run.payload.scopeId || created.snapshotId !== store.run.payload.snapshotId ||
      ids.canonicalJson(created.budget) !== ids.canonicalJson(store.run.payload.budget) ||
      !['run-created', 'task-admitted', 'task-started', 'tool-intent'].every((kind) =>
        events.filter((ev) => ev.kind === kind).length === 1)) {
    throw new Error('resume-first-tool-state-mismatch');
  }
  for (const name of ['tool-ledger.jsonl', 'tool-results.jsonl', 'model-ledger.jsonl']) {
    const file = store.file(name);
    if (fs.existsSync(file) && fs.statSync(file).size) throw new Error('resume-first-tool-has-results');
  }
  if (fs.existsSync(store.file('evidence')) || fs.existsSync(store.file('model-calls')) ||
      fs.existsSync(store.file('vertical-analysis.json')) || fs.existsSync(store.file('checksums.json'))) {
    throw new Error('resume-first-tool-has-artifacts');
  }
  const activeWallMs = Math.max(0, Date.parse(last.at) - Date.parse(events[0].at));
  if (!Number.isFinite(activeWallMs)) throw new Error('resume-first-tool-time-invalid');
  return { resumeKind: 'first-tool-intent', pendingIntent: last, events, records,
    toolLedger: [], modelLedger: [], branch: null,
    checkpoint: { throughSeq: last.seq, activeWallMs,
      budget: { toolCalls: 0, modelRequests: 0, inputTokens: 0, outputTokens: 0 },
      tasks: { planned: 1, done: 0 } } };
}

function prepareTaskBoundary(store, fingerprint) {
  const manifest = store.readJson('manifest.json');
  if (manifest.resumeFingerprint !== fingerprint || !fingerprint) throw new Error('resume-input-drift');
  const checkpoint = store.readCheckpoint();
  if (!checkpoint || checkpoint.runId !== store.runId || checkpoint.mode !== store.run.payload.mode ||
      checkpoint.stoppedReason || !Number.isInteger(checkpoint.throughSeq) ||
      !Number.isInteger(checkpoint.activeWallMs) || checkpoint.activeWallMs < 0) {
    throw new Error('resume-checkpoint-invalid');
  }
  const read = (name) => {
    const rows = jsonl.readJsonl(store.file(name), { strict: true });
    if (rows.tailPartial) throw new Error(`resume-tail-partial:${name}`);
    return rows.rows;
  };
  const events = read('events.jsonl');
  if (!events.length || events.some((ev, i) => ev.seq !== i + 1 || ev.runId !== store.runId) ||
      events.at(-1).seq !== checkpoint.throughSeq ||
      events.at(-1).kind !== 'task-finished' || events.at(-1).to !== 'done' ||
      events.some((ev) => ev.kind === 'run-finished')) throw new Error('resume-not-at-task-boundary');
  const records = {};
  for (const [key, name] of Object.entries({ task: 'tasks.jsonl', question: 'questions.jsonl',
    missing: 'missing.jsonl', assessment: 'assessments.jsonl', context: 'contexts.jsonl' })) {
    records[key] = read(name);
  }
  const reduced = state.reduceTaskStates(events);
  if (!records.task.length || records.task.some((row) =>
    !['done', 'queued'].includes(row.payload.state) ||
    reduced.get(row.recordId)?.state !== row.payload.state) ||
      records.task.filter((row) => row.payload.state === 'done').length !== checkpoint.tasks.done ||
      records.task.length !== checkpoint.tasks.planned) throw new Error('resume-task-state-mismatch');
  const toolLedger = read('tool-ledger.jsonl');
  const results = read('tool-results.jsonl');
  if (toolLedger.length !== checkpoint.budget.toolCalls || results.length !== toolLedger.length) {
    throw new Error('resume-tool-budget-mismatch');
  }
  if (manifest.toolTraceVersion === '1') {
    const trace = reconcileToolEvents(events);
    if (trace.pendingTools.length ||
        JSON.stringify(trace.completedTools.map((item) => item.resultId).sort()) !==
        JSON.stringify(toolLedger.map((item) => item.resultId).sort())) {
      throw new Error('resume-tool-trace-mismatch');
    }
  }
  for (const row of toolLedger) {
    const file = store.file(`evidence/${row.resultId.replace(':', '-')}.json`);
    if (!fs.existsSync(file) || sha256File(file) !== row.archivedSha256) {
      throw new Error(`resume-evidence-drift:${row.resultId}`);
    }
  }
  const modelLedger = fs.existsSync(store.file('model-ledger.jsonl')) ? read('model-ledger.jsonl') : [];
  if (store.run.payload.mode === 'off' && (modelLedger.length || checkpoint.budget.modelRequests)) {
    throw new Error('resume-model-budget-mismatch');
  }
  if (store.run.payload.mode === 'replay' &&
      (checkpoint.budget.modelRequests || modelLedger.some((row) => row.status === 'reserved'))) {
    throw new Error('resume-model-budget-mismatch');
  }
  const branchName = store.run.payload.architectureVersion === '1.0.19-autonomous-static'
    ? 'analysis-branch.json' : 'vertical-branch.json';
  const branchFile = store.file(branchName);
  const branch = fs.existsSync(branchFile) ? store.readJson(branchName) : null;
  if (branch && (!records.task.some((row) => row.recordId === branch.task.taskId) ||
      !records.question.some((row) => row.recordId === branch.question.questionId))) {
    throw new Error('resume-branch-unbound');
  }
  if (store.run.payload.architectureVersion === '1.0.19-autonomous-static') {
    const proofs = store.readJson('static-proofs.json');
    const completed = records.task.filter((row) => row.payload.state === 'done' &&
      records.question.some((q) => q.payload.taskId === row.recordId && q.payload.kind === 'static-contract'));
    if (Object.keys(proofs).length !== completed.length ||
        completed.some((row) => !proofs[row.recordId])) throw new Error('resume-static-proof-state-mismatch');
  }
  return { checkpoint, events, records, toolLedger, modelLedger, branch };
}

module.exports = { reconcileModelLedger, reconcileToolEvents, prepareTaskBoundary,
  prepareFirstToolIntent, implementationFingerprint };
