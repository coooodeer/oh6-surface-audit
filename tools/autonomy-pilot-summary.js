'use strict';

/**
 * tools/autonomy-pilot-summary.js —— 从已提交的 run 产物生成 eval/autonomy/pilot-summary.json。
 *
 * 只读 run 目录，**不重新裁决**：所有数字都能从 tasks/questions/missing/assessments/
 * tool-ledger/model-ledger/report-model 逐条复算。
 *
 * 用法：
 *   node tools/autonomy-pilot-summary.js --run=RUN:<16hex> [--replay=RUN:<16hex>] [--out=eval/autonomy/pilot-summary.json]
 */

const fs = require('fs');
const path = require('path');

const jsonl = require('../lib/autonomy/jsonl');
const storeLib = require('../lib/autonomy/store');
const ids = require('../lib/autonomy/ids');

const TOOL_DIR = path.resolve(__dirname, '..');

function parseArgs(argv) {
  const out = {};
  for (const a of argv) {
    if (!a.startsWith('--')) continue;
    const eq = a.indexOf('=');
    if (eq < 0) out[a.slice(2)] = true;
    else out[a.slice(2, eq)] = a.slice(eq + 1);
  }
  return out;
}

function countBy(rows, keyFn) {
  const m = {};
  for (const r of rows) {
    const k = keyFn(r);
    if (k === undefined || k === null) continue;
    m[k] = (m[k] || 0) + 1;
  }
  const sorted = {};
  for (const k of Object.keys(m).sort()) sorted[k] = m[k];
  return sorted;
}

function readRows(dir, name) {
  const res = jsonl.readJsonl(path.join(dir, name));
  if (res.malformed.length || res.tailPartial) {
    throw new Error(`pilot-summary: ${name} is not clean (malformed=${res.malformed.length}, tailPartial=${res.tailPartial})`);
  }
  return res.rows;
}

function summarizeRun(dir) {
  const store = new storeLib.RunStore(dir);
  const run = store.run.payload;
  const tasks = readRows(dir, 'tasks.jsonl');
  const questions = readRows(dir, 'questions.jsonl');
  const missings = readRows(dir, 'missing.jsonl');
  const assessments = readRows(dir, 'assessments.jsonl');
  const toolResults = readRows(dir, 'tool-results.jsonl');
  const contexts = readRows(dir, 'contexts.jsonl');
  const reportModel = JSON.parse(fs.readFileSync(path.join(dir, 'report-model.json'), 'utf8'));
  const toolLedger = jsonl.readJsonl(path.join(dir, 'tool-ledger.jsonl')).rows;
  const modelLedger = jsonl.readJsonl(path.join(dir, 'model-ledger.jsonl')).rows;
  const events = readRows(dir, 'events.jsonl');
  const checkpoint = fs.existsSync(path.join(dir, 'checkpoints', 'state.json'))
    ? JSON.parse(fs.readFileSync(path.join(dir, 'checkpoints', 'state.json'), 'utf8'))
    : null;

  const runFinished = events.filter((e) => e.kind === 'run-finished').pop() || null;

  return {
    runId: store.runId,
    runDir: path.relative(TOOL_DIR, dir).split(path.sep).join('/'),
    scopeId: run.scopeId,
    snapshotId: run.snapshotId,
    inputManifestId: run.inputManifestId,
    mode: run.mode,
    budget: run.budget,
    counts: {
      tasks: tasks.length,
      tasksByOrigin: countBy(tasks, (t) => t.payload.origin),
      questions: questions.length,
      questionsByKind: countBy(questions, (q) => q.payload.kind),
      questionStatus: countBy(questions, (q) => q.payload.status),
      questionStatusByKind: questions.reduce((m, q) => {
        const k = q.payload.kind;
        if (!m[k]) m[k] = {};
        m[k][q.payload.status] = (m[k][q.payload.status] || 0) + 1;
        return m;
      }, {}),
      missing: missings.length,
      missingByReason: countBy(missings, (m) => m.payload.reasonCode),
      missingByCategory: countBy(missings, (m) => m.payload.category),
      assessments: assessments.length,
      assessmentsByDecision: countBy(assessments, (a) => a.payload.decision),
      toolResults: toolResults.length,
      toolResultsByTool: countBy(toolResults, (r) => r.payload.tool),
      toolResultsByStatus: countBy(toolResults, (r) => r.payload.status),
      contexts: contexts.length,
      modelCalls: modelLedger.length,
      modelCallsByStatus: countBy(modelLedger, (m) => m.status)
    },
    reportability: reportModel.counts,
    reportMissingByReason: reportModel.missingByReason,
    semanticHash: reportModel.semanticHash,
    toolUsage: {
      ledgerRows: toolLedger.length,
      wallMsTotal: toolLedger.reduce((s, r) => s + (r.wallMs || 0), 0),
      bytesReadTotal: toolLedger.reduce((s, r) => s + (r.bytesRead || 0), 0)
    },
    modelUsage: {
      ledgerRows: modelLedger.length,
      promptTokens: modelLedger.reduce((s, r) => s + (r.promptTokens || 0), 0),
      completionTokens: modelLedger.reduce((s, r) => s + (r.completionTokens || 0), 0),
      wallMsTotal: modelLedger.reduce((s, r) => s + (r.wallMs || 0), 0)
    },
    wallMs: runFinished ? runFinished.detail.wallMs : null,
    toolCalls: runFinished ? runFinished.detail.toolCalls : null,
    stoppedReason: checkpoint ? checkpoint.stoppedReason : null,
    events: events.length
  };
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.run) {
    process.stderr.write('usage: node tools/autonomy-pilot-summary.js --run=RUN:<16hex> [--replay=RUN:<16hex>] [--out=<file>]\n');
    process.exitCode = 2;
    return;
  }
  const dir = storeLib.RunStore.resolve(args.run);
  const summary = summarizeRun(dir);

  let replay = null;
  if (args.replay) {
    const rdir = storeLib.RunStore.resolve(args.replay);
    const rs = summarizeRun(rdir);
    replay = {
      runId: rs.runId,
      semanticHash: rs.semanticHash,
      sameSemanticHash: rs.semanticHash === summary.semanticHash,
      sameReportability: JSON.stringify(rs.reportability) === JSON.stringify(summary.reportability),
      sameCounts: JSON.stringify(rs.counts.questionStatusByKind) === JSON.stringify(summary.counts.questionStatusByKind)
    };
  }

  const doc = {
    summaryVersion: '1',
    generatedAt: new Date().toISOString(),
    generator: 'tools/autonomy-pilot-summary.js',
    note: '所有数字都可由 run 目录逐条复算；不重新裁决，不引入新结论。',
    labels: 'pending（eval/autonomy/labels.json 只有 schema 与 status=pending，未做人工标注）',
    run: summary,
    replay
  };
  const outFile = path.isAbsolute(args.out || '')
    ? args.out
    : path.join(TOOL_DIR, args.out || 'eval/autonomy/pilot-summary.json');
  fs.mkdirSync(path.dirname(outFile), { recursive: true });
  fs.writeFileSync(outFile, `${JSON.stringify(doc, null, 2)}\n`, 'utf8');
  process.stdout.write(`${JSON.stringify({
    out: path.relative(TOOL_DIR, outFile).split(path.sep).join('/'),
    runId: summary.runId,
    counts: summary.reportability,
    missingByReason: summary.counts.missingByReason,
    questionStatus: summary.counts.questionStatus,
    semanticHash: summary.semanticHash,
    replay
  }, null, 2)}\n`);
}

if (require.main === module) main();

module.exports = { summarizeRun, main, countBy, ids };
