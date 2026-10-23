'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '..');
const labels = require('../eval/autonomy/static-builder-labels.json');

function summarize(rows) {
  const agreed = rows.filter((row) => row.expected === row.observed).length;
  return { labelSource: labels.labelSource, modelFamily: labels.modelFamily, familyCount: 1,
    sampleCount: rows.length, agreementWithBuilderLabels: agreed / rows.length,
    findingPrecisionAgainstBuilderLabels: rows.filter((row) => row.observed === 'finding').length
      ? rows.filter((row) => row.observed === 'finding' && row.expected === 'finding').length /
        rows.filter((row) => row.observed === 'finding').length : null,
    independentAccuracy: null, discoveryRecall: null, abcdComparison: 'not-run',
    limitation: 'Two production entries in one component/family; Builder labels are not independent truth.', rows };
}

function evaluate() {
  const rows = [];
  for (const label of labels.labels) {
    const runDir = path.join(root, 'out', 'autonomy', label.runId.replace(':', '-'));
    const result = spawnSync(process.execPath, ['bin/autonomy.js', 'check', `--run=${label.runId}`],
      { cwd: root, encoding: 'utf8' });
    if (result.status !== 0) throw new Error(`check failed for ${label.runId}: ${result.stdout} ${result.stderr}`);
    const report = fs.readFileSync(path.join(runDir, 'report-model.jsonl'), 'utf8').trim()
      .split('\n').map(JSON.parse).filter((row) => row.payload.entryRef === label.entryRef &&
        row.payload.origin === 'entry-scan');
    if (report.length !== 1) throw new Error(`entry report not unique: ${label.runId}`);
    rows.push({ method: label.method, runId: label.runId, expected: label.expected,
      observed: report[0].payload.reportability, source: label.source });
  }
  return summarize(rows);
}

if (require.main === module) {
  try { process.stdout.write(`${JSON.stringify(evaluate(), null, 2)}\n`); }
  catch (e) { process.stderr.write(`${e.message}\n`); process.exitCode = 1; }
}

module.exports = { evaluate, summarize };
