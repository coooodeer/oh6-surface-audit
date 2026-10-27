'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { AUTONOMY_ROOT } = require('../lib/autonomy/store');

const root = path.join(__dirname, '..');
const knowledge = [
  'K/norms/050e10d78c6e93541813beb477a3c1000cbfd46817a5bf8fbf7bc5dc21b7572c/knowledge.json',
  'K/norms/7b1ad465ab401111ad3bfa060d31e4e790e390ad3c6f68d7b30b74ee09fd215f/knowledge.json'
].join(',');
function cli(...args) {
  return spawnSync(process.execPath, ['bin/autonomy.js', ...args], { cwd: root, encoding: 'utf8' });
}

test('scope-only static trajectory names followups, reuses proof, and isolates an operation view', () => {
  const run = cli('run', '--mode=off', '--legacy-contract', '--scope=K/policies/autonomy-pilot-scope.json',
    '--budget=K/policies/autonomy-pilot-budget.json', '--knowledge=' + knowledge);
  assert.equal(run.status, 0, run.stderr);
  const { runId } = JSON.parse(run.stdout);
  const dir = path.resolve(AUTONOMY_ROOT, runId.replace(':', '-'));
  assert.ok(dir.startsWith(path.resolve(AUTONOMY_ROOT) + path.sep));
  try {
    const file = path.join(dir, 'events.jsonl');
    const events = fs.readFileSync(file, 'utf8').trim().split('\n').map(JSON.parse);
    assert.ok(events.some((event) => event.kind === 'gap-opened' &&
      event.detail.tool === 'inspectDelegation'));
    assert.ok(events.some((event) => event.kind === 'gap-closed' &&
      event.detail.reasonCode === 'permission-argument-unresolved'));
    assert.ok(events.some((event) => event.kind === 'summary-reused'));
    const answers = fs.readFileSync(path.join(dir, 'tool-results.jsonl'), 'utf8').trim()
      .split('\n').map(JSON.parse).filter((row) => row.payload.tool === 'inspectStaticContract');
    assert.equal(answers.length, 17);
    assert.ok(answers.some((row) => row.payload.answer.status === 'refuted' &&
      row.payload.observations.status === 'finding'));
    assert.ok(answers.some((row) => row.payload.usage.cacheHit));
    assert.equal(events.filter((event) => event.kind === 'view-changed' &&
      event.detail.view === 'operation-target').length, 1);
    assert.equal(cli('check', '--run=' + runId).status, 0);
    const close = events.find((event) => event.kind === 'gap-closed');
    const originalResultId = close.detail.resultId;
    close.detail.resultId = 'EVID:ffffffffffffffff';
    fs.writeFileSync(file, events.map(JSON.stringify).join('\n') + '\n', 'utf8');
    const broken = JSON.parse(cli('check', '--run=' + runId).stdout);
    assert.ok(broken.errors.some((error) => error.code === 'gap-trace-drift'));
    close.detail.resultId = originalResultId;
    const hit = events.find((event) => event.kind === 'summary-reused');
    hit.detail.fingerprint = 'f'.repeat(64);
    fs.writeFileSync(file, events.map(JSON.stringify).join('\n') + '\n', 'utf8');
    const badSummary = JSON.parse(cli('check', '--run=' + runId).stdout);
    assert.ok(badSummary.errors.some((error) => error.code === 'summary-trace-drift'));
  } finally {
    if (/^RUN-[0-9a-f]{16}$/.test(path.basename(dir))) fs.rmSync(dir, { recursive: true, force: true });
  }
});
