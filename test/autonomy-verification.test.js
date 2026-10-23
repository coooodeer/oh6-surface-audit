'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { AUTONOMY_ROOT } = require('../lib/autonomy/store');

const root = path.join(__dirname, '..');
function cli(...args) {
  return spawnSync(process.execPath, ['bin/autonomy.js', ...args], { cwd: root, encoding: 'utf8' });
}

test('vertical verification rejects unbound plans and blocks unapproved execution', () => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'oh6-verify-'));
  let runDir;
  try {
    const started = cli('run', '--experiment=vertical-v1', '--mode=off',
      '--scope=K/policies/autonomy-pilot-scope.json', '--budget=K/policies/autonomy-pilot-budget.json',
      '--task=TASK:108bcc806d3fc6f0');
    assert.equal(started.status, 0, started.stderr);
    const run = JSON.parse(started.stdout);
    runDir = path.resolve(root, run.runDir);
    const tasks = fs.readFileSync(path.join(runDir, 'tasks.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
    const questions = fs.readFileSync(path.join(runDir, 'questions.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
    const plan = { ...require('../K/verification/sandbox-setpolicy-input-plan.json'),
      taskId: tasks.find((t) => t.payload.origin === 'analysis-branch').recordId };
    plan.questionIds = [questions.find((q) => q.payload.taskId === plan.taskId).recordId];
    const planFile = path.join(temporary, 'plan.json');
    fs.writeFileSync(planFile, JSON.stringify(plan), 'utf8');
    const before = fs.readFileSync(path.join(runDir, 'events.jsonl'), 'utf8');

    const unbound = { ...plan, questionIds: ['Q:aaaaaaaaaaaaaaaa'] };
    fs.writeFileSync(planFile, JSON.stringify(unbound), 'utf8');
    const rejected = cli('verify', `--run=${run.runId}`, `--plan=${planFile}`);
    assert.equal(rejected.status, 2, rejected.stderr);
    assert.match(rejected.stderr, /verification-plan-task-or-question-unbound/);
    assert.equal(fs.readFileSync(path.join(runDir, 'events.jsonl'), 'utf8'), before);

    fs.writeFileSync(planFile, JSON.stringify(plan), 'utf8');
    const blocked = cli('verify', `--run=${run.runId}`, `--plan=${planFile}`);
    assert.equal(blocked.status, 0, blocked.stderr);
    assert.equal(JSON.parse(blocked.stdout).status, 'blocked');
    const artifact = JSON.parse(fs.readFileSync(path.join(runDir, 'verification/placeholder.json'), 'utf8'));
    assert.deepEqual(artifact.executedCommands, []);
    assert.equal(artifact.entryFaithfulness, 'unknown');
    const checked = cli('check', `--run=${run.runId}`);
    assert.equal(checked.status, 0, checked.stderr);
    assert.deepEqual(JSON.parse(checked.stdout).errors, []);
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
    if (runDir && runDir.startsWith(path.resolve(AUTONOMY_ROOT) + path.sep) &&
        /^RUN-[0-9a-f]{16}$/.test(path.basename(runDir))) fs.rmSync(runDir, { recursive: true, force: true });
  }
});
