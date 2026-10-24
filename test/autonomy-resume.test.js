'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');
const { AUTONOMY_ROOT } = require('../lib/autonomy/store');

const root = path.join(__dirname, '..');
function cli(...args) {
  return spawnSync(process.execPath, ['bin/autonomy.js', ...args], { cwd: root, encoding: 'utf8' });
}
function rows(file) { return fs.readFileSync(file, 'utf8').trim().split('\n').map(JSON.parse); }
function cleanup(dir) {
  if (dir && path.resolve(dir).startsWith(path.resolve(AUTONOMY_ROOT) + path.sep) &&
      /^RUN-[0-9a-f]{16}$/.test(path.basename(dir))) fs.rmSync(dir, { recursive: true, force: true });
}

test('static suite resumes with pinned knowledge and proof at a task boundary', () => {
  const knowledge = [
    'K/norms/050e10d78c6e93541813beb477a3c1000cbfd46817a5bf8fbf7bc5dc21b7572c/knowledge.json',
    'K/norms/7b1ad465ab401111ad3bfa060d31e4e790e390ad3c6f68d7b30b74ee09fd215f/knowledge.json'
  ].join(',');
  const args = ['--mode=off', '--scope=K/policies/autonomy-pilot-scope.json',
    '--budget=K/policies/autonomy-pilot-budget.json'];
  const clean = cli('run', ...args, '--knowledge=' + knowledge);
  assert.equal(clean.status, 0, clean.stderr);
  const cleanDir = path.resolve(root, JSON.parse(clean.stdout).runDir);
  const crashed = spawnSync(process.execPath,
    ['tools/fixtures/crash-after-vertical-task.js', '--static-suite'],
    { cwd: root, encoding: 'utf8' });
  assert.equal(crashed.status, 71, crashed.stderr);
  const { runId, dir } = JSON.parse(crashed.stdout);
  try {
    const before = rows(path.join(dir, 'events.jsonl'));
    assert.equal(before.at(-1).kind, 'task-finished');
    assert.equal(Object.keys(JSON.parse(fs.readFileSync(path.join(dir, 'static-proofs.json'), 'utf8'))).length, 1);
    const resumed = cli('resume', '--run=' + runId, ...args);
    assert.equal(resumed.status, 0, resumed.stderr);
    assert.equal(cli('check', '--run=' + runId).status, 0);
    const expected = JSON.parse(fs.readFileSync(path.join(cleanDir, 'report-model.json'), 'utf8'));
    const actual = JSON.parse(fs.readFileSync(path.join(dir, 'report-model.json'), 'utf8'));
    assert.equal(actual.semanticHash, expected.semanticHash);
    const events = rows(path.join(dir, 'events.jsonl'));
    assert.equal(events.filter((ev) => ev.kind === 'summary-reused').length, 1);
    assert.equal(events.filter((ev) => ev.kind === 'view-changed').length, 1);
  } finally { cleanup(dir); cleanup(cleanDir); }
});

test('vertical-v2 resumes at the first tool intent and the committed task boundary', () => {
  const clean = cli('run', '--experiment=vertical-v2', '--mode=off',
    '--scope=K/policies/autonomy-pilot-scope.json', '--budget=K/policies/autonomy-pilot-budget.json',
    '--task=TASK:ce534608cd00a85c');
  assert.equal(clean.status, 0, clean.stderr);
  const cleanDir = path.resolve(root, JSON.parse(clean.stdout).runDir);
  try {
    const hash = JSON.parse(fs.readFileSync(path.join(cleanDir, 'report-model.json'), 'utf8')).semanticHash;
    for (const fixture of ['crash-tool-intent.js', 'crash-after-vertical-task.js']) {
      const crashed = spawnSync(process.execPath, [`tools/fixtures/${fixture}`, '--experiment=vertical-v2'],
        { cwd: root, encoding: 'utf8' });
      assert.equal(crashed.status, 71, crashed.stderr);
      const { runId, dir } = JSON.parse(crashed.stdout);
      try {
        const resumed = cli('resume', `--run=${runId}`, '--mode=off',
          '--scope=K/policies/autonomy-pilot-scope.json',
          '--budget=K/policies/autonomy-pilot-budget.json');
        assert.equal(resumed.status, 0, resumed.stderr);
        assert.equal(cli('check', `--run=${runId}`).status, 0);
        const events = rows(path.join(dir, 'events.jsonl'));
        assert.equal(events.filter((ev) => ev.kind === 'task-started').length, 1);
        assert.equal(events.filter((ev) => ev.kind === 'tool-intent').length, 9);
        assert.equal(events.filter((ev) => ev.kind === 'tool-completed').length, 9);
        assert.equal(JSON.parse(fs.readFileSync(path.join(dir, 'report-model.json'), 'utf8')).semanticHash, hash);
      } finally { cleanup(dir); }
    }
  } finally { cleanup(cleanDir); }
});

test('Windows crash at committed task boundary resumes only queued branch', () => {
  const crashed = spawnSync(process.execPath, ['tools/fixtures/crash-after-vertical-task.js'],
    { cwd: root, encoding: 'utf8' });
  assert.equal(crashed.status, 71, crashed.stderr);
  const { runId, dir } = JSON.parse(crashed.stdout);
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'oh6-resume-'));
  let cleanDir;
  try {
    const before = rows(path.join(dir, 'events.jsonl'));
    assert.equal(before.at(-1).kind, 'task-finished');
    const checkpoint = JSON.parse(fs.readFileSync(path.join(dir, 'checkpoints/state.json'), 'utf8'));
    assert.equal(checkpoint.throughSeq, before.at(-1).seq);
    assert.equal(checkpoint.tasks.done, 1);
    assert.ok(checkpoint.activeWallMs > 0);
    const changedBudget = { ...require('../K/policies/autonomy-pilot-budget.json') };
    changedBudget.budget = { ...changedBudget.budget, maxToolCalls: 401 };
    const badFile = path.join(tmp, 'budget.json');
    fs.writeFileSync(badFile, JSON.stringify(changedBudget), 'utf8');
    const rejected = cli('resume', `--run=${runId}`, '--mode=off',
      '--scope=K/policies/autonomy-pilot-scope.json', `--budget=${badFile}`);
    assert.notEqual(rejected.status, 0);
    assert.equal(rows(path.join(dir, 'events.jsonl')).length, before.length);

    const lockFile = path.join(dir, 'run.lock');
    const previousLock = fs.readFileSync(lockFile, 'utf8');
    fs.writeFileSync(lockFile, JSON.stringify({ ...JSON.parse(previousLock), pid: process.pid }), 'utf8');
    const active = cli('resume', `--run=${runId}`, '--mode=off',
      '--scope=K/policies/autonomy-pilot-scope.json', '--budget=K/policies/autonomy-pilot-budget.json');
    assert.equal(active.status, 3);
    assert.match(active.stderr, /original writer may still be running/);
    assert.equal(rows(path.join(dir, 'events.jsonl')).length, before.length);
    fs.writeFileSync(lockFile, previousLock, 'utf8');

    const resumed = cli('resume', `--run=${runId}`, '--mode=off',
      '--scope=K/policies/autonomy-pilot-scope.json', '--budget=K/policies/autonomy-pilot-budget.json');
    assert.equal(resumed.status, 0, resumed.stderr);
    assert.equal(JSON.parse(resumed.stdout).runId, runId);
    const checked = cli('check', `--run=${runId}`);
    assert.equal(checked.status, 0, checked.stderr);
    const events = rows(path.join(dir, 'events.jsonl'));
    assert.equal(events.filter((ev) => ev.kind === 'run-resumed').length, 1);
    assert.equal(events.filter((ev) => ev.kind === 'task-started' &&
      ev.taskId === 'TASK:108bcc806d3fc6f0').length, 1);
    assert.equal(rows(path.join(dir, 'tool-ledger.jsonl')).length, 8);
    const finishedCheckpoint = JSON.parse(fs.readFileSync(path.join(dir, 'checkpoints/state.json'), 'utf8'));
    assert.ok(finishedCheckpoint.activeWallMs >= checkpoint.activeWallMs);
    assert.equal(fs.existsSync(path.join(dir, 'run.lock')), false);

    const clean = cli('run', '--experiment=vertical-v1', '--mode=off',
      '--scope=K/policies/autonomy-pilot-scope.json', '--budget=K/policies/autonomy-pilot-budget.json',
      '--task=TASK:108bcc806d3fc6f0');
    assert.equal(clean.status, 0, clean.stderr);
    cleanDir = path.resolve(root, JSON.parse(clean.stdout).runDir);
    const expected = JSON.parse(fs.readFileSync(path.join(cleanDir, 'report-model.json'), 'utf8'));
    const actual = JSON.parse(fs.readFileSync(path.join(dir, 'report-model.json'), 'utf8'));
    assert.equal(actual.semanticHash, expected.semanticHash);
    assert.equal(actual.counts.finding, 0);
  } finally {
    cleanup(cleanDir);
    cleanup(dir);
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('changed archived evidence blocks resume before any new event', () => {
  const crashed = spawnSync(process.execPath, ['tools/fixtures/crash-after-vertical-task.js'],
    { cwd: root, encoding: 'utf8' });
  assert.equal(crashed.status, 71, crashed.stderr);
  const { runId, dir } = JSON.parse(crashed.stdout);
  try {
    const before = rows(path.join(dir, 'events.jsonl')).length;
    const ledger = rows(path.join(dir, 'tool-ledger.jsonl'));
    fs.appendFileSync(path.join(dir, 'evidence', `${ledger[0].resultId.replace(':', '-')}.json`), ' ');
    const rejected = cli('resume', `--run=${runId}`, '--mode=off',
      '--scope=K/policies/autonomy-pilot-scope.json', '--budget=K/policies/autonomy-pilot-budget.json');
    assert.equal(rejected.status, 3);
    assert.match(rejected.stderr, /resume-evidence-drift/);
    assert.equal(rows(path.join(dir, 'events.jsonl')).length, before);
  } finally { cleanup(dir); }
});

test('implementation drift blocks task-boundary resume before any new event', () => {
  const crashed = spawnSync(process.execPath, ['tools/fixtures/crash-after-vertical-task.js'],
    { cwd: root, encoding: 'utf8' });
  assert.equal(crashed.status, 71, crashed.stderr);
  const { runId, dir } = JSON.parse(crashed.stdout);
  try {
    const manifestFile = path.join(dir, 'manifest.json');
    const manifest = JSON.parse(fs.readFileSync(manifestFile, 'utf8'));
    assert.match(manifest.implementationFingerprint, /^[0-9a-f]{64}$/);
    const before = fs.readFileSync(path.join(dir, 'events.jsonl'), 'utf8');
    manifest.implementationFingerprint = '0'.repeat(64);
    fs.writeFileSync(manifestFile, JSON.stringify(manifest), 'utf8');
    const rejected = cli('resume', `--run=${runId}`, '--mode=off',
      '--scope=K/policies/autonomy-pilot-scope.json', '--budget=K/policies/autonomy-pilot-budget.json');
    assert.equal(rejected.status, 3);
    assert.match(rejected.stderr, /resume implementation drift/);
    assert.equal(fs.readFileSync(path.join(dir, 'events.jsonl'), 'utf8'), before);
  } finally { cleanup(dir); }
});

test('changed tool completion blocks task-boundary resume before a new event', () => {
  const crashed = spawnSync(process.execPath, ['tools/fixtures/crash-after-vertical-task.js'],
    { cwd: root, encoding: 'utf8' });
  assert.equal(crashed.status, 71, crashed.stderr);
  const { runId, dir } = JSON.parse(crashed.stdout);
  try {
    const file = path.join(dir, 'events.jsonl');
    const events = rows(file);
    events.find((ev) => ev.kind === 'tool-completed').detail.resultId = 'EVID:ffffffffffffffff';
    fs.writeFileSync(file, events.map((ev) => JSON.stringify(ev)).join('\n') + '\n', 'utf8');
    const rejected = cli('resume', '--run=' + runId, '--mode=off',
      '--scope=K/policies/autonomy-pilot-scope.json', '--budget=K/policies/autonomy-pilot-budget.json');
    assert.equal(rejected.status, 3);
    assert.match(rejected.stderr, /resume-tool-trace-mismatch/);
    assert.equal(rows(file).length, events.length);
  } finally { cleanup(dir); }
});
