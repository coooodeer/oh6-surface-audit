'use strict';

/**
 * test/autonomy-check-failures.test.js —— P3 的 `check` 失败用例。
 *
 * 每个用例都从一次**干净运行**的副本开始，人为制造一种损坏，断言 `check` 以 exit 3 + 具名 code 报出，
 * 而不是静默通过（§6/P3 失败用例：末行截断 ⇒ tail-partial；中间坏行 ⇒ ledger-corrupt；其余为
 * dangling-ref / report-model-drift / checksum-mismatch / forbidden-token / evidence 丢失）。
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { main } = require('../bin/autonomy');
const storeLib = require('../lib/autonomy/store');
const jsonl = require('../lib/autonomy/jsonl');

const TOOL_DIR = path.join(__dirname, '..');
const SCOPE = 'K/policies/autonomy-pilot-scope.json';
const BUDGET = 'K/policies/autonomy-pilot-budget.json';

let sourceRunDir = null;
const tempDirs = [];

async function runCli(argv) {
  const out = [];
  const err = [];
  const so = process.stdout.write;
  const se = process.stderr.write;
  process.stdout.write = (chunk) => { out.push(Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk)); return true; };
  process.stderr.write = (chunk) => { err.push(Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk)); return true; };
  try {
    const code = await main(argv);
    return { code, stdout: out.join(''), stderr: err.join('') };
  } finally {
    process.stdout.write = so;
    process.stderr.write = se;
  }
}

async function ensureSourceRun() {
  if (sourceRunDir) return sourceRunDir;
  const res = await runCli(['run', `--scope=${SCOPE}`, `--budget=${BUDGET}`, '--mode=off', '--max-tasks=1']);
  assert.strictEqual(res.code, 0, res.stderr);
  const out = JSON.parse(res.stdout);
  sourceRunDir = path.join(TOOL_DIR, out.runDir.split('/').join(path.sep));
  return sourceRunDir;
}

function copyRun() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'autonomy-check-'));
  const dest = path.join(dir, path.basename(sourceRunDir));
  fs.cpSync(sourceRunDir, dest, { recursive: true });
  tempDirs.push(dir);
  return { root: dir, dir: dest };
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function writeJson(file, obj) {
  fs.writeFileSync(file, `${JSON.stringify(obj, null, 2)}\n`, 'utf8');
}

async function checkOf(dir) {
  const res = await runCli(['check', `--run=${dir}`]);
  const out = JSON.parse(res.stdout);
  return { ...res, out };
}

function codes(out) {
  return out.errors.map((e) => e.code);
}

test('基线：干净运行的 check 必须通过', async () => {
  await ensureSourceRun();
  const { dir } = copyRun();
  const r = await checkOf(dir);
  assert.strictEqual(r.code, 0, r.stderr);
  assert.deepStrictEqual(r.out.errors, []);
  assert.deepStrictEqual(r.out.warnings, []);
  assert.strictEqual(r.out.counts.tasks, 1);
});

test('tool completion referencing another result is rejected', async () => {
  await ensureSourceRun();
  const { dir } = copyRun();
  const file = path.join(dir, 'events.jsonl');
  const events = fs.readFileSync(file, 'utf8').trim().split('\n').map(JSON.parse);
  const completed = events.find((ev) => ev.kind === 'tool-completed');
  assert.ok(completed);
  completed.detail.resultId = 'EVID:ffffffffffffffff';
  fs.writeFileSync(file, events.map((ev) => JSON.stringify(ev)).join('\n') + '\n', 'utf8');
  const checked = await checkOf(dir);
  assert.strictEqual(checked.code, 3);
  assert.ok(codes(checked.out).includes('tool-completion-missing-result'));
  assert.ok(codes(checked.out).includes('tool-trace-result-mismatch'));
});

test('events.jsonl 中间坏行 ⇒ ledger-corrupt（不静默跳过）', async () => {
  await ensureSourceRun();
  const { dir } = copyRun();
  const file = path.join(dir, 'events.jsonl');
  const lines = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean);
  lines.splice(2, 0, '{this is not json');
  fs.writeFileSync(file, `${lines.join('\n')}\n`, 'utf8');
  const r = await checkOf(dir);
  assert.strictEqual(r.code, 3);
  assert.ok(codes(r.out).includes('ledger-corrupt'), JSON.stringify(r.out.errors));
});

test('events.jsonl 末行被截断 ⇒ tail-partial', async () => {
  await ensureSourceRun();
  const { dir } = copyRun();
  const file = path.join(dir, 'events.jsonl');
  const text = fs.readFileSync(file, 'utf8');
  const lastLine = text.split('\n').filter(Boolean).pop();
  fs.writeFileSync(file, text.slice(0, text.length - lastLine.length - 1) + lastLine.slice(0, Math.floor(lastLine.length / 2)), 'utf8');
  const r = await checkOf(dir);
  assert.strictEqual(r.code, 3);
  assert.ok(codes(r.out).includes('tail-partial'), JSON.stringify(r.out.errors));
});

test('evidence 归档缺失 ⇒ evidence-archived-missing', async () => {
  await ensureSourceRun();
  const { dir } = copyRun();
  const evidenceDir = path.join(dir, 'evidence');
  const victim = fs.readdirSync(evidenceDir)[0];
  fs.unlinkSync(path.join(evidenceDir, victim));
  const r = await checkOf(dir);
  assert.strictEqual(r.code, 3);
  assert.ok(codes(r.out).includes('evidence-archived-missing'), JSON.stringify(r.out.errors));
});

test('task/question 引用断裂 ⇒ dangling-ref', async () => {
  await ensureSourceRun();
  const { dir } = copyRun();
  const file = path.join(dir, 'tasks.jsonl');
  const rows = jsonl.readJsonl(file).rows;
  rows[0].payload.questionRefs = [...rows[0].payload.questionRefs, 'Q:deadbeefdeadbeef'];
  jsonl.writeJsonl(file, rows);
  const r = await checkOf(dir);
  assert.strictEqual(r.code, 3);
  assert.ok(codes(r.out).includes('dangling-ref'), JSON.stringify(r.out.errors));
});

test('report-model 语义哈希被篡改 ⇒ report-model-drift', async () => {
  await ensureSourceRun();
  const { dir } = copyRun();
  const file = path.join(dir, 'report-model.json');
  const doc = readJson(file);
  doc.semanticHash = `sha256:${'0'.repeat(64)}`;
  writeJson(file, doc);
  const r = await checkOf(dir);
  assert.strictEqual(r.code, 3);
  assert.ok(codes(r.out).includes('report-model-drift'), JSON.stringify(r.out.errors));
  // checksums 也要跟着报（篡改产物必然对不上）
  assert.ok(codes(r.out).includes('checksum-mismatch'), JSON.stringify(r.out.errors));
});

test('assessment 出现禁用词 / 非法枚举 ⇒ forbidden-token + bad-enum', async () => {
  await ensureSourceRun();
  const { dir } = copyRun();
  const file = path.join(dir, 'assessments.jsonl');
  const rows = jsonl.readJsonl(file).rows;
  rows[0].payload.decision = 'runtime-verified';
  jsonl.writeJsonl(file, rows);
  const r = await checkOf(dir);
  assert.strictEqual(r.code, 3);
  assert.ok(codes(r.out).includes('forbidden-token'), JSON.stringify(r.out.errors));
  assert.ok(codes(r.out).includes('bad-enum'), JSON.stringify(r.out.errors));
});

test('task 记录状态与事件归约不一致 ⇒ task-state-mismatch', async () => {
  await ensureSourceRun();
  const { dir } = copyRun();
  const file = path.join(dir, 'tasks.jsonl');
  const rows = jsonl.readJsonl(file).rows;
  rows[0].payload.state = 'queued';
  jsonl.writeJsonl(file, rows);
  const r = await checkOf(dir);
  assert.strictEqual(r.code, 3);
  assert.ok(codes(r.out).includes('task-state-mismatch'), JSON.stringify(r.out.errors));
});

test('run.json 不合法 ⇒ schema-invalid / run-unparsable', async () => {
  await ensureSourceRun();
  const { dir } = copyRun();
  const file = path.join(dir, 'run.json');
  const doc = readJson(file);
  delete doc.payload.budget.maxToolCalls;
  writeJson(file, doc);
  const r1 = await checkOf(dir);
  assert.strictEqual(r1.code, 3);
  assert.ok(codes(r1.out).includes('schema-invalid'), JSON.stringify(r1.out.errors));

  const { dir: dir2 } = copyRun();
  fs.writeFileSync(path.join(dir2, 'run.json'), '{broken', 'utf8');
  const r2 = await checkOf(dir2);
  assert.strictEqual(r2.code, 3);
  assert.ok(codes(r2.out).includes('run-unparsable'), JSON.stringify(r2.out.errors));
});

test('verify：缺 plan / plan 不可解析 ⇒ exit 2，不产生执行', async () => {
  await ensureSourceRun();
  const runId = readJson(path.join(sourceRunDir, 'run.json')).recordId;
  const miss = await runCli(['verify', `--run=${runId}`, '--plan=/no/such/plan.json']);
  assert.strictEqual(miss.code, 2);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'autonomy-badplan-'));
  tempDirs.push(dir);
  const bad = path.join(dir, 'bad.json');
  fs.writeFileSync(bad, 'not json', 'utf8');
  const res = await runCli(['verify', `--run=${runId}`, `--plan=${bad}`]);
  assert.strictEqual(res.code, 2);
  assert.match(res.stderr, /unparsable/);
});

test.after(() => {
  for (const dir of tempDirs.splice(0)) {
    const abs = path.resolve(dir);
    if (abs.startsWith(path.resolve(os.tmpdir()))) fs.rmSync(abs, { recursive: true, force: true });
  }
  if (sourceRunDir) {
    const abs = path.resolve(sourceRunDir);
    if (abs.startsWith(path.resolve(storeLib.AUTONOMY_ROOT) + path.sep) && /RUN-[0-9a-f]{16}$/.test(abs)) {
      fs.rmSync(abs, { recursive: true, force: true });
    }
    sourceRunDir = null;
  }
});
