'use strict';

/**
 * test/autonomy-pipeline.test.js —— P3/P5/P6 端到端（进程内调用 CLI，不 spawn）。
 *
 * 覆盖：
 *   - run(off) 0 次模型调用、事件 seq 连续、check 通过、report 幂等、FINDINGS 空且注明原因；
 *   - 同参数两次运行 report-model 语义哈希一致（确定性）；
 *   - mock 模式命中 fixture；live 缺 key 明确失败（不降级）；
 *   - 预算耗尽 ⇒ exit 6 + checkpoint + budget-stop 事件；
 *   - --task 只跑一个任务；verify 只占位 blocked。
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

const created = [];

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

function parseJsonOut(res) {
  return JSON.parse(res.stdout.trim());
}

function track(runDir) {
  created.push(runDir);
  return runDir;
}

function cleanup() {
  for (const dir of created.splice(0)) {
    const abs = path.resolve(dir);
    if (!abs.startsWith(path.resolve(storeLib.AUTONOMY_ROOT) + path.sep)) continue;
    if (!/RUN-[0-9a-f]{16}$/.test(abs)) continue;
    fs.rmSync(abs, { recursive: true, force: true });
  }
}

function readRun(runDir) {
  const store = new storeLib.RunStore(runDir);
  return {
    store,
    manifest: JSON.parse(fs.readFileSync(path.join(runDir, 'manifest.json'), 'utf8')),
    reportModel: JSON.parse(fs.readFileSync(path.join(runDir, 'report-model.json'), 'utf8')),
    events: jsonl.readJsonl(path.join(runDir, 'events.jsonl')).rows,
    tasks: jsonl.readJsonl(path.join(runDir, 'tasks.jsonl')).rows
  };
}

test('run(off)：0 次模型调用、事件 seq 连续、check 通过、report 幂等、静态 finding 为空', async () => {
  try {
    const res = await runCli(['run', `--scope=${SCOPE}`, `--budget=${BUDGET}`, '--mode=off', '--max-tasks=2']);
    assert.strictEqual(res.code, 0, res.stderr);
    const out = parseJsonOut(res);
    assert.strictEqual(out.mode, 'off');
    assert.strictEqual(out.planned.tasks, 2);
    assert.strictEqual(out.executed.modelRequests, 0);
    assert.strictEqual(out.executed.modelCalls, 0);

    const runDir = path.join(TOOL_DIR, out.runDir.split('/').join(path.sep));
    track(runDir);
    const run = readRun(runDir);
    assert.strictEqual(run.manifest.modelRequests, 0, 'off 模式必须 0 次模型请求');
    assert.strictEqual(run.manifest.modelCalls, 0);
    assert.strictEqual(fs.existsSync(path.join(runDir, 'model-calls')), false, 'off 模式不得产生模型调用台账');
    assert.strictEqual(run.tasks.length, 2);

    // 事件 seq 从 1 连续
    const seqs = run.events.map((e) => e.seq);
    assert.deepStrictEqual(seqs, seqs.map((_, i) => i + 1));
    assert.ok(run.events.some((e) => e.kind === 'run-created'));
    assert.ok(run.events.some((e) => e.kind === 'run-finished'));
    assert.ok(run.events.some((e) => e.kind === 'report-written'));

    // check
    const check = await runCli(['check', `--run=${out.runId}`]);
    assert.strictEqual(check.code, 0, check.stderr);
    const checkOut = parseJsonOut(check);
    assert.strictEqual(checkOut.ok, true);
    assert.deepStrictEqual(checkOut.errors, []);
    assert.strictEqual(checkOut.counts.tasks, 2);
    assert.strictEqual(checkOut.counts.questions, 6);
    assert.strictEqual(checkOut.counts.assessments, 6);

    // 报告三件套
    for (const f of ['CANDIDATES.md', 'OBSERVATIONS.md', 'FINDINGS.md', 'report.md', 'report-model.jsonl', 'checksums.json']) {
      assert.strictEqual(fs.existsSync(path.join(runDir, f)), true, `缺 ${f}`);
    }
    const findings = fs.readFileSync(path.join(runDir, 'FINDINGS.md'), 'utf8');
    assert.match(findings, /^# STATIC FINDINGS\n\n/);
    assert.match(findings, /没有加载已发布适用规范/);
    assert.doesNotMatch(findings, /runtime witness|verify/);
    assert.strictEqual(run.reportModel.counts.finding, 0);
    assert.strictEqual(run.reportModel.counts.candidate + run.reportModel.counts.observation + run.reportModel.counts.excluded, 2);
    assert.ok(run.reportModel.semanticHash.startsWith('sha256:'));

    // report 幂等：不重新裁决，产物逐字节不变
    const before = fs.readFileSync(path.join(runDir, 'CANDIDATES.md'), 'utf8');
    const beforeRows = fs.readFileSync(path.join(runDir, 'report-model.jsonl'), 'utf8');
    const rep = await runCli(['report', `--run=${out.runId}`]);
    assert.strictEqual(rep.code, 0, rep.stderr);
    const repOut = parseJsonOut(rep);
    assert.strictEqual(repOut.semanticHash, run.reportModel.semanticHash);
    assert.strictEqual(fs.readFileSync(path.join(runDir, 'CANDIDATES.md'), 'utf8'), before);
    assert.strictEqual(fs.readFileSync(path.join(runDir, 'report-model.jsonl'), 'utf8'), beforeRows);

    // check 仍通过（checksums 已随之重算）
    const check2 = await runCli(['check', `--run=${out.runId}`]);
    assert.strictEqual(check2.code, 0, check2.stderr);
  } finally {
    cleanup();
  }
});

test('确定性：同参数两次运行 report-model 语义哈希一致（排除 createdAt）', async () => {
  try {
    const a = await runCli(['run', `--scope=${SCOPE}`, `--budget=${BUDGET}`, '--mode=off', '--max-tasks=3']);
    const b = await runCli(['run', `--scope=${SCOPE}`, `--budget=${BUDGET}`, '--mode=off', '--max-tasks=3']);
    assert.strictEqual(a.code, 0, a.stderr);
    assert.strictEqual(b.code, 0, b.stderr);
    const oa = parseJsonOut(a);
    const ob = parseJsonOut(b);
    assert.notStrictEqual(oa.runId, ob.runId, '两次运行必须是不同 runId');
    assert.strictEqual(oa.semanticHash, ob.semanticHash, '语义哈希必须一致');
    const da = path.join(TOOL_DIR, oa.runDir.split('/').join(path.sep));
    const db = path.join(TOOL_DIR, ob.runDir.split('/').join(path.sep));
    track(da); track(db);
    assert.strictEqual(
      fs.readFileSync(path.join(da, 'report-model.json'), 'utf8').length > 0,
      true
    );
    const rowsA = jsonl.readJsonl(path.join(da, 'report-model.jsonl')).rows.map((r) => ({ ...r, createdAt: undefined }));
    const rowsB = jsonl.readJsonl(path.join(db, 'report-model.jsonl')).rows.map((r) => ({ ...r, createdAt: undefined }));
    assert.deepStrictEqual(rowsA, rowsB);
    assert.strictEqual(fs.readFileSync(path.join(da, 'CANDIDATES.md'), 'utf8'), fs.readFileSync(path.join(db, 'CANDIDATES.md'), 'utf8'));
  } finally {
    cleanup();
  }
});

test('mock 模式：命中 fixture，一切仍走程序证据门，check 通过', async () => {
  try {
    const res = await runCli(['run', `--scope=${SCOPE}`, `--budget=${BUDGET}`, '--mode=mock', '--max-tasks=1']);
    assert.strictEqual(res.code, 0, res.stderr);
    const out = parseJsonOut(res);
    assert.strictEqual(out.executed.modelCalls, 1);
    assert.strictEqual(out.executed.modelRequests, 0, 'mock 不消耗 live 预算');
    const runDir = path.join(TOOL_DIR, out.runDir.split('/').join(path.sep));
    track(runDir);
    const calls = fs.readdirSync(path.join(runDir, 'model-calls'));
    assert.strictEqual(calls.length, 1);
    const call = JSON.parse(fs.readFileSync(path.join(runDir, 'model-calls', calls[0]), 'utf8'));
    assert.strictEqual(call.mode, 'mock');
    assert.strictEqual(call.status, 'ok');
    assert.strictEqual(call.parsed.decision, 'insufficient');
    const ledger = jsonl.readJsonl(path.join(runDir, 'model-ledger.jsonl')).rows;
    assert.strictEqual(ledger.length, 1);
    assert.strictEqual(ledger[0].status, 'ok');
    const check = await runCli(['check', `--run=${out.runId}`]);
    assert.strictEqual(check.code, 0, check.stderr);
  } finally {
    cleanup();
  }
});

test('mock 模式：purpose 无 fixture ⇒ replay-miss（不伪造响应）', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'autonomy-nofx-'));
  try {
    const empty = path.join(dir, 'model');
    fs.mkdirSync(empty, { recursive: true });
    const modelLib = require('../lib/autonomy/model');
    const gw = modelLib.ModelGateway.create({ mode: 'mock', fixturesDir: empty });
    const res = await gw.invoke({ purpose: 'check-presence', taskId: 'TASK:0123456789abcdef', contextId: 'CTX:0123456789abcdef', messages: [] });
    assert.strictEqual(res.status, 'error');
    assert.strictEqual(res.reason, 'replay-miss');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('live 缺 key：明确失败（exit 2 + missing-key），不得降级为 mock', async () => {
  const saved = process.env.OH6_LLM_API_KEY;
  delete process.env.OH6_LLM_API_KEY;
  try {
    const res = await runCli(['run', `--scope=${SCOPE}`, `--budget=${BUDGET}`, '--mode=live', '--max-tasks=1']);
    assert.strictEqual(res.code, 2);
    assert.match(res.stderr, /missing-key/);
    assert.match(res.stderr, /never downgrades to mock/);
  } finally {
    if (saved !== undefined) process.env.OH6_LLM_API_KEY = saved;
  }
});

test('预算耗尽：exit 6 + checkpoint 记 stoppedReason + budget-stop 事件', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'autonomy-budget-'));
  try {
    const base = JSON.parse(fs.readFileSync(path.join(TOOL_DIR, BUDGET), 'utf8'));
    const tiny = JSON.parse(JSON.stringify(base));
    tiny.budget.maxToolCalls = 2;
    tiny.budget.maxTaskToolCalls = 20;
    tiny.budget.maxTasks = 10;
    const file = path.join(dir, 'tiny-budget.json');
    fs.writeFileSync(file, JSON.stringify(tiny, null, 2), 'utf8');
    const res = await runCli(['run', `--scope=${SCOPE}`, `--budget=${file}`, '--mode=off', '--max-tasks=0']);
    assert.strictEqual(res.code, 6, res.stderr);
    const out = parseJsonOut(res);
    assert.strictEqual(out.stoppedReason, 'budget-exhausted');
    assert.strictEqual(out.ok, false);
    const runDir = path.join(TOOL_DIR, out.runDir.split('/').join(path.sep));
    track(runDir);
    const cp = JSON.parse(fs.readFileSync(path.join(runDir, 'checkpoints', 'state.json'), 'utf8'));
    assert.strictEqual(cp.stoppedReason, 'budget-exhausted');
    assert.strictEqual(cp.budget.toolCalls, 2);
    const events = jsonl.readJsonl(path.join(runDir, 'events.jsonl')).rows;
    assert.ok(events.some((e) => e.kind === 'budget-stop'));
    const seqs = events.map((e) => e.seq);
    assert.deepStrictEqual(seqs, seqs.map((_, i) => i + 1));
    // 预算停止后仍要能 check（记录自洽）
    const check = await runCli(['check', `--run=${out.runId}`]);
    assert.strictEqual(check.code, 0, check.stderr);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
    cleanup();
  }
});

test('--task：只跑指定任务；非法 ID ⇒ exit 2', async () => {
  try {
    const first = await runCli(['run', `--scope=${SCOPE}`, `--budget=${BUDGET}`, '--mode=off', '--max-tasks=2']);
    const o1 = parseJsonOut(first);
    const dir1 = path.join(TOOL_DIR, o1.runDir.split('/').join(path.sep));
    track(dir1);
    const tasks = jsonl.readJsonl(path.join(dir1, 'tasks.jsonl')).rows;
    assert.strictEqual(tasks.length, 2);
    const one = tasks[0].recordId;

    const res = await runCli(['run', `--scope=${SCOPE}`, `--budget=${BUDGET}`, '--mode=off', '--max-tasks=0', `--task=${one}`]);
    assert.strictEqual(res.code, 0, res.stderr);
    const out = parseJsonOut(res);
    assert.strictEqual(out.planned.tasks, 1);
    const dir2 = path.join(TOOL_DIR, out.runDir.split('/').join(path.sep));
    track(dir2);
    const only = jsonl.readJsonl(path.join(dir2, 'tasks.jsonl')).rows;
    assert.strictEqual(only.length, 1);
    assert.strictEqual(only[0].recordId, one);
  } finally {
    cleanup();
  }
  const bad = await runCli(['run', `--scope=${SCOPE}`, '--budget=${BUDGET}', '--mode=off', '--task=TASK:zz']);
  assert.strictEqual(bad.code, 2);
});

test('verify：只登记占位并返回 blocked，不执行任何命令', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'autonomy-plan-'));
  try {
    const first = await runCli(['run', `--scope=${SCOPE}`, `--budget=${BUDGET}`, '--mode=off', '--max-tasks=1']);
    const o1 = parseJsonOut(first);
    const runDir = path.join(TOOL_DIR, o1.runDir.split('/').join(path.sep));
    track(runDir);
    const planFile = path.join(dir, 'plan.json');
    fs.writeFileSync(planFile, JSON.stringify({ planId: 'p1', requested: ['hdc', 'build-harness'] }), 'utf8');
    const res = await runCli(['verify', `--run=${o1.runId}`, `--plan=${planFile}`]);
    assert.strictEqual(res.code, 0, res.stderr);
    const out = parseJsonOut(res);
    assert.strictEqual(out.result, 'blocked');
    assert.strictEqual(out.status, 'blocked');
    assert.deepStrictEqual(out.executedCommands, []);
    assert.strictEqual(out.missing.length, 1);
    assert.strictEqual(out.missing[0].category, 'environment');
    assert.strictEqual(out.missing[0].reasonCode, 'verification-disabled');
    const placeholder = JSON.parse(fs.readFileSync(path.join(runDir, 'verification', 'placeholder.json'), 'utf8'));
    assert.strictEqual(placeholder.status, 'blocked');
    assert.deepStrictEqual(placeholder.executedCommands, []);
    assert.deepStrictEqual(placeholder.planKeys, ['planId', 'requested']);
    const check = await runCli(['check', `--run=${o1.runId}`]);
    assert.strictEqual(check.code, 0, check.stderr);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
    cleanup();
  }
});

test('参数/配置错误：未知命令 exit 2、非法 mode exit 2、缺 --run exit 2', async () => {
  assert.strictEqual((await runCli(['nope'])).code, 2);
  assert.strictEqual((await runCli(['run', `--scope=${SCOPE}`, `--budget=${BUDGET}`, '--mode=bogus'])).code, 2);
  assert.strictEqual((await runCli(['check'])).code, 2);
  assert.strictEqual((await runCli(['report'])).code, 2);
  assert.strictEqual((await runCli(['doctor', '--scope=K/policies/nope.json'])).code, 2);
  assert.strictEqual((await runCli(['help'])).code, 0);
});
