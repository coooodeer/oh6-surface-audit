'use strict';

/**
 * test/autonomy-contract.test.js —— P0 契约层单元与失败用例。
 *
 * 覆盖：7+2 张 schema 可加载 / schema 校验器拒绝缺必填与未知关键字 /
 *       ID 确定性与非法 ID 拒绝 / semanticHash 排除 createdAt /
 *       JSONL 跨块 UTF-8 不截断、坏行计数、tail-partial /
 *       Task 状态迁移白名单 / missing reason 注册表 /
 *       report-model 的三分支映射 / live 程序证据门四条。
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ids = require('../lib/autonomy/ids');
const jsonl = require('../lib/autonomy/jsonl');
const state = require('../lib/autonomy/state');
const schema = require('../lib/autonomy/schema');
const assessment = require('../lib/autonomy/assessment');
const reportLib = require('../lib/autonomy/report');

const SCHEMA_DIR = path.join(__dirname, '..', 'K', 'schemas');
const SCHEMA_NAMES = ['run', 'task', 'question', 'missing', 'toolresult', 'assessment', 'report-model', 'context', 'event'];

function tmpdir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'autonomy-contract-'));
}

test('9 张 schema 可加载且是对象', () => {
  for (const name of SCHEMA_NAMES) {
    const s = schema.loadSchema(SCHEMA_DIR, name);
    assert.strictEqual(typeof s, 'object', `${name} 应为对象`);
    assert.strictEqual(s.type, 'object', `${name} 顶层应为 object`);
    assert.ok(Array.isArray(s.required) && s.required.length, `${name} 应有 required`);
    assert.strictEqual(s.additionalProperties, false, `${name} 应禁止额外字段`);
  }
});

test('schema 校验器：缺必填 / 未知关键字 / 枚举越界都要报错', () => {
  const s = schema.loadSchema(SCHEMA_DIR, 'missing');
  const good = {
    recordId: 'MISS:0123456789abcdef',
    recordType: 'missing',
    schemaVersion: '1',
    manifestId: 'AM-0123456789abcdef',
    createdAt: '2026-01-01T00:00:00.000Z',
    producer: { kind: 'analyzer', name: 'assessment', version: '1' },
    dependencyRefs: [],
    payload: {
      missingId: 'MISS:0123456789abcdef',
      questionId: 'Q:0123456789abcdef',
      category: 'precision',
      reasonCode: 'dominance-unproven',
      targetRefs: [],
      whyNeeded: '需要支配关系分析',
      blocking: true,
      nextActions: [],
      terminalReason: null
    }
  };
  assert.strictEqual(schema.validate(s, good).valid, true);
  const noPayload = { ...good };
  delete noPayload.payload;
  const r1 = schema.validate(s, noPayload);
  assert.strictEqual(r1.valid, false);
  assert.ok(r1.errors.some((e) => e.keyword === 'required'));
  const badEnum = JSON.parse(JSON.stringify(good));
  badEnum.payload.category = 'nonsense';
  assert.strictEqual(schema.validate(s, badEnum).valid, false);
  const extra = JSON.parse(JSON.stringify(good));
  extra.payload.extra = 1;
  assert.strictEqual(schema.validate(s, extra).valid, false);
  const unsupported = schema.validate({ type: 'object', minProperties: 1 }, {});
  assert.strictEqual(unsupported.valid, false, '未知关键字不得静默接受');
  assert.strictEqual(unsupported.errors[0].keyword, 'unsupported-keyword');
});

test('ID：内容确定、非法 ID 抛错、semanticHash 排除 createdAt', () => {
  const a = ids.taskId('task', { anchorRefs: ['ENT:aaaaaaaaaaaaaaaa'], origin: 'entry-scan' });
  const b = ids.taskId('task', { origin: 'entry-scan', anchorRefs: ['ENT:aaaaaaaaaaaaaaaa'] });
  assert.strictEqual(a, b, '键序不应影响内容 ID');
  assert.match(a, /^TASK:[0-9a-f]{16}$/);
  const c = ids.taskId('task', { anchorRefs: ['ENT:bbbbbbbbbbbbbbbb'], origin: 'entry-scan' });
  assert.notStrictEqual(a, c);

  assert.strictEqual(ids.assertId(a, 'task'), a);
  assert.throws(() => ids.assertId('TASK:zz', 'task'), /bad TASK id/);
  assert.throws(() => ids.assertId('Q:0123456789abcdef', 'task'), /bad TASK id/);
  assert.strictEqual(ids.isId('Q:0123456789abcdef', 'question'), true);
  assert.strictEqual(ids.isId('Q:0123', 'question'), false);
  assert.throws(() => ids.entityId('entry', { v: NaN }), /non-finite/);

  const h1 = ids.semanticHash([{ recordId: 'R:1', createdAt: '2026-01-01T00:00:00Z', x: 1 }]);
  const h2 = ids.semanticHash([{ recordId: 'R:1', createdAt: '2027-09-09T09:09:09Z', x: 1 }]);
  assert.strictEqual(h1, h2, 'createdAt 不参与语义哈希');
  const h3 = ids.semanticHash([{ recordId: 'R:1', createdAt: '2026-01-01T00:00:00Z', x: 2 }]);
  assert.notStrictEqual(h1, h3);

  assert.strictEqual(ids.runDirName('RUN:0123456789abcdef'), 'RUN-0123456789abcdef');
  assert.strictEqual(ids.normalizeRunId('RUN-0123456789abcdef'), 'RUN:0123456789abcdef');
  assert.strictEqual(ids.normalizeRunId('RUN:0123456789abcdef'), 'RUN:0123456789abcdef');
  assert.strictEqual(ids.normalizeRunId('nope'), null);
});

test('JSONL：跨块 UTF-8 不截断、坏行计数、tail-partial（失败用例）', () => {
  const dir = tmpdir();
  try {
    const file = path.join(dir, 'big.jsonl');
    const rows = [];
    for (let i = 0; i < 9000; i += 1) rows.push({ i, s: `中文测试-${i}-Ω` });
    fs.writeFileSync(file, rows.map((r) => JSON.stringify(r)).join('\n') + '\n', 'utf8');
    assert.ok(fs.statSync(file).size > jsonl.CHUNK, '文件必须跨多个读块');
    const res = jsonl.readJsonl(file);
    assert.strictEqual(res.malformed.length, 0, '跨块不得产生坏行');
    assert.strictEqual(res.rows.length, 9000);
    assert.strictEqual(res.rows[4321].s, '中文测试-4321-Ω');
    assert.strictEqual(res.tailPartial, false);
    const raw = fs.readFileSync(file, 'utf8');
    assert.strictEqual(raw.includes('\uFFFD'), false, '不得出现替换字符');

    // 中间坏行
    const broken = path.join(dir, 'broken.jsonl');
    fs.writeFileSync(broken, '{"a":1}\n{not-json}\n{"a":3}\n', 'utf8');
    const rb = jsonl.readJsonl(broken);
    assert.strictEqual(rb.rows.length, 2);
    assert.strictEqual(rb.malformed.length, 1);
    assert.strictEqual(rb.malformed[0].line, 2);
    assert.throws(() => jsonl.readJsonl(broken, { strict: true }), (e) => e.code === 'malformed-record');

    // 末尾被截断（无换行 + 半条 JSON）
    const tail = path.join(dir, 'tail.jsonl');
    fs.writeFileSync(tail, '{"a":1}\n{"a":', 'utf8');
    const rt = jsonl.readJsonl(tail);
    assert.strictEqual(rt.tailPartial, true);
    assert.strictEqual(rt.malformed.length, 1);
    assert.strictEqual(rt.malformed[0].reason, 'tail-partial');

    // needle 预过滤：只 parse 命中行
    const mixed = path.join(dir, 'mixed.jsonl');
    fs.writeFileSync(mixed, '{"repo":"a"}\n{"repo":"b"}\n{"repo":"a"}\n', 'utf8');
    const rm = jsonl.readJsonl(mixed, { needle: '"repo":"a"' });
    assert.strictEqual(rm.rows.length, 2);
    assert.strictEqual(rm.lines, 3);

    // writeJsonl 固定 UTF-8 无 BOM
    const out = path.join(dir, 'out.jsonl');
    jsonl.writeJsonl(out, [{ s: '中文' }]);
    const buf = fs.readFileSync(out);
    assert.deepStrictEqual([...buf.subarray(0, 3)], [0x7b, 0x22, 0x73]);
    assert.strictEqual(buf.toString('utf8'), '{"s":"中文"}\n');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('Task 状态迁移：白名单内通过，越界抛错', () => {
  assert.strictEqual(state.transitionTask('queued', 'running'), 'running');
  assert.strictEqual(state.transitionTask('running', 'done'), 'done');
  assert.throws(() => state.transitionTask('queued', 'done'), (e) => e.code === 'task-transition-invalid');
  assert.throws(() => state.transitionTask('done', 'running'), (e) => e.code === 'task-transition-invalid');
  assert.throws(() => state.transitionTask('nope', 'running'), (e) => e.code === 'task-state-unknown');
  assert.throws(() => state.assertQuestionStatus('bogus'), (e) => e.code === 'question-status-invalid');
});

test('Missing：未注册 reasonCode 必须报错，已注册则分类与 ID 确定', () => {
  assert.throws(() => state.buildMissing({ questionId: 'Q:0123456789abcdef', reasonCode: 'made-up' }), (e) => e.code === 'missing-reason-unknown');
  const m1 = state.buildMissing({ questionId: 'Q:0123456789abcdef', reasonCode: 'dominance-unproven', targetRefs: ['ENT:aaaaaaaaaaaaaaaa'], nextActions: ['b', 'a'] });
  const m2 = state.buildMissing({ questionId: 'Q:0123456789abcdef', reasonCode: 'dominance-unproven', targetRefs: ['ENT:aaaaaaaaaaaaaaaa'], nextActions: ['a', 'b'] });
  assert.strictEqual(m1.missingId, m2.missingId);
  assert.strictEqual(m1.category, 'precision');
  assert.deepStrictEqual(m1.nextActions, ['a', 'b'], 'nextActions 必须排序去重');
  assert.strictEqual(m1.blocking, true);
});

function fakeQuestion(kind, taskId) {
  return {
    taskId,
    questionId: ids.questionId('question', { taskId, kind }),
    kind,
    proposition: state.TASK_QUESTION_TEXT[kind],
    polarity: kind === 'dominance' ? 'forall' : 'exists',
    status: 'unknown',
    basis: 'derived',
    assurance: 'bounded-analysis',
    evidenceRefs: [],
    missingRefs: []
  };
}

function fakeRecord(recordType, payload, idKey) {
  return {
    recordId: payload[idKey],
    recordType,
    schemaVersion: '1',
    manifestId: 'AM-0123456789abcdef',
    createdAt: '2026-01-01T00:00:00.000Z',
    producer: { kind: 'analyzer', name: 'test', version: '1' },
    dependencyRefs: [],
    payload
  };
}

test('report-model 映射三分支：refuted ⇒ candidate；supported ⇒ observation；未绑定 ⇒ observation', () => {
  const taskId = ids.taskId('task', { anchorRefs: ['ENT:aaaaaaaaaaaaaaaa'], origin: 'entry-scan' });
  const qb = fakeQuestion('binding', taskId);
  const qc = fakeQuestion('check-presence', taskId);
  const qd = fakeQuestion('dominance', taskId);
  const mkAssessment = (q, decision) => {
    const payload = {
      assessmentId: ids.assessmentId('assessment', { taskId, questionId: q.questionId, decision, evidenceRefs: [], missingRefs: [] }),
      taskId,
      questionId: q.questionId,
      proposition: q.proposition,
      scope: { entryRefs: ['ENT:aaaaaaaaaaaaaaaa'], snapshotId: `sha256:${'0'.repeat(64)}` },
      decision,
      basis: 'derived',
      assurance: 'bounded-analysis',
      evidenceRefs: [],
      counterEvidenceRefs: [],
      assumptions: [],
      missingRefs: [],
      contextId: null,
      modelCallRef: null,
      rationale: 'r'
    };
    return fakeRecord('assessment', payload, 'assessmentId');
  };
  const task = fakeRecord('task', {
    taskId,
    origin: 'entry-scan',
    anchorRefs: ['ENT:aaaaaaaaaaaaaaaa'],
    question: 'q',
    state: 'done',
    questionRefs: [qb.questionId, qc.questionId, qd.questionId],
    missingRefs: [],
    revision: 1
  }, 'taskId');
  const questions = [qb, qc, qd].map((q) => fakeRecord('question', q, 'questionId'));

  const check = (binding, chk) => {
    const assessments = [mkAssessment(qb, binding), mkAssessment(qc, chk), mkAssessment(qd, 'insufficient')];
    const summary = reportLib.buildReportModel({
      tasks: [task],
      questions,
      assessments,
      missing: [],
      manifestId: 'AM-0123456789abcdef',
      snapshotId: `sha256:${'0'.repeat(64)}`
    });
    return summary.rows[0];
  };
  assert.strictEqual(check('supported', 'refuted').reportability, 'candidate');
  assert.strictEqual(check('supported', 'supported').reportability, 'observation');
  assert.strictEqual(check('insufficient', 'refuted').reportability, 'observation', 'binding 不足时不得 candidate');
  assert.strictEqual(check('insufficient', 'insufficient').reportability, 'observation');
  const row = check('supported', 'refuted');
  assert.strictEqual(row.decision, 'insufficient');
  assert.strictEqual(row.reportability.includes('finding'), false);
});

async function liveGate(parsed, opts = {}) {
  const gateway = {
    invoke: async () => (opts.invokeError
      ? { status: 'error', reason: opts.invokeError, callId: 'CALL:0123456789abcdef' }
      : { status: 'ok', parsed, callId: 'CALL:0123456789abcdef', content: JSON.stringify(parsed) })
  };
  const taskId = ids.taskId('task', { anchorRefs: ['ENT:aaaaaaaaaaaaaaaa'], origin: 'entry-scan' });
  const q = fakeQuestion('check-presence', taskId);
  return assessment.adjudicateLiveCheck({
    gateway,
    task: { taskId, anchorRefs: ['ENT:aaaaaaaaaaaaaaaa'] },
    question: q,
    context: { contextId: 'CTX:0123456789abcdef' },
    allowedRefs: new Set(['EVID:0123456789abcdef']),
    contextText: 'facts'
  });
}

test('live 程序证据门：supported 降级、越界引用拒绝、禁用词拒绝、枚举外拒绝', async () => {
  const downgraded = await liveGate({ decision: 'supported', rationale: 'ok', evidenceRefs: ['EVID:0123456789abcdef'] });
  assert.strictEqual(downgraded.decision, 'insufficient', 'supported 必须因无 runtime witness 降级');
  assert.strictEqual(downgraded.gate, 'downgraded:no-runtime-witness');
  assert.strictEqual(downgraded.missingRefs.length, 0);

  const badRef = await liveGate({ decision: 'refuted', rationale: 'x', evidenceRefs: ['EVID:deadbeefdeadbeef'] });
  assert.strictEqual(badRef.decision, 'insufficient');
  assert.match(badRef.gate, /unresolvable-evidence-ref/);
  assert.strictEqual(badRef.extraMissing.length, 1);
  assert.strictEqual(badRef.extraMissing[0].reasonCode, 'model-output-invalid');

  const forbidden = await liveGate({ decision: 'refuted', rationale: 'runtime-verified', evidenceRefs: [] });
  assert.strictEqual(forbidden.decision, 'insufficient');
  assert.match(forbidden.gate, /forbidden-token/);

  const badEnum = await liveGate({ decision: 'vulnerable', rationale: 'x', evidenceRefs: [] });
  assert.strictEqual(badEnum.decision, 'insufficient');
  assert.match(badEnum.gate, /decision-not-in-enum/);

  const noOutput = await liveGate(null, { invokeError: 'transport-error' });
  assert.strictEqual(noOutput.decision, 'insufficient');
  assert.strictEqual(noOutput.extraMissing.length, 1);
});
