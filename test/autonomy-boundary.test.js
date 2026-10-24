'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const model = require('../lib/autonomy/model');
const doctor = require('../lib/autonomy/doctor');
const { makeHttpTransport } = require('../lib/autonomy/http');

const root = path.resolve(__dirname, '..');

test('model transport and default config belong to this agent', async () => {
  assert.equal(model.LLM_CONFIG, path.join(root, 'config', 'autonomy-llm.json'));
  assert.equal(model.HTTP_MODULE, path.join(root, 'lib', 'autonomy', 'http.js'));
  const config = model.loadConfig(model.LLM_CONFIG);
  assert.ok(config.baseUrl && config.model);
  const original = process.env.OH6_LLM_API_KEY;
  process.env.OH6_LLM_API_KEY = 'test-only-credential';
  try {
    const requests = [];
    const gateway = new model.ModelGateway({ mode: 'live', configPath: model.LLM_CONFIG,
      fetchImpl: async (url, request) => {
      requests.push({ url, request });
      return { ok: true, json: async () => ({ model: config.model,
        choices: [{ message: { content: '{"decision":"insufficient"}' }, finish_reason: 'stop' }],
        usage: { prompt_tokens: 5, completion_tokens: 3 } }) };
      } });
    const result = await gateway.invoke({ purpose: 'transport-test', messages: [{ role: 'user', content: 'test' }] });
    assert.equal(result.status, 'ok');
    assert.equal(requests[0].url, config.baseUrl + '/chat/completions');
    assert.equal(JSON.parse(requests[0].request.body).model, config.model);
  } finally {
    if (original === undefined) delete process.env.OH6_LLM_API_KEY;
    else process.env.OH6_LLM_API_KEY = original;
  }
});

test('doctor and model resolve the same selected profile', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'autonomy-profile-'));
  const previous = process.env.OH6_AUTONOMY_MODEL_HOME;
  process.env.OH6_AUTONOMY_MODEL_HOME = home;
  try {
    const active = path.join(home, 'active.json');
    fs.writeFileSync(active, JSON.stringify({ baseUrl: 'https://fixture.test/v1', model: 'fixture-model' }));
    assert.equal(model.defaultConfigPath(), active);
    const result = doctor.runDoctor({ scopePath: 'K/policies/autonomy-pilot-scope.json' });
    assert.equal(result.gateway.model, model.loadConfig().model);
    assert.equal(result.gateway.model, 'fixture-model');
  } finally {
    if (previous === undefined) delete process.env.OH6_AUTONOMY_MODEL_HOME;
    else process.env.OH6_AUTONOMY_MODEL_HOME = previous;
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('local transport classifies provider failures without exposing the key', async () => {
  const previous = process.env.OH6_LLM_API_KEY;
  process.env.OH6_LLM_API_KEY = 'fixture-secret-key';
  try {
    for (const [status, kind] of [[401, 'auth-failed'], [429, 'rate-limited']]) {
      const transport = makeHttpTransport({ baseUrl: 'https://fixture.test/v1', model: 'fixture',
        fetchImpl: async () => ({ ok: false, status,
          text: async () => 'Bearer fixture-secret-key' }) });
      const result = await transport.send({ unitId: 'test', attempt: 1, messages: [] });
      assert.equal(result.kind, kind);
      assert.doesNotMatch(JSON.stringify(result), /fixture-secret-key/);
    }
  } finally {
    if (previous === undefined) delete process.env.OH6_LLM_API_KEY;
    else process.env.OH6_LLM_API_KEY = previous;
  }
});

test('controlled evaluation labels stay source-bound and outside production results', () => {
  const manifest = require('../eval/autonomy/static-builder-mutants.json');
  const dir = path.join(root, 'test', 'fixtures', 'autonomy', 'mutants');
  assert.equal(manifest.sourceType, 'controlled-mutant');
  assert.equal(manifest.labelAuthority, 'builder-llm-oracle');
  assert.equal(manifest.needsHumanTuning, true);
  assert.equal(new Set(manifest.labels.map((label) => label.familyId)).size, manifest.labels.length);
  for (const label of manifest.labels) {
    assert.match(label.file, /^[a-z-]+\.cpp$/);
    const actual = crypto.createHash('sha256').update(fs.readFileSync(path.join(dir, label.file))).digest('hex');
    assert.equal(label.sha256, actual, label.file);
    assert.ok(['finding', 'excluded', 'insufficient'].includes(label.expected));
  }
});
