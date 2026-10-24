'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { ModelGateway } = require('../lib/autonomy/model');

test('Windows agent provider profiles, one-time key and failure ledger stay local', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'oh6-agent-model-'));
  const priorHome = process.env.OH6_AUTONOMY_MODEL_HOME;
  const priorKey = process.env.OH6_LLM_API_KEY;
  process.env.OH6_AUTONOMY_MODEL_HOME = home;
  const managerPath = require.resolve('../tools/autonomy-model-manager');
  delete require.cache[managerPath];
  const manager = require(managerPath);
  const ps = path.join(__dirname, '..', 'tools', 'autonomy-model.ps1');
  try {
    assert.equal(manager.show().selected, 'commandcode');
    manager.configure({ name: 'fixture', 'base-url': 'https://example.test/v1',
      model: 'deepseek/deepseek-v4.1-flash', 'response-format': 'json_schema',
      'headers-json': '{"x-cmd-zdr":"1"}', 'timeout-ms': '4000' });
    assert.equal(manager.show().selected, 'fixture');
    assert.equal(manager.show().timeoutMs, 4000);
    assert.deepEqual(manager.show().headerNames, ['x-cmd-zdr']);
    const configured = spawnSync('pwsh', ['-NoProfile', '-File', ps, 'configure',
      '--name=fixture', '--timeout-ms=5000'], { cwd: path.join(__dirname, '..'),
      env: { ...process.env, OH6_AUTONOMY_MODEL_HOME: home }, encoding: 'utf8' });
    assert.equal(configured.status, 0, configured.stderr);
    assert.equal(manager.show().timeoutMs, 5000);
    manager.use('commandcode');
    manager.use('fixture');
    const fake = "& '" + ps.replace(/'/g, "''") + "' set-key " +
      "-Secret (ConvertTo-SecureString 'fixture-only' -AsPlainText -Force)";
    const stored = spawnSync('pwsh', ['-NoProfile', '-Command', fake], {
      cwd: path.join(__dirname, '..'), env: { ...process.env, OH6_AUTONOMY_MODEL_HOME: home }, encoding: 'utf8' });
    assert.equal(stored.status, 0, stored.stderr);
    assert.equal(manager.show().keyFilePresent, true);
    const keyFile = path.join(home, 'keys', 'fixture.key');
    assert.equal(fs.readFileSync(keyFile, 'utf8'), 'fixture-only\n');
    const roundTrip = spawnSync('pwsh', ['-NoProfile', '-File', ps, 'validate-key'],
      { cwd: path.join(__dirname, '..'), env: { ...process.env,
        OH6_AUTONOMY_MODEL_HOME: home, OH6_LLM_API_KEY: '' }, encoding: 'utf8' });
    assert.equal(roundTrip.status, 0, roundTrip.stderr);
    assert.match(roundTrip.stdout, /key-loaded/);
    assert.doesNotMatch(roundTrip.stdout, /fixture-only/);

    manager.use('commandcode');
    assert.equal(manager.show().keyFilePresent, false);
    assert.equal(manager.loadKey(), false);
    manager.use('fixture');

    delete process.env.OH6_LLM_API_KEY;
    assert.equal(manager.loadKey(), true);
    const requests = [];
    const gateway = new ModelGateway({ mode: 'live', configPath: manager.ACTIVE,
      fetchImpl: async (_url, request) => {
        requests.push(request);
        return { ok: true, json: async () => ({ model: 'deepseek/deepseek-v4.1-flash',
          choices: [{ message: { content: '{"ok":true}' }, finish_reason: 'stop' }],
          usage: { prompt_tokens: 5, completion_tokens: 4 } }) };
      } });
    const actual = await gateway.invoke({ purpose: 'provider-preflight',
      messages: [{ role: 'user', content: 'probe' }], maxTokens: 1200 });
    assert.equal(actual.status, 'ok');
    assert.equal(requests[0].headers['x-cmd-zdr'], '1');
    assert.equal(JSON.parse(requests[0].body).response_format.type, 'json_schema');

    const okGateway = () => ({ maxTokens: 1200, invoke: async () => ({ status: 'ok',
      parsed: { ok: true }, usageKnown: true, usage: { promptTokens: 5, completionTokens: 4 },
      finishReason: 'stop' }) });
    delete process.env.OH6_LLM_API_KEY;
    assert.equal((await manager.probe({ gatewayFactory: okGateway })).status, 'ok');
    assert.equal(process.env.OH6_LLM_API_KEY, 'fixture-only');
    const run = await manager.run({ 'max-tasks': '2', 'max-model-requests': '2' }, {
      gatewayFactory: okGateway, runner: (_exe, args, opts) => {
        assert.ok(args.includes('--max-model-requests=2'));
        assert.equal(opts.env.OH6_AUTONOMY_LLM_CONFIG, manager.ACTIVE);
        assert.equal(opts.env.OH6_LLM_API_KEY, 'fixture-only');
        return { status: 0, stdout: JSON.stringify({ ok: true,
          runId: 'RUN:aaaaaaaaaaaaaaaa', counts: { finding: 1 } }) };
      }
    });
    assert.equal(run.status, 'ok');
    assert.equal(run.runId, 'RUN:aaaaaaaaaaaaaaaa');
    const evaluated = await manager.evalModel({ gatewayFactory: okGateway,
      runner: (_exe, args, opts) => {
        assert.deepEqual(args, ['tools/autonomy-static-eval.js', '--model-abcd', '--write']);
        assert.equal(opts.env.OH6_LLM_API_KEY, 'fixture-only');
        return { status: 0, stdout: JSON.stringify({ rows: Array(20).fill({ verdict: 'finding' }), requests: 20,
          groups: ['A', 'B', 'C', 'D'].map((group) => ({ group, total: 5 })),
          logFile: 'out/autonomy/eval/fixture.jsonl' }) };
      } });
    assert.equal(evaluated.status, 'ok');
    assert.equal(evaluated.requests, 20);
    const incomplete = await manager.evalModel({ gatewayFactory: okGateway,
      runner: () => ({ status: 0, stdout: JSON.stringify({ rows: Array(20).fill({ verdict: null }),
        requests: 20, groups: [], logFile: 'out/autonomy/eval/incomplete.jsonl' }) }) });
    assert.equal(incomplete.status, 'failed');
    assert.equal(incomplete.reason, 'invalid-model-verdict:20');
    let launched = false;
    const denied = await manager.run({}, { gatewayFactory: () => ({ maxTokens: 1200,
      invoke: async () => ({ status: 'error', reason: 'auth-failed', usageKnown: false }) }),
    runner: () => { launched = true; } });
    assert.equal(denied.reason, 'auth-failed');
    assert.equal(launched, false);
    const history = fs.readFileSync(manager.HISTORY, 'utf8');
    assert.doesNotMatch(history, /fixture-only/);
    assert.match(history, /auth-failed/);
    assert.match(history, /RUN:aaaaaaaaaaaaaaaa/);

    const removed = spawnSync('pwsh', ['-NoProfile', '-File', ps, 'remove-key'],
      { cwd: path.join(__dirname, '..'), env: { ...process.env, OH6_AUTONOMY_MODEL_HOME: home }, encoding: 'utf8' });
    assert.equal(removed.status, 0, removed.stderr);
    assert.equal(manager.show().keyFilePresent, false);
    const absent = spawnSync('pwsh', ['-NoProfile', '-File', ps, 'probe'],
      { cwd: path.join(__dirname, '..'), env: { ...process.env,
        OH6_AUTONOMY_MODEL_HOME: home, OH6_LLM_API_KEY: '' }, encoding: 'utf8' });
    assert.equal(absent.status, 2);
    assert.match(fs.readFileSync(manager.HISTORY, 'utf8'), /key-not-set-for-provider/);
  } finally {
    if (priorHome === undefined) delete process.env.OH6_AUTONOMY_MODEL_HOME;
    else process.env.OH6_AUTONOMY_MODEL_HOME = priorHome;
    if (priorKey === undefined) delete process.env.OH6_LLM_API_KEY;
    else process.env.OH6_LLM_API_KEY = priorKey;
    delete require.cache[managerPath];
    if (home.startsWith(path.resolve(os.tmpdir()) + path.sep) &&
        path.basename(home).startsWith('oh6-agent-model-')) fs.rmSync(home, { recursive: true, force: true });
  }
});
