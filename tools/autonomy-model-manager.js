'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { LLM_CONFIG, ModelGateway } = require('../lib/autonomy/model');

const ROOT = path.resolve(__dirname, '..');
const HOME = path.resolve(process.env.OH6_AUTONOMY_MODEL_HOME || path.join(ROOT, 'runtime', 'autonomy-model'));
const STATE = path.join(HOME, 'providers.json');
const ACTIVE = path.join(HOME, 'active.json');
const HISTORY = path.join(HOME, 'history.jsonl');
const SUITE = [
  'K/norms/050e10d78c6e93541813beb477a3c1000cbfd46817a5bf8fbf7bc5dc21b7572c/knowledge.json',
  'K/norms/7b1ad465ab401111ad3bfa060d31e4e790e390ad3c6f68d7b30b74ee09fd215f/knowledge.json'
].join(',');
const NAME = /^[a-z][a-z0-9_-]{0,31}$/;

function options(args) {
  const out = {};
  for (const arg of args) {
    const match = /^--([a-z][a-z0-9-]*)=(.*)$/.exec(arg);
    if (!match || Object.hasOwn(out, match[1])) throw new Error(`invalid option: ${arg}`);
    out[match[1]] = match[2];
  }
  return out;
}

function selectedState() {
  if (fs.existsSync(STATE)) return JSON.parse(fs.readFileSync(STATE, 'utf8'));
  const defaults = JSON.parse(fs.readFileSync(LLM_CONFIG, 'utf8'));
  return { version: 1, selected: 'commandcode', profiles: {
    commandcode: { baseUrl: defaults.baseUrl, model: defaults.model, apiKeyEnv: 'OH6_LLM_API_KEY',
      responseFormat: defaults.responseFormat, extraHeaders: defaults.extraHeaders || {},
      requestExtra: defaults.requestExtra || {}, timeoutMs: defaults.timeoutMs || 120000,
      budgets: { maxTokensPerRequest: defaults.budgets?.maxTokensPerRequest || 32768 } }
  } };
}

function save(state) {
  fs.mkdirSync(HOME, { recursive: true });
  fs.writeFileSync(STATE, JSON.stringify(state, null, 2) + '\n', 'utf8');
  fs.writeFileSync(ACTIVE, JSON.stringify(state.profiles[state.selected], null, 2) + '\n', 'utf8');
}

function jsonObject(value, label) {
  const parsed = JSON.parse(value);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error(`${label} must be a JSON object`);
  return parsed;
}

function configure(flags) {
  const allowed = new Set(['name', 'base-url', 'model', 'response-format', 'timeout-ms',
    'max-tokens', 'headers-json', 'request-extra-json']);
  if (Object.keys(flags).some((key) => !allowed.has(key))) throw new Error('unknown configure option');
  const state = selectedState();
  const name = flags.name || state.selected;
  if (!NAME.test(name)) throw new Error('invalid provider name');
  const existing = state.profiles[name];
  if (!existing && (!flags['base-url'] || !flags.model)) throw new Error('new provider needs --base-url and --model');
  const profile = { ...(existing || { apiKeyEnv: 'OH6_LLM_API_KEY', responseFormat: null,
    extraHeaders: {}, requestExtra: {}, timeoutMs: 120000,
    budgets: { maxTokensPerRequest: 32768 } }),
    ...(flags['base-url'] ? { baseUrl: flags['base-url'] } : {}),
    ...(flags.model ? { model: flags.model } : {}) };
  const url = new URL(profile.baseUrl);
  if (!['https:', 'http:'].includes(url.protocol) || !url.hostname || url.username || url.password ||
      url.search || url.hash || !profile.model || !/^[A-Za-z0-9][A-Za-z0-9_./:-]*$/.test(profile.model)) {
    throw new Error('invalid provider endpoint or model');
  }
  profile.apiKeyEnv = 'OH6_LLM_API_KEY';
  if (flags['response-format']) {
    const format = flags['response-format'];
    if (!['json_schema', 'json_object', 'none'].includes(format)) throw new Error('invalid response format');
    profile.responseFormat = format === 'none' ? null : format === 'json_object'
      ? { type: 'json_object' } : { type: 'json_schema', json_schema: {
        name: 'agent_output', schema: { type: 'object', additionalProperties: true } } };
  }
  if (flags['timeout-ms']) {
    const n = Number(flags['timeout-ms']);
    if (!Number.isInteger(n) || n < 1000 || n > 600000) throw new Error('invalid timeout-ms');
    profile.timeoutMs = n;
  }
  if (flags['max-tokens']) {
    const n = Number(flags['max-tokens']);
    if (!Number.isInteger(n) || n < 128 || n > 65536) throw new Error('invalid max-tokens');
    profile.budgets = { maxTokensPerRequest: n };
  }
  if (flags['headers-json']) {
    const headers = jsonObject(flags['headers-json'], 'headers-json');
    if (Object.keys(headers).some((key) => /authorization|api.?key|token/i.test(key)) ||
        Object.values(headers).some((value) => typeof value !== 'string')) {
      throw new Error('headers-json must contain only non-credential string headers');
    }
    profile.extraHeaders = headers;
  }
  if (flags['request-extra-json']) profile.requestExtra = jsonObject(flags['request-extra-json'], 'request-extra-json');
  state.profiles[name] = profile;
  state.selected = name;
  save(state);
  return show();
}

function use(name) {
  const state = selectedState();
  if (!NAME.test(name) || !state.profiles[name]) throw new Error('provider not configured');
  state.selected = name;
  save(state);
  return show();
}

function show() {
  const state = selectedState();
  const profile = state.profiles[state.selected];
  return { selected: state.selected, providers: Object.keys(state.profiles).sort(),
    baseUrl: profile.baseUrl, model: profile.model, responseFormat: profile.responseFormat,
    timeoutMs: profile.timeoutMs, maxTokensPerRequest: profile.budgets?.maxTokensPerRequest,
    headerNames: Object.keys(profile.extraHeaders || {}).sort(),
    requestExtraNames: Object.keys(profile.requestExtra || {}).sort(),
    keyFilePresent: fs.existsSync(keyFile(state.selected)) };
}

function keyFile(name = selectedState().selected) {
  return path.join(HOME, 'keys', `${name}.key`);
}

function storeKey() {
  const key = process.env.OH6_LLM_API_KEY?.trim();
  if (!key) throw new Error('key-missing-current-process');
  const file = keyFile();
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, key + '\n', 'utf8');
  return { status: 'key-stored', provider: selectedState().selected };
}

function loadKey() {
  const file = keyFile();
  if (!fs.existsSync(file)) return false;
  const key = fs.readFileSync(file, 'utf8').trim();
  if (!key) return false;
  process.env.OH6_LLM_API_KEY = key;
  return true;
}

function removeKey() {
  const file = keyFile();
  if (fs.existsSync(file)) fs.unlinkSync(file);
  return { status: 'key-removed', provider: selectedState().selected };
}

function record(row) {
  fs.mkdirSync(HOME, { recursive: true });
  fs.appendFileSync(HISTORY, JSON.stringify({ at: new Date().toISOString(), ...row }) + '\n', 'utf8');
}

async function probe({ writeHistory = true, gatewayFactory = ModelGateway.create } = {}) {
  const state = selectedState();
  const profile = state.profiles[state.selected];
  const row = { action: 'probe', provider: state.selected, model: profile.model,
    baseUrl: profile.baseUrl, profileSha256: crypto.createHash('sha256')
      .update(JSON.stringify(profile)).digest('hex') };
  if (!loadKey()) {
    Object.assign(row, { status: 'failed', reason: 'key-not-set-for-provider' });
  } else {
    try {
      save(state);
      const gateway = gatewayFactory({ mode: 'live', configPath: ACTIVE,
        maxTokens: Math.min(8192, profile.budgets?.maxTokensPerRequest || 8192) });
      const result = await gateway.invoke({ purpose: 'provider-preflight', maxTokens: gateway.maxTokens,
        messages: [{ role: 'user', content: 'Return exactly {"ok":true} as JSON.' }] });
      const ok = result.status === 'ok' && result.parsed?.ok === true && result.usageKnown;
      Object.assign(row, { status: ok ? 'ok' : 'failed', reason: ok ? null :
        result.reason || (result.usageKnown === false ? 'usage-unknown' : 'probe-output-invalid'),
        chatProbeKind: result.status, finishReason: result.finishReason || null,
        inputTokens: result.usage?.promptTokens || 0, outputTokens: result.usage?.completionTokens || 0 });
    } catch (_) { Object.assign(row, { status: 'failed', reason: 'provider-probe-error' }); }
  }
  if (writeHistory) record(row);
  return row;
}

async function run(flags, { gatewayFactory = ModelGateway.create, runner = spawnSync } = {}) {
  const allowed = new Set(['max-tasks', 'max-model-requests', 'task']);
  if (Object.keys(flags).some((key) => !allowed.has(key))) throw new Error('unknown run option');
  const maxTasks = flags['max-tasks'] === undefined ? 3 : Number(flags['max-tasks']);
  const maxRequests = flags['max-model-requests'] === undefined ? 30 : Number(flags['max-model-requests']);
  if (!Number.isInteger(maxTasks) || maxTasks < 0 ||
      !Number.isInteger(maxRequests) || maxRequests < 1 || maxRequests > 30) {
    throw new Error('run requires max-tasks >= 0 and 1 <= max-model-requests <= 30');
  }
  const preflight = await probe({ writeHistory: false, gatewayFactory });
  if (preflight.status !== 'ok') {
    const row = { ...preflight, action: 'run', status: 'failed', exitCode: 2 };
    record(row);
    return row;
  }
  save(selectedState());
  const args = ['bin/autonomy.js', 'run', '--mode=live',
    '--scope=K/policies/autonomy-pilot-scope.json', '--budget=K/policies/autonomy-pilot-budget.json',
    `--knowledge=${SUITE}`, `--max-tasks=${maxTasks}`, `--max-model-requests=${maxRequests}`,
    ...(flags.task ? [`--task=${flags.task}`] : [])];
  const child = runner(process.execPath, args, { cwd: ROOT, encoding: 'utf8',
    env: { ...process.env, OH6_AUTONOMY_LLM_CONFIG: ACTIVE }, maxBuffer: 8 * 1024 * 1024 });
  let result = null;
  try { result = JSON.parse(child.stdout || ''); } catch (_) { /* CLI failure has no JSON summary. */ }
  const reasons = [];
  if (result?.runDir && /^out\/autonomy\/RUN-[0-9a-f]{16}$/.test(result.runDir)) {
    const calls = path.join(ROOT, result.runDir, 'model-calls');
    if (fs.existsSync(calls)) {
      for (const file of fs.readdirSync(calls).filter((name) => /^CALL-[0-9a-f]{16}\.json$/.test(name))) {
        const call = JSON.parse(fs.readFileSync(path.join(calls, file), 'utf8'));
        if (call.status !== 'ok') reasons.push(call.reason || call.status);
      }
    }
  }
  const row = { action: 'run', provider: preflight.provider, model: preflight.model,
    baseUrl: preflight.baseUrl, profileSha256: preflight.profileSha256,
    preflight: 'ok', status: child.status === 0 && !reasons.length && result?.ok ? 'ok' : 'failed',
    reason: reasons[0] || result?.stoppedReason || (child.error ? 'process-error' :
      child.status === 0 ? 'run-incomplete' : `cli-exit-${child.status}`),
    exitCode: child.status, runId: result?.runId || null,
    counts: result?.counts || null, modelFailures: reasons.length };
  if (row.status === 'ok') row.reason = null;
  record(row);
  return row;
}

async function evalModel({ runner = spawnSync, gatewayFactory = ModelGateway.create } = {}) {
  const preflight = await probe({ writeHistory: false, gatewayFactory });
  if (preflight.status !== 'ok') {
    const failed = { ...preflight, action: 'eval', status: 'failed', exitCode: 2 };
    record(failed);
    return failed;
  }
  save(selectedState());
  const child = runner(process.execPath, ['tools/autonomy-static-eval.js', '--model-abcd', '--write'],
    { cwd: ROOT, encoding: 'utf8', env: { ...process.env, OH6_AUTONOMY_LLM_CONFIG: ACTIVE },
      maxBuffer: 8 * 1024 * 1024 });
  let result = null;
  try { result = JSON.parse(child.stdout || ''); } catch (_) { /* failure is recorded below */ }
  const invalid = result?.rows?.filter((row) => !row.verdict).length || 0;
  const row = { action: 'eval', provider: preflight.provider, model: preflight.model,
    baseUrl: preflight.baseUrl, profileSha256: preflight.profileSha256,
    status: child.status === 0 && result?.rows?.length === 20 && !invalid ? 'ok' : 'failed',
    reason: invalid ? `invalid-model-verdict:${invalid}` :
      child.status === 0 && result?.rows?.length === 20 ? null :
        String(child.stderr || child.error?.message || 'eval-incomplete').slice(0, 400),
    exitCode: child.status, requests: result?.requests || 0,
    groups: result?.groups || null, invalid, logFile: result?.logFile || null };
  record(row);
  return row;
}

async function main(argv) {
  if (process.platform !== 'win32') throw new Error('windows-native-required');
  const [action, ...rest] = argv;
  const flags = options(rest);
  let result;
  if (action === 'show' && !Object.keys(flags).length) result = show();
  else if (action === 'configure') result = configure(flags);
  else if (action === 'use' && Object.keys(flags).length === 1 && flags.name) result = use(flags.name);
  else if (action === 'store-key' && !Object.keys(flags).length) result = storeKey();
  else if (action === 'remove-key' && !Object.keys(flags).length) result = removeKey();
  else if (action === 'validate-key' && !Object.keys(flags).length) {
    result = loadKey() ? { status: 'key-loaded', provider: selectedState().selected }
      : { status: 'failed', reason: 'key-not-set-for-provider' };
  }
  else if (action === 'probe' && !Object.keys(flags).length) result = await probe();
  else if (action === 'run') result = await run(flags);
  else if (action === 'eval' && !Object.keys(flags).length) result = await evalModel();
  else throw new Error('usage: show | configure --name=... --base-url=... --model=... | use --name=... | probe | run [--max-tasks=N] [--max-model-requests=N] [--task=TASK:id]');
  process.stdout.write(JSON.stringify(result) + '\n');
  return result.status === 'failed' ? 2 : 0;
}

if (require.main === module) main(process.argv.slice(2)).then((code) => { process.exitCode = code; })
  .catch((e) => { process.stderr.write(`${e.message}\n`); process.exitCode = 2; });

module.exports = { HOME, ACTIVE, HISTORY, selectedState, configure, use, show,
  storeKey, loadKey, removeKey, probe, run, evalModel, main };
