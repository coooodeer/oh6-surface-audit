'use strict';

/**
 * lib/autonomy/model.js —— 模型网关（off / live / mock）。
 *
 * 纪律（§6/P5）：
 *   - `off`：**零调用**，`invoke` 直接返回 `{status:'disabled'}`，不占预算；
 *   - `live`：缺 key **明确失败**（`missing-key`），不得降级为 mock；
 *   - `mock`：只读 `test/fixtures/autonomy/model/*.json`，无 fixture ⇒ `replay-miss`；
 *   - 预算：请求前预留、完成后按 usage 结算；usage 缺失 ⇒ `usage-unknown` 并停止后续 live；
 *   - 台账：`model-calls/<CALL>.json` + `model-ledger.jsonl`；密钥只报存在性。
 */

const fs = require('fs');
const path = require('path');

const ids = require('./ids');
const state = require('./state');

const TOOL_DIR = path.resolve(__dirname, '..', '..');
const WORKSPACE = path.resolve(TOOL_DIR, '..');
const LLM_CONFIG = path.join(WORKSPACE, 'oh6-vuln-agent', 'config', 'llm.json');
const HTTP_MODULE = path.join(WORKSPACE, 'oh6-vuln-agent', 'src', 'llm', 'http.js');
const FIXTURES_DIR = path.join(TOOL_DIR, 'test', 'fixtures', 'autonomy', 'model');

const MODES = Object.freeze(['off', 'live', 'mock', 'replay']);

function sourceFilesSha256(files) {
  const pinned = Object.fromEntries(Object.entries(files).filter(([name]) =>
    name !== 'manifest.json' && name !== 'events.jsonl' && !name.startsWith('verification/')));
  return ids.sha256Hex(ids.canonicalJson(pinned));
}

function loadReplaySource(store) {
  if (!store || store.run.payload.mode !== 'live' ||
      !['1.0.5-vertical-experiment', '1.0.6-vertical-experiment',
        '1.0.7-vertical-experiment', '1.0.8-vertical-experiment',
        '1.0.9-vertical-experiment', '1.0.10-vertical-experiment',
        '1.0.11-vertical-experiment', '1.0.12-vertical-experiment',
        '1.0.13-vertical-experiment', '1.0.14-static-experiment'].includes(store.run.payload.architectureVersion) ||
      !store.run.payload.modelId) throw fail('replay-source-invalid', 'replay requires a vertical live source run');
  const saved = JSON.parse(fs.readFileSync(store.file('checksums.json'), 'utf8'));
  if (ids.canonicalJson(saved.files) !== ids.canonicalJson(store.computeChecksums())) {
    throw fail('replay-source-drift', 'source run checksums do not match');
  }
  const rows = require('./jsonl').readJsonl(store.file('model-ledger.jsonl'), { strict: true });
  if (rows.tailPartial) throw fail('replay-source-invalid', 'source model ledger is incomplete');
  const reconciled = require('./recovery').reconcileModelLedger(rows.rows);
  if (reconciled.pending.length || reconciled.legacyWithoutIntent.length) {
    throw fail('replay-source-invalid', 'source model intent/result pairs are incomplete');
  }
  const byId = new Map();
  for (const row of rows.rows) {
    const pair = byId.get(row.callId) || {};
    if (row.status === 'reserved') pair.intent = row;
    else pair.result = row;
    byId.set(row.callId, pair);
  }
  const calls = new Map();
  for (const [callId, pair] of byId) {
    if (!pair.intent || !/^[0-9a-f]{64}$/.test(pair.intent.requestSha256 || '') ||
        !pair.result || pair.result.status !== 'ok') {
      throw fail('replay-source-invalid', `source call ${callId} is not settled and successful`);
    }
    const archived = JSON.parse(fs.readFileSync(store.file(`model-calls/${callId.replace(':', '-')}.json`), 'utf8'));
    if (archived.callId !== callId || archived.status !== 'ok' || !archived.parsed ||
        archived.taskId !== pair.intent.taskId || archived.contextId !== pair.intent.contextId ||
        archived.purpose !== pair.intent.purpose) {
      throw fail('replay-source-invalid', `source call ${callId} does not match its intent`);
    }
    const key = ids.canonicalJson({ purpose: archived.purpose, taskId: archived.taskId,
      contextId: archived.contextId, requestSha256: pair.intent.requestSha256 });
    if (calls.has(key)) throw fail('replay-source-invalid', `duplicate source request ${callId}`);
    calls.set(key, archived);
  }
  return { runId: store.runId, architectureVersion: store.run.payload.architectureVersion,
    snapshotId: store.run.payload.snapshotId,
    scopeId: store.run.payload.scopeId, knowledgeVersion: store.run.payload.knowledgeVersion,
    modelId: store.run.payload.modelId, checksumsSha256: ids.sha256Hex(fs.readFileSync(store.file('checksums.json'))),
    sourceFilesSha256: sourceFilesSha256(saved.files), calls };
}

function fail(code, message, extra) {
  const e = new Error(message);
  e.code = code;
  if (extra) Object.assign(e, extra);
  return e;
}

function loadConfig(configPath) {
  const file = configPath || LLM_CONFIG;
  if (!fs.existsSync(file)) throw fail('config-missing', `model: llm config missing at ${file}`);
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

/** 从模型输出里抽出第一个平衡的 JSON 对象（容忍 ```json 围栏与前后废话） */
function extractJsonObject(text) {
  const s = String(text || '');
  const fence = s.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const candidates = fence ? [fence[1], s] : [s];
  for (const cand of candidates) {
    let depth = 0;
    let inStr = false;
    let esc = false;
    let start = -1;
    for (let i = 0; i < cand.length; i += 1) {
      const ch = cand[i];
      if (inStr) {
        if (esc) esc = false;
        else if (ch === '\\') esc = true;
        else if (ch === '"') inStr = false;
        continue;
      }
      if (ch === '"') { inStr = true; continue; }
      if (ch === '{') { if (depth === 0) start = i; depth += 1; continue; }
      if (ch === '}') {
        depth -= 1;
        if (depth === 0 && start >= 0) {
          const slice = cand.slice(start, i + 1);
          try { return { ok: true, value: JSON.parse(slice), raw: slice }; } catch (_) { start = -1; }
        }
      }
    }
  }
  return { ok: false, reason: 'no-json-object' };
}

class ModelGateway {
  constructor(o = {}) {
    this.mode = o.mode || 'off';
    if (!MODES.includes(this.mode)) throw fail('invalid-mode', `model: bad mode ${this.mode}`);
    this.store = o.store || null;
    this.budget = o.budget || null;
    this.maxTokens = o.maxTokens || 1024;
    this.timeoutMs = o.timeoutMs || 120000;
    this.configPath = o.configPath || LLM_CONFIG;
    this.modelOverride = o.modelOverride || null;
    this.fixturesDir = o.fixturesDir || FIXTURES_DIR;
    this.fetchImpl = o.fetchImpl || null;
    this.replaySource = o.replaySource || null;
    this._transport = null;
    this._config = null;
    this._fixtures = null;
    this.calls = [];
    this.stopped = null;
  }

  static create(o) { return new ModelGateway(o); }

  get config() {
    if (!this._config) this._config = loadConfig(this.configPath);
    return this._config;
  }

  get transport() {
    if (this._transport) return this._transport;
    if (!fs.existsSync(HTTP_MODULE)) throw fail('transport-missing', `model: ${HTTP_MODULE} not found`);
    const { makeHttpTransport } = require(HTTP_MODULE);
    const cfg = this.config;
    this._transport = makeHttpTransport({
      baseUrl: cfg.baseUrl,
      model: this.modelOverride || cfg.model,
      apiKeyEnv: cfg.apiKeyEnv || 'OH6_LLM_API_KEY',
      timeoutMs: this.timeoutMs,
      maxTokensPerRequest: Math.min(this.maxTokens, (cfg.budgets && cfg.budgets.maxTokensPerRequest) || this.maxTokens),
      requestExtra: cfg.requestExtra || {},
      responseFormat: cfg.responseFormat === undefined ? undefined : cfg.responseFormat,
      fetchImpl: this.fetchImpl || undefined
    });
    return this._transport;
  }

  keyPresent() {
    try {
      return this.transport.keyPresent();
    } catch (_) {
      return !!process.env.OH6_LLM_API_KEY;
    }
  }

  loadFixtures() {
    if (this._fixtures) return this._fixtures;
    const map = new Map();
    if (fs.existsSync(this.fixturesDir)) {
      for (const name of fs.readdirSync(this.fixturesDir).sort()) {
        if (!name.endsWith('.json')) continue;
        const doc = JSON.parse(fs.readFileSync(path.join(this.fixturesDir, name), 'utf8'));
        for (const fx of doc.fixtures || []) {
          if (!fx || !fx.match || !fx.response) continue;
          map.set(JSON.stringify(fx.match), fx);
        }
      }
    }
    this._fixtures = map;
    return map;
  }

  /**
   * @param {{purpose:string, taskId:string, contextId:string, messages:Array, requestId?:string, maxTokens?:number}} req
   * @returns {{status:string, reason?:string, callId:string, parsed?:object, content?:string, usage?:object}}
   */
  invoke(req) {
    const purpose = req.purpose;
    const requestId = req.requestId || ids.sha256Hex(ids.canonicalJson({
      runId: this.store ? this.store.runId : null,
      taskId: req.taskId,
      purpose,
      contextId: req.contextId
    })).slice(0, 16);
    const semantic = { mode: this.mode, purpose, requestId, taskId: req.taskId, contextId: req.contextId };
    const callId = ids.modelCallId('model-call', semantic);

    if (this.mode === 'off') {
      return { status: 'disabled', reason: 'mode-off', callId, ledgerWritten: false };
    }

    if (this.mode === 'mock') {
      const fixtures = this.loadFixtures();
      const matchKey = JSON.stringify({ purpose, requestId });
      const fx = fixtures.get(matchKey) || fixtures.get(JSON.stringify({ purpose }));
      if (!fx) {
        return this._record(callId, semantic, {
          status: 'error',
          reason: 'replay-miss',
          detail: `no fixture for purpose=${purpose} requestId=${requestId}`
        });
      }
      const parsed = typeof fx.response === 'string'
        ? extractJsonObject(fx.response)
        : { ok: true, value: fx.response, raw: JSON.stringify(fx.response) };
      return this._record(callId, semantic, {
        status: parsed.ok ? 'ok' : 'error',
        reason: parsed.ok ? null : 'schema-invalid',
        content: typeof fx.response === 'string' ? fx.response : JSON.stringify(fx.response),
        parsed: parsed.ok ? parsed.value : null,
        usage: { promptTokens: 0, completionTokens: 0, cacheHitTokens: 0, cacheMissTokens: 0 },
        usageKnown: true,
        finishReason: 'fixture'
      });
    }

    if (this.mode === 'replay') {
      const requestSha256 = ids.sha256Hex(ids.canonicalJson({ messages: req.messages || [],
        maxTokens: req.maxTokens || this.maxTokens }));
      const key = ids.canonicalJson({ purpose, taskId: req.taskId, contextId: req.contextId, requestSha256 });
      const source = this.replaySource && this.replaySource.calls.get(key);
      if (!source) throw fail('replay-miss', `no archived response for ${purpose} ${req.contextId}`);
      return this._record(callId, semantic, { status: 'ok', parsed: source.parsed,
        model: source.model, sourceCallId: source.callId,
        sourceRunId: this.replaySource.runId, finishReason: 'replay' });
    }

    // live
    if (this.stopped) {
      return this._record(callId, semantic, { status: 'error', reason: this.stopped, detail: 'live stopped earlier in this run' });
    }
    let transport;
    try {
      transport = this.transport;
    } catch (e) {
      return this._record(callId, semantic, { status: 'error', reason: 'config-invalid', detail: e.message });
    }
    if (!transport.keyPresent()) {
      return this._record(callId, semantic, {
        status: 'error',
        reason: 'missing-key',
        detail: `${this.config.apiKeyEnv || 'OH6_LLM_API_KEY'} is not set (live does not downgrade to mock)`
      });
    }
    const estimated = Math.ceil(Buffer.byteLength(JSON.stringify(req.messages || []), 'utf8') / 4);
    if (this.budget) {
      try {
        this.budget.reserveModel(req.taskId, estimated);
      } catch (e) {
        return this._record(callId, semantic, { status: 'cancelled', reason: e.code || 'budget-exhausted', detail: e.message });
      }
    }
    if (this.store) this.store.appendModelLedger({
      at: state.nowIso(), callId, mode: 'live', model: this.modelOverride || this.config.model,
      purpose: semantic.purpose, taskId: semantic.taskId || null,
      contextId: semantic.contextId || null, status: 'reserved',
      requestSha256: ids.sha256Hex(ids.canonicalJson({ messages: req.messages || [],
        maxTokens: req.maxTokens || this.maxTokens }))
    });
    const sent = transport.send({
      unitId: callId,
      attempt: 1,
      messages: req.messages || [],
      maxTokens: req.maxTokens || this.maxTokens
    });
    return sent.then((res) => {
      if (!res || res.kind !== 'ok') {
        return this._record(callId, semantic, {
          status: 'error',
          reason: res ? res.kind : 'transport-error',
          detail: res ? `${res.reason || ''} ${res.detail || ''}`.trim().slice(0, 400) : 'no result',
          wallMs: res ? res.wallMs : 0
        });
      }
      const usage = res.usage || null;
      if (this.budget) this.budget.settleModel({ inputTokens: usage ? usage.promptTokens : 0, outputTokens: usage ? usage.completionTokens : 0 });
      if (!res.usageKnown) {
        this.stopped = 'usage-unknown';
      }
      const parsed = extractJsonObject(res.content);
      const complete = res.finishReason === 'stop';
      return this._record(callId, semantic, {
        status: complete && parsed.ok ? 'ok' : 'error',
        reason: complete ? (parsed.ok ? null : 'schema-invalid') : 'model-response-incomplete',
        detail: complete ? (parsed.ok ? null : parsed.reason) : 'finishReason is not stop',
        content: res.content,
        parsed: complete && parsed.ok ? parsed.value : null,
        usage,
        usageKnown: !!res.usageKnown,
        finishReason: res.finishReason,
        wallMs: res.wallMs,
        model: res.model
      });
    });
  }

  _record(callId, semantic, result) {
    const call = {
      callId,
      mode: this.mode,
      purpose: semantic.purpose,
      taskId: semantic.taskId || null,
      contextId: semantic.contextId || null,
      requestId: semantic.requestId,
      status: result.status,
      reason: result.reason || null,
      detail: result.detail || null,
      content: null,
      contentSha256: result.content ? ids.sha256Hex(result.content) : null,
      model: result.model || this.modelOverride || (this.mode === 'live' ? this.config.model : null),
      ...(result.sourceCallId ? { sourceCallId: result.sourceCallId } : {}),
      ...(result.sourceRunId ? { sourceRunId: result.sourceRunId } : {}),
      parsed: result.parsed === undefined ? null : result.parsed,
      usage: result.usage || { promptTokens: 0, completionTokens: 0, cacheHitTokens: 0, cacheMissTokens: 0 },
      usageKnown: result.usageKnown === undefined ? null : result.usageKnown,
      finishReason: result.finishReason || null,
      wallMs: Number(result.wallMs || 0),
      createdAt: state.nowIso()
    };
    this.calls.push(call);
    if (this.store) {
      this.store.writeModelCall(callId, call);
      this.store.appendModelLedger({
        at: call.createdAt,
        callId,
        mode: call.mode,
        model: call.model,
        purpose: call.purpose,
        taskId: call.taskId,
        status: call.status,
        reason: call.reason,
        promptTokens: call.usage.promptTokens,
        completionTokens: call.usage.completionTokens,
        wallMs: call.wallMs
      });
    }
    return { ...call };
  }
}

module.exports = { ModelGateway, MODES, extractJsonObject, loadConfig, loadReplaySource,
  LLM_CONFIG, FIXTURES_DIR, HTTP_MODULE };
