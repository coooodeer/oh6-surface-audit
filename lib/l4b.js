'use strict';

/**
 * l4b.js —— 有界语义判定（P6 item 级 / P3 producer 可空性）。
 *
 * 口径：
 *   - 单次模型调用优先，不做工具循环；
 *   - 程序按 items 计算敏感项集合，不直接相信模型给的整体结论；
 *   - sensitive=yes 才进入 C4；unknown 不能当命中，也不能当否定；
 *   - schema/引用/枚举由程序校验；不合法只允许一次格式修复；
 *   - 没有 key 时用 fixture/mock 跑结构测试，live 判定标 blocked，不伪造；
 *   - 日志只记录 unitId/tokens/attempts/contentHash/schema 结果，不记录 key。
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WORKSPACE, OUT_ROOT, ensureDir, readJsonl, writeJsonl, writeJson } = require('./util.js');

const L4B_DIR = path.join(OUT_ROOT, 'l4b');
const LOG_DIR = path.join(OUT_ROOT, '..', 'logs');
const LOG_FILE = path.join(LOG_DIR, 'l4b.jsonl');
const CONFIG_FILE = path.join(WORKSPACE, 'oh6-vuln-agent', 'config', 'llm.json');
const TRANSPORT_FILE = path.join(WORKSPACE, 'oh6-vuln-agent', 'src', 'llm', 'http.js');

const P6_SCHEMA_HINT = [
  '{"items":[{"item":"<payload item>","sensitive":"yes|no|unknown","evidenceRef":"E1:L88"}],"reason":"<=2 句","evidenceRefs":["E1:L88"]}'
].join('\n');

const P3_SCHEMA_HINT = '{"producerMayNull":"yes|no|unknown","reason":"<=2 句","evidenceRefs":["E1:L88"]}';

function sha(s) {
  return crypto.createHash('sha256').update(String(s), 'utf8').digest('hex');
}

function parseJsonContent(text) {
  let s = String(text == null ? '' : text).trim();
  s = s.replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/i, '').trim();
  const a = s.indexOf('{');
  const b = s.lastIndexOf('}');
  if (a >= 0 && b > a) s = s.slice(a, b + 1);
  return JSON.parse(s);
}

function loadConfig(file = CONFIG_FILE) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

/**
 * Node 25 的 undici 在本机对部分 endpoint 的 IPv6 自动选择会 connect timeout；
 * 显式 family=4 + agent:false 的实现可稳定连通。仅用于 live 调用。
 *
 * 协议按 baseUrl 选：本机网关（http://127.0.0.1:7864）必须走 http，否则
 * https.request 会抛 ERR_INVALID_PROTOCOL。见 docs/48（vuln-agent）。
 */
function makeFetchIPv4() {
  return function fetchIPv4(url, options = {}) {
    return new Promise((resolve, reject) => {
      const u = new URL(url);
      const mod = u.protocol === 'http:' ? require('http') : require('https');
      const req = mod.request({
        protocol: u.protocol,
        hostname: u.hostname,
        port: u.port || (u.protocol === 'http:' ? 80 : 443),
        path: `${u.pathname}${u.search}`,
        method: options.method || 'GET',
        headers: options.headers || {},
        family: 4,
        agent: false,
        timeout: 120000
      }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const body = Buffer.concat(chunks).toString('utf8');
          resolve(new Response(body, { status: res.statusCode, headers: res.headers }));
        });
      });
      req.on('error', reject);
      req.on('timeout', () => req.destroy(new Error('ipv4-fetch-timeout')));
      if (options.body) req.write(options.body);
      req.end();
    });
  };
}

/** 复用 oh6-vuln-agent 的 OpenAI-compatible 运输层；强制 connection: close。 */
function makeTransport(opts = {}) {
  const cfg = opts.cfg || loadConfig();
  const { makeHttpTransport } = require(TRANSPORT_FILE);
  return makeHttpTransport({
    baseUrl: cfg.baseUrl,
    model: opts.model || cfg.model,
    apiKeyEnv: cfg.apiKeyEnv || 'OH6_LLM_API_KEY',
    timeoutMs: Number(opts.timeoutMs || cfg.timeoutMs || 120000),
    maxTokensPerRequest: Number(opts.maxTokens || 4096),
    requestExtra: cfg.requestExtra || {},
    responseFormat: cfg.responseFormat === undefined ? undefined : cfg.responseFormat,
    extraHeaders: { ...(cfg.extraHeaders || {}), connection: 'close' },
    fetchImpl: opts.fetchImpl || makeFetchIPv4()
  });
}

function lineRef(refId, line) {
  return `E${refId}:L${line}`;
}

function packEvidence(id, file, line, text, label) {
  return { ref: `E${id}:L${line}`, id: `E${id}`, file, line, label, text: String(text || '').slice(0, 800) };
}

function p6ItemsOf(claim, l1) {
  const site = l1.minerSite(claim.entry.siteKey);
  const slice = l1.minerSlice(claim.entry.siteKey);
  const writes = ((site && site.payloadWrites) || (slice && slice.writes) || [])
    .filter((w) => String(w.setter || '').toLowerCase() !== 'setaction' && String(w.key || '') !== 'SetAction');
  const items = [];
  const seen = new Set();
  for (const w of writes) {
    const raw = w.key || (w.classified && w.classified.member) || w.resolvedValueExpr || w.rawValueExpr;
    if (!raw) continue;
    // SetWant/SetCode/SetData 是整对象写点，用载荷字段名而不是 setter 名作为 item
    const name = /^SetWant$/i.test(raw) ? 'want'
      : /^SetCode$/i.test(raw) ? 'code'
        : /^SetData$/i.test(raw) ? 'data'
          : String(raw);
    if (seen.has(name)) continue;
    seen.add(name);
    items.push({ item: name, origin: raw, line: w.line || null, value: w.resolvedValueExpr || w.rawValueExpr || null });
  }
  return { site, slice, writes, items };
}

/** P6 证据包：item 级 + 可校验的 E#:L# 引用 */
function buildP6Pack(claim, l1, opts = {}) {
  const { site, slice, writes, items } = p6ItemsOf(claim, l1);
  const sink = claim.sink || {};
  const evidence = [];
  let refId = 1;
  if (sink.file && sink.line) {
    const lines = l1.sourceLines(claim.entry.repo || (site && site.repo) || '', sink.file);
    const text = lines ? lines[sink.line - 1] : '';
    evidence.push(packEvidence(refId++, sink.file, sink.line, text, 'publish-site'));
  }
  for (const w of writes.slice(0, 6)) {
    const key = w.key == null ? (w.classified && w.classified.member) : w.key;
    if (!key) continue;
    const text = w.resolvedValueExpr || w.rawValueExpr || w.value || '';
    const file = sink.file;
    const line = w.line || sink.line;
    if (!file || !line) continue;
    evidence.push(packEvidence(refId++, file, line, `SetParam/SetData ${key} = ${text}`, 'payload-write'));
  }
  // 发布函数体内的上下文（最多 3 行），只用于给模型“方向”证据
  if (sink.file && sink.line) {
    const lines = l1.sourceLines(claim.entry.repo || '', sink.file);
    if (lines) {
      for (let ln = Math.max(1, sink.line - 3); ln <= Math.min(lines.length, sink.line + 2); ln += 1) {
        if (ln === sink.line) continue;
        if (evidence.length >= 9) break;
        evidence.push(packEvidence(refId++, sink.file, ln, lines[ln - 1], 'publish-context'));
      }
    }
  }
  const refs = evidence.map((e) => e.ref);
  return {
    id: `L4B-P6-${claim.entry.siteKey}`,
    kind: 'P6',
    claimId: claim.claimId,
    siteKey: claim.entry.siteKey,
    action: claim.entry.action,
    group: claim.group,
    sink,
    sliceStatus: slice ? slice.status : null,
    subscriberPermissions: (site && site.subscriberPermissions) || [],
    items: items.map((i) => i.item),
    itemDetails: items,
    evidence,
    refs,
    schema: P6_SCHEMA_HINT,
    ask: 'items 中每个 payload item 是否包含敏感/受限数据（账号、设备标识、位置、通知内容、应用私有数据等）？'
  };
}

/** P3 证据包：producer 可空性 */
function buildP3Pack(claim, l1) {
  const evidence = [];
  let refId = 1;
  const src = claim.source;
  const lines = l1.sourceLines(src.repo, src.file);
  if (lines) {
    for (let ln = Math.max(1, src.line - 2); ln <= Math.min(lines.length, src.line + 1); ln += 1) {
      evidence.push(packEvidence(refId++, src.file, ln, lines[ln - 1], ln === src.line ? 'deref' : 'deref-context'));
    }
  }
  if (claim.producer && claim.producer.file && claim.producer.startLine) {
    const plines = l1.sourceLines(src.repo, claim.producer.file);
    if (plines) {
      const start = claim.producer.startLine;
      for (let ln = start; ln <= Math.min(plines.length, start + 12); ln += 1) {
        evidence.push(packEvidence(refId++, claim.producer.file, ln, plines[ln - 1], 'producer-body'));
      }
    }
  }
  return {
    id: `L4B-P3-${claim.derefId || claim.claimId}`,
    kind: 'P3',
    claimId: claim.claimId,
    derefId: claim.derefId,
    repo: src.repo,
    file: src.file,
    line: src.line,
    text: src.text,
    producer: claim.producer,
    evidence,
    refs: evidence.map((e) => e.ref),
    schema: P3_SCHEMA_HINT,
    ask: 'producer 调用是否可能返回 nullptr/NULL（或失败时返回空指针）？'
  };
}

function buildMessages(pack) {
  const system = pack.kind === 'P6'
    ? [
      '你是 OpenHarmony CommonEvent 载荷敏感度判定器。只依据给定证据判断每个 payload item 是否包含敏感/受限数据。',
      '敏感示例：账号标识（userId/accountId/domain/accountName）、设备标识（IMEI/SN/MAC/udid）、位置、通知内容、应用私有数据。',
      '非敏感示例：公共枚举状态、数值统计码、公开 API 可获得的几何信息。',
      '聚合对象（如 want）无法展开时标 unknown；证据不足标 unknown；不要猜测。',
      '只输出 JSON 对象，不要 Markdown，不要解释性前后缀。schema：',
      pack.schema,
      '每个 evidenceRef 必须来自输入的证据引用列表。'
    ].join('\n')
    : [
      '你是 C/C++ 空指针风险判定器。只依据给定证据判断 producer 调用是否可能返回 nullptr/NULL。',
      'new (std::nothrow)、malloc/calloc、失败返回 nullptr、find 未命中返回 end 等都算可能为空；',
      '返回静态对象地址、引用、值类型对象不算空。证据不足标 unknown。',
      '只输出 JSON 对象，不要 Markdown，不要解释性前后缀。schema：',
      pack.schema,
      '每个 evidenceRef 必须来自输入的证据引用列表。'
    ].join('\n');
  const ev = pack.evidence.map((e) => `${e.ref} [${e.label}] ${e.file || ''}:${e.line || ''}  ${e.text}`).join('\n');
  const user = pack.kind === 'P6'
    ? [
      `action: ${pack.action}`,
      `payload items: ${JSON.stringify(pack.items)}`,
      `subscriberPermissions: ${JSON.stringify(pack.subscriberPermissions)}`,
      `sliceStatus: ${pack.sliceStatus}`,
      '',
      '证据：',
      ev,
      '',
      `问题：${pack.ask}`,
      `请返回一个 items 数组，item 必须逐字覆盖 payload items：${JSON.stringify(pack.items)}`
    ].join('\n')
    : [
      `repo/file/line: ${pack.repo}/${pack.file}:${pack.line}`,
      `deref: ${pack.text}`,
      `producer: ${pack.producer && pack.producer.name}`,
      '',
      '证据：',
      ev,
      '',
      `问题：${pack.ask}`
    ].join('\n');
  return [
    { role: 'system', content: system },
    { role: 'user', content: user }
  ];
}

function validateRefs(refs, allowed) {
  if (!Array.isArray(refs) || !refs.length) return { ok: false, reason: 'evidenceRefs-empty' };
  const bad = refs.filter((r) => !allowed.includes(r));
  if (bad.length) return { ok: false, reason: `evidenceRefs-not-in-pack:${bad.join(',')}` };
  return { ok: true };
}

function validateP6(obj, pack) {
  const errors = [];
  if (!obj || !Array.isArray(obj.items) || !obj.items.length) errors.push('items-empty');
  if (typeof obj.reason !== 'string') errors.push('reason-not-string');
  const allowed = new Set(pack.items);
  const seen = new Set();
  for (const it of obj.items || []) {
    if (!it || typeof it.item !== 'string' || !it.item) { errors.push('item-name-missing'); continue; }
    if (!allowed.has(it.item)) errors.push(`unknown-item:${it.item}`);
    if (seen.has(it.item)) errors.push(`duplicate-item:${it.item}`);
    seen.add(it.item);
    if (!['yes', 'no', 'unknown'].includes(it.sensitive)) errors.push(`bad-sensitive:${it.item}`);
    if (!/^E\d+:L\d+$/.test(String(it.evidenceRef || ''))) errors.push(`bad-item-evidenceRef:${it.item}`);
    else if (!pack.refs.includes(it.evidenceRef)) errors.push(`item-evidenceRef-not-in-pack:${it.item}`);
  }
  // 允许模型少报 item；程序把缺失项一律当 unknown（不是 no），避免把漏答当否定。
  const refCheck = validateRefs(obj.evidenceRefs, pack.refs);
  if (!refCheck.ok) errors.push(refCheck.reason);
  return { ok: errors.length === 0, errors };
}

function validateP3(obj, pack) {
  const errors = [];
  if (!obj || !['yes', 'no', 'unknown'].includes(obj.producerMayNull)) errors.push('bad-producerMayNull');
  if (typeof obj.reason !== 'string') errors.push('reason-not-string');
  const refCheck = validateRefs(obj.evidenceRefs, pack.refs);
  if (!refCheck.ok) errors.push(refCheck.reason);
  return { ok: errors.length === 0, errors };
}

function aggregateP6(obj, pack) {
  const items = (obj && obj.items) || [];
  const yes = items.filter((i) => i.sensitive === 'yes').map((i) => i.item);
  const unknown = items.filter((i) => i.sensitive === 'unknown').map((i) => i.item);
  const no = items.filter((i) => i.sensitive === 'no').map((i) => i.item);
  const covered = new Set(items.map((i) => i.item));
  for (const item of (pack && pack.items) || []) {
    if (!covered.has(item)) unknown.push(item);
  }
  const aggregate = yes.length ? 'yes' : (unknown.length ? 'unknown' : 'no');
  return { yes, unknown, no, aggregate };
}

function repairMessages(pack, content, errors) {
  const errs = Array.isArray(errors) && errors.length ? errors : ['schema-invalid'];
  return [
    ...buildMessages(pack),
    { role: 'assistant', content: String(content || '').slice(0, 4000) },
    {
      role: 'user',
      content: `上面的输出不符合 schema/引用要求：${errs.join('; ')}。只修复格式与引用，不要改变判定；只输出合法 JSON。`
    }
  ];
}

async function judgePack(pack, transport, opts = {}) {
  const log = [];
  let attempts = 0;
  let last = null;
  let repairUsed = false;
  const maxAttempts = opts.maxAttempts || 2;
  while (attempts < maxAttempts) {
    attempts += 1;
    const messages = attempts === 1 || !last ? buildMessages(pack) : repairMessages(pack, last && last.content, last && last.errors);
    const t0 = Date.now();
    const res = await transport.send({ unitId: pack.id, attempt: attempts, messages, maxTokens: opts.maxTokens || 4096 });
    const wallMs = Date.now() - t0;
    const row = {
      ts: new Date().toISOString(),
      unitId: pack.id,
      kind: pack.kind,
      attempt: attempts,
      transportKind: res.kind,
      model: res.model || transport.model || null,
      promptTokens: (res.usage && res.usage.promptTokens) || 0,
      completionTokens: (res.usage && res.usage.completionTokens) || 0,
      totalTokens: ((res.usage && res.usage.promptTokens) || 0) + ((res.usage && res.usage.completionTokens) || 0),
      wallMs: res.wallMs || wallMs,
      contentHash: res.content ? sha(res.content) : null,
      schemaOk: false,
      refsOk: false
    };
    if (res.kind !== 'ok') {
      row.error = res.kind;
      row.detail = res.detail ? String(res.detail).slice(0, 300) : null;
      log.push(row);
      if (res.kind === 'transport-error' && attempts < maxAttempts && !opts.noRetry) {
        await new Promise((r) => setTimeout(r, 1000 * attempts));
        continue;
      }
      return { ok: false, blocked: true, reason: res.kind, attempts, log };
    }
    let parsed = null;
    let errors = [];
    try {
      parsed = parseJsonContent(res.content);
      const v = pack.kind === 'P6' ? validateP6(parsed, pack) : validateP3(parsed, pack);
      errors = v.errors;
      row.schemaOk = v.ok;
      row.refsOk = v.ok;
    } catch (e) {
      errors = [`parse-error:${String(e.message || e)}`];
    }
    last = { content: res.content, errors };
    row.parsedOk = errors.length === 0;
    if (errors.length) {
      row.schemaErrors = errors.slice(0, 10);
      row.contentPreview = String(res.content || '').slice(0, 400);
    }
    log.push(row);
    if (!errors.length) {
      const agg = pack.kind === 'P6' ? aggregateP6(parsed, pack) : null;
      return { ok: true, parsed, aggregate: agg, attempts, log, repairUsed, usage: res.usage || null, contentHash: row.contentHash };
    }
    if (repairUsed || attempts >= maxAttempts) break;
    repairUsed = true;
  }
  return { ok: false, blocked: false, reason: 'schema-invalid', errors: last && last.errors, attempts, log, repairUsed };
}

function mockResponse(pack) {
  if (pack.kind === 'P6') {
    const items = pack.items.map((item, i) => ({
      item,
      sensitive: /user|account|domain|bundle|udid|imei|location|want/i.test(item) ? 'unknown' : 'no',
      evidenceRef: pack.refs[Math.min(i, pack.refs.length - 1)]
    }));
    return { items, reason: 'mock: 证据不足时按 unknown 处理', evidenceRefs: [pack.refs[0]] };
  }
  return { producerMayNull: 'unknown', reason: 'mock: 单凭窗口无法确认可空性', evidenceRefs: [pack.refs[0]] };
}

function makeMockTransport(packs) {
  const byId = new Map((packs || []).map((p) => [p.id, p]));
  return {
    id: 'mock',
    simulated: true,
    implemented: true,
    model: 'mock',
    keyPresent: () => true,
    async send({ unitId }) {
      const pack = byId.get(unitId);
      return {
        kind: 'ok',
        content: JSON.stringify(mockResponse(pack || { kind: 'P6', items: [], refs: ['E1:L1'] })),
        usage: { promptTokens: 10, completionTokens: 10, cacheHitTokens: 0, cacheMissTokens: 10 },
        usageKnown: true,
        finishReason: 'stop',
        model: 'mock',
        maxTokensSent: 4096,
        wallMs: 1
      };
    }
  };
}

function appendLog(rows, file = LOG_FILE) {
  ensureDir(path.dirname(file));
  const existing = readJsonl(file);
  fs.writeFileSync(file, [...existing, ...rows].map((r) => JSON.stringify(r)).join('\n') + (existing.length + rows.length ? '\n' : ''), 'utf8');
}

async function runBatch(packs, opts = {}) {
  const transport = opts.transport || makeTransport(opts);
  const results = [];
  const allLogs = [];
  if (opts.resultsFile) {
    ensureDir(path.dirname(opts.resultsFile));
    fs.writeFileSync(opts.resultsFile, '', 'utf8');
  }
  for (const pack of packs) {
    const r = await judgePack(pack, transport, opts);
    allLogs.push(...r.log);
    results.push({
      id: pack.id,
      kind: pack.kind,
      claimId: pack.claimId,
      siteKey: pack.siteKey || null,
      simulated: transport.simulated === true,
      ok: r.ok,
      blocked: r.blocked === true,
      reason: r.reason || null,
      errors: r.errors || null,
      attempts: r.attempts,
      repairUsed: r.repairUsed === true,
      parsed: r.parsed || null,
      aggregate: r.aggregate || null,
      usage: r.usage || null,
      contentHash: r.contentHash || null
    });
    if (opts.log !== false) appendLog(r.log, opts.logFile);
    if (opts.resultsFile) {
      appendLog([results[results.length - 1]], opts.resultsFile);
    }
    if (opts.onResult) opts.onResult(results[results.length - 1]);
  }
  const ok = results.filter((r) => r.ok);
  const summary = {
    generatedAt: new Date().toISOString(),
    simulated: transport.simulated === true,
    packs: packs.length,
    ok: ok.length,
    blocked: results.filter((r) => r.blocked).length,
    schemaFail: results.filter((r) => !r.ok && !r.blocked).length,
    schemaSuccessRate: packs.length ? Number((ok.length / packs.length).toFixed(3)) : 0,
    refsOkRate: packs.length ? Number((ok.length / packs.length).toFixed(3)) : 0,
    promptTokens: results.reduce((n, r) => n + ((r.usage && r.usage.promptTokens) || 0), 0),
    completionTokens: results.reduce((n, r) => n + ((r.usage && r.usage.completionTokens) || 0), 0),
    attempts: results.reduce((n, r) => n + (r.attempts || 0), 0),
    results
  };
  summary.totalTokens = summary.promptTokens + summary.completionTokens;
  return { results, summary, log: allLogs, transport };
}

/** 选择 L4b 包：只选确定性 O6 未闭合的 site；不足则补弱命中 finding。 */
function selectP6L4bClaims(claims, verdicts, l1, n = 10) {
  const byClaim = new Map(verdicts.map((v) => [v.claimId, v]));
  const hasItems = (c) => {
    if (!l1) return true;
    const site = l1.minerSite(c.entry.siteKey);
    const slice = l1.minerSlice(c.entry.siteKey);
    const writes = ((site && site.payloadWrites) || (slice && slice.writes) || [])
      .filter((w) => String(w.setter || '').toLowerCase() !== 'setaction' && String(w.key || '') !== 'SetAction');
    return writes.length > 0;
  };
  const osResidual = claims.filter((c) => {
    const v = byClaim.get(c.claimId);
    const o6 = v && v.obligations.find((o) => o.id === 'O6');
    const o5 = v && v.obligations.find((o) => o.id === 'O5');
    const o10 = v && v.obligations.find((o) => o.id === 'O10');
    return c.group === 'os-account'
      && hasItems(c)
      && ((o6 && o6.status === 'unproven') || (o5 && o5.status === 'unproven') || (o10 && o10.status === 'unproven'));
  });
  const osRestricted = claims.filter((c) => {
    const v = byClaim.get(c.claimId);
    const o6 = v && v.obligations.find((o) => o.id === 'O6');
    const o3 = v && v.obligations.find((o) => o.id === 'O3');
    return c.group === 'os-account' && o3 && o3.status === 'disproven' && o6 && o6.status === 'unproven' && hasItems(c);
  });
  const weakFindings = claims.filter((c) => {
    const v = byClaim.get(c.claimId);
    const o6 = v && v.obligations.find((o) => o.id === 'O6');
    return c.group === 'miner-finding' && o6 && o6.weak === true && hasItems(c);
  });
  const primaryOs = [...new Map([...osResidual, ...osRestricted].map((c) => [c.claimId, c])).values()];
  const selected = [];
  const seen = new Set();
  for (const c of [...primaryOs.slice(0, Math.max(0, n - 5)), ...weakFindings.slice(0, 5)]) {
    if (seen.has(c.claimId)) continue;
    seen.add(c.claimId);
    selected.push(c);
  }
  for (const c of [...claims.filter((x) => x.group === 'os-account'), ...weakFindings, ...claims]) {
    if (selected.length >= n) break;
    if (seen.has(c.claimId) || !hasItems(c)) continue;
    seen.add(c.claimId);
    selected.push(c);
  }
  return selected.slice(0, n);
}

function selectP3L4bClaims(claims, verdicts, n = 5) {
  const byClaim = new Map(verdicts.map((v) => [v.claimId, v]));
  const unproven = claims.filter((c) => {
    const v = byClaim.get(c.claimId);
    const o2 = v && v.obligations.find((o) => o.id === 'O2');
    return o2 && o2.status === 'unproven';
  });
  const proven = claims.filter((c) => {
    const v = byClaim.get(c.claimId);
    const o2 = v && v.obligations.find((o) => o.id === 'O2');
    return o2 && o2.status === 'proven';
  });
  return [...unproven.slice(0, 3), ...proven.slice(0, Math.max(0, n - Math.min(3, unproven.length)))].slice(0, n);
}

function applyP6L4bToVerdict(verdict, l4bResult) {
  const out = { ...verdict, obligations: verdict.obligations.map((o) => ({ ...o, evidence: { ...(o.evidence || {}) } })) };
  const o6 = out.obligations.find((o) => o.id === 'O6');
  if (!o6 || !l4bResult || !l4bResult.ok) return out;
  const agg = l4bResult.aggregate;
  if (!agg) return out;
  const observation = {
    aggregate: agg.aggregate, yes: agg.yes, unknown: agg.unknown, no: agg.no,
    contentHash: l4bResult.contentHash,
    scope: 'observation-only',
    note: 'P6-9 public-api-residual 本轮不参与 verdict；仅记录 item 级语义标注'
  };
  if (o6.status === 'unproven') {
    o6.evidence = { ...(o6.evidence || {}), l4b: observation };
    if (agg.aggregate === 'yes') {
      o6.status = 'proven';
      o6.weak = false;
      o6.reason = 'l4b-item-hit';
    } else if (agg.aggregate === 'no') {
      o6.status = 'disproven';
      o6.reason = 'l4b-no-sensitive-item';
    }
  } else {
    // 已由 miner C1–C4 确定性闭合的 claim：L4b 只做 observation，
    // 不改 O6 状态，避免把 public-overlap（本轮显式不做）误升成 verdict。
    out.l4bObservation = observation;
  }
  return out;
}

module.exports = {
  L4B_DIR,
  LOG_FILE,
  P6_SCHEMA_HINT,
  P3_SCHEMA_HINT,
  buildP6Pack,
  buildP3Pack,
  buildMessages,
  validateP6,
  validateP3,
  aggregateP6,
  judgePack,
  runBatch,
  makeTransport,
  makeMockTransport,
  mockResponse,
  loadConfig,
  selectP6L4bClaims,
  selectP3L4bClaims,
  applyP6L4bToVerdict,
  appendLog,
  parseJsonContent,
  makeFetchIPv4,
  sha
};
