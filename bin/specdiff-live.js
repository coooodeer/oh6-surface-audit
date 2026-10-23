'use strict';

/**
 * specdiff-live.js —— 用现有 oh6-vuln-agent 的 HTTP 运输层，对 spec 差分做 live 模型判定。
 *
 * 输入：out/specdiff/prompts/<id>.json（由 specdiff.js 生成，含 pre/post 区域）
 * 输出：out/specdiff/live/{results.jsonl,summary.json,ledger.jsonl}
 *
 * 用法：
 *   node bin/specdiff-live.js --ids INV-HIST-2c307697,INV-HIST-5af29df4,INV-HIST-99d126b9
 *   node bin/specdiff-live.js --all
 *
 * 密钥：只从 process.env[config.llm.apiKeyEnv] 读；本脚本不写 key。
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.resolve(__dirname, '..');
const TOOL = path.resolve(ROOT, '..', 'oh6-vuln-agent');
const OUT = path.join(ROOT, 'out', 'specdiff', 'live');
const PROMPTS = path.join(ROOT, 'out', 'specdiff', 'prompts');

const { makeHttpTransport } = require(path.join(TOOL, 'src', 'llm', 'http.js'));
const cfg = JSON.parse(fs.readFileSync(path.join(TOOL, 'config', 'llm.json'), 'utf8'));

const PILOT = ['INV-HIST-2c307697', 'INV-HIST-5af29df4', 'INV-HIST-99d126b9'];

function sha(s) {
  return crypto.createHash('sha256').update(String(s), 'utf8').digest('hex');
}
function ensureDir(d) { fs.mkdirSync(d, { recursive: true }); }
function readJsonl(file) {
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, 'utf8').split(/\r?\n/).filter(Boolean).map((l) => JSON.parse(l));
}
function writeJsonl(file, rows) {
  ensureDir(path.dirname(file));
  fs.writeFileSync(file, rows.map((r) => JSON.stringify(r)).join('\n') + (rows.length ? '\n' : ''), 'utf8');
}
function writeJson(file, obj) {
  ensureDir(path.dirname(file));
  fs.writeFileSync(file, JSON.stringify(obj, null, 2) + '\n', 'utf8');
}

function parseJsonContent(text) {
  let s = String(text == null ? '' : text).trim();
  s = s.replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/i, '').trim();
  const a = s.indexOf('{');
  const b = s.lastIndexOf('}');
  if (a >= 0 && b > a) s = s.slice(a, b + 1);
  return JSON.parse(s);
}

function buildMessages(p) {
  const system = [
    '你是安全补丁规范验证器。给定一条候选规范（entity + constraint）和同一函数在补丁前/后的代码，',
    '判断两件事：',
    '1) preViolates：补丁前代码是否违反该约束；',
    '2) postSatisfies：补丁后代码是否满足该约束。',
    '只依据给出的规范与代码，不引入外部知识；无法判断时也要给出布尔判断并在 reason 说明依据。',
    '严格输出 JSON 对象，不要 Markdown：',
    '{"preViolates": true|false, "postSatisfies": true|false, "reason": "≤2 句，点名代码里的标识符"}'
  ].join('\n');
  const user = [
    `候选规范：${JSON.stringify(p.spec)}`,
    '',
    `补丁前（${p.pre.repo}@${p.pre.sha} ${p.pre.file}:${p.pre.line}）：`,
    p.pre.region.text,
    '',
    `补丁后（${p.post.repo}@${p.post.sha} ${p.post.file}:${p.post.line}）：`,
    p.post.region.text
  ].join('\n');
  return [
    { role: 'system', content: system },
    { role: 'user', content: user }
  ];
}

async function callOne(transport, prompt, maxTokens) {
  const messages = buildMessages(prompt);
  let last = null;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    let res = await transport.send({ unitId: prompt.id, attempt, messages, maxTokens });
    // 输出截断/空内容时，允许一次更大的输出重试（不是语义重试）
    if (res.kind === 'ok' && (!res.content || res.finishReason === 'length') && maxTokens < 8192) {
      const retry = await transport.send({ unitId: prompt.id, attempt: attempt + 1, messages, maxTokens: 8192 });
      if (retry.kind === 'ok' && retry.content) {
        retry.retriedForLength = true;
        res = retry;
      }
    }
    res.transportAttempts = attempt;
    if (res.kind !== 'transport-error') return res;
    last = res;
    // 网络瞬断（实测 Windows/undici 偶发 fetch failed）重试；鉴权/参数错误不重试
    if (attempt < 3) await new Promise((r) => setTimeout(r, 2000 * attempt));
  }
  return last;
}

async function main() {
  const args = process.argv.slice(2);
  const idsArg = args.find((a) => a.startsWith('--ids='));
  const all = args.includes('--all');
  const maxTokens = Number((args.find((a) => a.startsWith('--max-tokens=')) || '').split('=')[1] || 4096);
  const ids = all
    ? fs.readdirSync(PROMPTS).filter((f) => f.endsWith('.json')).map((f) => f.replace(/\.json$/, '')).sort()
    : idsArg
      ? idsArg.split('=')[1].split(',').map((s) => s.trim()).filter(Boolean)
      : PILOT;
  if (args.includes('--missing')) {
    const done = new Set(readJsonl(path.join(OUT, 'results.jsonl')).filter((r) => r.ok).map((r) => r.id));
    for (let i = ids.length - 1; i >= 0; i -= 1) if (done.has(ids[i])) ids.splice(i, 1);
  }

  if (!transport.keyPresent()) {
    process.stderr.write(`缺密钥：${cfg.apiKeyEnv}（行内注入后再跑）\n`);
    process.exit(2);
  }

  const results = [];
  const ledger = [];
  const resultsFile = path.join(OUT, 'results.jsonl');
  const ledgerFile = path.join(OUT, 'ledger.jsonl');
  const existingResults = readJsonl(resultsFile);
  const existingLedger = readJsonl(ledgerFile);
  for (const id of ids) {
    const file = path.join(PROMPTS, `${id}.json`);
    if (!fs.existsSync(file)) {
      results.push({ id, kind: 'missing-prompt', ok: false });
      continue;
    }
    const prompt = JSON.parse(fs.readFileSync(file, 'utf8'));
    const t0 = Date.now();
    process.stdout.write(`[${id}] calling ... `);
    const res = await callOne(transport, prompt, maxTokens);
    const wallMs = Date.now() - t0;
    const rec = {
      id,
      family: prompt.spec.family,
      entity: prompt.spec.entity,
      witness: prompt.spec.witness,
      kind: res.kind,
      ok: false,
      model: res.model || cfg.model,
      maxTokensSent: res.maxTokensSent || null,
      finishReason: res.finishReason || null,
      usage: res.usage || null,
      usageKnown: res.usageKnown === true,
      wallMs: res.wallMs || wallMs,
      contentHash: res.content ? sha(res.content) : null,
      parsed: null,
      parseError: null,
      reason: res.reason || null,
      detail: res.detail ? String(res.detail).slice(0, 500) : null,
      retriedForLength: res.retriedForLength === true,
      transportAttempts: res.transportAttempts || 1
    };
    if (res.kind === 'ok') {
      try {
        const parsed = parseJsonContent(res.content);
        const ok = typeof parsed.preViolates === 'boolean'
          && typeof parsed.postSatisfies === 'boolean'
          && typeof parsed.reason === 'string';
        rec.parsed = parsed;
        rec.ok = ok;
        if (!ok) rec.parseError = 'schema-mismatch';
      } catch (e) {
        rec.parseError = String((e && e.message) || e);
        rec.contentPreview = String(res.content || '').slice(0, 500);
      }
    }
    results.push(rec);
    ledger.push({
      ts: new Date().toISOString(),
      id,
      kind: res.kind,
      model: rec.model,
      maxTokensSent: rec.maxTokensSent,
      finishReason: rec.finishReason,
      usage: rec.usage,
      wallMs: rec.wallMs,
      contentHash: rec.contentHash
    });
    process.stdout.write(`${res.kind}${rec.ok ? ' ok' : ' invalid'} ${rec.usage ? `${rec.usage.promptTokens}+${rec.usage.completionTokens}t` : ''}\n`);
    // 逐条落盘：即使进程在退出时触发 Windows/undici 断言，已完成的结果也不会丢
    writeJsonl(resultsFile, existingResults.filter((r) => !ids.includes(r.id)).concat(results));
    writeJsonl(ledgerFile, existingLedger.concat(ledger));
  }

  const allResults = existingResults.filter((r) => !ids.includes(r.id)).concat(results);
  const okRows = results.filter((r) => r.ok);
  const summary = {
    generatedAt: new Date().toISOString(),
    endpoint: transport.endpoint,
    model: cfg.model,
    requested: ids.length,
    ok: okRows.length,
    failed: results.filter((r) => !r.ok).length,
    totalPromptTokens: okRows.reduce((a, r) => a + ((r.usage && r.usage.promptTokens) || 0), 0),
    totalCompletionTokens: okRows.reduce((a, r) => a + ((r.usage && r.usage.completionTokens) || 0), 0),
    accumulated: {
      rows: allResults.length,
      ok: allResults.filter((r) => r.ok).length,
      promptTokens: allResults.reduce((a, r) => a + ((r.usage && r.usage.promptTokens) || 0), 0),
      completionTokens: allResults.reduce((a, r) => a + ((r.usage && r.usage.completionTokens) || 0), 0)
    },
    results: allResults.map((r) => ({
      id: r.id, family: r.family, kind: r.kind, ok: r.ok,
      preViolates: r.parsed ? r.parsed.preViolates : null,
      postSatisfies: r.parsed ? r.parsed.postSatisfies : null,
      reason: r.parsed ? r.parsed.reason : null,
      parseError: r.parseError
    }))
  };
  writeJsonl(resultsFile, allResults);
  writeJsonl(ledgerFile, existingLedger.concat(ledger));
  writeJson(path.join(OUT, 'summary.json'), summary);
  process.stdout.write(`done: ${summary.ok}/${summary.requested} parsed, ${summary.totalPromptTokens}+${summary.totalCompletionTokens} tokens\n`);
  process.exit(summary.failed ? 3 : 0);
}

const transport = makeHttpTransport({
  baseUrl: cfg.baseUrl,
  model: cfg.model,
  apiKeyEnv: cfg.apiKeyEnv,
  timeoutMs: Number((process.argv.find((a) => a.startsWith('--timeout-ms=')) || '').split('=')[1] || cfg.timeoutMs),
  maxTokensPerRequest: 4096,
  requestExtra: cfg.requestExtra || {},
  responseFormat: cfg.responseFormat === undefined ? undefined : cfg.responseFormat,
  // 大 prompt/长响应后 undici keep-alive 连接可能失效；close 让每次请求走新连接
  extraHeaders: { ...(cfg.extraHeaders || {}), connection: 'close' }
});

main().catch((e) => {
  process.stderr.write(`fatal: ${e && e.stack ? e.stack : e}\n`);
  process.exit(1);
});
