'use strict';

/**
 * spec-obligations.js —— 把 12 条 concrete spec 自动落成可机械检查的义务。
 *
 * 输入：out/specmine/specs.jsonl + OpenHarmony 源码函数体
 * 输出：out/obligations/obligations.jsonl（每条 spec 的 obligations；含 literal→regex 与校验）
 *
 * 约束：模型只能从固定 kind 里选，片段必须是源码里的精确子串；不能匹配的片段被标 invalid，
 * 不作为 violation 交给 prover。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const SRC = path.join(ROOT, '..', 'OpenHarmony');
const TOOL = path.join(ROOT, '..', 'oh6-vuln-agent');
const OUT = path.join(ROOT, 'out', 'obligations');

const { makeHttpTransport } = require(path.join(TOOL, 'src', 'llm', 'http.js'));
const { findFunction } = require(path.join(ROOT, 'lib', 'prover.js'));
const cfg = JSON.parse(fs.readFileSync(path.join(TOOL, 'config', 'llm.json'), 'utf8'));

const transport = makeHttpTransport({
  baseUrl: cfg.baseUrl,
  model: cfg.model,
  apiKeyEnv: cfg.apiKeyEnv,
  timeoutMs: 300000,
  maxTokensPerRequest: 8192,
  requestExtra: cfg.requestExtra || {},
  responseFormat: cfg.responseFormat === undefined ? undefined : cfg.responseFormat,
  extraHeaders: { ...(cfg.extraHeaders || {}), connection: 'close' }
});
const MAX_TOKENS = Number((process.argv.find((a) => a.startsWith('--max-tokens=')) || '').split('=')[1] || 8192);

const KINDS = new Set([
  'guard-before-sink',
  'lock-acquire-before-sink',
  'lock-release-on-return',
  'existence-check-before-mutation',
  'guard-branch-exits'
]);

function ensureDir(d) { fs.mkdirSync(d, { recursive: true }); }
function readJsonl(file) {
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, 'utf8').split(/\r?\n/).filter(Boolean).map((l) => JSON.parse(l));
}
function writeJsonl(file, rows) {
  ensureDir(path.dirname(file));
  fs.writeFileSync(file, rows.map((r) => JSON.stringify(r)).join('\n') + (rows.length ? '\n' : ''), 'utf8');
}
function sha(s) { return require('crypto').createHash('sha256').update(String(s), 'utf8').digest('hex'); }
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
function parseJsonContent(text) {
  let s = String(text == null ? '' : text).trim();
  s = s.replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/i, '').trim();
  const a = s.indexOf('{');
  const b = s.lastIndexOf('}');
  if (a >= 0 && b > a) s = s.slice(a, b + 1);
  return JSON.parse(s);
}
async function callJson({ unitId, messages, attempts = 3 }) {
  let last = null;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    const res = await transport.send({ unitId, attempt, messages, maxTokens: MAX_TOKENS });
    if (res.kind === 'ok') {
      try { return { ok: true, parsed: parseJsonContent(res.content), usage: res.usage, wallMs: res.wallMs, attempts: attempt, contentHash: sha(res.content) }; }
      catch (e) { return { ok: false, kind: 'parse-failed', error: String((e && e.message) || e), usage: res.usage, wallMs: res.wallMs, attempts: attempt }; }
    }
    last = { ok: false, kind: res.kind, error: res.reason || res.detail || null, usage: res.usage || null, wallMs: res.wallMs || null, attempts: attempt };
    if (res.kind !== 'transport-error') return last;
    if (attempt < attempts) await sleep(2000 * attempt);
  }
  return last;
}

function escapeRe(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
/** 精确子串 → 允许空白差异的正则 */
function literalToRegex(s) {
  return escapeRe(String(s).trim()).split(/\s+/).join('\\s*');
}
function identifiers(s) {
  return [...new Set(String(s || '').match(/[A-Za-z_]\w{3,}/g) || [])];
}
function identifiersInBody(body) {
  const set = new Set(body.match(/[A-Za-z_]\w{3,}/g) || []);
  return set;
}
function normalizeObligation(raw, body, specId, index) {
  const id = raw.id || `O${index + 1}`;
  const kind = raw.kind;
  if (!KINDS.has(kind)) return { id, kind, status: 'invalid', reason: 'unsupported-kind', raw };
  const conf = raw.confidence || 'medium';
  const base = { id, kind, text: raw.text || '', confidence: conf, rationale: raw.rationale || null, raw };
  const bodyIds = identifiersInBody(body);
  const req = (field) => {
    if (typeof raw[field] !== 'string' || !raw[field].trim()) return null;
    const first = raw[field].split(/\r?\n/).map((x) => x.trim()).filter(Boolean)[0];
    if (raw[field].includes('\n')) base.normalizedFromMultiline = true;
    return first || null;
  };
  const setRe = (field) => (req(field) ? { [field]: literalToRegex(req(field)) } : {});

  if (kind === 'guard-before-sink') {
    const sink = req('sink');
    const guard = req('guard');
    if (!sink) return { ...base, status: 'invalid', reason: 'missing-sink' };
    if (!new RegExp(literalToRegex(sink)).test(body)) return { ...base, status: 'invalid', reason: 'sink-not-in-body', literal: { sink, guard } };
    const guardIds = identifiers(guard);
    if (guard && guardIds.length && !guardIds.some((x) => bodyIds.has(x))) return { ...base, status: 'invalid', reason: 'guard-identifier-not-in-body', literal: { sink, guard } };
    return { ...base, status: 'valid', requireExit: raw.requireExit === true, guard: guard ? literalToRegex(guard) : null, sink: literalToRegex(sink), literal: { guard, sink } };
  }
  if (kind === 'lock-acquire-before-sink') {
    const acquire = req('acquire'); const sink = req('sink');
    if (!acquire || !sink) return { ...base, status: 'invalid', reason: 'missing-acquire-or-sink' };
    if (!new RegExp(literalToRegex(acquire)).test(body)) return { ...base, status: 'invalid', reason: 'acquire-not-in-body', literal: { acquire, sink } };
    if (!new RegExp(literalToRegex(sink)).test(body)) return { ...base, status: 'invalid', reason: 'sink-not-in-body', literal: { acquire, sink } };
    return { ...base, status: 'valid', acquire: literalToRegex(acquire), sink: literalToRegex(sink), literal: { acquire, sink } };
  }
  if (kind === 'lock-release-on-return') {
    const acquire = req('acquire'); const release = req('release');
    if (!acquire || !release) return { ...base, status: 'invalid', reason: 'missing-acquire-or-release' };
    if (!new RegExp(literalToRegex(acquire)).test(body)) return { ...base, status: 'invalid', reason: 'acquire-not-in-body', literal: { acquire, release } };
    return { ...base, status: 'valid', acquire: literalToRegex(acquire), release: literalToRegex(release), literal: { acquire, release } };
  }
  if (kind === 'existence-check-before-mutation') {
    const mutation = req('mutation'); const existence = req('existence'); const notFound = req('notFound');
    if (!mutation) return { ...base, status: 'invalid', reason: 'missing-mutation' };
    if (!notFound) return { ...base, status: 'invalid', reason: 'missing-notFound' };
    if (!new RegExp(literalToRegex(mutation)).test(body)) return { ...base, status: 'invalid', reason: 'mutation-not-in-body', literal: { existence, mutation, notFound } };
    const exIds = identifiers(existence);
    if (existence && exIds.length && !exIds.some((x) => bodyIds.has(x))) return { ...base, status: 'invalid', reason: 'existence-identifier-not-in-body', literal: { existence, mutation, notFound } };
    return { ...base, status: 'valid', existence: existence ? literalToRegex(existence) : null, mutation: literalToRegex(mutation), notFound: notFound ? literalToRegex(notFound) : null, literal: { existence, mutation, notFound } };
  }
  // guard-branch-exits
  const guard = req('guard'); const exit = req('exit');
  if (!guard || !exit) return { ...base, status: 'invalid', reason: 'missing-guard-or-exit' };
  if (!new RegExp(literalToRegex(guard)).test(body)) return { ...base, status: 'invalid', reason: 'guard-not-in-body', literal: { guard, exit } };
  return { ...base, status: 'valid', guard: literalToRegex(guard), exit: literalToRegex(exit), literal: { guard, exit } };
}

function buildMessages(spec, body) {
  const system = [
    '你是 audit spec 的义务化器。给你一条已实例化的规范和一个候选函数体。',
    '把规范落成 1–4 条可机械检查的义务，只能使用这些 kind：',
    '- guard-before-sink：某个判空/检查片段必须出现在某个解引用/调用片段之前；字段 guard, sink, requireExit(boolean)',
    '- lock-acquire-before-sink：某个加锁片段必须出现在被保护操作之前；字段 acquire, sink',
    '- lock-release-on-return：取得锁后每个 return 前必须释放；字段 acquire, release',
    '- existence-check-before-mutation：修改集合前必须先检查目标存在，找不到时返回错误；字段 existence, mutation, notFound',
    '- guard-branch-exits：某个判空/检查分支必须 return/continue/break；字段 guard, exit',
    '硬要求：',
    '1) guard/acquire/sink/release/existence/mutation/notFound/exit 必须是函数体里的**精确代码子串**，不要写正则、不要改写空白；',
    '2) 尽量短且唯一；不要编造函数体里没有的片段；',
    '3) 只写你能从给出的函数体直接核对的义务，不要补充外部知识；',
    '4) 每条给 confidence=high|medium|low 与 rationale（≤1 句）。',
    '只输出 JSON：{"obligations":[{id,kind,text,guard?,sink?,acquire?,release?,existence?,mutation?,notFound?,exit?,requireExit?,confidence,rationale}]}'
  ].join('\n');
  const user = [
    `specId: ${spec.specId}`,
    `family: ${spec.family}`,
    `behavior: ${spec.behavior}`,
    `constraint: ${spec.constraint}`,
    `instantiatedConstraint: ${spec.instantiatedConstraint}`,
    `function: ${spec.candidate.repo}/${spec.candidate.file} ${spec.candidate.name}`,
    '函数体：',
    body.slice(0, 8000)
  ].join('\n');
  return [{ role: 'system', content: system }, { role: 'user', content: user }];
}

async function main() {
  ensureDir(OUT);
  if (!transport.keyPresent()) { process.stderr.write(`缺密钥：${cfg.apiKeyEnv}\n`); process.exit(2); }
  const specs = readJsonl(path.join(ROOT, 'out', 'specmine', 'specs.jsonl'))
    .slice(0, Number((process.argv.find((a) => a.startsWith('--limit=')) || '').split('=')[1] || 0) || undefined);
  const file = path.join(OUT, 'obligations.jsonl');
  const existing = new Map(readJsonl(file).map((r) => [r.specId, r]));
  const onlyArg = (process.argv.find((a) => a.startsWith('--ids=')) || '').split('=')[1];
  const ONLY = onlyArg ? new Set(onlyArg.split(',').map((s) => s.trim()).filter(Boolean)) : null;
  const byId = new Map(existing);
  for (const spec of specs) {
    if (ONLY && !ONLY.has(spec.specId)) continue;
    if (byId.has(spec.specId) && byId.get(spec.specId).ok) continue;
    const abs = path.join(SRC, spec.candidate.repo, spec.candidate.file);
    if (!fs.existsSync(abs)) { byId.set(spec.specId, { specId: spec.specId, ok: false, error: 'file-not-found', obligations: [] }); writeJsonl(file, [...byId.values()]); continue; }
    const text = fs.readFileSync(abs, 'utf8');
    const fn = findFunction(text, spec.candidate.name);
    if (!fn) { byId.set(spec.specId, { specId: spec.specId, ok: false, error: 'function-not-found', obligations: [] }); writeJsonl(file, [...byId.values()]); continue; }
    process.stdout.write(`[obligations ${spec.specId}] ... `);
    const r = await callJson({ unitId: `obligations:${spec.specId}`, messages: buildMessages(spec, fn.body), attempts: 3 });
    const rawObs = r.ok && r.parsed && Array.isArray(r.parsed.obligations) ? r.parsed.obligations : [];
    const obs = rawObs.slice(0, 5).map((o, i) => normalizeObligation(o, fn.body, spec.specId, i));
    const rec = {
      specId: spec.specId,
      seedId: spec.seedId,
      family: spec.family,
      title: spec.instantiatedConstraint,
      repo: spec.candidate.repo,
      file: spec.candidate.file,
      functionName: spec.candidate.name,
      functionRange: { start: fn.startLine, end: fn.endLine },
      ok: r.ok && obs.filter((o) => o.status === 'valid').length > 0,
      error: r.ok ? (obs.filter((o) => o.status === 'valid').length ? null : 'no-valid-obligations') : (r.error || r.kind),
      obligations: obs,
      call: { usage: r.usage || null, wallMs: r.wallMs || null, attempts: r.attempts || null, contentHash: r.contentHash || null }
    };
    byId.set(spec.specId, rec);
    writeJsonl(file, [...byId.values()]);
    process.stdout.write(`${rec.ok ? 'ok' : 'FAIL'} valid=${obs.filter((o) => o.status === 'valid').length}/${obs.length} ${r.usage ? `${r.usage.promptTokens}+${r.usage.completionTokens}t` : ''}\n`);
  }
  const results = [...byId.values()];
  process.stdout.write(`obligations: ${results.filter((r) => r.ok).length}/${results.length} specs with valid obligations\n`);
}

main().catch((e) => { process.stderr.write(`fatal: ${e && e.stack ? e.stack : e}\n`); process.exit(1); });
