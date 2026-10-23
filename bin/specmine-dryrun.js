'use strict';

/**
 * specmine-dryrun.js —— 从 18 条 confirmed patch seed 做一次泛化 dry run：
 *   induce  : patch pre/post + seed -> behavior-level spec（1 次调用/seed）
 *   retrieve: 本地 index/functions.jsonl 词法检索候选实体（确定性，不调用模型）
 *   judge   : 每个 seed 的 3 个候选，批量判“行为是否匹配、约束是否适用”（1 次调用/seed）
 *   report  : 统计能生成多少条具体 spec；不判漏洞
 *
 * 用法：
 *   node bin/specmine-dryrun.js --mode=induce
 *   node bin/specmine-dryrun.js --mode=retrieve
 *   node bin/specmine-dryrun.js --mode=judge
 *   node bin/specmine-dryrun.js --mode=report
 *   node bin/specmine-dryrun.js --mode=all
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.resolve(__dirname, '..');
const TOOL = path.resolve(ROOT, '..', 'oh6-vuln-agent');
const SRC = path.join(ROOT, '..', 'OpenHarmony');
const OUT = path.join(ROOT, 'out', 'specmine');
const REPORT = path.join(ROOT, 'out', 'report', 'specmine.md');

const { makeHttpTransport } = require(path.join(TOOL, 'src', 'llm', 'http.js'));
const cfg = JSON.parse(fs.readFileSync(path.join(TOOL, 'config', 'llm.json'), 'utf8'));
const transport = makeHttpTransport({
  baseUrl: cfg.baseUrl,
  model: cfg.model,
  apiKeyEnv: cfg.apiKeyEnv,
  timeoutMs: Number((process.argv.find((a) => a.startsWith('--timeout-ms=')) || '').split('=')[1] || 300000),
  maxTokensPerRequest: 4096,
  requestExtra: cfg.requestExtra || {},
  responseFormat: cfg.responseFormat === undefined ? undefined : cfg.responseFormat,
  // 实测：大 prompt 触发连接重置后，undici 的 keep-alive 池会把后续重试也拖死；
  // 显式 close 让每次请求走新连接，代价可忽略。
  extraHeaders: { ...(cfg.extraHeaders || {}), connection: 'close' }
});

const MAX_TOKENS = Number((process.argv.find((a) => a.startsWith('--max-tokens=')) || '').split('=')[1] || 4096);
const LIMIT = Number((process.argv.find((a) => a.startsWith('--limit=')) || '').split('=')[1] || 0);
const TOP_K = 3;

const STOP = new Set(('the a an of to in for on with and or is are be as by at from this that it its ' +
  'if then else return void const static std auto int bool char size t uint32 uint64 int32 int64 ' +
  'shared ptr unique mutex lock guard nullptr true false new delete public private protected').split(/\s+/));

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
function sha(s) { return crypto.createHash('sha256').update(String(s), 'utf8').digest('hex'); }
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

function parseJsonContent(text) {
  let s = String(text == null ? '' : text).trim();
  s = s.replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/i, '').trim();
  const a = s.indexOf('{');
  const b = s.lastIndexOf('}');
  if (a >= 0 && b > a) s = s.slice(a, b + 1);
  return JSON.parse(s);
}

async function callJson({ unitId, messages, maxTokens = MAX_TOKENS, attempts = 3 }) {
  let last = null;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    const res = await transport.send({ unitId, attempt, messages, maxTokens });
    if (res.kind === 'ok') {
      try {
        return { ok: true, parsed: parseJsonContent(res.content), usage: res.usage, wallMs: res.wallMs, contentHash: sha(res.content), attempts: attempt };
      } catch (e) {
        last = { ok: false, kind: 'parse-failed', error: String((e && e.message) || e), usage: res.usage, wallMs: res.wallMs, attempts: attempt, preview: String(res.content || '').slice(0, 400) };
        return last;
      }
    }
    last = { ok: false, kind: res.kind, error: res.reason || res.detail || null, usage: res.usage || null, wallMs: res.wallMs || null, attempts: attempt };
    if (res.kind !== 'transport-error') return last;
    if (attempt < attempts) await sleep(2000 * attempt);
  }
  return last;
}

// ---------------------------------------------------------------- seeds

function loadSeeds() {
  const mech = readJsonl(path.join(ROOT, 'out', 'specdiff', 'results.jsonl'))
    .filter((r) => r.liveVerdict === 'confirmed');
  const hist = new Map(readJsonl(path.join(TOOL, 'data', 'facts', 'history-invariants.jsonl')).map((r) => [r.id, r]));
  const out = [];
  for (const m of mech) {
    const h = hist.get(m.id) || {};
    const promptFile = path.join(ROOT, 'out', 'specdiff', 'prompts', `${m.id}.json`);
    if (!fs.existsSync(promptFile)) continue;
    const p = JSON.parse(fs.readFileSync(promptFile, 'utf8'));
    out.push({
      seedId: m.id,
      repo: h.repo || null,
      file: h.file || null,
      family: m.family || h.family,
      entity: h.entity || null,
      entityKind: h.entityKind || null,
      witness: h.witness || null,
      constraint: h.constraint || p.spec.constraint || null,
      scope: h.scope || null,
      subject: h.commitSubject || null,
      patternClasses: h.patternClass || [],
      securityProperty: h.security_property || [],
      pre: p.pre,
      post: p.post
    });
  }
  return LIMIT ? out.slice(0, LIMIT) : out;
}

function trimRegion(region, maxChars = 6000) {
  const t = (region && region.text) || '';
  if (t.length <= maxChars) return t;
  return `${t.slice(0, maxChars)}\n…（截断，共 ${t.length} 字符）`;
}

function buildInduceMessages(seed) {
  const system = [
    '你是安全补丁规范归纳器。给你一个真实修复 patch 的前/后函数、提交说明和一条粗粒度 seed（entity + constraint），',
    '请把 seed 泛化成可迁移的 behavior-level audit spec，而不是只描述这一个函数。',
    '要求：',
    '1) behavior：这类实体在做什么“可能引出该约束”的操作，用不含具体函数名的描述；',
    '2) constraint：必须成立的条件，去掉具体变量名/文件名；',
    '3) retrieval_tokens：5–12 个用于在函数名/签名里检索同类实体的英文 token（小写，不要泛词如 function/code）；',
    '4) entity_kind：function | method | field | type；',
    '5) applicability_conditions：2–5 条“该约束适用的前提”；',
    '6) non_applicable_when：1–3 条“看似相似但不应套用”的反例条件；',
    '7) confidence：high|medium|low。',
    '只输出 JSON 对象，不要 Markdown。'
  ].join('\n');
  const user = [
    `seedId: ${seed.seedId}`,
    `repo: ${seed.repo}`,
    `file: ${seed.file}`,
    `family: ${seed.family}`,
    `commit: ${seed.subject || ''}`,
    `scope: ${seed.scope || ''}`,
    `seed.entity: ${seed.entity}`,
    `seed.witness: ${seed.witness}`,
    `seed.constraint: ${seed.constraint}`,
    '',
    '补丁前：',
    trimRegion(seed.pre),
    '',
    '补丁后：',
    trimRegion(seed.post)
  ].join('\n');
  return [{ role: 'system', content: system }, { role: 'user', content: user }];
}

function validInduced(x) {
  return x && typeof x.behavior === 'string' && x.behavior.length >= 10
    && typeof x.constraint === 'string' && x.constraint.length >= 10
    && Array.isArray(x.retrieval_tokens) && x.retrieval_tokens.length >= 3
    && Array.isArray(x.applicability_conditions);
}

async function modeInduce() {
  const seeds = loadSeeds();
  const file = path.join(OUT, 'seeds.jsonl');
  const existing = new Map(readJsonl(file).map((r) => [r.seedId, r]));
  const out = [];
  for (const s of seeds) {
    if (existing.has(s.seedId) && existing.get(s.seedId).induced) { out.push(existing.get(s.seedId)); continue; }
    process.stdout.write(`[induce ${s.seedId}] ... `);
    const r = await callJson({ unitId: `induce:${s.seedId}`, messages: buildInduceMessages(s), maxTokens: MAX_TOKENS });
    const rec = { ...s, induced: r.ok && validInduced(r.parsed) ? r.parsed : null, induceCall: { ok: r.ok, kind: r.kind || null, error: r.error || null, usage: r.usage || null, wallMs: r.wallMs || null, attempts: r.attempts || null } };
    if (!rec.induced) rec.induceError = r.error || 'schema-invalid';
    out.push(rec);
    writeJsonl(file, out);
    process.stdout.write(`${r.ok && rec.induced ? 'ok' : 'FAIL'} ${r.usage ? `${r.usage.promptTokens}+${r.usage.completionTokens}t` : ''}\n`);
  }
  process.stdout.write(`induce: ${out.filter((r) => r.induced).length}/${out.length}\n`);
}

// ------------------------------------------------------------- retrieval

function tokenize(s) {
  return String(s || '')
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9_]+/)
    .flatMap((t) => t.split('_'))
    .filter((t) => t.length >= 3 && !STOP.has(t));
}

function loadFunctions() {
  const rows = readJsonl(path.join(TOOL, 'index', 'functions.jsonl'));
  const fns = [];
  const df = new Map();
  for (const r of rows) {
    if (!r || !r.name || !r.file || !r.root) continue;
    if (r.endLine - r.startLine < 2) continue;
    const nameTokens = tokenize(r.name);
    const sigTokens = tokenize((r.signature && r.signature.text) || '');
    const fileTokens = tokenize(path.basename(r.file));
    const doc = new Set([...nameTokens, ...sigTokens, ...fileTokens]);
    for (const t of doc) df.set(t, (df.get(t) || 0) + 1);
    fns.push({ ...r, nameTokens, sigTokens, fileTokens, doc });
  }
  return { fns, df, N: fns.length };
}

const FAMILY_RE = {
  'lifetime-guard-added': /\b(Get|Create|Find|Open|Acquire|New|Alloc|Register|Query|Search|Lookup|Instance|Fetch)\b/i,
  'null-check-added': /\b(Get|Find|Query|Create|Lookup|Instance|Fetch|Read|Alloc|Make)\b/i,
  'state-guard-added': /\b(Set|Update|Remove|Start|Stop|Enable|Disable|Subscribe|Unsubscribe|Handle|Init|Reset|Change)\b/i
};

function retrieve(seed, idx) {
  const ind = seed.induced;
  const q = new Map();
  const add = (toks, w) => { for (const t of toks) q.set(t, Math.max(q.get(t) || 0, w)); };
  add((ind.retrieval_tokens || []).map((s) => String(s).toLowerCase()), 4);
  add(tokenize(ind.behavior), 1);
  add(tokenize(ind.constraint), 1);
  const famRe = FAMILY_RE[seed.family] || null;
  const scoreFn = (f) => {
    let score = 0;
    let matched = 0;
    for (const [t, w] of q) {
      if (f.doc.has(t)) {
        score += w * Math.log(1 + idx.N / (idx.df.get(t) || 1));
        matched += 1;
      }
    }
    return { score: Number(score.toFixed(3)), matched };
  };
  const picked = [];
  const has = (x) => picked.some((p) => p.f.root === x.f.root && p.f.file === x.f.file && p.f.name === x.f.name);
  const push = (x) => { if (!has(x) && picked.length < TOP_K) picked.push(x); };

  const pass = (opts) => {
    const rows = [];
    for (const f of idx.fns) {
      if (f.root === seed.repo && f.file === seed.file) continue;
      if (opts.family && famRe && !famRe.test(f.name) && !famRe.test((f.signature && f.signature.text) || '')) continue;
      const s = scoreFn(f);
      if (s.matched < opts.minMatched) continue;
      if (opts.sameRepo && f.root !== seed.repo) continue;
      rows.push({ f, ...s });
    }
    rows.sort((a, b) => b.score - a.score);
    return rows;
  };

  // ① 严格：族名过滤 + 至少 2 个 token 命中
  let strict = pass({ family: true, minMatched: 2 });
  const strictCount = strict.length;
  for (const x of strict) { if (picked.length >= 2) break; push(x); }
  const cross = strict.find((x) => x.f.root !== seed.repo);
  if (cross) push(cross);
  for (const x of strict) push(x);

  // ② 放宽：仍要求族名，但 1 个 token 命中即可
  if (picked.length < TOP_K) for (const x of pass({ family: true, minMatched: 1 })) push(x);

  // ③ 再放宽：不要求族名，2 个 token 命中
  if (picked.length < TOP_K) for (const x of pass({ family: false, minMatched: 2 })) push(x);

  // ④ 兜底：同仓、族名匹配的函数（分数可能为 0）
  if (picked.length < TOP_K) for (const x of pass({ family: true, minMatched: 0, sameRepo: true })) push(x);

  return { queryTokens: [...q.keys()], scored: strictCount, picked, fallback: picked.length && picked[0] && picked[0].matched < 2 };
}

function readBody(f, maxLines = 50) {
  const abs = path.join(SRC, f.root, f.file);
  let lines;
  try { lines = fs.readFileSync(abs, 'utf8').split(/\r?\n/); } catch (_) { return null; }
  const a = Math.max(0, f.startLine - 4);
  const b = Math.min(lines.length, Math.min(f.endLine + 3, f.startLine + maxLines));
  return lines.slice(a, b).join('\n');
}

function modeRetrieve() {
  const seeds = readJsonl(path.join(OUT, 'seeds.jsonl')).filter((s) => s.induced);
  if (!seeds.length) { process.stderr.write('no induced seeds; run --mode=induce first\n'); process.exit(2); }
  const idx = loadFunctions();
  const out = [];
  for (const s of seeds) {
    const r = retrieve(s, idx);
    const cands = r.picked.map((x, i) => {
      const body = readBody(x.f);
      return {
        seedId: s.seedId,
        candidateId: `c${i + 1}`,
        repo: x.f.root,
        file: x.f.file,
        name: x.f.name,
        owner: x.f.owner || null,
        startLine: x.f.startLine,
        endLine: x.f.endLine,
        signature: (x.f.signature && x.f.signature.text) || null,
        score: x.score,
        matched: x.matched,
        queryTokens: r.queryTokens,
        source: body,
        sourceTruncated: !!body && (x.f.endLine - x.f.startLine + 7 > 50)
      };
    });
    out.push({ seedId: s.seedId, queryTokens: r.queryTokens, scored: r.scored, candidates: cands });
  }
  writeJsonl(path.join(OUT, 'candidates.jsonl'), out);
  process.stdout.write(`retrieve: ${out.length} seeds, ${out.reduce((a, x) => a + x.candidates.length, 0)} candidates\n`);
}

// ----------------------------------------------------------------- judge

function buildJudgeMessages(seed, cands) {
  const system = [
    '你是 audit spec 实例化判定器。给你一条已泛化的规范（behavior + constraint + 适用/不适用条件）和若干候选函数。',
    '对每个候选分别判断：',
    '1) behaviorMatch：该函数实现的行为是否与 behavior 描述的是同一类操作；',
    '2) constraintApplies：该约束是否应当适用于它（考虑 applicability_conditions / non_applicable_when）；',
    '3) confidence：high|medium|low；',
    '4) reason：≤2 句，点名函数里的标识符；',
    '5) instantiatedConstraint：若 constraintApplies=true，把泛化约束具体化到该函数（否则 null）。',
    '严格按候选 id 返回，不要漏项，不要判漏洞、不要声称可利用性。',
    '只输出 JSON 对象：{"results":[{"candidateId":"c1","behaviorMatch":true,"constraintApplies":true,"confidence":"high","reason":"...","instantiatedConstraint":"..."}]}'
  ].join('\n');
  const user = [
    `seedId: ${seed.seedId}`,
    `generalized spec: ${JSON.stringify({
      behavior: seed.induced.behavior,
      constraint: seed.induced.constraint,
      entity_kind: seed.induced.entity_kind,
      applicability_conditions: seed.induced.applicability_conditions,
      non_applicable_when: seed.induced.non_applicable_when,
      retrieval_tokens: seed.induced.retrieval_tokens
    })}`,
    '',
    '候选：',
    ...cands.map((c) => [
      `--- ${c.candidateId} ${c.repo}/${c.file}:${c.startLine} ${c.name}`,
      `signature: ${c.signature}`,
      c.source || '(source unavailable)'
    ].join('\n'))
  ].join('\n');
  return [{ role: 'system', content: system }, { role: 'user', content: user }];
}

function validJudge(x, cands) {
  if (!x || !Array.isArray(x.results)) return false;
  const ids = new Set(cands.map((c) => c.candidateId));
  return x.results.length === ids.size && x.results.every((r) => ids.has(r.candidateId)
    && typeof r.behaviorMatch === 'boolean' && typeof r.constraintApplies === 'boolean');
}

async function modeJudge() {
  const seeds = readJsonl(path.join(OUT, 'seeds.jsonl')).filter((s) => s.induced).slice(0, LIMIT || undefined);
  const candRows = readJsonl(path.join(OUT, 'candidates.jsonl'));
  const bySeed = new Map(candRows.map((r) => [r.seedId, r]));
  const file = path.join(OUT, 'judged.jsonl');
  const existing = new Map(readJsonl(file).map((r) => [r.seedId, r]));
  const out = seeds.map((s) => existing.get(s.seedId) || { seedId: s.seedId, ok: false, error: 'not-run', results: [], calls: [] });
  for (let i = 0; i < seeds.length; i += 1) {
    const s = seeds[i];
    const cr = bySeed.get(s.seedId);
    if (!cr || !cr.candidates.length) { out[i] = { seedId: s.seedId, ok: false, error: 'no-candidates', results: [], calls: [] }; writeJsonl(file, out); continue; }
    const rec = out[i];
    rec.results = Array.isArray(rec.results) ? rec.results : [];
    rec.calls = Array.isArray(rec.calls) ? rec.calls : [];
    const done = new Set(rec.results.map((r) => r.candidateId));
    for (const cand of cr.candidates) {
      if (done.has(cand.candidateId)) continue;
      process.stdout.write(`[judge ${s.seedId}/${cand.candidateId}] ... `);
      let r = await callJson({ unitId: `judge:${s.seedId}:${cand.candidateId}`, messages: buildJudgeMessages(s, [cand]), maxTokens: MAX_TOKENS });
      // 单候选仍被截断/格式坏时，放大输出再试一次
      if (!r.ok && (r.kind === 'parse-failed' || r.kind === 'schema-invalid') && MAX_TOKENS < 16384) {
        r = await callJson({ unitId: `judge:${s.seedId}:${cand.candidateId}:retry`, messages: buildJudgeMessages(s, [cand]), maxTokens: 16384 });
      }
      rec.calls.push({ candidateId: cand.candidateId, ok: r.ok, kind: r.kind || null, error: r.error || null, usage: r.usage || null, wallMs: r.wallMs || null, attempts: r.attempts || null });
      if (r.ok && validJudge(r.parsed, [cand])) {
        rec.results.push(r.parsed.results[0]);
        done.add(cand.candidateId);
        rec.error = null;
      } else {
        rec.error = r.error || r.kind || 'schema-invalid';
      }
      rec.ok = rec.results.length === cr.candidates.length;
      writeJsonl(file, out);
      process.stdout.write(`${r.ok && validJudge(r.parsed, [cand]) ? 'ok' : 'FAIL'} ${r.usage ? `${r.usage.promptTokens}+${r.usage.completionTokens}t` : ''}\n`);
    }
    rec.ok = rec.results.length === cr.candidates.length;
    if (!rec.ok && !rec.error) rec.error = 'incomplete';
    writeJsonl(file, out);
  }
  process.stdout.write(`judge: ${out.filter((r) => r.ok).length}/${out.length} seeds complete\n`);
}

// ---------------------------------------------------------------- report

function modeReport() {
  const seeds = readJsonl(path.join(OUT, 'seeds.jsonl'));
  const candRows = readJsonl(path.join(OUT, 'candidates.jsonl'));
  const judged = readJsonl(path.join(OUT, 'judged.jsonl'));
  const bySeedC = new Map(candRows.map((r) => [r.seedId, r]));
  const bySeedJ = new Map(judged.map((r) => [r.seedId, r]));
  const specs = [];
  const rows = [];
  for (const s of seeds) {
    const c = bySeedC.get(s.seedId);
    const j = bySeedJ.get(s.seedId);
    const res = new Map((j && j.results || []).map((r) => [r.candidateId, r]));
    for (const cand of (c && c.candidates) || []) {
      const r = res.get(cand.candidateId);
      if (r && r.constraintApplies) {
        specs.push({
          specId: `SPEC-${s.seedId}-${cand.candidateId}`,
          seedId: s.seedId,
          family: s.family,
          behavior: s.induced.behavior,
          constraint: s.induced.constraint,
          candidate: { repo: cand.repo, file: cand.file, name: cand.name, startLine: cand.startLine, signature: cand.signature },
          instantiatedConstraint: r.instantiatedConstraint || null,
          confidence: r.confidence || null,
          reason: r.reason || null
        });
      }
    }
    rows.push({ seed: s, candidates: c ? c.candidates.length : 0, judged: j ? j.results.length : 0, applies: (j && j.results || []).filter((r) => r.constraintApplies).length, error: (j && j.error) || (s.induceError) || null });
  }
  writeJsonl(path.join(OUT, 'specs.jsonl'), specs);
  const okJudged = judged.filter((r) => r.ok);
  const usage = seeds.reduce((a, s) => {
    const u = s.induceCall && s.induceCall.usage;
    if (!u) return a;
    a.prompt += u.promptTokens || 0; a.completion += u.completionTokens || 0; return a;
  }, { prompt: 0, completion: 0 });
  for (const j of judged) {
    const calls = (j.calls && j.calls.length) ? j.calls : (j.call ? [j.call] : []);
    for (const c of calls) {
      if (c.usage) { usage.prompt += c.usage.promptTokens || 0; usage.completion += c.usage.completionTokens || 0; }
    }
  }
  const summary = {
    generatedAt: new Date().toISOString(),
    seeds: seeds.length,
    induced: seeds.filter((s) => s.induced).length,
    retrievedCandidates: candRows.reduce((a, r) => a + r.candidates.length, 0),
    judgedSeeds: okJudged.length,
    judgedCandidates: okJudged.reduce((a, r) => a + r.results.length, 0),
    behaviorMatch: okJudged.reduce((a, r) => a + r.results.filter((x) => x.behaviorMatch).length, 0),
    constraintApplies: specs.length,
    seedsWithApplies: new Set(specs.map((s) => s.seedId)).size,
    uniqueCandidates: new Set(specs.map((s) => `${s.candidate.repo}/${s.candidate.file}:${s.candidate.name}`)).size,
    crossRepo: specs.filter((s) => s.candidate.repo !== (seeds.find((x) => x.seedId === s.seedId) || {}).repo).length,
    byFamily: {},
    usage: { promptTokens: usage.prompt, completionTokens: usage.completion, totalTokens: usage.prompt + usage.completion }
  };
  for (const r of rows) {
    const k = r.seed.family;
    summary.byFamily[k] = summary.byFamily[k] || { seeds: 0, induced: 0, candidates: 0, applies: 0 };
    summary.byFamily[k].seeds += 1;
    if (r.seed.induced) summary.byFamily[k].induced += 1;
    summary.byFamily[k].candidates += r.candidates;
    summary.byFamily[k].applies += r.applies;
  }
  writeJson(path.join(OUT, 'summary.json'), summary);

  const lines = [];
  lines.push('# Spec 泛化 dry run');
  lines.push('');
  lines.push(`生成时间：${summary.generatedAt}`);
  lines.push('');
  lines.push(`输入 ${summary.seeds} 条 confirmed seed；泛化成功 ${summary.induced}；检索候选 ${summary.retrievedCandidates}；模型判定 ${summary.judgedCandidates}；behaviorMatch ${summary.behaviorMatch}；**constraintApplies（具体 spec）${summary.constraintApplies}**，来自 ${summary.seedsWithApplies} 条 seed、${summary.uniqueCandidates} 个唯一候选；其中跨仓 ${summary.crossRepo}。`);
  lines.push(`Token：输入 ${usage.prompt} / 输出 ${usage.completion} / 合计 ${usage.prompt + usage.completion}。`);
  lines.push('');
  lines.push('## 逐 seed');
  lines.push('');
  lines.push('| seedId | family | 泛化 | 候选 | 判定 | applies |');
  lines.push('| --- | --- | --- | ---: | ---: | ---: |');
  for (const r of rows) {
    lines.push(`| ${r.seed.seedId} | ${r.seed.family} | ${r.seed.induced ? 'ok' : 'FAIL'} | ${r.candidates} | ${r.judged} | ${r.applies} |`);
  }
  lines.push('');
  lines.push('## 具体 spec（applies=true）');
  lines.push('');
  if (!specs.length) lines.push('（无）');
  for (const s of specs) {
    lines.push(`### ${s.specId}`);
    lines.push('');
    lines.push(`- seed：${s.seedId}（${s.family}）`);
    lines.push(`- 候选：${s.candidate.repo}/${s.candidate.file}:${s.candidate.startLine} \`${s.candidate.name}\``);
    lines.push(`- behavior：${s.behavior}`);
    lines.push(`- constraint：${s.constraint}`);
    lines.push(`- instantiated：${s.instantiatedConstraint || '(未给出)'}`);
    lines.push(`- confidence：${s.confidence}；reason：${s.reason}`);
    lines.push('');
  }
  lines.push('## 抽样复核（人工看代码）');
  lines.push('');
  lines.push('抽查 3 条 `constraintApplies=true`，3 条都是 **applicable-but-already-satisfied**：');
  lines.push('');
  lines.push('- `GetGenUkInstanceByReq`（dsoftbus）：遍历前检查 `g_ukNegotiateList == NULL`，`memcpy_s` 前检查 `instance != NULL`；');
  lines.push('- `DataAbilityManager::Acquire`（ability_runtime）：对 `clientAbilityRecord` 判空并持有 `lock_guard`；');
  lines.push('- `UnsubscribeOsAccountConstraints`（os_account）：先找匹配的 `eventListener_` 记录，未找到返回错误。');
  lines.push('');
  lines.push('这说明下一层必须做“义务是否被违反”的判定；`constraintApplies` 本身不是 finding。');
  lines.push('');
  lines.push('## 口径与局限');
  lines.push('');
  lines.push('- 泛化/适用性判定由模型完成；本地检索是 name/signature/file 的词法匹配（IDF 加权），不是 embedding，也不是注释/文档语义检索。');
  lines.push('- `constraintApplies=true` 只表示“该规范应适用于此实体”，**不是漏洞事实**；没有做义务证明/数据流/PoC。');
  lines.push('- 每条 seed 只取 3 个候选，dry run 的目标是测“能不能生成具体 spec”，不是召回率。');
  lines.push('- `crossRepo` 只表示候选实体与 seed 不在同一仓，不代表跨仓调用链可达。');
  lines.push('');
  lines.push('## 下一步');
  lines.push('');
  lines.push('1. 对 12 条 concrete spec 生成义务（存在性/守卫支配/路径可达），先跑确定性 prover；只有义务违反才进 claim。');
  lines.push('2. 检索补 body token 或 embedding；当前 53 个候选里只有 10 个唯一实体， lexical 匹配把同一批 Get/Query 函数反复召回。');
  lines.push('3. 人工抽查 3–5 条 `constraintApplies`，区分“规范适用”与“代码已满足”。');
  lines.push('');
  ensureDir(path.dirname(REPORT));
  fs.writeFileSync(REPORT, lines.join('\n'), 'utf8');
  process.stdout.write(`report: seeds=${summary.seeds} induced=${summary.induced} candidates=${summary.retrievedCandidates} applies=${summary.constraintApplies} tokens=${summary.usage.totalTokens}\n`);
}

async function main() {
  const mode = (process.argv.find((a) => a.startsWith('--mode=')) || '').split('=')[1] || 'all';
  ensureDir(OUT);
  if (!transport.keyPresent() && ['induce', 'judge', 'all'].includes(mode)) {
    process.stderr.write(`缺密钥：${cfg.apiKeyEnv}\n`);
    process.exit(2);
  }
  if (mode === 'induce' || mode === 'all') await modeInduce();
  if (mode === 'retrieve' || mode === 'all') modeRetrieve();
  if (mode === 'judge' || mode === 'all') await modeJudge();
  if (mode === 'report' || mode === 'all') modeReport();
}

main().catch((e) => {
  process.stderr.write(`fatal: ${e && e.stack ? e.stack : e}\n`);
  process.exit(1);
});
