'use strict';

/**
 * lib/agent/l4b-global.js —— 全类 L4b 语义层（P1–P8）。
 *
 * 统一流程：
 *   claims/verdicts（各 campaign 产物） -> 每类选 1–N 条 -> 通用证据包
 *   -> L4b 单次判定（有 key 用 live，否则 mock unknown）
 *   -> 写 out/global/l4b/{results,claims-refined,verdicts-refined}.jsonl
 *   -> 写 out/report/global-l4b-{summary.json,md}
 *
 * 纪律：
 *   - 只改 P1/P2/P7/P8 的 O5/O6（语义守卫/覆盖）；不改 O10；
 *   - P3/P4/P5/P6 只记录 observation，不改原 verdict；
 *   - 没有 key 时 mock 一律 unknown，不产生假 T4；
 *   - 任何 refined 结果都不得出现 PROVEN-VULN / T1。
 */

const fs = require('fs');
const path = require('path');
const { OUT_ROOT, ensureDir, writeJson, writeJsonl } = require('../util.js');
const l4b = require('../l4b.js');
const {
  CLASS_IDS, RESIDUAL_TIERS, loadClassArtifacts, selectGlobalClaims, buildGlobalPack, buildMessages
} = require('./classes.js');
const { tierOfProduct } = require('../p1p2p7p8/common.js');

const GLOBAL_DIR = path.join(OUT_ROOT, 'global', 'l4b');
const SUMMARY_FILE = path.join(OUT_ROOT, 'report', 'global-l4b-summary.json');
const REPORT_FILE = path.join(OUT_ROOT, 'report', 'global-l4b.md');
const ALLOWED_ASSESSMENTS = new Set(['support', 'refute', 'unknown']);
const ALLOWED_GAPS = new Set(['completed', 'partial', 'unresolved', 'not-applicable']);
const APPLY_CLASSES = new Set(['P1', 'P2', 'P7', 'P8']);

function makeMockTransport(packs) {
  const byId = new Map(packs.map((p) => [p.id, p]));
  return {
    id: 'mock-global-l4b',
    simulated: true,
    model: 'mock',
    keyPresent: () => true,
    async send({ unitId }) {
      const pack = byId.get(unitId);
      const refs = pack && pack.refs.length ? [pack.refs[0]] : [];
      return {
        kind: 'ok',
        content: JSON.stringify({
          assessment: 'unknown',
          gapResolution: pack && pack.mode === 'complete-gap' ? 'unresolved' : 'not-applicable',
          reason: 'mock: no OH6_LLM_API_KEY; semantic evidence is unknown',
          evidenceRefs: refs,
          missingEvidence: pack && pack.mode === 'complete-gap' ? ['live-model-unavailable'] : [],
          suggestedEvidence: []
        }),
        usage: { promptTokens: 10, completionTokens: 10 },
        usageKnown: true,
        model: 'mock',
        finishReason: 'stop',
        maxTokensSent: 2048,
        wallMs: 1
      };
    }
  };
}

function parseResult(content, pack) {
  let obj;
  try {
    obj = l4b.parseJsonContent(content);
  } catch (e) {
    return {
      ok: false,
      errors: [`parse-failed:${e && e.message ? e.message : String(e)}`],
      assessment: null,
      gapResolution: null,
      reason: null,
      evidenceRefs: [],
      missingEvidence: [],
      suggestedEvidence: []
    };
  }
  const errors = [];
  if (!obj || typeof obj !== 'object') errors.push('not-object');
  const assessment = obj && String(obj.assessment || 'unknown').toLowerCase();
  if (!ALLOWED_ASSESSMENTS.has(assessment)) errors.push('bad-assessment');
  let gapResolution = obj && obj.gapResolution != null
    ? String(obj.gapResolution).toLowerCase()
    : (pack.mode === 'complete-gap' ? 'unresolved' : 'not-applicable');
  if (!ALLOWED_GAPS.has(gapResolution)) errors.push('bad-gap-resolution');
  if (!Array.isArray(obj && obj.evidenceRefs)) errors.push('evidenceRefs-not-array');
  const refs = (obj && obj.evidenceRefs) || [];
  for (const r of refs) if (!pack.refs.includes(r)) errors.push(`unknown-ref:${r}`);
  const missingEvidence = Array.isArray(obj && obj.missingEvidence)
    ? obj.missingEvidence.map((x) => String(x).slice(0, 300)).slice(0, 12)
    : [];
  const suggestedEvidence = Array.isArray(obj && obj.suggestedEvidence)
    ? obj.suggestedEvidence.filter((x) => x && typeof x === 'object' && pack.refs.includes(x.ref)).map((x) => ({
      ref: x.ref,
      why: x.why ? String(x.why).slice(0, 500) : null
    })).slice(0, 12)
    : [];
  if ((assessment === 'support' || assessment === 'refute') && refs.length === 0) errors.push('missing-evidence-ref');
  if (gapResolution === 'completed' && refs.length === 0) errors.push('completed-without-evidence');
  return {
    ok: errors.length === 0,
    errors,
    assessment: ALLOWED_ASSESSMENTS.has(assessment) ? assessment : null,
    gapResolution: ALLOWED_GAPS.has(gapResolution) ? gapResolution : null,
    reason: obj && obj.reason ? String(obj.reason).slice(0, 800) : null,
    evidenceRefs: refs.filter((r) => pack.refs.includes(r)),
    missingEvidence,
    suggestedEvidence
  };
}

function repairMessages(pack, errors) {
  const base = buildMessages(pack);
  return [
    ...base,
    {
      role: 'user',
      content: `上一次输出不合法：${errors.join(', ')}。请严格按 schema 只输出 JSON，evidenceRefs 必须来自 ${JSON.stringify(pack.refs)}。`
    }
  ];
}

async function judgePack(pack, transport, opts = {}) {
  let last = null;
  for (let attempt = 1; attempt <= 2; attempt += 1) {
    const messages = attempt === 1 ? buildMessages(pack) : repairMessages(pack, last ? last.errors : []);
    let res;
    try {
      res = await transport.send({ unitId: pack.id, attempt, messages, maxTokens: opts.maxTokens || 2048 });
    } catch (e) {
      last = { ok: false, blocked: true, errors: [`transport:${e && e.message ? e.message : String(e)}`], assessment: null, gapResolution: null, reason: null, evidenceRefs: [], missingEvidence: [], suggestedEvidence: [] };
      continue;
    }
    if (!res || res.kind !== 'ok') {
      last = { ok: false, blocked: true, errors: [res && res.kind ? res.kind : 'transport'], assessment: null, gapResolution: null, reason: null, evidenceRefs: [], missingEvidence: [], suggestedEvidence: [] };
      continue;
    }
    const parsed = parseResult(res.content, pack);
    const result = {
      ...parsed,
      ok: parsed.ok,
      blocked: false,
      contentHash: l4b.sha(res.content),
      usage: res.usage || null,
      model: res.model || null
    };
    if (result.ok) return result;
    last = result;
  }
  return last || { ok: false, blocked: true, errors: ['no-attempt'], assessment: null, gapResolution: null, reason: null, evidenceRefs: [], missingEvidence: [], suggestedEvidence: [] };
}

function claimsWithObligations(record) {
  const base = record.verdict && Array.isArray(record.verdict.obligations)
    ? record.verdict.obligations
    : (record.claim && record.claim.obligations) || [];
  return base.map((o) => ({ ...o, evidence: { ...(o.evidence || {}) } }));
}

function refineRecord(record, result, pack) {
  const claim = JSON.parse(JSON.stringify(record.claim));
  const verdict = record.verdict ? JSON.parse(JSON.stringify(record.verdict)) : null;
  if (verdict) {
    verdict.claimId = verdict.claimId || record.claimId;
    verdict.class = verdict.class || record.class;
  }
  const observation = {
    source: 'global-l4b',
    mode: pack.mode,
    tier: record.tier,
    simulated: Boolean(result.simulated),
    ok: Boolean(result.ok),
    assessment: result.assessment || null,
    gapResolution: result.gapResolution || null,
    reason: result.reason || null,
    evidenceRefs: result.evidenceRefs || [],
    missingEvidence: result.missingEvidence || [],
    suggestedEvidence: result.suggestedEvidence || [],
    errors: result.errors || []
  };
  claim.l4b = observation;
  if (verdict) verdict.l4b = observation;
  let changed = false;
  let evidenceChanged = false;
  let gapCompleted = false;
  let gapPartial = false;
  const isT2 = String(record.tier || '').startsWith('T2');
  const isT3 = record.tier === 'T3-instrumentation-gap';

  if (result.ok && !result.simulated && isT2 && result.assessment === 'support') {
    const support = {
      source: 'global-l4b',
      assessment: 'support',
      evidenceRefs: result.evidenceRefs || [],
      suggestedEvidence: result.suggestedEvidence || [],
      reason: result.reason || null
    };
    claim.l4bSupport = support;
    if (verdict) verdict.l4bSupport = support;
    evidenceChanged = true;
  }

  if (verdict && result.ok && !result.simulated && isT2 && result.assessment === 'refute' && APPLY_CLASSES.has(record.class)) {
    const safe = true;
    const status = 'proven';
    const reason = 'global-l4b-refute';
    const beforeObligations = JSON.stringify(claimsWithObligations(record));
    const beforeProduct = verdict.productVerdict;
    const beforeTier = verdict.tier;
    const obligations = claimsWithObligations(record);
    for (const o of obligations) {
      if (o.id === 'O5' || o.id === 'O6') {
        o.status = status;
        o.reason = reason;
        o.evidence = { ...(o.evidence || {}), l4b: observation };
      }
    }
    const product = safe ? 'NOT-VULN' : 'PROVEN-WEAKNESS';
    const afterTier = tierOfProduct(product);
    changed = beforeProduct !== product || beforeTier !== afterTier || beforeObligations !== JSON.stringify(obligations);
    if (changed) {
      verdict.obligations = obligations;
      verdict.productVerdict = product;
      verdict.claimVerdict = safe ? 'SATISFIED' : 'VIOLATION';
      verdict.tier = afterTier;
      verdict.l4bRefined = true;
    }
  }

  if (result.ok && !result.simulated && isT3) {
    const gap = {
      source: 'global-l4b',
      gapResolution: result.gapResolution || null,
      evidenceRefs: result.evidenceRefs || [],
      missingEvidence: result.missingEvidence || [],
      suggestedEvidence: result.suggestedEvidence || [],
      reason: result.reason || null
    };
    claim.l4bGap = gap;
    if (verdict) verdict.l4bGap = gap;
    if (result.gapResolution === 'completed') gapCompleted = true;
    else if (result.gapResolution === 'partial') gapPartial = true;
  }

  return { claim, verdict, changed, evidenceChanged, gapCompleted, gapPartial, observation };
}

function renderReport(summary) {
  const lines = [];
  lines.push('# Global L4b（P1–P8）');
  lines.push('');
  lines.push(`生成时间：${summary.generatedAt}`);
  lines.push('');
  lines.push(`allGatesPass：**${summary.allGatesPass}**`);
  lines.push('');
  lines.push(`- simulated：${summary.simulated}；liveBlocked：${summary.liveBlocked}`);
  const requested = summary.requestedClasses || summary.classes.map((c) => c.class);
  const requestedRows = summary.classes.filter((c) => requested.includes(c.class));
  lines.push(`- classes：${requestedRows.filter((c) => c.eligible > 0).length}/${requestedRows.length} with eligible T2/T3`);
  lines.push(`- reviewed：${summary.totals.reviewed}/${summary.totals.selected}（eligible ${summary.totals.eligible}）；verdictChanges：${summary.totals.verdictChanges}；evidenceChanges：${summary.totals.evidenceChanges}`);
  lines.push(`- gaps：completed ${summary.totals.gapsCompleted} / partial ${summary.totals.gapsPartial}`);
  lines.push(`- T1：${summary.totals.t1}`);
  lines.push('');
  lines.push('| 类 | eligible | selected | reviewed | support | refute | unknown | gap-completed | evidence | verdict |');
  lines.push('| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |');
  for (const c of summary.classes) {
    lines.push(`| ${c.class} | ${c.eligible} | ${c.selected} | ${c.reviewed} | ${c.support} | ${c.refute} | ${c.unknown} | ${c.gapsCompleted} | ${c.evidenceChanges} | ${c.changes} |`);
  }
  lines.push('');
  lines.push('## Gates');
  lines.push('');
  for (const g of summary.gates) lines.push(`- ${g.pass ? 'PASS' : 'FAIL'} ${g.name}: ${g.detail || ''}`);
  lines.push('');
  lines.push('## Results');
  lines.push('');
  for (const r of summary.results) {
    const verdict = r.mode === 'complete-gap'
      ? `gap=${r.gapResolution || 'invalid'}`
      : `assessment=${r.assessment || 'invalid'}`;
    lines.push(`- ${r.class} ${r.claimId} [${r.tier}] -> ${verdict}${r.simulated ? ' (simulated)' : ''}${r.reason ? `: ${r.reason}` : ''}`);
  }
  lines.push('');
  return lines.join('\n');
}

async function runGlobalL4b(opts = {}) {
  const classes = opts.classes || CLASS_IDS;
  const requestedClasses = [...classes];
  const perClass = opts.perClass == null ? 0 : Number(opts.perClass);
  const loaded = opts.records ? { records: opts.records } : loadClassArtifacts(classes);
  const selected = selectGlobalClaims(loaded.records, { perClass }).filter((r) => classes.includes(r.class));
  const packs = selected.map(buildGlobalPack);
  const mode = opts.mode || 'auto';
  const hasKey = Boolean(process.env.OH6_LLM_API_KEY);
  const live = mode === 'live' || (mode !== 'mock' && hasKey);
  const transport = opts.transport || (live ? l4b.makeTransport({ maxTokens: 2048, timeoutMs: 90000 }) : makeMockTransport(packs));
  const results = [];
  for (let i = 0; i < packs.length; i += 1) {
    const pack = packs[i];
    const raw = await judgePack(pack, transport, opts);
    results.push({
      ...raw,
      simulated: !live,
      class: pack.class,
      claimId: pack.claimId,
      packId: pack.id,
      tier: pack.tier,
      mode: pack.mode
    });
  }
  const refinedClaims = [];
  const refinedVerdicts = [];
  const perClassMap = new Map(CLASS_IDS.map((c) => [c, {
    class: c, eligible: 0, selected: 0, reviewed: 0, support: 0, refute: 0, unknown: 0,
    gapsCompleted: 0, gapsPartial: 0, errors: 0, evidenceChanges: 0, changes: 0
  }]));
  for (const cls of CLASS_IDS) {
    perClassMap.get(cls).eligible = loaded.records.filter((r) => r.class === cls && r.productionEligible && RESIDUAL_TIERS.includes(r.tier)).length;
  }
  for (const r of selected) perClassMap.get(r.class).selected += 1;
  let verdictChanges = 0;
  let evidenceChanges = 0;
  let gapsCompleted = 0;
  let gapsPartial = 0;
  for (let i = 0; i < selected.length; i += 1) {
    const record = selected[i];
    const pack = packs[i];
    const result = results[i];
    const refined = refineRecord(record, result, pack);
    refinedClaims.push(refined.claim);
    if (refined.verdict) refinedVerdicts.push(refined.verdict);
    const c = perClassMap.get(record.class);
    if (result.ok) c.reviewed += 1;
    else c.errors += 1;
    if (result.assessment === 'support') c.support += 1;
    else if (result.assessment === 'refute') c.refute += 1;
    else c.unknown += 1;
    if (result.gapResolution === 'completed') { c.gapsCompleted += 1; gapsCompleted += 1; }
    else if (result.gapResolution === 'partial') { c.gapsPartial += 1; gapsPartial += 1; }
    if (refined.evidenceChanged) { c.evidenceChanges += 1; evidenceChanges += 1; }
    if (refined.changed) { c.changes += 1; verdictChanges += 1; }
  }
  const t1 = refinedVerdicts.filter((v) => v.productVerdict === 'PROVEN-VULN' || v.tier === 'T1-confirmed').length;
  const o10Changed = selected.some((r, i) => {
    const before = claimsWithObligations(r).find((o) => o.id === 'O10');
    const after = (refinedVerdicts[i] && refinedVerdicts[i].obligations || []).find((o) => o.id === 'O10');
    return before && after && before.status !== after.status;
  });
  ensureDir(GLOBAL_DIR);
  writeJsonl(path.join(GLOBAL_DIR, 'results.jsonl'), results);
  writeJsonl(path.join(GLOBAL_DIR, 'claims-refined.jsonl'), refinedClaims);
  writeJsonl(path.join(GLOBAL_DIR, 'verdicts-refined.jsonl'), refinedVerdicts);
  const summary = {
    generatedAt: new Date().toISOString(),
    simulated: !live,
    liveBlocked: !live && mode !== 'mock',
    mode,
    o10Changed,
    requestedClasses,
    perClass,
    classes: [...perClassMap.values()],
    totals: {
      classes: CLASS_IDS.length,
      eligible: loaded.records.filter((r) => r.productionEligible && RESIDUAL_TIERS.includes(r.tier)).length,
      selected: selected.length,
      reviewed: results.filter((r) => r.ok).length,
      support: results.filter((r) => r.assessment === 'support').length,
      refute: results.filter((r) => r.assessment === 'refute').length,
      unknown: results.filter((r) => r.assessment === 'unknown').length,
      errors: results.filter((r) => !r.ok).length,
      gapsCompleted,
      gapsPartial,
      evidenceChanges,
      verdictChanges,
      t1,
      tokens: results.reduce((n, r) => n + ((r.usage && (r.usage.promptTokens || 0) + (r.usage.completionTokens || 0)) || 0), 0)
    },
    results,
    artifacts: {
      results: 'out/global/l4b/results.jsonl',
      claims: 'out/global/l4b/claims-refined.jsonl',
      verdicts: 'out/global/l4b/verdicts-refined.jsonl'
    }
  };
  const coveragePass = requestedClasses.every((id) => {
    const row = summary.classes.find((x) => x.class === id);
    if (!row || row.eligible === 0) return true;
    if (perClass > 0) return row.selected > 0 && row.reviewed === row.selected;
    return row.selected === row.eligible && row.reviewed === row.selected;
  });
  const gates = [
    {
      name: 'global-l4b class coverage',
      pass: coveragePass,
      detail: requestedClasses.map((id) => {
        const row = summary.classes.find((x) => x.class === id);
        return `${id}:${row ? row.selected : 0}/${row ? row.eligible : 0}`;
      }).join(', ')
    },
    {
      name: 'global-l4b schema',
      pass: results.length > 0 && results.every((r) => r.ok),
      detail: `${results.filter((r) => r.ok).length}/${results.length} ok`
    },
    {
      name: 'global-l4b no T1 / O10 stable',
      pass: t1 === 0 && !o10Changed,
      detail: `t1=${t1}, o10Changed=${o10Changed}`
    },
    {
      name: 'global-l4b artifacts',
      pass: ['results.jsonl', 'claims-refined.jsonl', 'verdicts-refined.jsonl'].every((f) => fs.existsSync(path.join(GLOBAL_DIR, f))),
      detail: 'out/global/l4b/*.jsonl'
    },
    {
      name: 'global-l4b report',
      pass: false,
      detail: 'written after summary'
    }
  ];
  const allGatesPass = gates.every((g) => g.pass);
  const finalSummary = { ...summary, gates, allGatesPass };
  ensureDir(path.dirname(REPORT_FILE));
  fs.writeFileSync(REPORT_FILE, renderReport(finalSummary), 'utf8');
  gates[4].pass = fs.existsSync(REPORT_FILE);
  gates[4].detail = 'out/report/global-l4b.md';
  const finalSummary2 = { ...summary, gates, allGatesPass: gates.every((g) => g.pass) };
  writeJson(SUMMARY_FILE, finalSummary2);
  fs.writeFileSync(REPORT_FILE, renderReport(finalSummary2), 'utf8');
  return finalSummary2;
}

module.exports = {
  GLOBAL_DIR,
  SUMMARY_FILE,
  REPORT_FILE,
  makeMockTransport,
  parseResult,
  judgePack,
  refineRecord,
  renderReport,
  runGlobalL4b
};
