'use strict';

/**
 * lib/l7/model.js —— 从 claim/verdict 生成 L7 finding card / observation。
 *
 * 纪律：
 *   - T1 必须有 L5 dynamic evidence；当前没有 L5 时不得生成 T1。
 *   - T2 -> finding card；T3 -> observation；T4 -> 只计数。
 *   - 每张卡必须有可解析 file:line；解析失败进 unresolved，不静默丢。
 */

const fs = require('fs');
const path = require('path');
const { OUT_ROOT, sha256, readJsonl } = require('../util.js');
const { CLASS_IDS, loadClassArtifacts, claimLocation, buildEvidence } = require('../agent/classes.js');
const { readSource, linesOf, tierOfProduct, normalizeTier } = require('../p1p2p7p8/common.js');

const CLASS_INFO = {
  P1: { name: '内存破坏', cwe: 'CWE-787', impact: 'out-of-bounds write/read or memory corruption' },
  P2: { name: 'UAF/生命周期', cwe: 'CWE-416', impact: 'use-after-free or dangling reference' },
  P3: { name: '空指针解引用', cwe: 'CWE-476', impact: 'null pointer dereference / crash' },
  P4: { name: '整数溢出/回绕', cwe: 'CWE-190', impact: 'integer overflow leading to undersized allocation or OOB' },
  P5: { name: '权限提升', cwe: 'CWE-862', impact: 'missing/incorrect authorization covering a privileged sink' },
  P6: { name: '信息泄露', cwe: 'CWE-200', impact: 'sensitive payload exposed through a public/common event' },
  P7: { name: '拒绝服务', cwe: 'CWE-400', impact: 'unbounded work/allocation or amplification' },
  P8: { name: '逻辑漏洞', cwe: 'CWE-670', impact: 'state/invariant violation with security-relevant effect' }
};

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };
const TEST_PATH_RE = /(^|\/)(tests?|fuzztest|unittest|testdata)(\/|$)/i;

function tierRank(t) {
  return t === 'T1-confirmed' ? 4 : String(t || '').startsWith('T2') ? 3 : String(t || '').startsWith('T3') ? 2 : 1;
}

function compactText(s, n = 300) {
  return String(s == null ? '' : s).replace(/\s+/g, ' ').trim().slice(0, n);
}

function resolveEvidence(record) {
  const ev = buildEvidence(record);
  const evidence = [];
  const unresolved = [];
  for (const e of ev.evidence) {
    if (!e.file) {
      unresolved.push(`missing-file:${e.ref}`);
      continue;
    }
    const text = readSource(e.file);
    if (text == null) {
      unresolved.push(`missing-source:${e.file}`);
      continue;
    }
    const lines = linesOf(text);
    if (!e.line || e.line < 1 || e.line > lines.length) {
      unresolved.push(`line-out-of-range:${e.file}:${e.line}`);
      continue;
    }
    evidence.push({
      ref: e.ref,
      file: e.file,
      line: e.line,
      text: compactText(lines[e.line - 1], 500),
      source: 'L1/L4a'
    });
  }
  return { evidence, unresolved, file: ev.file, line: ev.line };
}

function severityFor(record, evidenceOk) {
  const cls = record.class;
  const entry = (record.claim && record.claim.entry) || {};
  const entryKind = String(entry.kind || '');
  if (!evidenceOk) return { level: 'low', rationale: 'evidence unresolved; not reportable as a vulnerability' };
  if ((cls === 'P1' || cls === 'P2') && /ipc|napi|parser|socket|binder|sa/i.test(entryKind)) {
    return { level: 'medium', rationale: 'memory-safety candidate reachable from a system entry; static only, no dynamic confirmation' };
  }
  if (cls === 'P5' || cls === 'P8') {
    return { level: 'medium', rationale: 'authorization/logic candidate at a privileged sink; static only' };
  }
  if (cls === 'P7') return { level: 'low', rationale: 'DoS/amplification candidate; impact and bounds are not dynamically measured' };
  return { level: 'medium', rationale: 'static weak candidate; not dynamically confirmed' };
}

function remediationFor(record) {
  const cls = record.class;
  const sink = (record.claim && record.claim.sink) || {};
  const where = `${sink.file || (record.claim && record.claim.source && record.claim.source.file) || ''}:${sink.line || (record.claim && record.claim.source && record.claim.source.line) || ''}`;
  const map = {
    P1: 'validate the length/capacity on the same value before the allocation or copy; reject negative/rounded sizes',
    P2: 'tie the captured object lifetime to the async task (ownership/refcount/join) and do not release before the task completes',
    P3: 'check the producer result for null before dereference, or make the producer contract non-null',
    P4: 'check the arithmetic bound and width before allocation; use checked/size_t arithmetic',
    P5: 'add a server-side caller identity/permission/object-identity check that covers the privileged sink',
    P6: 'avoid publishing sensitive payload items, or require an explicit permission and minimize the payload',
    P7: 'add a literal cap/limiter or bounded loop and measure the resource amplification',
    P8: 'guard the state write with the applicable invariant and reject the wrong-state path'
  };
  return `${map[cls] || 'add an explicit guard before the sink'}; sink=${where}`;
}

function attackScenarioFor(record) {
  const c = record.claim || {};
  const entry = c.entry || {};
  const source = c.source || {};
  const sink = c.sink || {};
  const entryText = entry.kind || 'entry';
  const srcText = source.text || source.kind || 'attacker-influenced input';
  const sinkText = sink.text || sink.callee || sink.kind || 'privileged operation';
  return `An attacker reaching ${entryText}${entry.id ? ` (${entry.id})` : ''} can influence ${compactText(srcText, 160)} and reach ${compactText(sinkText, 160)}. This is a static T2 candidate; it is not dynamically confirmed.`;
}

function makeCard(record, resolved) {
  const c = record.claim || {};
  const v = record.verdict || {};
  const info = CLASS_INFO[record.class] || { name: record.class, cwe: null, impact: 'security-relevant behavior' };
  const loc = claimLocation(record);
  const rootCause = compactText(v.productReason || v.reason || c.productReason || c.reason || `${record.class}-static-rule`, 300);
  const findingId = `FND-${sha256([record.class, loc.repo, loc.file, loc.line, c.entry && c.entry.function, rootCause].join('|')).slice(0, 16)}`;
  const obligations = (v.obligations || c.obligations || []).map((o) => ({
    id: o.id,
    kind: o.kind || null,
    status: o.status || null,
    reason: o.reason || null
  }));
  const severity = severityFor(record, resolved.evidence.length > 0 && resolved.unresolved.length === 0);
  const dynamic = record.tier === 'T1-confirmed' && v.l5 && v.l5.result === 'confirmed';
  return {
    findingId,
    claimIds: [c.claimId].filter(Boolean),
    claimId: c.claimId || null,
    class: record.class,
    tier: record.tier,
    title: `${record.class} ${info.name} in ${c.entry && c.entry.function ? c.entry.function : (loc.file || 'unknown')}`,
    component: loc.repo || (c.entry && c.entry.repo) || null,
    repo: loc.repo || null,
    file: loc.file || null,
    line: loc.line || null,
    function: (c.entry && c.entry.function) || (c.sink && c.sink.function) || null,
    entry: c.entry ? {
      kind: c.entry.kind || null,
      id: c.entry.id || c.entry.entryKey || null,
      attackerPositions: (c.entry.entry && c.entry.entry.attacker_position) || c.entry.attackerPositions || []
    } : null,
    weakness: { type: info.name, cwe: info.cwe, rootCause },
    evidence: resolved.evidence,
    obligations,
    attackScenario: dynamic
      ? `${attackScenarioFor(record)} Dynamic confirmation: ${v.l5.sanitizer || 'sanitizer'} run ${v.l5.runId || 'n/a'}.`
      : attackScenarioFor(record),
    impact: info.impact,
    prerequisites: [
      c.entry && c.entry.kind ? `reachable ${c.entry.kind} entry` : 'reachable entry',
      record.inTarget ? 'target source' : 'non-target source'
    ],
    reproduction: {
      kind: dynamic ? 'dynamic' : 'static',
      runId: dynamic ? (v.l5.runId || null) : null,
      command: dynamic ? (v.l5.command || null) : null,
      sanitizer: dynamic ? (v.l5.sanitizer || null) : null,
      inputHash: dynamic ? (v.l5.sourceHash || null) : null
    },
    severity,
    confidence: dynamic ? 'high' : (resolved.evidence.length > 0 ? 'medium' : 'low'),
    remediation: remediationFor(record),
    references: [c.claimId, c.entry && (c.entry.id || c.entry.entryKey)].filter(Boolean),
    origin: c.origin || (c.productionEligible ? 'target' : 'unknown'),
    productionEligible: c.productionEligible === true,
    status: resolved.evidence.length > 0 && resolved.unresolved.length === 0 ? 'reportable' : 'excluded',
    generatedAt: new Date().toISOString()
  };
}

function makeObservation(record, resolved) {
  const c = record.claim || {};
  const v = record.verdict || {};
  const loc = claimLocation(record);
  return {
    observationId: `OBS-${sha256([record.class, c.claimId, v.gapReason || v.reason || ''].join('|')).slice(0, 16)}`,
    claimId: c.claimId || null,
    class: record.class,
    tier: record.tier,
    file: loc.file || null,
    line: loc.line || null,
    function: (c.entry && c.entry.function) || null,
    reason: compactText(v.gapReason || v.reason || c.reason || 'instrumentation-gap', 300),
    missingEvidence: v.l4bGap && v.l4bGap.missingEvidence ? v.l4bGap.missingEvidence : [],
    evidence: resolved.evidence,
    status: 'observation'
  };
}

function dedupe(cards) {
  const by = new Map();
  for (const card of cards) {
    const key = [card.repo, card.file, card.line, card.function, card.class, card.weakness.rootCause].join('|');
    const prev = by.get(key);
    if (!prev) { by.set(key, card); continue; }
    prev.claimIds = [...new Set([...(prev.claimIds || []), ...(card.claimIds || [])])];
    prev.evidence = [...prev.evidence, ...(card.evidence || [])].filter((e, i, arr) => arr.findIndex((x) => x.ref === e.ref && x.file === e.file && x.line === e.line) === i);
    if (tierRank(card.tier) > tierRank(prev.tier)) prev.tier = card.tier;
    if (SEVERITY_RANK[card.severity.level] > SEVERITY_RANK[prev.severity.level]) prev.severity = card.severity;
  }
  return [...by.values()];
}

function loadGlobalL4bOverrides() {
  const file = path.join(OUT_ROOT, 'global', 'l4b', 'verdicts-refined.jsonl');
  const rows = readJsonl(file);
  return new Map(rows.map((v) => [v.claimId, v]));
}

function loadL5Overrides() {
  const file = path.join(OUT_ROOT, 'l5', 'verdicts-with-l5.jsonl');
  const rows = readJsonl(file);
  return new Map(rows.map((v) => [v.claimId, v]));
}

function buildL7(classes = CLASS_IDS, overridesArg = null) {
  const loaded = loadClassArtifacts(classes);
  const globalOverrides = loadGlobalL4bOverrides();
  const l5Overrides = overridesArg || loadL5Overrides();
  const cards = [];
  const observations = [];
  const counts = { T1: 0, T2: 0, T3: 0, T4: 0, total: 0 };
  const unresolved = [];
  const excluded = [];
  for (const baseRecord of loaded.records) {
    const g = globalOverrides.get(baseRecord.claimId);
    const l5 = l5Overrides.get(baseRecord.claimId);
    const override = l5 || g;
    const record = override
      ? {
        ...baseRecord,
        verdict: override,
        tier: normalizeTier(override.tier || baseRecord.tier || tierOfProduct(override.productVerdict)),
        productVerdict: override.productVerdict || baseRecord.productVerdict
      }
      : baseRecord;
    const shortTier = String(record.tier || '').startsWith('T1') ? 'T1'
      : String(record.tier || '').startsWith('T2') ? 'T2'
        : String(record.tier || '').startsWith('T3') ? 'T3'
          : String(record.tier || '').startsWith('T4') ? 'T4' : 'other';
    counts[shortTier] = (counts[shortTier] || 0) + 1;
    counts.total += 1;
    if (record.tier === 'T4-negative') continue;
    if (record.tier === 'T1-confirmed') {
      // T1 必须有 L5 dynamic evidence 且 promotionEligible。
      const l5 = record.verdict && record.verdict.l5;
      if (!l5 || l5.result !== 'confirmed' || !record.verdict.l5Promotion || record.verdict.l5Promotion.eligible !== true) {
        unresolved.push(`T1-without-eligible-L5:${record.claimId}`);
        continue;
      }
    }
    const resolved = resolveEvidence(record);
    const loc = claimLocation(record);
    if (TEST_PATH_RE.test(String(loc.file || ''))) {
      excluded.push({
        claimId: record.claimId,
        class: record.class,
        tier: record.tier,
        file: loc.file || null,
        line: loc.line || null,
        reason: 'test-only-path'
      });
      continue;
    }
    if (record.tier === 'T3-instrumentation-gap') {
      observations.push(makeObservation(record, resolved));
      continue;
    }
    const card = makeCard(record, resolved);
    for (const u of resolved.unresolved) unresolved.push(`${record.claimId}:${u}`);
    cards.push(card);
  }
  const deduped = dedupe(cards);
  deduped.sort((a, b) => (SEVERITY_RANK[b.severity.level] - SEVERITY_RANK[a.severity.level]) || String(a.findingId).localeCompare(String(b.findingId)));
  return {
    cards: deduped,
    observations,
    counts,
    unresolved,
    excluded,
    sourceCounts: Object.fromEntries(CLASS_IDS.map((c) => [c, loaded.records.filter((r) => r.class === c).length]))
  };
}

module.exports = { CLASS_INFO, TEST_PATH_RE, buildL7, dedupe, resolveEvidence, makeCard, severityFor };
