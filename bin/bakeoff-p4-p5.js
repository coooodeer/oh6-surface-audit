'use strict';

/**
 * bakeoff-p4-p5.js —— P4 vs P5 的结构性义务闭合率 bake-off。
 *
 * 只读候选与入口契约，不调用模型、不做动态。
 * 同一 6 条义务模板：
 *   O1 entry-resolved
 *   O2 sink-resolved
 *   O3 class-fact
 *   O4 type-or-impl-resolved
 *   O5 check-or-guard
 *   O6 oracle
 *
 * 输出：out/bakeoff/{p4,p5}.jsonl、summary.json、report.md
 */

const fs = require('fs');
const path = require('path');
const { TOOL_ROOT, OUT_ROOT, readJsonl, writeJsonl, writeJson, ensureDir } = require('../lib/util.js');

const CANDIDATES = path.join(TOOL_ROOT, '..', 'oh6-vuln-agent', 'result', 'latest', 'candidates.jsonl');
const ENTRIES = path.join(TOOL_ROOT, '..', 'oh6-vuln-agent', 'result', 'latest', 'contracts', 'entries.jsonl');
const OUT = path.join(OUT_ROOT, 'bakeoff');

const o = (status, evidence, reason) => ({ status, evidence, ...(reason ? { reason } : {}) });
const has = (arr, x) => Array.isArray(arr) && arr.includes(x);

function pickP4(rows) {
  return rows.filter((r) => r.generator === 'G-P4').slice(0, 10);
}

function pickP5(rows) {
  return rows
    .filter((r) => r.generator === 'G-P5' && (r.entryIds || []).length === 1)
    .sort((a, b) => (b.signal.codeCount || 0) - (a.signal.codeCount || 0) || a.candidateId.localeCompare(b.candidateId))
    .slice(0, 10);
}

function evalP4(r) {
  const s = r.signal || {};
  const b = r.binding || {};
  const g = s.detectionGate || {};
  const obligations = [
    { id: 'O1', kind: 'entry-resolved', ...o(b.status === 'verified' ? 'proven' : 'unproven', { binding: b.status || null, entryBinding: s.entryBinding || null }, b.status === 'suspect' ? 'binding-suspect' : undefined) },
    { id: 'O2', kind: 'sink-resolved', ...o(r.origin && r.origin.line && s.sizeExpr ? 'proven' : 'unproven', { line: r.origin && r.origin.line, sizeExpr: s.sizeExpr || null }) },
    { id: 'O3', kind: 'class-fact', ...o(s.sizeExprArith && (s.widthMix || []).length ? 'proven' : 'unproven', { sizeExprArith: !!s.sizeExprArith, widthMix: s.widthMix || [] }) },
    { id: 'O4', kind: 'type-or-impl-resolved', ...o('unproven', { widthMix: s.widthMix || [], explicitCast: s.explicitCast }, 'type-width-not-proven') },
    { id: 'O5', kind: 'check-or-guard', ...o(s.boundCheckInWindow === false ? 'disproven' : (s.boundCheckInWindow === true ? 'proven' : 'unproven'), { boundCheckInWindow: s.boundCheckInWindow, basis: s.boundCheckBasis || null }, s.boundCheckInWindow === false ? 'no-bound-check-in-window' : undefined) },
    { id: 'O6', kind: 'oracle', ...o(g.requiresStage === 'dynamic' ? 'unproven' : 'unproven', { detectionGate: g.id || null, requiresStage: g.requiresStage || null }, 'dynamic-not-run') }
  ];
  return { candidateId: r.candidateId, class: 'P4', origin: r.origin, binding: b.status || null, facts: { sizeExpr: s.sizeExpr, widthMix: s.widthMix, boundCheckInWindow: s.boundCheckInWindow, detectionGate: g }, obligations };
}

function evalP5(r, entry) {
  const s = r.signal || {};
  const b = r.binding || {};
  const checks = entry && entry.required_checks ? entry.required_checks : [];
  const implResolved = !!(r.origin && (r.origin.implFile || r.origin.pairingFile)) || !!s.pathScoped || (s.checkSitesOnImplPath || 0) > 0;
  const obligations = [
    { id: 'O1', kind: 'entry-resolved', ...o(entry && entry.evidence && entry.evidence.verified && (b.status === 'verified' || b.status === 'resolved') ? 'proven' : 'unproven', { binding: b.status || null, entryVerified: !!(entry && entry.evidence && entry.evidence.verified) }, entry ? 'candidate-binding-not-verified' : 'entry-not-found') },
    { id: 'O2', kind: 'sink-resolved', ...o(r.origin && r.origin.harness && r.origin.harness.line ? 'proven' : 'unproven', { idlLine: r.origin && r.origin.harness && r.origin.harness.line }) },
    { id: 'O3', kind: 'class-fact', ...o(has(checks, 'token-permission') ? 'proven' : 'unproven', { requiredChecks: checks }, has(checks, 'token-permission') ? undefined : 'token-permission-not-required') },
    { id: 'O4', kind: 'type-or-impl-resolved', ...o(implResolved ? 'proven' : 'unproven', { implFile: r.origin && r.origin.implFile, pathScoped: !!s.pathScoped, checkSitesOnImplPath: s.checkSitesOnImplPath || 0 }, implResolved ? undefined : 'pairing-unresolved') },
    { id: 'O5', kind: 'check-or-guard', ...o((s.checkSitesOnImplPath || 0) > 0 ? 'proven' : (s.noCheckOnImplPath === true ? 'disproven' : 'unproven'), { checkSitesOnImplPath: s.checkSitesOnImplPath || 0, noCheckOnImplPath: s.noCheckOnImplPath, codeCount: s.codeCount || 0 }, 'check-not-path-scoped') },
    { id: 'O6', kind: 'oracle', ...o('unproven', { oracle: 'none' }, 'no-static-oracle') }
  ];
  return { candidateId: r.candidateId, class: 'P5', origin: r.origin, binding: b.status || null, facts: { entryId: r.entryId, entryReachability: entry && entry.reachability, implFile: r.origin && r.origin.implFile, codeCount: s.codeCount, checkSitesOnImplPath: s.checkSitesOnImplPath }, obligations };
}

function summarize(rows) {
  const c = { proven: 0, disproven: 0, unproven: 0, invalid: 0, total: 0 };
  for (const r of rows) for (const o of r.obligations) { c.total += 1; c[o.status] = (c[o.status] || 0) + 1; }
  const closure = c.total ? (c.proven + c.disproven) / c.total : 0;
  return { ...c, closure, unprovenRate: c.total ? c.unproven / c.total : 0 };
}

function main() {
  ensureDir(OUT);
  const all = readJsonl(CANDIDATES);
  const entryById = new Map(readJsonl(ENTRIES).map((e) => [e.id, e]));
  const p4rows = pickP4(all).map(evalP4);
  const p5rows = pickP5(all).map((r) => evalP5(r, entryById.get(r.entryId)));
  writeJsonl(path.join(OUT, 'p4.jsonl'), p4rows);
  writeJsonl(path.join(OUT, 'p5.jsonl'), p5rows);
  const summary = {
    generatedAt: new Date().toISOString(),
    method: 'structural-only; no LLM, no dynamic',
    template: ['entry-resolved', 'sink-resolved', 'class-fact', 'type-or-impl-resolved', 'check-or-guard', 'oracle'],
    p4: { candidates: p4rows.length, ...summarize(p4rows) },
    p5: { candidates: p5rows.length, ...summarize(p5rows) }
  };
  writeJson(path.join(OUT, 'summary.json'), summary);
  const lines = [];
  lines.push('# P4 vs P5 bake-off（结构性义务闭合率）');
  lines.push('');
  lines.push(`生成时间：${summary.generatedAt}`);
  lines.push('方法：只读候选/入口契约；同一 6 条义务模板；不调用模型、不做动态。');
  lines.push('');
  lines.push('| 类 | 样本 | proven | disproven | unproven | closure | unprovenRate |');
  lines.push('| --- | ---: | ---: | ---: | ---: | ---: | ---: |');
  for (const k of ['p4', 'p5']) {
    const s = summary[k];
    lines.push(`| ${k.toUpperCase()} | ${s.candidates} | ${s.proven} | ${s.disproven} | ${s.unproven} | ${s.closure.toFixed(3)} | ${s.unprovenRate.toFixed(3)} |`);
  }
  lines.push('');
  lines.push('## 口径');
  lines.push('');
  lines.push('- O1 要求 candidate binding 已 verified/resolved；P4 11/11 suspect、P5 单入口候选 pairing 全 unresolved，因此 O1 均 unproven。');
  lines.push('- O2/O3 用局部事实：P4 有 sizeExpr/widthMix；P5 有 IDL 行与 required_checks。');
  lines.push('- O4 要求类型或实现解析；P4 widthMix 不等于类型，P5 implFile/path/check 均无。');
  lines.push('- O5：P4 是“窗口内无 bound check”，只能算结构性 disproven；P5 没有 path-scoped check。');
  lines.push('- O6：P4 依赖 L5 UBSan，P5 无 oracle，均 unproven。');
  lines.push('');
  lines.push('## 结论');
  lines.push('');
  lines.push(summary.p4.unprovenRate <= summary.p5.unprovenRate
    ? 'P4 的 unprovenRate 不高于 P5；当前数据下 P4 仍是更可闭合的扩展。P5 需要先补 impl/pairing 才能竞争。'
    : 'P5 的 unprovenRate 低于 P4；但仍需检查其 O1/O4 是否只是“入口存在”而实现未闭合。');
  ensureDir(path.join(OUT_ROOT, 'report'));
  fs.writeFileSync(path.join(OUT_ROOT, 'report', 'bakeoff-p4-p5.md'), lines.join('\n'), 'utf8');
  process.stdout.write(`bakeoff: P4 closure=${summary.p4.closure.toFixed(3)} unproven=${summary.p4.unprovenRate.toFixed(3)}; P5 closure=${summary.p5.closure.toFixed(3)} unproven=${summary.p5.unprovenRate.toFixed(3)}\n`);
}

main();
