'use strict';

/**
 * p5-l4b.js —— P5 有界语义判定（只判 check 是否覆盖 sink/对象）。
 *
 * 输入：P5 claim + paths 中的 server check 列表。
 * 输出：每个 check 的 covers=yes|no|unknown；程序聚合后只改 O7，不直接改最终 verdict。
 */

const fs = require('fs');
const path = require('path');
const { OUT_ROOT, ensureDir, readJsonl, writeJsonl, writeJson } = require('./util.js');
const l4b = require('./l4b.js');
const { p5Verdict, productForP5 } = require('./prover-p5.js');

const LOG_FILE = path.join(OUT_ROOT, '..', 'logs', 'p5-l4b.jsonl');

function checkItems(claim, pathInfo) {
  const items = [];
  const seen = new Set();
  for (const c of (pathInfo && pathInfo.checks) || []) {
    if (c.side !== 'server') continue;
    const key = `${c.file}:${c.line}:${c.kind}`;
    if (seen.has(key)) continue;
    seen.add(key);
    items.push({ check: key, file: c.file, line: c.line, kind: c.kind, text: c.text || '', permissions: c.permissions || [] });
  }
  return items;
}

function evidenceFor(claim, items, l1, shortEvidence = false) {
  const evidence = [];
  let n = 1;
  const sinkLine = claim.sink && claim.sink.line;
  const sinkFile = claim.sink && claim.sink.file;
  if (sinkFile && sinkLine) {
    evidence.push({ ref: `E${n++}:L${sinkLine}`, file: sinkFile, line: sinkLine, label: 'sink', text: l1.lineAt(claim.entry.repo, sinkFile, sinkLine) || '' });
    if (!shortEvidence) {
      for (let ln = Math.max(1, sinkLine - 2); ln <= sinkLine + 2; ln += 1) {
        if (ln === sinkLine) continue;
        evidence.push({ ref: `E${n++}:L${ln}`, file: sinkFile, line: ln, label: 'sink-context', text: l1.lineAt(claim.entry.repo, sinkFile, ln) || '' });
      }
    }
  }
  for (const it of items) {
    const text = l1.lineAt(claim.entry.repo, it.file, it.line) || it.text;
    evidence.push({ ref: `E${n++}:L${it.line}`, file: it.file, line: it.line, label: `check:${it.kind}`, text });
  }
  return evidence;
}

function buildP5Pack(claim, pathInfo, l1, opts = {}) {
  const items = checkItems(claim, pathInfo).slice(0, Number(opts.maxChecks || 1));
  const evidence = evidenceFor(claim, items, l1, opts.shortEvidence !== false);
  return {
    id: `L4B-P5-${claim.claimId.replace(/^L3-P5-/, '')}`,
    kind: 'P5',
    claimId: claim.claimId,
    unitId: claim.unitId,
    repo: claim.entry.repo,
    interface: claim.entry.interface,
    method: claim.entry.method,
    sink: claim.sink,
    obligations: claim.obligations.map((o) => ({ id: o.id, status: o.status, reason: o.reason || null, evidence: o.evidence })),
    items: items.map((i) => i.check),
    itemDetails: items,
    evidence,
    refs: evidence.map((e) => e.ref),
    schema: '{"checks":[{"check":"<file:line:kind>","covers":"yes|no|unknown","evidenceRef":"E1:L88"}],"reason":"<=2 句","evidenceRefs":["E1:L88"]}',
    ask: '每个检查是否覆盖该 claim 的 sink 与目标对象（不是 client/NAPI 检查，不是只检查无关对象）？'
  };
}

function buildMessages(pack) {
  const system = [
    '你是 OpenHarmony IPC 权限/身份检查复核器。只依据给定证据判断每个 check 是否覆盖该 sink 与目标对象。',
    '只有 server 侧、在 sink 前、使用 caller 身份或目标对象的检查才算覆盖；client/NAPI、无关对象、sink 后检查不算。',
    '证据不足标 unknown。只输出 JSON，不要 Markdown。schema：',
    pack.schema
  ].join('\n');
  const user = [
    `interface: ${pack.interface}`,
    `method: ${pack.method}`,
    `sink: ${pack.sink.file}:${pack.sink.line} ${pack.sink.functionName || ''}`,
    `checks: ${JSON.stringify(pack.itemDetails.map((i) => ({ check: i.check, kind: i.kind, text: i.text })))}`,
    '',
    '证据：',
    ...pack.evidence.map((e) => `${e.ref} [${e.label}] ${e.file}:${e.line} ${e.text}`),
    '',
    `问题：${pack.ask}`,
    `请逐 check 返回：${JSON.stringify(pack.items)}`
  ].join('\n');
  return [{ role: 'system', content: system }, { role: 'user', content: messagesBody(pack) }];
}

function messagesBody(pack) {
  return [
    `interface: ${pack.interface}`,
    `method: ${pack.method}`,
    `sink: ${pack.sink.file}:${pack.sink.line} ${pack.sink.functionName || ''}`,
    `checks: ${JSON.stringify(pack.itemDetails.map((i) => ({ check: i.check, kind: i.kind, text: i.text })))}`,
    '',
    '证据：',
    ...pack.evidence.map((e) => `${e.ref} [${e.label}] ${e.file}:${e.line} ${e.text}`),
    '',
    `问题：${pack.ask}`,
    `请逐 check 返回：${JSON.stringify(pack.items)}`
  ].join('\n');
}

function validateP5(obj, pack) {
  const errors = [];
  if (!obj || !Array.isArray(obj.checks) || !obj.checks.length) errors.push('checks-empty');
  if (typeof obj.reason !== 'string') errors.push('reason-not-string');
  const allowed = new Set(pack.items);
  const seen = new Set();
  for (const c of obj.checks || []) {
    if (!c || typeof c.check !== 'string') { errors.push('check-name-missing'); continue; }
    if (!allowed.has(c.check)) errors.push(`unknown-check:${c.check}`);
    if (seen.has(c.check)) errors.push(`duplicate-check:${c.check}`);
    seen.add(c.check);
    if (!['yes', 'no', 'unknown'].includes(c.covers)) errors.push(`bad-covers:${c.check}`);
    if (!/^E\d+:L\d+$/.test(String(c.evidenceRef || ''))) errors.push(`bad-evidenceRef:${c.check}`);
    else if (!pack.refs.includes(c.evidenceRef)) errors.push(`evidenceRef-not-in-pack:${c.check}`);
  }
  if (!Array.isArray(obj.evidenceRefs) || !obj.evidenceRefs.length) errors.push('evidenceRefs-empty');
  else if (obj.evidenceRefs.some((r) => !pack.refs.includes(r))) errors.push('evidenceRefs-not-in-pack');
  return { ok: errors.length === 0, errors };
}

function aggregate(obj) {
  const checks = (obj && obj.checks) || [];
  const yes = checks.filter((c) => c.covers === 'yes').map((c) => c.check);
  const no = checks.filter((c) => c.covers === 'no').map((c) => c.check);
  const unknown = checks.filter((c) => c.covers === 'unknown').map((c) => c.check);
  return { yes, no, unknown, covers: yes.length ? 'yes' : (unknown.length ? 'unknown' : 'no') };
}

async function judgePack(pack, transport, opts = {}) {
  const messages = buildMessages(pack);
  const timeoutMs = Number(opts.timeoutMs || 60000);
  let timer = null;
  const res = await Promise.race([
    transport.send({ unitId: pack.id, attempt: 1, messages, maxTokens: opts.maxTokens || 2048 }),
    new Promise((resolve) => {
      timer = setTimeout(() => resolve({ kind: 'timeout', reason: `p5-review-timeout-${timeoutMs}ms` }), timeoutMs);
    })
  ]);
  if (timer) clearTimeout(timer);
  const row = {
    ts: new Date().toISOString(),
    unitId: pack.id,
    kind: 'P5',
    attempt: 1,
    transportKind: res.kind,
    promptTokens: (res.usage && res.usage.promptTokens) || 0,
    completionTokens: (res.usage && res.usage.completionTokens) || 0,
    contentHash: res.content ? l4b.sha(res.content) : null,
    schemaOk: false
  };
  if (res.kind !== 'ok') return { ok: false, blocked: true, reason: res.kind, log: [row] };
  let parsed;
  let errors;
  try {
    parsed = l4b.parseJsonContent(res.content);
    errors = validateP5(parsed, pack).errors;
  } catch (e) {
    errors = [`parse:${e.message}`];
  }
  row.schemaOk = errors.length === 0;
  if (errors.length) row.schemaErrors = errors.slice(0, 5);
  return { ok: errors.length === 0, parsed, aggregate: errors.length ? null : aggregate(parsed), errors, log: [row] };
}

function selectP5L4bClaims(claims, paths, n = 10) {
  const pathBy = new Map(paths.map((p) => [p.unitId, p]));
  const withChecks = claims.filter((c) => {
    const p = pathBy.get(c.unitId);
    return p && p.checks.some((x) => x.side === 'server');
  });
  const t3 = withChecks.filter((c) => c.productVerdict === 'CONDITIONS-NOT-MET');
  const sat = withChecks.filter((c) => c.claimVerdict === 'SATISFIED');
  const chosen = [...t3, ...sat];
  const seen = new Set();
  const out = [];
  for (const c of chosen) {
    if (seen.has(c.claimId)) continue;
    seen.add(c.claimId);
    out.push(c);
    if (out.length >= n) break;
  }
  for (const c of withChecks) {
    if (out.length >= n) break;
    if (seen.has(c.claimId)) continue;
    seen.add(c.claimId);
    out.push(c);
  }
  return { claims: out, t3: out.filter((c) => c.productVerdict === 'CONDITIONS-NOT-MET').length, satisfied: out.filter((c) => c.claimVerdict === 'SATISFIED').length };
}

function applyP5L4b(claim, result) {
  const out = { ...claim, obligations: claim.obligations.map((o) => ({ ...o, evidence: { ...(o.evidence || {}) } })) };
  if (!result || !result.ok) return out;
  const o7 = out.obligations.find((o) => o.id === 'O7');
  if (!o7 || (o7.status !== 'unproven' && o7.status !== 'proven' && o7.status !== 'disproven')) return out;
  // 显式 permission/system-app 检查是确定性证据，不允许模型覆盖。
  if (o7.status === 'proven' && ((o7.evidence && o7.evidence.explicitChecks) || []).length > 0) return out;
  const agg = result.aggregate;
  o7.evidence = { ...(o7.evidence || {}), p5L4b: agg };
  if (agg.covers === 'yes') { o7.status = 'proven'; o7.reason = 'l4b-check-covers-sink'; }
  else if (agg.covers === 'no') { o7.status = 'disproven'; o7.reason = 'l4b-check-does-not-cover-sink'; }
  const v = p5Verdict(out.obligations);
  const p = productForP5(v.claimVerdict, out.obligations, { impact: out.impact });
  out.claimVerdict = v.claimVerdict;
  out.reason = v.reason;
  out.productVerdict = p.productVerdict;
  out.productReason = p.reason;
  return out;
}

module.exports = { LOG_FILE, buildP5Pack, buildMessages, validateP5, aggregate, judgePack, selectP5L4bClaims, applyP5L4b };
