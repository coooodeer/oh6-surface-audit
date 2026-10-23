'use strict';

const ids = require('./ids');
const knowledgeLib = require('./knowledge');
const summaries = require('./summaries');
const vertical = require('./vertical');

const PROPOSITION = 'In the bounded SandboxManagerService::SetPolicy excerpt, is a calling-token CheckPermission followed by an early failure return before the policy-setting callsite? This does not establish end-to-end authorization.';
const SYSTEM = 'Return only JSON with decision (supported|refuted|insufficient|conflict), evidenceRefs (array of supplied IDs), and short rationale. Decide only the local proposition. A call name does not establish its exact target, execution path, norm applicability, or runtime outcome.';

function prepare(facts, binding) {
  if (binding.binding !== 'resolved' || !binding.bound) throw new Error('diagnostic-binding-unresolved');
  const local = vertical.selectEvidence(facts, binding.bound);
  if (local.status !== 'observed') throw new Error(`diagnostic-${local.reason}`);
  const knowledge = knowledgeLib.loadAuthorization(facts);
  const summary = summaries.resolve(new Map(), local, knowledge.knowledgeVersion, facts.snapshotId);
  const refs = [...new Set([local.edgeRef, local.calleeRef, ...local.checkRefs,
    ...local.operationCallsites.map((c) => c.ref)])].sort();
  const sourceRefs = [
    `SRC:${ids.sha256Hex(ids.canonicalJson(local.entry)).slice(0, 16)}`,
    `SRC:${ids.sha256Hex(ids.canonicalJson({ ...local.callee, text: local.text })).slice(0, 16)}`
  ];
  const raw = { proposition: PROPOSITION, entry: { ...local.entry, ref: sourceRefs[0] },
    callee: { ...local.callee, text: local.text, ref: sourceRefs[1] }, allowedRefs: sourceRefs };
  const structured = { ...raw, edgeRef: local.edgeRef, checkRefs: local.checkRefs,
    operationCallsites: local.operationCallsites, parseQuality: local.parseQuality,
    unresolvedCalls: local.unresolvedCalls, allowedRefs: [...sourceRefs, ...refs] };
  const groups = [
    { id: 'A', input: raw, allowedRefs: sourceRefs },
    { id: 'B', input: structured, allowedRefs: [...sourceRefs, ...refs] },
    { id: 'C', input: { ...structured, norm: knowledge.norm, summary,
      caveat: 'Norm is proposed, not published; the summary is bounded and insufficient.' },
    allowedRefs: [...sourceRefs, ...refs, knowledge.norm.normId, summary.summaryId] },
    { id: 'D', input: { proposition: PROPOSITION, verifiedLocalExcerpt: local.text,
      source: local.callee, checkRefs: local.checkRefs, operationCallsites: local.operationCallsites,
      caveat: 'Program-curated source for the local proposition only; not an independent evaluator oracle or sufficient for the full authorization claim.',
      allowedRefs: refs }, allowedRefs: refs }
  ];
  return { snapshotId: facts.snapshotId, knowledgeVersion: knowledge.knowledgeVersion,
    sourceHashes: { entry: local.entry.sha256, callee: local.callee.sha256 }, groups };
}

function score(call, allowedRefs) {
  if (call.status !== 'ok' || !call.parsed) return { status: 'unavailable', reason: call.reason };
  const p = call.parsed;
  if (!['supported', 'refuted', 'insufficient', 'conflict'].includes(p.decision) ||
      !Array.isArray(p.evidenceRefs) || p.evidenceRefs.length > 20 ||
      p.evidenceRefs.some((ref) => typeof ref !== 'string')) {
    return { status: 'invalid', reason: 'bad-decision-or-reference-shape' };
  }
  const unknownRefs = p.evidenceRefs.filter((ref) => !allowedRefs.includes(ref));
  if (unknownRefs.length) return { status: 'invalid', reason: 'unknown-evidence-refs',
    unknownRefs: unknownRefs.map((ref) => String(ref).slice(0, 120)) };
  if (['supported', 'refuted'].includes(p.decision) &&
      !p.evidenceRefs.some((ref) => ref.startsWith('SRC:') || ref.startsWith('F:'))) {
    return { status: 'invalid', reason: 'no-primary-evidence' };
  }
  return { status: 'recorded', decision: p.decision, evidenceRefs: p.evidenceRefs,
    rationale: String(p.rationale || '').slice(0, 400) };
}

async function compare(prepared, gateway, taskId, maxTokens = 1200) {
  const rows = [];
  for (const group of prepared.groups) {
    const contextId = ids.contextId('diagnostic', { snapshotId: prepared.snapshotId,
      group: group.id, input: group.input });
    const call = await gateway.invoke({ purpose: `diagnostic-${group.id}`, taskId, contextId,
      maxTokens, messages: [{ role: 'system', content: SYSTEM },
        { role: 'user', content: JSON.stringify(group.input) }] });
    rows.push({ group: group.id, contextId, inputSha256: ids.sha256Hex(ids.canonicalJson(group.input)),
      callId: call.callId, model: call.model, mode: call.mode, wallMs: call.wallMs, usage: call.usage,
      responseSha256: call.contentSha256, finishReason: call.finishReason,
      result: score(call, group.allowedRefs) });
  }
  return { kind: 'development-diagnostic-not-holdout', proposition: PROPOSITION,
    snapshotId: prepared.snapshotId, knowledgeVersion: prepared.knowledgeVersion,
    sourceHashes: prepared.sourceHashes, maxTokens, rows };
}

module.exports = { prepare, compare, score, PROPOSITION };
