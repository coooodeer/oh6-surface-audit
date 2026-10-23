'use strict';

/** One bounded, entity-resolved hop. A check call is evidence to investigate, not proof of authorization. */
function inspect(facts, bound, vocabulary = {}, limit = 8) {
  const idx = facts.index();
  const calls = facts.callsOf(bound.qualified || bound.name, { limit: 101 });
  const byId = new Map(idx.functions.map((fn) => [fn.factId, fn]));
  const edges = calls.filter((c) => c.callee && c.quality && c.quality.resolution === 'exact');
  const unresolvedEdges = calls.length - edges.length;
  const partial = idx.truncated.calls || calls.length >= 101 || edges.length > limit || unresolvedEdges > 0;
  const delegates = [];
  const refs = [];
  const strong = vocabulary.strong || [];

  for (const edge of edges.slice(0, limit)) {
    const fn = byId.get(edge.callee);
    if (!fn || fn.factId === bound.factId) continue;
    const file = fn.sourceRange && fn.sourceRange.file;
    const verified = file && facts.verifyFile(file);
    if (!verified || !verified.ok) {
      delegates.push({ edgeRef: edge.factId, calleeRef: edge.callee, checkRefs: [], status: 'stale-or-unresolved' });
      continue;
    }
    const nextCalls = facts.callsOf(fn.qualified || fn.name, { limit: 101 });
    const checks = nextCalls.filter((c) => strong.some((name) => String(c.calleeName || '').includes(name)));
    delegates.push({
      edgeRef: edge.factId,
      calleeRef: fn.factId,
      name: fn.qualified || fn.name,
      file,
      line: fn.startLine,
      checkRefs: checks.map((c) => c.factId).filter(Boolean).sort(),
      status: nextCalls.length >= 101 ? 'truncated' : (checks.length ? 'check-observed' : 'no-direct-check')
    });
    refs.push(edge.factId, fn.factId, ...checks.map((c) => c.factId));
  }

  return {
    delegates,
    evidenceRefs: [...new Set(refs.filter(Boolean))].sort(),
    partial: partial || delegates.some((d) => d.status === 'stale-or-unresolved' || d.status === 'truncated'),
    scannedEdges: Math.min(edges.length, limit),
    unresolvedEdges
  };
}

module.exports = { inspect };
