'use strict';

const ids = require('./ids');

function resolve(cache, local, knowledgeVersion, snapshotId) {
  const key = local.calleeRef;
  const deps = {
    snapshotId, knowledgeVersion,
    calleeSha256: local.callee.sha256,
    checkRefs: local.checkRefs,
    operationRefs: local.operationCallsites.map((c) => c.ref),
    operationCandidates: local.operationCandidates || []
  };
  const fingerprint = ids.sha256Hex(ids.canonicalJson(deps));
  const previous = cache.get(key);
  if (previous && previous.fingerprint === fingerprint) {
    return { ...previous, cacheHit: true };
  }
  const answer = {
    summaryId: `SUM:${ids.sha256Hex(ids.canonicalJson({ key, fingerprint })).slice(0, 16)}`,
    scope: 'one exact delegate and its direct calls',
    basis: 'derived',
    assurance: 'bounded-analysis',
    status: 'insufficient',
    observation: local.checkRefs.length
      ? 'callee contains an exact check call; effectiveness and target resolution remain open'
      : 'no exact check call was observed in this bounded query',
    dependencies: deps,
    fingerprint
  };
  cache.set(key, answer);
  return { ...answer, cacheHit: false };
}

module.exports = { resolve };
