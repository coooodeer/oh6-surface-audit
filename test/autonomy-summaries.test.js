'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const summaries = require('../lib/autonomy/summaries');

function local(sha = 'first') {
  return { calleeRef: 'F:callee', edgeRef: 'F:edge', entry: { sha256: sha },
    callee: { sha256: sha }, checkRefs: ['F:check'],
    operationCallsites: [{ ref: 'F:operation', resolution: 'name-only' }] };
}

test('bounded answer is reused only while source, norm and snapshot dependencies match', () => {
  const cache = new Map();
  const first = summaries.resolve(cache, local(), 'K:one', 'S:one');
  const hit = summaries.resolve(cache, local(), 'K:one', 'S:one');
  assert.equal(first.cacheHit, false);
  assert.equal(hit.cacheHit, true);
  assert.equal(hit.summaryId, first.summaryId);
  assert.equal(hit.status, 'insufficient');
  const otherEntry = { ...local(), entry: { sha256: 'different-entry' }, edgeRef: 'F:other-edge' };
  assert.equal(summaries.resolve(cache, otherEntry, 'K:one', 'S:one').cacheHit, true);
  assert.equal(summaries.resolve(cache, otherEntry, 'K:one', 'S:one').assurance, 'bounded-analysis');
  assert.equal(summaries.resolve(cache, local('changed'), 'K:one', 'S:one').cacheHit, false);
  assert.equal(summaries.resolve(cache, local('changed'), 'K:changed', 'S:one').cacheHit, false);
  assert.equal(summaries.resolve(cache, local('changed'), 'K:changed', 'S:changed').cacheHit, false);
});
