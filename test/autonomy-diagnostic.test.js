'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const factsLib = require('../lib/autonomy/facts');
const discovery = require('../lib/autonomy/discovery');
const diagnostic = require('../lib/autonomy/diagnostic');
const scope = require('../K/policies/autonomy-pilot-scope.json');

test('four development groups are pinned, distinct, and keep proposal out of A/B', async () => {
  const facts = factsLib.AutonomyFacts.open({ snapshot: scope.snapshotId, scope });
  const anchors = discovery.buildAnchors(facts, scope);
  const entry = anchors.entries.find((a) => a.method === 'SetPolicyAsync');
  const binding = discovery.resolveBinding(entry.entityId, { facts, scope, anchors: anchors.anchors });
  const prepared = diagnostic.prepare(facts, binding);
  assert.deepEqual(prepared.groups.map((g) => g.id), ['A', 'B', 'C', 'D']);
  assert.equal(prepared.groups[0].allowedRefs.length, 2);
  assert.ok(prepared.groups[0].allowedRefs.every((ref) => ref.startsWith('SRC:')));
  assert.equal(prepared.groups[1].input.norm, undefined);
  assert.equal(prepared.groups[2].input.norm.state, 'proposed');
  assert.equal(prepared.groups[2].input.summary.status, 'insufficient');
  assert.match(prepared.groups[3].input.caveat, /not an independent evaluator/);
  const calls = [];
  const result = await diagnostic.compare(prepared, { invoke: async (req) => {
    calls.push(req);
    return { status: 'ok', parsed: { decision: 'insufficient', evidenceRefs: [] },
      callId: `CALL:${String(calls.length).padStart(16, '0')}`, mode: 'mock', usage: {}, wallMs: 1 };
  } }, 'TASK:108bcc806d3fc6f0');
  assert.equal(result.kind, 'development-diagnostic-not-holdout');
  assert.equal(new Set(result.rows.map((r) => r.inputSha256)).size, 4);
  assert.equal(new Set(calls.map((r) => r.contextId)).size, 4);
  assert.ok(calls.every((r) => r.maxTokens === 1200));
});

test('model cannot introduce a fabricated reference or decision', () => {
  assert.deepEqual(diagnostic.score({ status: 'ok', parsed: { decision: 'supported', evidenceRefs: ['F:fake'] } }, []),
    { status: 'invalid', reason: 'unknown-evidence-refs', unknownRefs: ['F:fake'] });
  assert.equal(diagnostic.score({ status: 'ok', parsed: { decision: 'safe', evidenceRefs: [] } }, []).status, 'invalid');
  assert.equal(diagnostic.score({ status: 'ok', parsed: { decision: 'supported', evidenceRefs: ['NORM:x'] } }, ['NORM:x']).reason, 'no-primary-evidence');
  assert.equal(diagnostic.score({ status: 'error', reason: 'rate-limit' }, []).status, 'unavailable');
});
