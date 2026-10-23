'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const factsLib = require('../lib/autonomy/facts');
const branch = require('../lib/autonomy/branch');
const scope = require('../K/policies/autonomy-pilot-scope.json');

test('a name-only parser call admits an input-boundary branch, not a proven target', () => {
  const facts = factsLib.AutonomyFacts.open({ snapshot: scope.snapshotId, scope });
  const parent = { taskId: 'TASK:108bcc806d3fc6f0', anchorRefs: ['ENT:2205b0adf9f58c1f'] };
  const vertical = { status: 'observation', parserTypeHint: true, parserCallsites: [{ ref: 'F:parser-call',
    line: 391, resolution: 'name-only' }] };
  const out = branch.proposeInputBoundary(vertical, parent, facts);
  assert.equal(out.task.origin, 'analysis-branch');
  assert.equal(out.view, 'input-boundary');
  assert.equal(out.candidate.binding, 'type-hint-only');
  assert.equal(out.question.status, 'unknown');
  assert.equal(branch.proposeInputBoundary({ ...vertical, parserCallsites: [] }, parent, facts), null);
});
