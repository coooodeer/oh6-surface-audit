'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { buildL7, TEST_PATH_RE, makeCard } = require('../lib/l7/model.js');
const { renderCard } = require('../lib/l7/render.js');

test('L7: T2 cards and T3 observations, no T1 / no test-path cards', () => {
  const r = buildL7();
  assert.ok(r.cards.length > 0);
  assert.ok(r.observations.length > 0);
  assert.equal(r.counts.T1, 0);
  assert.ok(r.cards.every((c) => String(c.tier || '').startsWith('T2')));
  assert.ok(r.observations.every((o) => o.tier === 'T3-instrumentation-gap'));
  assert.ok(r.cards.every((c) => !TEST_PATH_RE.test(String(c.file || ''))));
  assert.ok(r.excluded.every((e) => e.reason === 'test-only-path'));
  assert.equal(r.unresolved.length, 0);
  assert.equal(new Set(r.cards.flatMap((c) => c.claimIds)).size + r.excluded.filter((e) => e.tier.startsWith('T2')).length, r.counts.T2);
});

test('L7: card has resolvable file:line, evidence, severity and remediation', () => {
  const r = buildL7();
  const card = r.cards[0];
  assert.ok(card.findingId.startsWith('FND-'));
  assert.ok(card.file);
  assert.ok(card.line > 0);
  assert.ok(card.evidence.length > 0);
  assert.ok(card.severity.level && card.severity.rationale);
  assert.ok(card.remediation.length > 10);
  const md = renderCard(card);
  assert.match(md, /## 证据/);
  assert.match(md, /## 修复建议/);
  assert.match(md, new RegExp(`${card.file.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}:${card.line}`));
});

test('L7: T1 card requires dynamic reproduction', () => {
  const record = {
    class: 'P4',
    tier: 'T1-confirmed',
    claim: {
      claimId: 'P4-t1-test',
      entry: { kind: 'ipc-remote', id: 'EN-TEST', repo: 'base/account/os_account', file: 'x.cpp', function: 'F' },
      source: { file: 'x.cpp', line: 10, text: 'int x = f();' },
      sink: { file: 'x.cpp', line: 11, text: 'use(x);' }
    },
    verdict: {
      claimId: 'P4-t1-test',
      productVerdict: 'PROVEN-VULN',
      l5: { result: 'confirmed', runId: 'run-1', sanitizer: 'ubsan', sourceHash: 'abc' },
      l5Promotion: { eligible: true },
      obligations: [{ id: 'O10', status: 'proven' }]
    }
  };
  const card = makeCard(record, {
    evidence: [{ ref: 'E1:L10', file: 'x.cpp', line: 10, text: 'int x = f();', source: 'L1/L4a' }],
    unresolved: [],
    file: 'x.cpp',
    line: 10
  });
  assert.equal(card.tier, 'T1-confirmed');
  assert.equal(card.reproduction.kind, 'dynamic');
  assert.equal(card.reproduction.runId, 'run-1');
  assert.equal(card.confidence, 'high');
});

test('L7: buildL7 consumes L5 promoted T1 override', () => {
  const r = buildL7();
  const p4 = r.cards.find((c) => c.class === 'P4') || r.observations.find((o) => o.class === 'P4');
  assert.ok(p4, 'missing P4 record');
  const claimId = p4.claimId;
  const override = {
    claimId,
    class: 'P4',
    tier: 'T1-confirmed',
    productVerdict: 'PROVEN-VULN',
    l5: { result: 'confirmed', runId: 'synthetic-run', sanitizer: 'ubsan', sourceHash: 'abc' },
    l5Promotion: { eligible: true },
    obligations: [{ id: 'O10', status: 'proven' }]
  };
  const withT1 = buildL7(undefined, new Map([[claimId, override]]));
  const card = withT1.cards.find((c) => c.claimId === claimId);
  assert.ok(card, 'T1 override did not produce a card');
  assert.equal(card.tier, 'T1-confirmed');
  assert.equal(card.reproduction.kind, 'dynamic');
  assert.equal(card.reproduction.runId, 'synthetic-run');
});
