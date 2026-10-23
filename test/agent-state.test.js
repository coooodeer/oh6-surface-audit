'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const readJson = (p) => JSON.parse(fs.readFileSync(p, 'utf8'));
const state = readJson(path.join(ROOT, 'out', 'report', 'agent-state.json'));

test('unified agent state: 6 campaigns, 70 gates, all pass', () => {
  assert.equal(state.schemaVersion, 1);
  assert.equal(state.overall.allPass, true);
  assert.equal(state.overall.status, 'PASS');
  assert.equal(state.overall.campaignCount, 6);
  assert.equal(state.overall.campaignsPassed, 6);
  assert.equal(state.overall.gates.total, 70);
  assert.equal(state.overall.gates.passed, 70);
  assert.equal(state.overall.gates.failed, 0);
  assert.equal(state.consistency.ok, true);
  assert.deepEqual(state.consistency.issues, []);
});

test('unified agent state: campaign gate counts are 20/15/13/5/8/8', () => {
  const expected = { p3p4p6: 20, p5: 13, p1p2p7p8: 15, 'global-l4b': 5, l5: 8, l7: 8 };
  for (const c of state.campaigns) {
    assert.equal(c.pass, true, c.id);
    assert.equal(c.status, 'PASS', c.id);
    assert.equal(c.gateCount, expected[c.id], c.id);
    assert.equal(c.passedGates, expected[c.id], c.id);
    assert.equal(c.failedGates, 0, c.id);
    assert.ok(c.generatedAt, c.id);
    assert.ok(c.summary && c.summary.exists, c.id);
    assert.equal(c.missingArtifacts.length, 0, c.id);
  }
  const ids = new Set(state.gates.map((g) => g.id));
  assert.equal(ids.size, state.gates.length);
  assert.ok(state.gates.some((g) => g.id === 'tests/node'));
  assert.ok(state.gates.some((g) => g.id.startsWith('global-l4b/')));
  assert.ok(state.gates.every((g) => g.pass === true));
});

test('unified agent state: node --test report exists and has no failures', () => {
  assert.ok(state.tests.report, 'missing test report');
  assert.ok(state.tests.exists, 'test report file missing');
  assert.ok(state.tests.total > 0, 'test total missing');
  assert.equal(state.tests.failed, 0);
  assert.equal(state.tests.passed, state.tests.total);
  assert.equal(state.overall.tests.pass, true);
  const raw = fs.readFileSync(path.join(ROOT, state.tests.report), 'utf8');
  assert.ok(!/not ok/i.test(raw), 'test report contains not ok');
});

test('unified agent state: markdown gates report is generated', () => {
  const md = fs.readFileSync(path.join(ROOT, 'out', 'report', 'agent-gates.md'), 'utf8');
  assert.match(md, /allGatesPass：\*\*true\*\*/);
  assert.match(md, /P3\/P4\/P6/);
  assert.match(md, /P5/);
  assert.match(md, /P1\/P2\/P7\/P8/);
  assert.match(md, /Global L4b/);
  assert.match(md, /L5 \(Dynamic Oracle\)/);
  assert.match(md, /L7 \(Reporter\/Delivery\)/);
  assert.match(md, /tests\/node/);
});

test('gate registry: campaigns auto-discovered with stable 20/15/13/5/8/8 gate definitions', () => {
  const registry = require('../lib/agent/registry.js');
  const campaigns = registry.listCampaigns();
  assert.deepEqual(campaigns.map((c) => c.id), ['p3p4p6', 'p1p2p7p8', 'p5', 'global-l4b', 'l5', 'l7']);
  const expected = { p3p4p6: 20, p1p2p7p8: 15, p5: 13, 'global-l4b': 5, l5: 8, l7: 8 };
  for (const c of campaigns) {
    assert.equal(c.expectedGates, expected[c.id], c.id);
    assert.equal(c.gates.length, expected[c.id], c.id);
    const keys = new Set(c.gates.map((g) => g.key));
    const names = new Set(c.gates.map((g) => g.name));
    assert.equal(keys.size, c.gates.length, c.id);
    assert.equal(names.size, c.gates.length, c.id);
  }
  assert.deepEqual(registry.defaultCampaignIds(), ['p3p4p6', 'p1p2p7p8']);
});

test('gate registry: missing gateResult is an explicit FAIL, extra key is auditable', () => {
  const registry = require('../lib/agent/registry.js');
  const specs = registry.gateSpecs('p5');
  const missing = registry.buildGates('p5', {});
  assert.equal(missing.length, 13);
  assert.ok(missing.every((g) => g.pass === false));
  assert.ok(missing.every((g) => /missing gate result/.test(String(g.detail))));
  const all = Object.fromEntries(specs.map((g) => [g.key, { pass: true, detail: 'ok' }]));
  const rows = registry.buildGates('p5', all);
  assert.equal(rows.length, 13);
  assert.ok(rows.every((g) => g.pass === true));
  const audit = registry.auditGateResults('p5', { ...all, unexpected: { pass: true } });
  assert.deepEqual(audit.missing, []);
  assert.deepEqual(audit.extra, ['unexpected']);
});

test('gate registry: unified state campaign IDs match registry auto-discovery', () => {
  const registry = require('../lib/agent/registry.js');
  assert.deepEqual(state.campaigns.map((c) => c.id), registry.listCampaignIds());
  for (const c of state.campaigns) {
    assert.equal(c.gateCount, registry.getCampaign(c.id).expectedGates, c.id);
  }
});

test('gate registry: evaluator gates run without ctx and a new campaign auto-registers', () => {
  const registry = require('../lib/agent/registry.js');
  for (const c of registry.listCampaigns()) {
    assert.ok(c.gates.every((g) => typeof g.evaluate === 'function'), c.id);
    const rows = registry.runGates(c.id, {});
    assert.equal(rows.length, c.expectedGates, c.id);
    assert.ok(rows.every((g) => typeof g.pass === 'boolean'), c.id);
  }
  const def = {
    id: '__registry_test__',
    name: 'Registry Test',
    order: 999,
    defaultRun: false,
    summary: 'out/report/__registry_test__.json',
    runner: 'bin/__registry_test__.js',
    artifacts: [],
    gates: [{ key: 'smoke', name: 'Smoke', evaluate: () => ({ pass: true, detail: 'ok' }) }]
  };
  registry.registerCampaign(def);
  assert.ok(registry.listCampaignIds().includes('__registry_test__'));
  assert.equal(registry.getCampaign('__registry_test__').expectedGates, 1);
  const rows = registry.runGates('__registry_test__', {});
  assert.equal(rows.length, 1);
  assert.equal(rows[0].pass, true);
  assert.equal(rows[0].id, '__registry_test__/smoke');
});

test('global L4b: all 8 classes reviewed, 5 gates pass, no T1 / O10 drift', () => {
  const s = readJson(path.join(ROOT, 'out', 'report', 'global-l4b-summary.json'));
  assert.equal(s.classes.length, 8);
  assert.deepEqual(s.classes.map((c) => c.class), ['P1', 'P2', 'P3', 'P4', 'P5', 'P6', 'P7', 'P8']);
  assert.ok(s.classes.every((c) => c.eligible === undefined || c.eligible === 0 || c.selected > 0));
  assert.equal(s.gates.length, 5);
  assert.equal(s.allGatesPass, true);
  assert.equal(s.totals.t1, 0);
  assert.equal(s.o10Changed, false);
  assert.ok(s.totals.selected >= 8);
  assert.equal(s.totals.reviewed, s.totals.selected);
  for (const p of ['out/global/l4b/results.jsonl', 'out/global/l4b/claims-refined.jsonl', 'out/global/l4b/verdicts-refined.jsonl']) {
    assert.ok(fs.existsSync(path.join(ROOT, p)), p);
  }
  const refined = fs.readFileSync(path.join(ROOT, 'out/global/l4b/verdicts-refined.jsonl'), 'utf8')
    .split(/\r?\n/).filter(Boolean).map((l) => JSON.parse(l));
  assert.ok(refined.every((v) => v.productVerdict !== 'PROVEN-VULN'));
});

test('global L4b selection: default covers all T2/T3, excludes T4; perClass is only a cap', () => {
  const { selectGlobalClaims, buildGlobalPack } = require('../lib/agent/classes.js');
  const classes = ['P1', 'P2', 'P3', 'P4', 'P5', 'P6', 'P7', 'P8'];
  const records = [];
  for (const cls of classes) {
    records.push({ class: cls, claimId: `${cls}-T2`, productionEligible: true, tier: 'T2-weak-candidate' });
    records.push({ class: cls, claimId: `${cls}-T3`, productionEligible: true, tier: 'T3-instrumentation-gap' });
    records.push({ class: cls, claimId: `${cls}-T4`, productionEligible: true, tier: 'T4-negative' });
  }
  const all = selectGlobalClaims(records);
  assert.equal(all.length, 16);
  assert.ok(all.every((r) => r.tier === 'T2-weak-candidate' || r.tier === 'T3-instrumentation-gap'));
  assert.ok(!all.some((r) => r.claimId.endsWith('-T4')));
  const capped = selectGlobalClaims(records, { perClass: 1 });
  assert.equal(capped.length, 8);
  assert.ok(capped.every((r) => r.claimId.endsWith('-T2')));
  const t3Pack = buildGlobalPack({ ...records[1], claim: { claimId: 'P1-T3', obligations: [] }, verdict: null });
  assert.equal(t3Pack.mode, 'complete-gap');
});

test('global L4b refinement: T2 support/refute and T3 gap completion', () => {
  const { refineRecord } = require('../lib/agent/l4b-global.js');
  const obligations = [
    { id: 'O5', status: 'unproven' },
    { id: 'O6', status: 'unproven' },
    { id: 'O10', status: 'unproven' }
  ];
  const base = {
    class: 'P1',
    claimId: 'P1-test',
    tier: 'T2-weak-candidate',
    claim: { claimId: 'P1-test', obligations },
    verdict: { claimId: 'P1-test', productVerdict: 'PROVEN-WEAKNESS', tier: 'T2-weak-candidate', obligations }
  };
  const pack = { mode: 'strengthen' };
  const support = refineRecord(base, {
    ok: true, simulated: false, assessment: 'support', gapResolution: 'not-applicable',
    evidenceRefs: ['E1:L1'], missingEvidence: [], suggestedEvidence: []
  }, pack);
  assert.ok(support.claim.l4bSupport);
  assert.equal(support.verdict.productVerdict, 'PROVEN-WEAKNESS');
  const refute = refineRecord(base, {
    ok: true, simulated: false, assessment: 'refute', gapResolution: 'not-applicable',
    evidenceRefs: ['E1:L1'], missingEvidence: [], suggestedEvidence: []
  }, pack);
  assert.equal(refute.verdict.productVerdict, 'NOT-VULN');
  assert.equal(refute.verdict.obligations.find((o) => o.id === 'O10').status, 'unproven');
  const t3 = refineRecord({
    ...base, tier: 'T3-instrumentation-gap',
    verdict: { ...base.verdict, tier: 'T3-instrumentation-gap' }
  }, {
    ok: true, simulated: false, assessment: 'unknown', gapResolution: 'completed',
    evidenceRefs: ['E1:L1'], missingEvidence: [], suggestedEvidence: [{ ref: 'E1:L1', why: 'guard' }]
  }, { mode: 'complete-gap' });
  assert.ok(t3.claim.l4bGap);
  assert.equal(t3.verdict.tier, 'T3-instrumentation-gap');
  assert.equal(t3.gapCompleted, true);
});
