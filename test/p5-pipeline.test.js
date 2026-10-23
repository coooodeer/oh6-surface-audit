'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const OUT = path.join(__dirname, '..', 'out');
const readJson = (p) => JSON.parse(fs.readFileSync(p, 'utf8'));
const readJsonl = (p) => fs.readFileSync(p, 'utf8').split(/\r?\n/).filter(Boolean).map((l) => JSON.parse(l));

const fixtures = readJson(path.join(OUT, 'p5', 'fixture-summary.json'));
const claims = readJsonl(path.join(OUT, 'p5', 'claims.jsonl'));
const verdicts = readJsonl(path.join(OUT, 'p5', 'verdicts.jsonl'));
const inScope = readJsonl(path.join(OUT, 'verdicts', 'p5-in-scope-verdicts.jsonl'));
const summary = readJson(path.join(OUT, 'verdicts', 'p5-summary.json'));

test('P5 fixtures: dsoftbus pre/post 1/1 + synthetic 10/10', () => {
  assert.equal(fixtures.cases, 11);
  assert.equal(fixtures.historical.preViolation, 1);
  assert.equal(fixtures.historical.postSatisfied, 1);
  assert.equal(fixtures.synthetic.originalSatisfied, 10);
  assert.equal(fixtures.synthetic.mutantViolation, 10);
  assert.equal(fixtures.gate, true);
});

test('P5 claims: 20-40 method-level claims, O1–O10 each', () => {
  assert.ok(claims.length >= 20 && claims.length <= 40, `claims=${claims.length}`);
  for (const c of claims) {
    assert.equal(c.class, 'P5');
    assert.equal(c.obligations.length, 10, c.claimId);
    assert.ok(c.obligations.every((o) => o.id && o.kind && o.status && o.evidence), c.claimId);
    assert.ok(c.unitId && c.entry.interface && c.entry.method, c.claimId);
    assert.ok(['VIOLATION', 'SATISFIED', 'UNPROVEN', 'NOT-VULN', 'NOT-APPLICABLE'].includes(c.claimVerdict), c.claimId);
  }
});

test('P5 claims: no PROVEN-VULN without O10 or O6/O7/O8 proof', () => {
  for (const c of claims) {
    if (c.productVerdict !== 'PROVEN-VULN') continue;
    assert.equal(c.obligations.find((o) => o.id === 'O10').status, 'proven', c.claimId);
    for (const id of ['O6', 'O7', 'O8']) assert.equal(c.obligations.find((o) => o.id === id).status, 'proven', c.claimId);
  }
});

test('P5 R1 summary: T1=0; tier counts consistent with verdict rows', () => {
  assert.equal(summary.claims.total, 30);
  assert.equal(summary.headline.newConfirmed, 0);
  const t2 = verdicts.filter((r) => r.tier === 'T2-weak-candidate').length;
  const t3 = verdicts.filter((r) => r.tier === 'T3-instrumentation-gap').length;
  const t4 = verdicts.filter((r) => r.tier === 'T4-negative').length;
  assert.equal(summary.headline.newWeak, t2);
  assert.equal(summary.headline.conditions, t3);
  assert.equal(summary.headline.negative, t4);
  assert.equal(t2 + t3 + t4, 30);
  assert.equal(inScope.length, t2 + t3);
  assert.ok(inScope.every((r) => r.scope === 'R1' && r.class === 'P5'));
  assert.ok(inScope.every((r) => r.tier !== 'T4-negative'));
});

test('P5 verdicts: every T2/T3 has gap/evidence; no out-of-R1 repo', () => {
  const repos = new Set(['base/account/os_account', 'foundation/communication/dsoftbus']);
  for (const r of verdicts) {
    assert.ok(repos.has(r.repo), `${r.verdictId} ${r.repo}`);
    if (r.tier === 'T3-instrumentation-gap') assert.ok(r.gapReason, r.verdictId);
    if (r.tier === 'T2-weak-candidate') assert.equal(r.counted, true);
  }
});

test('P5 identity/impact closure: O3 26/30, dsoftbus O3+impact explicit', () => {
  const claimSummary = readJson(path.join(OUT, 'p5', 'claim-summary.json'));
  assert.ok(claimSummary.obligations.O3.proven >= 26, JSON.stringify(claimSummary.obligations.O3));
  assert.ok(claimSummary.obligations.O2.proven >= 25, JSON.stringify(claimSummary.obligations.O2));
  assert.ok(claimSummary.impact.refuted >= 7, JSON.stringify(claimSummary.impact));
  assert.ok(claimSummary.impact.unproven >= 1, JSON.stringify(claimSummary.impact));
  const dsoftbus = claims.find((c) => c.entry.interface === 'OHOS.ISoftBusServer');
  assert.ok(dsoftbus, 'dsoftbus supplementary claim missing');
  assert.deepEqual(dsoftbus.source.params.map((p) => p.name).sort(), ['channelId', 'channelType']);
  assert.equal(dsoftbus.obligations.find((o) => o.id === 'O3').status, 'proven');
  assert.equal(dsoftbus.impact.status, 'unproven');
  assert.match(dsoftbus.impact.reason, /TransGetAndComparePid/);
});

test('P5 Phase 1: impact refuted -> T4; missed permission checks -> T4', () => {
  const claimSummary = readJson(path.join(OUT, 'p5', 'claim-summary.json'));
  assert.ok(claimSummary.impact.refuted >= 7, JSON.stringify(claimSummary.impact));
  const isExists = claims.find((c) => c.entry.method === 'IsOsAccountExists');
  assert.ok(isExists, 'IsOsAccountExists claim missing');
  assert.equal(isExists.impact.status, 'refuted');
  assert.equal(isExists.productVerdict, 'NOT-VULN');
  const dvid = claims.find((c) => c.entry.method === 'QueryDistributedVirtualDeviceId');
  assert.ok(dvid, 'QueryDistributedVirtualDeviceId claim missing');
  assert.equal(dvid.obligations.find((o) => o.id === 'O6').status, 'proven');
  assert.equal(dvid.obligations.find((o) => o.id === 'O7').status, 'proven');
  assert.equal(dvid.productVerdict, 'NOT-VULN');
});

test('P5 report/status files exist and state headline', () => {
  const md = fs.readFileSync(path.join(OUT, 'report', 'p5-implementation.md'), 'utf8');
  assert.match(md, new RegExp(`本仓新确认 P5 漏洞 \\*\\*${summary.headline.newConfirmed}\\*\\*`));
  assert.match(md, new RegExp(`weak 候选 \\*\\*${summary.headline.newWeak}\\*\\*`));
  assert.ok(fs.existsSync(path.join(__dirname, '..', 'IMPLEMENTATION-STATUS-P5.md')));
});

test('P5 artifacts contain no needs-human/pending', () => {
  for (const f of ['out/p5/claims.jsonl', 'out/p5/verdicts.jsonl', 'out/verdicts/p5-in-scope-verdicts.jsonl']) {
    const text = fs.readFileSync(path.join(__dirname, '..', f), 'utf8');
    assert.ok(!/needs-human|"pending"|: pending/i.test(text), f);
  }
});
