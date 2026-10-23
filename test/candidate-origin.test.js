'use strict';

const test = require('node:test');
const assert = require('node:assert');
const {
  ORIGINS, CODE_STATES, NOVELTY,
  originOf, productionEligible, noveltyFor, classify
} = require('../lib/candidate-origin.js');

test('target current-head is production, novelty=new', () => {
  const r = { origin: ORIGINS.TARGET, inTarget: true, codeState: CODE_STATES.CURRENT_HEAD };
  assert.equal(productionEligible(r), true);
  assert.equal(noveltyFor(r), NOVELTY.NEW);
  assert.deepEqual(classify(r).errors, []);
});

test('historical/miner current-head are production but known', () => {
  const h = { origin: ORIGINS.HISTORICAL_POSITIVE, inTarget: true, codeState: CODE_STATES.CURRENT_HEAD };
  const m = { origin: ORIGINS.MINER_EXISTING, inTarget: true, codeState: CODE_STATES.CURRENT_HEAD };
  assert.equal(productionEligible(h), true);
  assert.equal(noveltyFor(h), NOVELTY.KNOWN_REPRODUCED);
  assert.equal(productionEligible(m), true);
  assert.equal(noveltyFor(m), NOVELTY.KNOWN_REPRODUCED);
  assert.equal(noveltyFor({ ...h, regression: true }), NOVELTY.REGRESSION);
});

test('fixed/snapshot-only are never production', () => {
  for (const codeState of [CODE_STATES.FIXED, CODE_STATES.SNAPSHOT_ONLY]) {
    assert.equal(productionEligible({ origin: ORIGINS.HISTORICAL_POSITIVE, inTarget: true, codeState }), false);
    assert.equal(productionEligible({ origin: ORIGINS.TARGET, inTarget: true, codeState }), false);
  }
});

test('external-cve never maps to target and never production', () => {
  const r = { origin: ORIGINS.EXTERNAL_CVE, inTarget: false, codeState: CODE_STATES.CURRENT_HEAD };
  assert.equal(productionEligible(r), false);
  const mapped = { ...r, inTarget: true };
  assert.equal(productionEligible(mapped), false);
  assert.ok(classify(mapped).errors.includes('external-cve-must-not-map-to-target'));
  assert.ok(classify(mapped).errors.includes('external-cve-must-not-have-codeState'));
});

test('oracle-fixture is never production', () => {
  const r = { origin: ORIGINS.ORACLE_FIXTURE, inTarget: true, codeState: CODE_STATES.CURRENT_HEAD, constructed: true };
  assert.equal(productionEligible(r), false);
  assert.equal(noveltyFor(r), NOVELTY.NOT_APPLICABLE);
});

test('legacy groups map to origins', () => {
  assert.equal(originOf({ group: 'oh-candidate' }), ORIGINS.TARGET);
  assert.equal(originOf({ group: 'cve-calibration' }), ORIGINS.EXTERNAL_CVE);
  assert.equal(originOf({ group: 'miner-finding' }), ORIGINS.MINER_EXISTING);
  assert.equal(originOf({ group: 'oracle-fixture' }), ORIGINS.ORACLE_FIXTURE);
});
