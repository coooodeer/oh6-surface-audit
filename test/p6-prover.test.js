'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { loadL1 } = require('../lib/l1.js');
const { loadL2 } = require('../lib/l2.js');
const { readJsonl } = require('../lib/util.js');
const { buildP6Claims } = require('../lib/claims.js');
const {
  proveP6Claims, summarizeP6Verdicts, reconcileWithMiner, checkEvalCases, p6Verdict
} = require('../lib/prover-p6.js');

const l1 = loadL1();
const l2 = loadL2(l1);
const claims = buildP6Claims(l1, l2);
const verdicts = proveP6Claims(claims, l1);

test('P6: 95 os_account site + 20 miner finding site claims (3 RG1 negative excluded)', () => {
  assert.equal(claims.length, 115);
  assert.equal(claims.filter((c) => c.group === 'os-account').length, 95);
  assert.equal(claims.filter((c) => c.group === 'miner-finding').length, 20);
});

test('P6: RG1 negative action OnNotificationServiceDialogClicked is excluded from claims', () => {
  assert.equal(claims.filter((c) => c.action === 'OnNotificationServiceDialogClicked').length, 0);
});

test('P6 reconciliation: 95/95 site found; rejection distribution 71/19/5; all NOT-VULN', () => {
  const r = reconcileWithMiner(l1, l2, verdicts);
  assert.equal(r.osSites, 95);
  assert.equal(r.foundInMiner, 95);
  assert.deepEqual(r.rejectionCounts, {
    C4_no_sensitive_payload: 71,
    C3_event_requires_permission: 19,
    C3_subscriber_permission_required: 5
  });
  assert.equal(r.allNotVuln, true, JSON.stringify(r.notNotVuln.slice(0, 5)));
  assert.equal(r.reasonMismatch.length, 0, JSON.stringify(r.reasonMismatch.slice(0, 5)));
});

test('P6 os_account: 95/95 NOT-VULN (0 finding, no forced positive)', () => {
  const os = verdicts.filter((v) => v.group === 'os-account');
  assert.equal(os.length, 95);
  assert.ok(os.every((v) => v.claimVerdict === 'NOT-VULN'));
  assert.ok(os.every((v) => v.productVerdict === 'NOT-VULN'));
});

test('P6 positive fixtures: Kiosk ON/OFF and QuickFix APPLY/REVOKE are PROVEN-VULN', () => {
  const byAction = new Map(verdicts.filter((v) => v.group === 'miner-finding').map((v) => [v.action, v]));
  for (const action of [
    'usual.event.KIOSK_MODE_ON',
    'usual.event.KIOSK_MODE_OFF',
    'usual.event.QUICK_FIX_APPLY_RESULT',
    'usual.event.QUICK_FIX_REVOKE_RESULT'
  ]) {
    const v = byAction.get(action);
    assert.ok(v, action);
    assert.equal(v.claimVerdict, 'VIOLATION', action);
    assert.equal(v.productVerdict, 'PROVEN-VULN', action);
  }
});

test('P6 weak hits downgrade to PROVEN-WEAKNESS', () => {
  const weak = verdicts.filter((v) => v.productVerdict === 'PROVEN-WEAKNESS');
  assert.ok(weak.length >= 10);
  assert.ok(weak.every((v) => v.claimVerdict === 'PROVEN-WEAKNESS'));
  assert.ok(weak.some((v) => v.action === 'usual.event.wifi.CONN_STATE'));
  assert.ok(weak.some((v) => v.action === 'common.event.SPLIT_SCREEN'));
});

test('P6 truth table: O4 disproven -> NOT-VULN; O3 disproven -> NOT-VULN; O6 weak -> weakness', () => {
  const mk = (id, status, extra = {}) => ({ id, kind: id, status, evidence: {}, ...extra });
  const base = [mk('O1', 'proven'), mk('O2', 'proven'), mk('O3', 'proven'), mk('O4', 'proven'),
    mk('O5', 'proven'), mk('O6', 'proven'), mk('O7', 'proven'), mk('O8', 'proven'), mk('O9', 'unproven'), mk('O10', 'proven')];
  assert.equal(p6Verdict(base).claimVerdict, 'VIOLATION');
  assert.equal(p6Verdict(base.map((o) => (o.id === 'O4' ? { ...o, status: 'disproven' } : o))).claimVerdict, 'NOT-VULN');
  assert.equal(p6Verdict(base.map((o) => (o.id === 'O3' ? { ...o, status: 'disproven' } : o))).claimVerdict, 'NOT-VULN');
  const weak = base.map((o) => (o.id === 'O6' ? { ...o, status: 'proven', weak: true } : o));
  assert.equal(p6Verdict(weak).claimVerdict, 'PROVEN-WEAKNESS');
  const partial = base.map((o) => (o.id === 'O10' ? { ...o, status: 'unproven' } : o));
  assert.equal(p6Verdict(partial).claimVerdict, 'UNPROVEN');
});

test('P6 eval cases: 10/10 original receiverThirdParty=true, controls/restricted=false', () => {
  const cases = readJsonl(path.join(__dirname, '..', 'eval', 'p6', 'cases.jsonl'));
  const r = checkEvalCases(cases);
  assert.equal(r.pass, true, JSON.stringify(r.rows.filter((x) => !x.pass)));
  assert.equal(r.byVariant.original.pass, 10);
  assert.equal(r.byVariant['control-subscriber-permission'].pass, 10);
  assert.equal(r.byVariant['negative-restricted'].pass, 5);
});
