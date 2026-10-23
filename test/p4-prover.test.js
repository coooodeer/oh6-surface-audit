'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { loadL1 } = require('../lib/l1.js');
const { readJsonl } = require('../lib/util.js');
const { buildP4Claims } = require('../lib/claims.js');
const {
  proveP4Claims, summarizeP4Verdicts, checkHasArithmetic, parseOperations, detectFixKind, productForP4
} = require('../lib/prover-p4.js');

const l1 = loadL1();
const candidates = readJsonl(path.join(__dirname, '..', 'out', 'p4', 'candidates.jsonl'));
const cves = readJsonl(path.join(__dirname, '..', 'out', 'p4', 'cve-patches.jsonl'));
const claims = buildP4Claims(candidates, cves);
const verdicts = proveP4Claims(claims, l1, {
  candidateById: new Map(candidates.map((c) => [c.candidateId, c])),
  cveById: new Map(cves.map((c) => [c.cveId, c]))
});

test('P4: 11 OH candidates + 13 CVE calibration claims', () => {
  assert.equal(claims.length, 24);
  assert.equal(claims.filter((c) => c.group === 'oh-candidate').length, 11);
  assert.equal(claims.filter((c) => c.group === 'cve-calibration').length, 13);
});

test('P4: every claim has O1–O10 with evidence and a closed verdict', () => {
  for (const v of verdicts) {
    assert.equal(v.obligations.length, 10, v.claimId);
    assert.ok(v.claimVerdict, v.claimId);
    for (const ob of v.obligations) {
      assert.ok(['proven', 'disproven', 'unproven', 'invalid'].includes(ob.status), `${v.claimId} ${ob.id} ${ob.status}`);
      assert.ok(ob.evidence && typeof ob.evidence === 'object', `${v.claimId} ${ob.id}`);
    }
  }
});

test('P4: O2 operation-site always comes from a pre line / removed diff line', () => {
  for (const v of verdicts) {
    const o2 = v.obligations.find((o) => o.id === 'O2');
    assert.ok(Array.isArray(o2.evidence.removedLines) || o2.evidence.source === 'pre-line' || o2.evidence.source === 'pre-removed',
      `${v.claimId} ${JSON.stringify(o2.evidence)}`);
  }
});

test('P4 oracle: 1 confirmed / 10 blocked (7 no-driver + 3 compile-failed)', () => {
  const s = summarizeP4Verdicts(verdicts);
  assert.equal(s.oracle.confirmed, 1);
  assert.equal(s.oracle.blocked, 10);
  assert.equal(s.oracle.blockedReasons['no-driver-template'], 7);
  assert.equal(s.oracle.blockedReasons['compile-failed'], 3);
});

test('P4 confirmed fixture cd_G-P4_52b62a535a33 is VIOLATION but not PROVEN-VULN (entry suspect)', () => {
  const v = verdicts.find((x) => x.candidateId === 'cd_G-P4_52b62a535a33');
  assert.ok(v);
  assert.equal(v.claimVerdict, 'VIOLATION');
  assert.equal(v.productVerdict, 'PROVEN-WEAKNESS');
  assert.equal(v.obligations.find((o) => o.id === 'O10').status, 'proven');
});

test('P4: no OH candidate is promoted to PROVEN-VULN while entry binding is suspect', () => {
  const oh = verdicts.filter((v) => v.group === 'oh-candidate');
  assert.equal(oh.length, 11);
  assert.ok(oh.every((v) => v.productVerdict !== 'PROVEN-VULN'));
});

test('P4: blocked candidates are named CONDITIONS-NOT-MET / instrumentation-gap', () => {
  const blocked = verdicts.filter((v) => {
    const o = v.obligations.find((x) => x.id === 'O10');
    return o.status === 'unproven' && o.evidence && o.evidence.state === 'blocked';
  });
  assert.equal(blocked.length, 10);
  assert.ok(blocked.every((v) => v.productVerdict === 'CONDITIONS-NOT-MET'));
  assert.ok(blocked.every((v) => /instrumentation-gap/.test(v.productReason || '')));
});

test('P4 CVE: O7/O8 decided for all 13; known unsafe checks flagged', () => {
  const cve = verdicts.filter((v) => v.group === 'cve-calibration');
  assert.equal(cve.length, 13);
  assert.ok(cve.every((v) => ['proven', 'disproven', 'unproven'].includes(v.obligations.find((o) => o.id === 'O7').status)));
  assert.ok(cve.every((v) => ['proven', 'disproven', 'unproven'].includes(v.obligations.find((o) => o.id === 'O8').status)));
  for (const id of ['CVE-2011-4031', 'CVE-2015-1208', 'CVE-2022-0185']) {
    const v = cve.find((x) => x.cveId === id);
    const o8 = v.obligations.find((o) => o.id === 'O8');
    assert.equal(o8.status, 'disproven', `${id} ${JSON.stringify(o8.evidence)}`);
  }
});

test('P4 CVE-2020-15202 uses O9=type-widen, not guard', () => {
  const v = verdicts.find((x) => x.cveId === 'CVE-2020-15202');
  const o9 = v.obligations.find((o) => o.id === 'O9');
  assert.equal(o9.evidence.fixKind, 'type-widen');
});

test('P4 truth table: O1 proven without O10 confirmed never becomes PROVEN-VULN', () => {
  const base = [
    { id: 'O1', status: 'proven', evidence: {} },
    { id: 'O10', status: 'proven', evidence: { state: 'blocked', reason: 'no-driver-template' } }
  ];
  const blocked = productForP4('VIOLATION', base);
  assert.equal(blocked.productVerdict, 'CONDITIONS-NOT-MET');
  const confirmed = productForP4('VIOLATION', [
    base[0],
    { id: 'O10', status: 'proven', evidence: { state: 'confirmed' } }
  ]);
  assert.equal(confirmed.productVerdict, 'PROVEN-VULN');
});

test('P4 parser: sizeof/add/mul and check arithmetic', () => {
  const ops = parseOperations('sizeof(char) * (len + 1)', [{ type: 'uint32_t', name: 'len' }]);
  assert.ok(ops.some((o) => o.kind === 'add' && o.typeKnown));
  assert.ok(checkHasArithmetic('len > PAGE_SIZE - 2 - size').length > 0);
  assert.ok(checkHasArithmetic('total_size + 8 <= atom.size').length > 0);
  assert.ok(checkHasArithmetic('FFMIN(cur_len, len - off) < 0').length > 0);
  assert.equal(checkHasArithmetic('size > MAX_SIZE').length, 0);
  assert.equal(detectFixKind({ diff: '+ int64_t start_output' }, ['int64_t start_output']), 'type-widen');
});
