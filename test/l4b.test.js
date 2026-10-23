'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { loadL1 } = require('../lib/l1.js');
const { loadL2 } = require('../lib/l2.js');
const { buildP6Claims } = require('../lib/claims.js');
const { proveP6Claims } = require('../lib/prover-p6.js');
const { readJsonl } = require('../lib/util.js');
const l4b = require('../lib/l4b.js');

const l1 = loadL1();
const l2 = loadL2(l1);
const claims = buildP6Claims(l1, l2);
const verdicts = proveP6Claims(claims, l1);
const selected = l4b.selectP6L4bClaims(claims, verdicts, l1, 10);
const packs = selected.map((c) => l4b.buildP6Pack(c, l1));

test('L4b: 10 P6 packs selected, each has items and E#:L# refs', () => {
  assert.equal(packs.length, 10);
  for (const p of packs) {
    assert.ok(p.items.length > 0, p.id);
    assert.ok(p.refs.length > 0, p.id);
    assert.ok(p.refs.every((r) => /^E\d+:L\d+$/.test(r)), p.id);
  }
});

test('L4b: mock transport achieves schema/ref success 10/10', async () => {
  const transport = l4b.makeMockTransport(packs);
  const run = await l4b.runBatch(packs, { transport, log: false });
  assert.equal(run.summary.ok, 10);
  assert.equal(run.summary.schemaSuccessRate, 1);
  assert.equal(run.summary.refsOkRate, 1);
  assert.equal(run.summary.packs, 10);
});

test('L4b: schema validation rejects unknown item and bad evidence ref', () => {
  const pack = packs[0];
  const badItem = { items: [{ item: '__not_an_item__', sensitive: 'yes', evidenceRef: pack.refs[0] }], reason: 'x', evidenceRefs: [pack.refs[0]] };
  const r1 = l4b.validateP6(badItem, pack);
  assert.equal(r1.ok, false);
  assert.ok(r1.errors.some((e) => e.startsWith('unknown-item')));
  const badRef = { items: [{ item: pack.items[0], sensitive: 'no', evidenceRef: 'E99:L1' }], reason: 'x', evidenceRefs: [pack.refs[0]] };
  const r2 = l4b.validateP6(badRef, pack);
  assert.equal(r2.ok, false);
  assert.ok(r2.errors.some((e) => e.startsWith('item-evidenceRef-not-in-pack')));
});

test('L4b: missing items are treated as unknown, never as no', () => {
  const pack = packs[0];
  const partial = {
    items: [{ item: pack.items[0], sensitive: 'no', evidenceRef: pack.refs[0] }],
    reason: 'partial answer',
    evidenceRefs: [pack.refs[0]]
  };
  const v = l4b.validateP6(partial, pack);
  assert.equal(v.ok, true, JSON.stringify(v.errors));
  const agg = l4b.aggregateP6(partial, pack);
  assert.equal(agg.aggregate, 'unknown');
  assert.ok(agg.unknown.includes(pack.items[1]));
});

test('L4b: P3 producerMayNull schema accepts yes/no/unknown only', () => {
  const pack = l4b.buildP3Pack(require('../lib/claims.js').selectP3Candidates(l1, l2).claims[0], l1);
  assert.equal(l4b.validateP3({ producerMayNull: 'yes', reason: 'x', evidenceRefs: [pack.refs[0]] }, pack).ok, true);
  assert.equal(l4b.validateP3({ producerMayNull: 'maybe', reason: 'x', evidenceRefs: [pack.refs[0]] }, pack).ok, false);
});

test('L4b: latest live/mock summary gate is >=8/10 with refs 100%', () => {
  const file = path.join(__dirname, '..', 'out', 'l4b', 'summary.json');
  const s = JSON.parse(require('fs').readFileSync(file, 'utf8'));
  assert.ok(s.p6.packs >= 10, `packs=${s.p6.packs}`);
  assert.ok(s.p6.schemaSuccessRate >= 0.8, `rate=${s.p6.schemaSuccessRate}`);
  assert.equal(s.p6.refsOkRate, 1);
});

test('L4b: makeFetchIPv4 支持 http:// 端点（本机网关）', async () => {
  // 换供应商到 http://127.0.0.1:7864 后，旧的 https-only 实现会抛 ERR_INVALID_PROTOCOL
  const httpMod = require('http');
  const srv = httpMod.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true, path: req.url }));
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const port = srv.address().port;
  try {
    const fetchIpv4 = l4b.makeFetchIPv4();
    const res = await fetchIpv4(`http://127.0.0.1:${port}/v1/models`, { method: 'GET' });
    assert.equal(res.status, 200);
    const body = JSON.parse(await res.text());
    assert.deepEqual(body, { ok: true, path: '/v1/models' });
  } finally {
    await new Promise((r) => srv.close(r));
  }
});
