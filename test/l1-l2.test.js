'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { loadL1 } = require('../lib/l1.js');
const { loadL2 } = require('../lib/l2.js');

const l1 = loadL1();
const l2 = loadL2(l1);

test('L1 baseline: functions/call-edges/producers', () => {
  const s = l1.stats();
  assert.equal(s.functions, 17534);
  assert.equal(s.functionFiles, 1084);
  assert.equal(s.callEdges, 74574);
  assert.equal(s.producers, 17534);
});

test('L1 baseline: entries/actions/payload', () => {
  const s = l1.stats();
  assert.equal(s.entries, 694);
  assert.equal(s.entryFiles, 160);
  assert.equal(s.actionRows, 328);
  assert.equal(s.uniqueActions, 22);
  assert.equal(s.p6PayloadItems, 1058);
  assert.equal(s.p6PayloadRows, 328);
});

test('L1 baseline: miner 624 sites / 3321 entities / 23 findings / 601 rejections', () => {
  const s = l1.stats();
  assert.equal(s.minerSites, 624);
  assert.equal(s.minerEntities, 3321);
  assert.equal(s.minerFindings, 23);
  assert.equal(s.minerRejections, 601);
});

test('L1 queries return stable file:line / functionId', () => {
  const fn = l1.getFunction('base/account/os_account', 'services/accountmgr/src/osaccount/os_account_interface.cpp', 131);
  assert.ok(fn);
  assert.equal(fn.name, 'InnerSendToAMSAccountStop');
  assert.match(fn.functionId, /^base\/account\/os_account\|.*:\d+$/);
  assert.ok(Array.isArray(l1.guards(fn.functionId)));
  assert.ok(l1.callees(fn.functionId).length >= 1);
  assert.ok(l1.callers(fn.functionId).length >= 1);
  assert.ok(l1.producerType(fn.functionId));
});

test('L1 miner queries: site/gate/slice/entity/action', () => {
  const site = l1.minerSite('site_8ed0ff50d01a7243');
  assert.equal(site.action, 'usual.event.KIOSK_MODE_OFF');
  assert.equal(l1.minerGate(site.siteKey).C1, true);
  assert.equal(l1.minerSlice(site.siteKey).status, 'resolved');
  assert.equal(l1.minerEntity('sc_ad0f4801a9f6b7d0').symbol, 'KioskStatus');
  assert.ok(l1.minerSitesForAction(site.action).length >= 1);
});

test('L2: 95 os_account sites and 22 unique actions', () => {
  assert.equal(l2.p6Sites().length, 95);
  assert.equal(new Set(l2.p6Sites().map((s) => s.action)).size, 22);
});

test('L2 1a: 68 reachable-unbound are callgraph-name-only; 73 reachable', () => {
  const cls = l2.derefClassification();
  const reach = cls.filter((r) => r.reachable);
  const unbound = reach.filter((r) => l1.derefById(r.id).entryCount === 0);
  assert.equal(reach.length, 73);
  assert.equal(unbound.length, 68);
  assert.ok(unbound.every((r) => r.entryBinding === 'callgraph-name-only'));
  assert.equal(cls.filter((r) => !r.reachable).length, 109);
});

test('L2 resolveProducer is owner-aware and resolves the 20 expansion candidates', () => {
  const cls = l2.reachableDerefs();
  const shape = cls.filter((r) => {
    const p = l1.derefById(r.id);
    return p.status === 'potential-violation' || (p.producerMayNull && !p.guardBefore && p.typeKnown);
  });
  assert.equal(shape.length, 31);
  const proven = shape.filter((r) => l2.resolveProducer(r.repo, l1.derefById(r.id)).status === 'proven');
  assert.equal(proven.length, 25);
  const unresolved = cls
    .filter((r) => !shape.includes(r))
    .map((r) => l2.resolveProducer(r.repo, l1.derefById(r.id)));
  assert.ok(unresolved.length > 0);
});
