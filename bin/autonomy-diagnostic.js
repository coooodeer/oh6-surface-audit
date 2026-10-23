#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const factsLib = require('../lib/autonomy/facts');
const discovery = require('../lib/autonomy/discovery');
const diagnostic = require('../lib/autonomy/diagnostic');
const { ModelGateway } = require('../lib/autonomy/model');
const { createBudget } = require('../lib/autonomy/tools');
const scope = require('../K/policies/autonomy-pilot-scope.json');
const policy = require('../K/policies/autonomy-pilot-budget.json').budget;

async function main(argv = process.argv.slice(2)) {
  const opts = Object.fromEntries(argv.map((arg) => {
    const match = /^--(mode|model)=(.+)$/.exec(arg);
    if (!match) throw new Error(`unknown argument: ${arg}`);
    return [match[1], match[2]];
  }));
  const mode = opts.mode || 'off';
  if (!['off', 'live'].includes(mode)) throw new Error('mode must be off or live');
  if (opts.model && !/^(cn|global):[a-z0-9.-]+$/.test(opts.model)) throw new Error('invalid catalog model ID');
  const facts = factsLib.AutonomyFacts.open({ snapshot: scope.snapshotId, scope });
  const anchors = discovery.buildAnchors(facts, scope);
  const entry = anchors.entries.find((a) => a.kind === 'idl' && a.method === 'SetPolicyAsync');
  if (!entry) throw new Error('diagnostic entry missing');
  const binding = discovery.resolveBinding(entry.entityId, { facts, scope, anchors: anchors.anchors });
  const prepared = diagnostic.prepare(facts, binding);
  const budget = createBudget({ ...policy, maxModelRequests: 4, maxTaskModelRequests: 4 });
  const gateway = new ModelGateway({ mode, modelOverride: opts.model || null, budget,
    maxTokens: 1200, timeoutMs: 120000 });
  if (mode === 'live' && !gateway.keyPresent()) throw new Error('live key missing; no mock fallback');
  const result = await diagnostic.compare(prepared, gateway, 'TASK:108bcc806d3fc6f0');
  result.budget = { modelRequests: budget.modelRequests, inputTokens: budget.inputTokens,
    outputTokens: budget.outputTokens };
  const dir = path.join(__dirname, '..', 'out', 'autonomy', 'diagnostic');
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `${Date.now()}-${crypto.randomBytes(4).toString('hex')}.json`);
  fs.writeFileSync(file, `${JSON.stringify(result, null, 2)}\n`, 'utf8');
  console.log(JSON.stringify({ artifact: file, kind: result.kind, mode, budget: result.budget,
    results: result.rows.map((r) => ({ group: r.group, ...r.result })) }, null, 2));
  return result.rows.some((r) => r.result.status !== 'recorded') && mode === 'live' ? 3 : 0;
}

if (require.main === module) main().then((code) => { process.exitCode = code; }, (e) => {
  console.error(e.message); process.exitCode = 2;
});
module.exports = { main };
