'use strict';

/**
 * l3-claim-seeds.js —— 预生成 P3/P6 的 claim-seed（不是最终 claim，不含 evaluator 实现）。
 *
 * 输出：out/l3/{p3,p6}-claims.jsonl、out/l3/summary.json
 */

const fs = require('fs');
const path = require('path');
const { OUT_ROOT, readJsonl, writeJsonl, writeJson, ensureDir } = require('../lib/util.js');

const OUT = path.join(OUT_ROOT, 'l3');

function main() {
  ensureDir(OUT);
  const p3Reach = readJsonl(path.join(OUT_ROOT, 'gaps', 'p3-reachability.jsonl'));
  const p3Probe = new Map(readJsonl(path.join(OUT_ROOT, 'gaps', 'p3-probe.jsonl')).map((r) => [r.id, r]));
  const p3 = [];
  for (const r of p3Reach) {
    if (!r.reachable || r.status !== 'potential-violation') continue;
    const p = p3Probe.get(r.id);
    if (!p) continue;
    p3.push({
      claimId: `L3-P3-${r.id}`,
      seed: true,
      class: 'P3',
      repo: p.repo,
      entry: { file: p.file, function: p.function, depth: r.depth },
      source: { kind: 'deref', file: p.file, line: p.line },
      sink: { kind: 'deref', text: p.text },
      producer: p.producerFunction ? { name: p.producerFunction.name, file: p.producerFunction.file, line: p.producerFunction.startLine } : null,
      obligations: [
        { id: 'O1', kind: 'entry-reachable', status: 'proven', evidence: { depth: r.depth } },
        { id: 'O2', kind: 'producer-may-null', status: 'unproven', evidence: { producerMayNull: p.producerMayNull } },
        { id: 'O3', kind: 'guard-before-deref', status: p.guardBefore ? 'proven' : 'disproven', evidence: { guardBefore: p.guardBefore } },
        { id: 'O4', kind: 'deref-in-path', status: 'unproven', evidence: { requires: 'dataflow' } }
      ],
      status: 'seed'
    });
  }
  writeJsonl(path.join(OUT, 'p3-claims.jsonl'), p3);

  const actions = readJsonl(path.join(OUT_ROOT, 'l2', 'actions.jsonl'));
  const payloads = new Map(readJsonl(path.join(OUT_ROOT, 'l2', 'p6-payload.jsonl')).map((x) => [String(x.recordId), x]));
  const p6 = [];
  for (const a of actions) {
    if (a.thirdPartyReachability !== 'reachable') continue;
    if ((a.subscriberPermissions || []).length || (a.directedSubscriberUids || []).length) continue;
    const p = payloads.get(String(a.recordId));
    if (!p || !(p.payloadCandidates || []).length) continue;
    p6.push({
      claimId: `L3-P6-${a.recordId}`,
      seed: true,
      class: 'P6',
      entry: { action: a.action, recordId: a.recordId },
      source: { kind: 'broadcast-payload', payloads: p.payloadCandidates, names: p.payloadNames },
      sink: a.sink,
      obligations: [
        { id: 'O1', kind: 'payload-present', status: 'proven', evidence: { payloadCount: p.payloadCandidates.length } },
        { id: 'O2', kind: 'payload-sensitive', status: 'unproven', evidence: { requires: 'L4b' } },
        { id: 'O3', kind: 'receiver-third-party', status: 'proven', evidence: { permissions: a.subscriberPermissions, directed: a.directedSubscriberUids } },
        { id: 'O4', kind: 'no-public-equivalent', status: 'unproven', evidence: { requires: 'L4b' } },
        { id: 'O5', kind: 'publish-executes', status: a.analysisStatus === 'resolved' ? 'proven' : 'unproven', evidence: { analysisStatus: a.analysisStatus } }
      ],
      status: 'seed'
    });
  }
  writeJsonl(path.join(OUT, 'p6-claims.jsonl'), p6);
  const summary = { generatedAt: new Date().toISOString(), p3: p3.length, p6: p6.length, p6WithPayload: p6.length };
  writeJson(path.join(OUT, 'summary.json'), summary);
  process.stdout.write(`claim seeds: P3=${p3.length}, P6=${p6.length}\n`);
}

main();
