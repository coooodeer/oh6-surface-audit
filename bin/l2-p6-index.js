'use strict';

/**
 * l2-p6-index.js —— P6 的 restricted/public/design 交叉索引。
 * 输出 out/l2/p6-index.jsonl、out/l2/p6-index-summary.json
 */

const fs = require('fs');
const path = require('path');
const { TOOL_ROOT, OUT_ROOT, readJsonl, writeJsonl, writeJson, ensureDir } = require('../lib/util.js');

const ACTIONS = path.join(OUT_ROOT, 'l2', 'actions.jsonl');
const OUT = path.join(OUT_ROOT, 'l2', 'p6-index.jsonl');

function tokens(s) {
  return [...new Set(String(s || '').toLowerCase().replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(/[^a-z0-9_]+/).flatMap((t) => t.split('_')).filter((t) => t.length >= 3))];
}
function overlap(a, b) {
  const hit = a.filter((t) => b.has(t));
  return { score: hit.length, hit };
}

function main() {
  ensureDir(path.dirname(OUT));
  const restricted = readJsonl(path.join(TOOL_ROOT, 'data', 'facts', 'restricted-apis.jsonl'))
    .map((r) => ({ r, toks: new Set(tokens(`${r.name} ${r.qualifiedName}`)) }));
  const publics = readJsonl(path.join(TOOL_ROOT, 'data', 'facts', 'public-apis.jsonl'))
    .map((p) => ({ p, toks: new Set(tokens(`${p.apiName} ${p.module}`)) }));
  const design = readJsonl(path.join(TOOL_ROOT, 'data', 'facts', 'design-specs.jsonl'))
    .map((d) => ({ d, toks: new Set(tokens(`${(d.entity && d.entity.name) || ''} ${d.statement || ''}`)) }));
  const actions = readJsonl(ACTIONS);
  const payloadPath = path.join(OUT_ROOT, 'l2', 'p6-payload.jsonl');
  const payloads = fs.existsSync(payloadPath)
    ? new Map(readJsonl(payloadPath).map((x) => [String(x.recordId), x]))
    : new Map();

  const index = [];
  for (const a of actions) {
    const payloadRow = payloads.get(String(a.recordId));
    const params = payloadRow
      ? (payloadRow.payloadNames || [])
      : (a.params || []).map((p) => (typeof p === 'string' ? p : p && p.name)).filter(Boolean);
    for (const name of params) {
      const pt = tokens(name);
      const rHits = restricted.map((x) => ({ r: x.r, s: overlap(pt, x.toks) }))
        .filter((x) => x.s.score > 0).sort((a, b) => b.s.score - a.s.score).slice(0, 5);
      const pHits = publics.map((x) => ({ p: x.p, s: overlap(pt, x.toks) }))
        .filter((x) => x.s.score > 0).sort((a, b) => b.s.score - a.s.score).slice(0, 5);
      const dHits = design.map((x) => ({ d: x.d, s: overlap(pt, x.toks) }))
        .filter((x) => x.s.score > 0).sort((a, b) => b.s.score - a.s.score).slice(0, 5);
      const rBest = rHits[0] || null;
      const pBest = pHits.find((x) => x.p.permissionExpression === null && x.p.systemApi === false) || null;
      index.push({
        recordId: a.recordId,
        action: a.action,
        payload: name,
        sensitivity: rBest && rBest.s.score >= 2 ? 'restricted-token' : (dHits[0] && dHits[0].s.score >= 2 ? 'design-token' : 'unknown'),
        sensitivityMatches: rHits.map((x) => ({ name: x.r.name, qualifiedName: x.r.qualifiedName, permission: x.r.permissionExpression, systemApi: x.r.systemApi, score: x.s.score, hit: x.s.hit })),
        designMatches: dHits.map((x) => ({ name: (x.d.entity && x.d.entity.name) || null, topic: x.d.topic || null, score: x.s.score, hit: x.s.hit })),
        publicMatches: pHits.map((x) => ({ apiName: x.p.apiName, module: x.p.module, permission: x.p.permissionExpression, systemApi: x.p.systemApi, score: x.s.score, hit: x.s.hit })),
        publicZeroPermissionMatch: pBest ? { apiName: pBest.p.apiName, score: pBest.s.score, hit: pBest.s.hit } : null
      });
    }
  }
  writeJsonl(OUT, index);
  const summary = {
    generatedAt: new Date().toISOString(),
    actions: actions.length,
    actionsWithPayload: actions.filter((a) => (a.params || []).length).length,
    payloadItems: index.length,
    sensitivity: index.reduce((a, r) => { a[r.sensitivity] = (a[r.sensitivity] || 0) + 1; return a; }, {}),
    publicZeroPermission: index.filter((r) => r.publicZeroPermissionMatch).length,
    publicTokenAny: index.filter((r) => r.publicMatches.length).length
  };
  writeJson(path.join(OUT_ROOT, 'l2', 'p6-index-summary.json'), summary);
  process.stdout.write(`p6 index: payloadItems=${summary.payloadItems} sensitivity=${JSON.stringify(summary.sensitivity)} publicZero=${summary.publicZeroPermission}\n`);
}

main();
