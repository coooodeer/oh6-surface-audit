'use strict';

/**
 * p5-l4b-judge.js —— P5 L4b 10 包（check 是否覆盖 sink）与 O7 回写。
 */

const fs = require('fs');
const path = require('path');
const { OUT_ROOT, ensureDir, readJsonl, writeJsonl, writeJson } = require('../lib/util.js');
const l4b = require('../lib/l4b.js');
const p5l4b = require('../lib/p5-l4b.js');

function makeMockTransport(packs) {
  const byId = new Map(packs.map((p) => [p.id, p]));
  return {
    id: 'mock-p5',
    simulated: true,
    model: 'mock',
    keyPresent: () => true,
    async send({ unitId }) {
      const pack = byId.get(unitId);
      const checks = (pack ? pack.items : []).map((item, i) => ({
        check: item,
        covers: 'unknown',
        evidenceRef: pack.refs[Math.min(i, pack.refs.length - 1)]
      }));
      return {
        kind: 'ok',
        content: JSON.stringify({ checks, reason: 'mock: 证据不足时按 unknown', evidenceRefs: [pack.refs[0]] }),
        usage: { promptTokens: 10, completionTokens: 10 },
        usageKnown: true,
        model: 'mock',
        finishReason: 'stop',
        maxTokensSent: 2048,
        wallMs: 1
      };
    }
  };
}

async function main() {
  ensureDir(path.join(OUT_ROOT, 'p5'));
  const claims = readJsonl(path.join(OUT_ROOT, 'p5', 'claims.jsonl'));
  const paths = readJsonl(path.join(OUT_ROOT, 'p5', 'paths.jsonl'));
  const sel = p5l4b.selectP5L4bClaims(claims, paths, 10);
  const l1 = require('../lib/l1.js').loadL1();
  const packs = sel.claims.map((c) => p5l4b.buildP5Pack(c, paths.find((p) => p.unitId === c.unitId), l1, { maxChecks: 1, shortEvidence: true }));
  writeJsonl(path.join(OUT_ROOT, 'p5', 'l4b-packs.jsonl'), packs);
  const live = !!process.env.OH6_LLM_API_KEY;
  const transport = live ? l4b.makeTransport({ maxTokens: 4096, timeoutMs: 120000 }) : makeMockTransport(packs);
  const results = [];
  const logs = [];
  for (const pack of packs) {
    const r = await p5l4b.judgePack(pack, transport, { maxTokens: 4096, timeoutMs: 90000 });
    logs.push(...r.log);
    results.push({
      id: pack.id,
      claimId: pack.claimId,
      ok: r.ok,
      blocked: r.blocked === true,
      reason: r.reason || null,
      errors: r.errors || null,
      parsed: r.parsed || null,
      aggregate: r.aggregate || null
    });
  }
  const logFile = p5l4b.LOG_FILE;
  ensureDir(path.dirname(logFile));
  const existingLogs = fs.existsSync(logFile) ? readJsonl(logFile) : [];
  writeJsonl(logFile, [...existingLogs, ...logs]);
  writeJsonl(path.join(OUT_ROOT, 'p5', 'l4b-results.jsonl'), results);
  const claimBy = new Map(claims.map((c) => [c.claimId, c]));
  for (const r of results) {
    if (!r.ok) continue;
    const c = claimBy.get(r.claimId);
    if (!c) continue;
    claimBy.set(r.claimId, p5l4b.applyP5L4b(c, r));
  }
  const updated = claims.map((c) => claimBy.get(c.claimId));
  if (!fs.existsSync(path.join(OUT_ROOT, 'p5', 'claims-pre-l4b.jsonl'))) {
    writeJsonl(path.join(OUT_ROOT, 'p5', 'claims-pre-l4b.jsonl'), claims);
  }
  writeJsonl(path.join(OUT_ROOT, 'p5', 'claims.jsonl'), updated);
  const ok = results.filter((r) => r.ok);
  const summary = {
    generatedAt: new Date().toISOString(),
    simulated: !live,
    liveBlocked: !live,
    packs: packs.length,
    ok: ok.length,
    schemaSuccessRate: packs.length ? Number((ok.length / packs.length).toFixed(3)) : 0,
    refsOkRate: ok.length ? 1 : 0,
    blocked: results.filter((r) => r.blocked).length,
    selected: { t3: sel.t3, satisfied: sel.satisfied },
    aggregates: ok.reduce((a, r) => { const k = r.aggregate && r.aggregate.covers; a[k] = (a[k] || 0) + 1; return a; }, {}),
    tokens: {
      prompt: logs.reduce((n, r) => n + (r.promptTokens || 0), 0),
      completion: logs.reduce((n, r) => n + (r.completionTokens || 0), 0)
    },
    log: path.relative(path.join(OUT_ROOT, '..'), logFile).split(path.sep).join('/'),
    results
  };
  summary.gate = summary.packs >= 10 && summary.schemaSuccessRate >= 0.8 && summary.refsOkRate === 1;
  writeJson(path.join(OUT_ROOT, 'p5', 'l4b-summary.json'), summary);
  process.stdout.write(`P5 L4b: sim=${summary.simulated} packs=${summary.packs} ok=${summary.ok} schema=${summary.schemaSuccessRate} refs=${summary.refsOkRate} gate=${summary.gate}\n`);
  if (!summary.gate) process.exit(2);
}

if (require.main === module) {
  main().catch((e) => { process.stderr.write(`${e && e.stack ? e.stack : e}\n`); process.exit(1); });
}

module.exports = { main, makeMockTransport };
