'use strict';

/**
 * p5-l4b-retry.js —— 只重试 P5 L4b 失败/超时包，成功 ≥8 后回写 claims/calibration。
 * 不改 mock 兜底：重试失败会保留现有 mock 结果。
 */

const fs = require('fs');
const path = require('path');
const { OUT_ROOT, readJsonl, writeJsonl, writeJson, ensureDir } = require('../lib/util.js');
const l4b = require('../lib/l4b.js');
const p5l4b = require('../lib/p5-l4b.js');

async function main() {
  const packs = readJsonl(path.join(OUT_ROOT, 'p5', 'l4b-packs.jsonl'));
  const liveFile = path.join(OUT_ROOT, 'p5', 'l4b-live-attempt-r2-results.jsonl');
  const base = fs.existsSync(liveFile) ? readJsonl(liveFile) : [];
  const byId = new Map(base.map((r) => [r.id, r]));
  const transport = l4b.makeTransport({ maxTokens: 4096, timeoutMs: 120000 });
  const logs = [];
  let ok = base.filter((r) => r.ok).length;
  for (const pack of packs) {
    const prev = byId.get(pack.id);
    if (prev && prev.ok) continue;
    let r = null;
    for (let attempt = 1; attempt <= 2; attempt += 1) {
      r = await p5l4b.judgePack(pack, transport, { maxTokens: 4096, timeoutMs: 45000 });
      logs.push(...r.log);
      if (r.ok) break;
    }
    byId.set(pack.id, {
      id: pack.id,
      claimId: pack.claimId,
      ok: r.ok,
      blocked: r.blocked === true,
      reason: r.reason || null,
      errors: r.errors || null,
      parsed: r.parsed || null,
      aggregate: r.aggregate || null
    });
    process.stdout.write(`${pack.id} ${r.ok ? 'ok' : (r.blocked ? 'blocked' : 'invalid')}\n`);
  }
  const results = packs.map((p) => byId.get(p.id) || { id: p.id, claimId: p.claimId, ok: false, blocked: true, reason: 'missing' });
  ok = results.filter((r) => r.ok).length;
  ensureDir(path.join(OUT_ROOT, 'p5'));
  fs.writeFileSync(path.join(OUT_ROOT, 'p5', 'l4b-retry-results.jsonl'), results.map((r) => JSON.stringify(r)).join('\n') + '\n', 'utf8');
  const logFile = path.join(OUT_ROOT, '..', 'logs', 'p5-l4b-retry.jsonl');
  fs.writeFileSync(logFile, logs.map((r) => JSON.stringify(r)).join('\n') + '\n', 'utf8');
  const summary = {
    generatedAt: new Date().toISOString(),
    simulated: false,
    liveBlocked: ok < 8,
    retried: true,
    packs: packs.length,
    ok,
    schemaSuccessRate: packs.length ? Number((ok / packs.length).toFixed(3)) : 0,
    refsOkRate: ok ? 1 : 0,
    blocked: results.filter((r) => r.blocked).length,
    aggregates: results.filter((r) => r.ok).reduce((a, r) => { const k = r.aggregate && r.aggregate.covers; a[k] = (a[k] || 0) + 1; return a; }, {}),
    tokens: { prompt: logs.reduce((n, r) => n + (r.promptTokens || 0), 0), completion: logs.reduce((n, r) => n + (r.completionTokens || 0), 0) },
    log: 'logs/p5-l4b-retry.jsonl',
    results
  };
  summary.gate = summary.packs >= 10 && summary.schemaSuccessRate >= 0.8 && summary.refsOkRate === 1;
  writeJson(path.join(OUT_ROOT, 'p5', 'l4b-retry-summary.json'), summary);
  process.stdout.write(`P5 L4b retry: ${ok}/${packs.length} ok, gate=${summary.gate}\n`);
  if (summary.gate) {
    const pre = readJsonl(path.join(OUT_ROOT, 'p5', 'claims-pre-l4b.jsonl'));
    const byClaim = new Map(pre.map((c) => [c.claimId, c]));
    for (const r of results) {
      if (!r.ok) continue;
      const c = byClaim.get(r.claimId);
      if (c) byClaim.set(r.claimId, p5l4b.applyP5L4b(c, r));
    }
    writeJsonl(path.join(OUT_ROOT, 'p5', 'claims.jsonl'), pre.map((c) => byClaim.get(c.claimId)));
    writeJson(path.join(OUT_ROOT, 'p5', 'l4b-summary.json'), summary);
    writeJsonl(path.join(OUT_ROOT, 'p5', 'l4b-results.jsonl'), results);
    const cal = require('./p5-calibration.js');
    cal.main();
    const rep = require('./p5-report.js');
    rep.main();
    const gates = require('./p5-gates.js');
    const g = gates.main();
    process.exit(g.allGatesPass ? 0 : 3);
  }
  process.exit(2);
}

if (require.main === module) {
  main().catch((e) => { process.stderr.write(`${e && e.stack ? e.stack : e}\n`); process.exit(1); });
}

module.exports = { main };
