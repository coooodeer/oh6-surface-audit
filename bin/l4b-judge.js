'use strict';

/**
 * l4b-judge.js —— 单独的 L4b 批量入口（runner 内部也调用同一 lib/l4b.js）。
 *
 * 用法：
 *   node bin/l4b-judge.js --limit=10          # live（需要 OH6_LLM_API_KEY）
 *   node bin/l4b-judge.js --mock --limit=10   # mock 结构测试
 */

const fs = require('fs');
const path = require('path');
const { OUT_ROOT, writeJsonl, writeJson, ensureDir, readJsonl } = require('../lib/util.js');
const { loadL1 } = require('../lib/l1.js');
const { loadL2 } = require('../lib/l2.js');
const { buildP6Claims, selectP3Candidates } = require('../lib/claims.js');
const { proveP6Claims } = require('../lib/prover-p6.js');
const { proveP3Claims } = require('../lib/prover-p3.js');
const l4b = require('../lib/l4b.js');

function args() {
  const a = process.argv.slice(2);
  return {
    limit: Number((a.find((x) => x.startsWith('--limit=')) || '').split('=')[1] || 10),
    mock: a.includes('--mock'),
    model: (a.find((x) => x.startsWith('--model=')) || '').split('=')[1] || null,
    timeoutMs: Number((a.find((x) => x.startsWith('--timeout-ms=')) || '').split('=')[1] || 90000),
    maxTokens: Number((a.find((x) => x.startsWith('--max-tokens=')) || '').split('=')[1] || 8192)
  };
}

async function main() {
  const opts = args();
  const out = path.join(OUT_ROOT, 'l4b');
  ensureDir(out);
  const l1 = loadL1();
  const l2 = loadL2(l1);
  const p6Claims = buildP6Claims(l1, l2);
  const p6Verdicts = proveP6Claims(p6Claims, l1);
  const p3 = selectP3Candidates(l1, l2);
  const p3Verdicts = proveP3Claims(p3.claims, l1, l2, { impactNotAssessed: true });
  const p6Packs = l4b.selectP6L4bClaims(p6Claims, p6Verdicts, l1, opts.limit).map((c) => l4b.buildP6Pack(c, l1));
  const p3Packs = l4b.selectP3L4bClaims(p3.claims, p3Verdicts, 2).map((c) => l4b.buildP3Pack(c, l1));
  writeJsonl(path.join(out, 'p6-packs.jsonl'), p6Packs);
  writeJsonl(path.join(out, 'p3-packs.jsonl'), p3Packs);

  const live = !opts.mock && !!process.env.OH6_LLM_API_KEY;
  const transport = live
    ? l4b.makeTransport({ maxTokens: opts.maxTokens, timeoutMs: opts.timeoutMs, model: opts.model })
    : l4b.makeMockTransport([...p6Packs, ...p3Packs]);

  const p6Run = await l4b.runBatch(p6Packs, { transport, maxAttempts: 2 });
  const p3Run = await l4b.runBatch(p3Packs, { transport, maxAttempts: 2 });
  const results = [...p6Run.results, ...p3Run.results];
  writeJsonl(path.join(out, 'results.jsonl'), results);
  const okP6 = p6Run.results.filter((r) => r.ok);
  const summary = {
    generatedAt: new Date().toISOString(),
    simulated: !live,
    liveBlocked: !live,
    liveBlockedReason: live ? null : (opts.mock ? 'forced-mock' : 'OH6_LLM_API_KEY-missing'),
    p6: {
      packs: p6Packs.length,
      ok: okP6.length,
      schemaSuccessRate: p6Packs.length ? Number((okP6.length / p6Packs.length).toFixed(3)) : 0,
      refsOk: okP6.length,
      refsOkRate: okP6.length ? 1 : 0,
      blocked: p6Run.results.filter((r) => r.blocked).length,
      aggregates: okP6.reduce((a, r) => { const k = r.aggregate && r.aggregate.aggregate; a[k] = (a[k] || 0) + 1; return a; }, {})
    },
    p3: { packs: p3Packs.length, ok: p3Run.results.filter((r) => r.ok).length, blocked: p3Run.results.filter((r) => r.blocked).length },
    tokens: {
      prompt: results.reduce((n, r) => n + ((r.usage && r.usage.promptTokens) || 0), 0),
      completion: results.reduce((n, r) => n + ((r.usage && r.usage.completionTokens) || 0), 0),
      total: results.reduce((n, r) => n + ((r.usage && r.usage.promptTokens) || 0) + ((r.usage && r.usage.completionTokens) || 0), 0)
    },
    log: l4b.LOG_FILE
  };
  summary.gate = summary.p6.packs >= 10 && summary.p6.schemaSuccessRate >= 0.8 && summary.p6.refsOkRate === 1;
  writeJson(path.join(out, 'summary.json'), summary);
  process.stdout.write(`l4b: sim=${summary.simulated} p6 ${summary.p6.ok}/${summary.p6.packs} p3 ${summary.p3.ok}/${summary.p3.packs} tokens=${summary.tokens.total} gate=${summary.gate}\n`);
}

if (require.main === module) {
  main().catch((e) => {
    process.stderr.write(`fatal: ${e && e.stack ? e.stack : e}\n`);
    process.exit(1);
  });
}

module.exports = { main };

