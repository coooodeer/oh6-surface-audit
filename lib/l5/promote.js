'use strict';

/**
 * lib/l5/promote.js —— 把 L5 target 结果接到 O10 / promotion 的“副本”上。
 *
 * 不覆盖 campaign 原始 verdict；只写 out/l5/verdicts-with-l5.jsonl 和 oracle.jsonl。
 * T1 条件：O1–O10 全 proven + target/production + L5 confirmed；否则保持原 tier。
 */

const path = require('path');
const { OUT_ROOT, ensureDir, writeJson, writeJsonl } = require('../util.js');
const { CLASS_IDS, loadClassArtifacts } = require('../agent/classes.js');

function promoteRows(rows) {
  const loaded = loadClassArtifacts(CLASS_IDS);
  const byClaim = new Map(loaded.records.map((r) => [r.claimId, r]));
  const oracle = [];
  const promoted = [];
  const verdicts = [];
  for (const row of rows || []) {
    const rec = byClaim.get(row.claimId);
    if (!rec) continue;
    const v = JSON.parse(JSON.stringify(rec.verdict || {}));
    const claim = JSON.parse(JSON.stringify(rec.claim || {}));
    v.l5 = {
      result: row.result,
      reason: row.reason,
      runId: row.runId,
      sourceHash: row.sourceHash,
      harnessHash: row.harnessHash,
      sanitizer: row.sanitizer,
      compiler: row.compiler,
      repeat: row.repeat
    };
    claim.l5 = v.l5;
    const obs = (v.obligations || claim.obligations || []).map((o) => ({ ...o, evidence: { ...(o.evidence || {}) } }));
    const fidelity = row.harnessFidelity || 'pattern-only';
    const entryFaithful = fidelity === 'entry-faithful';
    const o10 = obs.find((o) => o.id === 'O10');
    const o9 = obs.find((o) => o.id === 'O9');
    if (row.result === 'confirmed' && entryFaithful && o9 && ['P1', 'P2', 'P4'].includes(row.class)) {
      o9.status = 'proven';
      o9.reason = 'l5-dynamic-memory-safety-signal';
      o9.evidence = {
        ...(o9.evidence || {}),
        impact: 'memory-safety-violation',
        basis: 'dynamic-sanitizer',
        runId: row.runId,
        sanitizer: row.sanitizer,
        note: 'dynamic signal confirms a memory-safety violation; not an exploitability claim'
      };
    }
    if (o10) {
      if (row.result === 'confirmed' && entryFaithful) {
        o10.status = 'proven';
        o10.reason = 'l5-dynamic-confirmed';
        o10.evidence = {
          ...(o10.evidence || {}),
          oracleKind: 'l5-target',
          runId: row.runId,
          sanitizer: row.sanitizer,
          sourceHash: row.sourceHash,
          harnessFidelity: fidelity
        };
      } else if (row.result === 'confirmed') {
        o10.status = 'unproven';
        o10.reason = `l5-harness-not-entry-faithful:${fidelity}`;
        o10.evidence = {
          ...(o10.evidence || {}),
          harnessFidelity: fidelity,
          runId: row.runId,
          note: 'function/pattern harness confirms only local behavior; does not prove claim-level O10'
        };
      } else if (row.result === 'no-signal') {
        o10.status = 'unproven';
        o10.reason = 'dynamic-no-signal';
      } else {
        o10.status = 'unproven';
        o10.reason = `dynamic-${row.result}:${row.reason || 'unknown'}`;
      }
    }
    v.obligations = obs;
    const allProven = obs.every((o) => o.status === 'proven');
    const eligible = row.result === 'confirmed'
      && allProven
      && rec.claim.productionEligible === true
      && rec.claim.inTarget === true
      && rec.claim.codeState === 'current-head';
    v.l5Promotion = {
      eligible,
      reason: eligible ? 'all-obligations-proven-and-l5-confirmed' : 'not-all-obligations-proven',
      unproven: obs.filter((o) => o.status !== 'proven').map((o) => o.id)
    };
    if (eligible) {
      v.productVerdict = 'PROVEN-VULN';
      v.tier = 'T1-confirmed';
      v.l5Promoted = true;
    }
    verdicts.push(v);
    promoted.push({
      claimId: row.claimId,
      class: row.class,
      result: row.result,
      harnessFidelity: row.harnessFidelity || 'pattern-only',
      promotionEligible: eligible,
      productVerdict: v.productVerdict,
      tier: v.tier,
      unproven: v.l5Promotion.unproven
    });
    oracle.push({
      oracleId: `L5-ORACLE-${row.claimId}`,
      claimId: row.claimId,
      class: row.class,
      result: row.result,
      reason: row.reason,
      harnessFidelity: row.harnessFidelity || 'pattern-only',
      runId: row.runId,
      sanitizer: row.sanitizer,
      compiler: row.compiler,
      sourceHash: row.sourceHash,
      harnessHash: row.harnessHash
    });
  }
  const outDir = path.join(OUT_ROOT, 'l5');
  ensureDir(outDir);
  writeJsonl(path.join(outDir, 'oracle.jsonl'), oracle);
  writeJsonl(path.join(outDir, 'verdicts-with-l5.jsonl'), verdicts);
  const summary = {
    generatedAt: new Date().toISOString(),
    total: rows.length,
    confirmed: rows.filter((r) => r.result === 'confirmed').length,
    promoted: promoted.filter((p) => p.promotionEligible).length,
    t1: verdicts.filter((v) => v.tier === 'T1-confirmed').length,
    rows: promoted
  };
  writeJson(path.join(outDir, 'promotion-summary.json'), summary);
  return { oracle, promoted, verdicts, summary };
}

module.exports = { promoteRows };
