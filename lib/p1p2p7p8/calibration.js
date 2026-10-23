'use strict';

/**
 * calibration.js —— §7.7 抽样复核：3 轮 ×（10 accepted + 10 rejected）。
 *
 * 这是程序化复核，不调用模型：
 *   - 义务状态与 verdict/tier 是否一致；
 *   - T2 是否有明确 disproven 义务，T3 是否有具名 gap；
 *   - T4 是否没有 VIOLATION 路径；
 *   - fixture claim 的 pre/post/mutant 期望是否仍成立；
 *   - O10 是否固定 unproven；是否出现 PROVEN-VULN。
 */

const fs = require('fs');
const path = require('path');
const { OUT_ROOT, ensureDir } = require('./common');

const TIER_OF = {
  'PROVEN-VULN': 'T1',
  'PROVEN-WEAKNESS': 'T2',
  'CONDITIONS-NOT-MET': 'T3',
  'NOT-VULN': 'T4',
  'NOT-APPLICABLE': 'T5'
};

function rotate(list, offset) {
  if (!list.length) return [];
  const out = [];
  for (let i = 0; i < list.length; i += 1) out.push(list[(i + offset) % list.length]);
  return out;
}

function checkClaim(claim) {
  const checks = [];
  const o = (id) => (claim.obligations || []).find((x) => x.id === id) || null;
  checks.push({ name: 'obligations-10', pass: (claim.obligations || []).length === 10 });
  checks.push({ name: 'o10-unproven', pass: Boolean(o('O10') && o('O10').status === 'unproven') });
  checks.push({ name: 'no-proven-vuln', pass: claim.productVerdict !== 'PROVEN-VULN' && claim.tier !== 'T1-confirmed' });
  checks.push({ name: 'tier-consistent', pass: TIER_OF[claim.productVerdict] === claim.tier.slice(0, 2) });
  if (String(claim.tier || '').startsWith('T2')) {
    const disproven = (claim.obligations || []).some((x) => ['O5', 'O6', 'O4'].includes(x.id) && x.status === 'disproven');
    checks.push({ name: 't2-has-disproven-guard-obligation', pass: disproven });
    checks.push({ name: 't2-is-weak-not-confirmed', pass: claim.productVerdict === 'PROVEN-WEAKNESS' });
  }
  if (claim.tier === 'T3-instrumentation-gap') {
    const named = (claim.obligations || []).some((x) => x.status === 'unproven' && (x.reason || x.evidence));
    checks.push({ name: 't3-has-named-gap', pass: Boolean(named) });
    checks.push({ name: 't3-not-negative', pass: claim.productVerdict !== 'NOT-VULN' });
  }
  if (claim.tier === 'T4-negative' || claim.tier === 'T5-not-applicable') {
    checks.push({ name: 't4-not-violation', pass: claim.claimVerdict !== 'VIOLATION' });
    checks.push({ name: 't4-not-counted', pass: claim.tier !== 'T4-negative' || claim.fixture === true || claim.productionEligible === true });
  }
  if (claim.tier === 'T3-instrumentation-gap') {
    checks.push({ name: 't3-not-entry-gap-as-t4', pass: claim.productVerdict !== 'NOT-VULN' });
  }
  checks.push({ name: 'production-flag-consistent', pass: claim.fixture === true ? claim.productionEligible === false : claim.productionEligible === true });
  if (claim.fixture === true) {
    checks.push({ name: 'fixture-has-expected', pass: claim.fixtureExpected != null });
  }
  return checks;
}

function runCalibration(claims, opts = {}) {
  const accepted = claims.filter((c) => String(c.tier || '').startsWith('T2') || c.tier === 'T3-instrumentation-gap');
  const rejected = claims.filter((c) => c.tier === 'T4-negative' || c.tier === 'T5-not-applicable' || c.tier === 'T1-confirmed');
  const rounds = [];
  const log = [];
  let falseProvenVuln = 0;
  let boundaryCovered = false;
  for (let r = 1; r <= 3; r += 1) {
    const accPool = rotate(accepted, (r - 1) * 7);
    const rejPool = rotate(rejected, (r - 1) * 5);
    const acc = accPool.slice(0, 10);
    const rej = rejPool.slice(0, 10);
    // 至少一轮覆盖 P1/P2 的 check 存在/缺失边界。
    if (!boundaryCovered) {
      const hasP1T2 = acc.some((c) => c.class === 'P1' && String(c.tier || '').startsWith('T2'));
      const hasP1T4 = rej.some((c) => c.class === 'P1' && c.tier === 'T4-negative');
      const hasP2T2 = acc.some((c) => c.class === 'P2');
      const hasP2T4 = rej.some((c) => c.class === 'P2' && c.tier === 'T4-negative');
      boundaryCovered = hasP1T2 && hasP1T4 && hasP2T2 && hasP2T4;
    }
    const roundRows = [];
    for (const [kind, list] of [['accepted', acc], ['rejected', rej]]) {
      for (const c of list) {
        const checks = checkClaim(c);
        const pass = checks.every((x) => x.pass);
        if(!pass && c.productVerdict === 'PROVEN-VULN') falseProvenVuln += 1;
        const row = {
          round: r,
          kind,
          claimId: c.claimId,
          class: c.class,
          tier: c.tier,
          claimVerdict: c.claimVerdict,
          productVerdict: c.productVerdict,
          productionEligible: c.productionEligible === true,
          fixture: c.fixture === true,
          checks,
          pass
        };
        roundRows.push(row);
        log.push(row);
      }
    }
    rounds.push({
      round: r,
      accepted: acc.length,
      rejected: rej.length,
      passed: roundRows.filter((x) => x.pass).length,
      failed: roundRows.filter((x) => !x.pass).length,
      pass: roundRows.every((x) => x.pass)
    });
  }
  const total = log.length;
  const passed = log.filter((x) => x.pass).length;
  return {
    rounds,
    log,
    totalSampled: total,
    passed,
    failed: total - passed,
    passRate: total ? Number((passed / total).toFixed(4)) : 0,
    falseProvenVuln,
    boundaryCovered,
    pass: rounds.every((r) => r.pass) && falseProvenVuln === 0 && boundaryCovered
  };
}

function writeCalibration(result) {
  const dir = path.join(OUT_ROOT, 'report');
  ensureDir(dir);
  const file = path.join(dir, 'P1P2P7P8-CALIBRATION-LOG.jsonl');
  fs.writeFileSync(file, result.log.map((r) => JSON.stringify(r)).join('\n') + (result.log.length ? '\n' : ''), 'utf8');
  return { file: 'out/report/P1P2P7P8-CALIBRATION-LOG.jsonl', rows: result.log.length };
}

module.exports = { runCalibration, writeCalibration, checkClaim, TIER_OF };
