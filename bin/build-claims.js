'use strict';

/**
 * build-claims.js —— L3 claim builder。
 *
 * 产物：
 *   out/l3/p3-claims.jsonl          P3 claim（现有 5 + 1a/2a 扩充）
 *   out/l3/p3-candidate-ledger.jsonl 73 条 reachable deref 的候选/拒绝原因
 *   out/l3/p3-deref-classification.jsonl 182 条 entryBinding 重分类
 *   out/l3/p6-claims.jsonl          95 os_account site + 23 miner finding site
 *   out/l3/p4-claims.jsonl          11 OH candidate + 13 CVE patch sample
 *   out/l3/summary.json
 */

const path = require('path');
const { OUT_ROOT, readJsonl, writeJsonl, writeJson, ensureDir } = require('../lib/util.js');
const { loadL1 } = require('../lib/l1.js');
const { loadL2 } = require('../lib/l2.js');
const { buildAllClaims, assertClaimShape } = require('../lib/claims.js');

const OUT = path.join(OUT_ROOT, 'l3');

function main() {
  ensureDir(OUT);
  const l1 = loadL1();
  const l2 = loadL2(l1);
  const candidates = readJsonl(path.join(OUT_ROOT, 'p4', 'candidates.jsonl'));
  const cvePatches = readJsonl(path.join(OUT_ROOT, 'p4', 'cve-patches.jsonl'));
  const all = buildAllClaims(l1, l2, { p4Candidates: candidates, p4CvePatches: cvePatches });
  const errors = [];
  for (const claim of [...all.p3.claims, ...all.p6, ...all.p4]) {
    for (const e of assertClaimShape(claim)) errors.push({ claimId: claim.claimId, error: e });
  }
  writeJsonl(path.join(OUT, 'p3-claims.jsonl'), all.p3.claims);
  writeJsonl(path.join(OUT, 'p3-candidate-ledger.jsonl'), all.p3.ledger);
  writeJsonl(path.join(OUT, 'p3-deref-classification.jsonl'), l2.derefClassification());
  writeJsonl(path.join(OUT, 'p6-claims.jsonl'), all.p6);
  writeJsonl(path.join(OUT, 'p4-claims.jsonl'), all.p4);
  const summary = {
    generatedAt: new Date().toISOString(),
    l1: l1.stats(),
    p3: all.p3.summary,
    p3Ledger: all.p3.ledger.reduce((a, r) => { const k = r.selected ? 'selected' : r.reason; a[k] = (a[k] || 0) + 1; return a; }, {}),
    p6: {
      total: all.p6.length,
      osAccount: all.p6.filter((c) => c.group === 'os-account').length,
      minerFindings: all.p6.filter((c) => c.group === 'miner-finding').length,
      obligations: all.p6[0] ? all.p6[0].obligations.length : 0
    },
    p4: {
      total: all.p4.length,
      ohCandidates: all.p4.filter((c) => c.group === 'oh-candidate').length,
      cveCalibration: all.p4.filter((c) => c.group === 'cve-calibration').length,
      obligations: all.p4[0] ? all.p4[0].obligations.length : 0
    },
    schemaErrors: errors
  };
  writeJson(path.join(OUT, 'summary.json'), summary);
  process.stdout.write(`claims: P3=${all.p3.claims.length} P6=${all.p6.length} P4=${all.p4.length}; schemaErrors=${errors.length}\n`);
  if (errors.length) process.exit(2);
}

if (require.main === module) main();

module.exports = { main };
