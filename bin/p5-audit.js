'use strict';

/**
 * p5-audit.js —— P5-0 数据审计：R1 候选拆分、方向、pairing、权限检查索引。
 *
 * 产物：
 *   out/p5/method-units.jsonl
 *   out/p5/pairing.jsonl
 *   out/p5/check-sites.jsonl
 *   out/p5/data-audit.json
 */

const fs = require('fs');
const path = require('path');
const { WORKSPACE, OUT_ROOT, ensureDir, readJsonl, writeJsonl, writeJson } = require('../lib/util.js');
const { loadL1 } = require('../lib/l1.js');
const { buildP5Units } = require('../lib/p5-units.js');
const { pairUnits, writePairing } = require('../lib/p5-pairing.js');
const { buildP5Checks, writeChecks } = require('../lib/p5-checks.js');
const { buildP5Paths, writePaths } = require('../lib/p5-paths.js');
const { isR1 } = require('../lib/in-scope.js');

const AGENT = path.join(WORKSPACE, 'oh6-vuln-agent');

function localFixtures(l1) {
  const positivesPath = path.join(AGENT, 'result', 'optimization', 'historical-positive-agent-list-20261012-final', 'positives.jsonl');
  const positives = fs.existsSync(positivesPath) ? readJsonl(positivesPath) : [];
  const cwe862 = positives.filter((p) => p.cwe && p.cwe.id === 'CWE-862');
  const r1 = cwe862.filter((p) => (p.roots || []).some((r) => isR1(r.componentRoot)));
  const invariants = readJsonl(path.join(AGENT, 'data', 'facts', 'history-invariants.jsonl'));
  const p5Inv = invariants.filter((r) => (r.patternClass || []).includes('P5'));
  return {
    historicalPositives: positives.length,
    cwe862: cwe862.length,
    cwe862InR1: r1.length,
    cwe862InR1Cases: r1.map((p) => ({ id: p.id, roots: (p.roots || []).map((x) => `${x.componentRoot}/${x.file}:${x.function}`) })),
    p5Invariants: p5Inv.length,
    p5InvariantCases: p5Inv.map((r) => ({ id: r.id, repo: r.repo, file: r.file, witness: r.witness }))
  };
}

function main() {
  ensureDir(path.join(OUT_ROOT, 'p5'));
  const candidates = readJsonl(path.join(AGENT, 'result', 'latest', 'candidates.jsonl')).filter((c) => c.generator === 'G-P5');
  const entries = readJsonl(path.join(AGENT, 'result', 'latest', 'contracts', 'entries.jsonl'));
  const l2Entries = readJsonl(path.join(OUT_ROOT, 'l2', 'entries.jsonl'));
  const l1 = loadL1();

  const unitResult = buildP5Units({ candidates, entries, l2Entries, l1 });
  writeJsonl(path.join(OUT_ROOT, 'p5', 'method-units.jsonl'), unitResult.units);

  const pairing = pairUnits(unitResult.units, l1, entries);
  writePairing(pairing);

  const checks = buildP5Checks(l1);
  writeChecks(checks);

  const paths = buildP5Paths(unitResult.units, pairing.rows, checks.rows, l1);
  writePaths(paths);

  const modules = candidates.reduce((a, c) => {
    const k = (c.origin && c.origin.module) || c.componentRoot || '?';
    a[k] = (a[k] || 0) + 1;
    return a;
  }, {});
  const signatureProblems = {
    implFileNull: candidates.filter((c) => !c.origin || !c.origin.implFile).length,
    pathScopedFalse: candidates.filter((c) => !(c.signal && c.signal.pathScoped)).length,
    checkSitesOnImplPathZero: candidates.filter((c) => !(c.signal && c.signal.checkSitesOnImplPath)).length,
    moduleChecksPositive: candidates.filter((c) => (c.signal && c.signal.checkSitesInModule) > 0).length
  };

  const summary = {
    generatedAt: new Date().toISOString(),
    scope: 'R1',
    candidates: {
      total: candidates.length,
      singleEntry: candidates.filter((c) => (c.entryIds || []).length === 1).length,
      multiEntry: candidates.filter((c) => (c.entryIds || []).length > 1).length,
      byModule: modules
    },
    units: unitResult.summary,
    pairing: pairing.summary,
    checks: checks.summary,
    paths: paths.summary,
    candidateSignals: signatureProblems,
    localFixtures: localFixtures(l1),
    outputs: {
      units: 'out/p5/method-units.jsonl',
      pairing: 'out/p5/pairing.jsonl',
      checks: 'out/p5/check-sites.jsonl'
    }
  };
  writeJson(path.join(OUT_ROOT, 'p5', 'data-audit.json'), summary);
  process.stdout.write(`P5 audit: candidates=${candidates.length} r1=${unitResult.summary.r1Aggregates} units=${unitResult.summary.units} service=${unitResult.summary.serviceUnits} callback=${unitResult.summary.callbackUnits} unknown=${unitResult.summary.unknownUnits}\n`);
  process.stdout.write(`pairing: service=${pairing.summary.service} resolved=${pairing.summary.serviceResolved} (${pairing.summary.serviceResolvedRate}) gap=${pairing.summary.serviceGap} overload=${pairing.summary.overload}\n`);
  process.stdout.write(`checks: total=${checks.summary.total} checks=${checks.summary.checks} identity=${checks.summary.identitySources} bySide=${JSON.stringify(checks.summary.bySide)}\n`);
  process.stdout.write(`paths: service=${paths.summary.service} pathScoped=${paths.summary.pathScoped} (${paths.summary.pathScopedRate}) noCheck=${paths.summary.noCheckOnPath} truncated=${paths.summary.truncated} clientOnly=${paths.summary.withClientOnlyCheck}\n`);
  process.stdout.write(`fixtures: CWE-862=${summary.localFixtures.cwe862} (R1 ${summary.localFixtures.cwe862InR1}), P5 invariants=${summary.localFixtures.p5Invariants}\n`);
}

if (require.main === module) {
  try { main(); } catch (e) { process.stderr.write(`${e && e.stack ? e.stack : e}\n`); process.exit(1); }
}

module.exports = { main, localFixtures };
