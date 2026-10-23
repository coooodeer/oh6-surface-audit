'use strict';

/**
 * p1p2p7p8-audit.js —— P1/P2/P7/P8 Round 1 数据审计（不写 verdict）。
 *
 * 产物：
 *   out/p1p2p7p8/data-audit.json
 *   out/p1p2p7p8/p1-candidates.jsonl
 *   out/p1p2p7p8/p2-candidates.jsonl
 */

const fs = require('fs');
const path = require('path');
const {
  OUT_ROOT, TOOL_ROOT, ensureDir, readJsonl, writeJson, writeJsonl
} = require('../lib/util');
const { D4_ROOTS, isD4, provenanceOf } = require('../lib/p1p2p7p8/common');
const { buildP1Facts } = require('../lib/p1p2p7p8/facts-p1');
const { buildP2Facts } = require('../lib/p1p2p7p8/facts-p2');
const { buildP7Facts } = require('../lib/p1p2p7p8/facts-p7');
const { buildP8Facts } = require('../lib/p1p2p7p8/facts-p8');
const { loadHistoryRows, isProductPath } = require('../lib/p1p2p7p8/history');
const { validateAll } = require('../eval/external-cve/p7-cases.js');

const AGENT = path.join(TOOL_ROOT);
const OUT = path.join(OUT_ROOT, 'p1p2p7p8');

function completeness(units, fields) {
  const out = { total: units.length, missing: {} };
  for (const f of fields) {
    const missing = units.filter((u) => {
      const parts = f.split('.');
      let v = u;
      for (const p of parts) v = v == null ? null : v[p];
      return v == null;
    }).length;
    out.missing[f] = missing;
  }
  return out;
}

function candidateOriginSelfCheck() {
  const checks = [];
  const external = provenanceOf({ origin: 'external-cve', inTarget: false, production: false });
  checks.push({ name: 'external-never-production', pass: external.productionEligible === false });
  const fixed = provenanceOf({ origin: 'historical-positive', inTarget: true, codeState: 'fixed' });
  checks.push({ name: 'fixed-never-production', pass: fixed.productionEligible === false });
  const snapshot = provenanceOf({ origin: 'target', inTarget: true, codeState: 'snapshot-only' });
  checks.push({ name: 'snapshot-never-production', pass: snapshot.productionEligible === false });
  const miner = provenanceOf({ origin: 'miner-existing', inTarget: true, codeState: 'current-head' });
  checks.push({ name: 'miner-current-head-production', pass: miner.productionEligible === true && miner.novelty === 'known-reproduced' });
  const target = provenanceOf({ origin: 'target', inTarget: true, codeState: 'current-head' });
  checks.push({ name: 'target-current-head-production', pass: target.productionEligible === true && target.novelty === 'new' });
  const fixture = provenanceOf({ origin: 'oracle-fixture', inTarget: true, codeState: 'current-head', constructed: true });
  checks.push({ name: 'oracle-fixture-never-production', pass: fixture.productionEligible === false });
  return { checks, pass: checks.every((c) => c.pass) };
}

function localHistoryAudit() {
  const bounds = loadHistoryRows({ family: 'bounds-check-added', cls: 'P1' });
  const lifetime = loadHistoryRows({ family: 'lifetime-guard-added', cls: 'P2' });
  const state = loadHistoryRows({ family: 'state-guard-added', cls: 'P8' });
  const product = (rows) => rows.filter((r) => isProductPath(r.file));
  const test = (rows) => rows.filter((r) => !isProductPath(r.file));
  return {
    bounds: { total: bounds.length, product: product(bounds).length, testOrFuzz: test(bounds).length, productIds: product(bounds).map((r) => r.id), testIds: test(bounds).map((r) => r.id) },
    lifetime: { total: lifetime.length, product: product(lifetime).length, testOrFuzz: test(lifetime).length, repos: [...new Set(product(lifetime).map((r) => r.repo))] },
    state: { total: state.length, product: product(state).length, testOrFuzz: test(state).length, productIds: product(state).map((r) => r.id) },
    note: 'test/fuzz 路径不作为产品 fixture；本地样本只作 fixture/校准，不进入生产 O10；不计入 D4'
  };
}

function fixtureStubs(cls, caseModule) {
  const groups = [];
  for (const key of ['synthetic', 'historyLocal', 'historyPositive']) {
    if (Array.isArray(caseModule[key])) groups.push(...caseModule[key]);
  }
  return groups.map((c) => {
    const unit = {
      candidateId: c.id,
      class: cls,
      fixture: true,
      origin: 'oracle-fixture',
      inTarget: false,
      codeState: null,
      constructed: true,
      componentRoot: 'eval/p1p2p7p8',
      unitId: `FIX-${c.id}`,
      source: { kind: 'fixture', file: `eval/p1p2p7p8/${cls.toLowerCase()}`, line: 0 },
      sink: { kind: 'fixture-sink', line: 0 },
      entry: { id: null, kind: null, repo: 'eval/p1p2p7p8', file: null, line: null, bindingScope: 'fixture' },
      analysis: { bounded: null, fixture: true },
      evidenceRefs: [`eval/p1p2p7p8/${cls.toLowerCase()}/${c.id}`]
    };
    unit.provenance = provenanceOf(unit);
    return unit;
  });
}

function runAudit(opts = {}) {
  ensureDir(OUT);
  const candidates = opts.candidates || readJsonl(path.join(AGENT, 'result', 'latest', 'candidates.jsonl'));
  const p1 = buildP1Facts({ candidates });
  const p2 = buildP2Facts({ candidates });
  const p7 = buildP7Facts({ candidates });
  const p8 = buildP8Facts({ candidates });
  const p1Fixtures = fixtureStubs('P1', require('../eval/p1p2p7p8/p1/cases.js'));
  const p2Fixtures = fixtureStubs('P2', require('../eval/p1p2p7p8/p2/cases.js'));
  writeJsonl(path.join(OUT, 'p1-candidates.jsonl'), [...p1.units, ...p1Fixtures]);
  writeJsonl(path.join(OUT, 'p2-candidates.jsonl'), [...p2.units, ...p2Fixtures]);
  const counts = { P1: 0, P2: 0, P7: 0, P8: 0 };
  const roots = {};
  for (const cls of ['P1', 'P2', 'P7', 'P8']) {
    for (const c of candidates) {
      if (c.patternClass !== cls) continue;
      if (!isD4(c.componentRoot)) continue;
      counts[cls] += 1;
      if (!roots[c.componentRoot]) roots[c.componentRoot] = { P1: 0, P2: 0, P7: 0, P8: 0, total: 0 };
      roots[c.componentRoot][cls] += 1;
      roots[c.componentRoot].total += 1;
    }
  }
  const audit = {
    generatedAt: new Date().toISOString(),
    scope: { name: 'D4', roots: D4_ROOTS },
    candidateCounts: counts,
    baseline: { P1: 1, P2: 1, P7: 660, P8: 821 },
    baselineMatches: counts.P1 === 1 && counts.P2 === 1 && counts.P7 === 660 && counts.P8 === 821,
    d4Distribution: roots,
    facts: {
      P1: p1.summary,
      P2: p2.summary,
      P7: p7.summary,
      P8: p8.summary
    },
    fieldCompleteness: {
      P1: completeness(p1.units, ['origin.api', 'origin.var', 'signal.useSink', 'signal.boundCheckInWindow', 'sink.kind', 'boundCheck.covering', 'entry.id']),
      P1SignalOriginal: {
        total: p1.units.filter((u) => u.originCandidate).length,
        boundCheckInWindow: p1.units.filter((u) => u.originCandidate && u.originCandidate.signal && u.originCandidate.signal.boundCheckInWindow != null).length,
        useSink: p1.units.filter((u) => u.originCandidate && u.originCandidate.signal && u.originCandidate.signal.useSink != null).length
      },
      P2: completeness(p2.units, ['signal.asyncKind', 'signal.captured', 'signal.lifecycleEvidence', 'lifetime.classification', 'entry.id']),
      P7: completeness(p7.units, ['signal.dosClass', 'signal.dosGate', 'dosClass', 'structure.boundedInWindow', 'criteria.raw', 'amplification.basis', 'entry.id']),
      P8: completeness(p8.units, ['signal.invariantPattern', 'signal.checksInFunction', 'invariant.pattern', 'source.text', 'sink.kind', 'analysis.guardStatus', 'entry.id'])
    },
    localHistory: localHistoryAudit(),
    externalCve: { ...validateAll(), production: false, note: '只作义务/裁决校准；不映射 target，不写 inTarget/codeState，不进入 D4' },
    candidateOrigin: candidateOriginSelfCheck(),
    outputs: {
      p1Candidates: 'out/p1p2p7p8/p1-candidates.jsonl',
      p2Candidates: 'out/p1p2p7p8/p2-candidates.jsonl',
      dataAudit: 'out/p1p2p7p8/data-audit.json'
    }
  };
  writeJson(path.join(OUT, 'data-audit.json'), audit);
  process.stdout.write(`P1P2P7P8 audit: D4 P1=${counts.P1} P2=${counts.P2} P7=${counts.P7} P8=${counts.P8} baseline=${audit.baselineMatches}\n`);
  process.stdout.write(`  facts P1=${p1.summary.realD4Candidates} P2=${p2.summary.realD4Candidates} P7=${p7.summary.realD4Candidates} P8=${p8.summary.realD4Candidates}\n`);
  process.stdout.write(`  local history bounds=${audit.localHistory.bounds.total}/${audit.localHistory.bounds.product} lifetime=${audit.localHistory.lifetime.total}/${audit.localHistory.lifetime.product} state=${audit.localHistory.state.total}/${audit.localHistory.state.product}\n`);
  return { candidates, p1, p2, p7, p8, audit };
}

if (require.main === module) {
  try { runAudit(); } catch (e) { process.stderr.write(`${e && e.stack ? e.stack : e}\n`); process.exit(1); }
}

module.exports = { runAudit, completeness, candidateOriginSelfCheck, localHistoryAudit };
