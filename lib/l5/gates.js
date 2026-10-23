'use strict';

/**
 * lib/l5/gates.js —— L5 硬门汇总（写 out/l5/summary.json）。
 */

const fs = require('fs');
const path = require('path');
const { OUT_ROOT, ensureDir, writeJson } = require('../util.js');

function readJson(rel, fallback = null) {
  try { return JSON.parse(fs.readFileSync(path.join(OUT_ROOT, 'l5', rel), 'utf8')); } catch (_) { return fallback; }
}

function readJsonl(rel) {
  try {
    return fs.readFileSync(path.join(OUT_ROOT, 'l5', rel), 'utf8').split(/\r?\n/).filter(Boolean).map((l) => JSON.parse(l));
  } catch (_) { return []; }
}

function buildL5Summary() {
  const env = readJson('environment.json', {});
  const fixtures = readJson('fixtures-summary.json', {});
  const select = readJson('select-summary.json', {});
  const targets = readJson('targets-summary.json', {});
  const promotion = readJson('promotion-summary.json', {});
  const targetRows = readJsonl('targets.jsonl');
  const fixtureRows = readJsonl('fixtures.jsonl');
  const unsupported = readJsonl('unsupported.jsonl');
  const oracle = readJsonl('oracle.jsonl');
  const positive = fixtureRows.filter((r) => r.class !== 'NEG' && r.result === 'confirmed').length;
  const negative = fixtureRows.filter((r) => r.class === 'NEG' && r.result === 'no-signal').length;
  const targetExecuted = targetRows.filter((r) => r.result === 'confirmed' || r.result === 'no-signal').length;
  const ledgerBad = [...fixtureRows, ...targetRows].filter((r) => !r.runId || !r.candidateId || !r.result || !r.buildCommand || !r.sourceHash || !r.repeat);
  const repeatBad = fixtureRows.concat(targetRows).filter((r) => r.result === 'confirmed' && (!Array.isArray(r.repeats) || r.repeats.some((x) => x.result !== 'confirmed')));
  const unsupportedClasses = new Set(unsupported.map((u) => u.class));
  const l5Classes = new Set(['P1', 'P2', 'P3', 'P4', 'P7']);
  const p6Eligible = (select.byClassAll && select.byClassAll.P6) || 0;
  const scopeOk = p6Eligible === 0 || unsupportedClasses.has('P6');
  const t1 = promotion.t1 || 0;
  const promotionOk = t1 === 0 || (promotion.rows || []).every((r) => !r.promotionEligible || r.result === 'confirmed');
  const gates = [
    { name: 'L5-1 environment', pass: Boolean(env.asan || env.ubsan), detail: `compiler=${env.compiler || 'n/a'} asan=${env.asan} ubsan=${env.ubsan}` },
    { name: 'L5-2 fixtures', pass: positive >= 3 && negative >= 2 && fixtures.allExpected === true, detail: `positive=${positive} negative=${negative} allExpected=${fixtures.allExpected}` },
    { name: 'L5-3 target probe', pass: targetRows.length > 0 && targetExecuted > 0, detail: `targets=${targetRows.length} executed=${targetExecuted}` },
    { name: 'L5-4 ledger', pass: ledgerBad.length === 0, detail: `bad=${ledgerBad.length}` },
    { name: 'L5-5 classifier/repeat', pass: repeatBad.length === 0, detail: `repeatBad=${repeatBad.length}` },
    { name: 'L5-6 O10/promotion', pass: promotionOk && oracle.length === targetRows.length, detail: `t1=${t1} oracle=${oracle.length}/${targetRows.length}` },
    { name: 'L5-7 scope', pass: scopeOk && unsupportedClasses.has('P5') && unsupportedClasses.has('P8'), detail: `p6Eligible=${p6Eligible} unsupportedClasses=${[...unsupportedClasses].join(',')}` },
    { name: 'L5-8 report', pass: fs.existsSync(path.join(OUT_ROOT, 'report', 'l5.md')), detail: 'out/report/l5.md' }
  ];
  const summary = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    environment: env,
    fixtures: { total: fixtures.total || 0, confirmed: fixtures.confirmed || 0, noSignal: fixtures.noSignal || 0, blocked: fixtures.blocked || 0, positive, negative, allExpected: fixtures.allExpected === true },
    selection: select,
    targets: { total: targetRows.length, confirmed: targets.confirmed || 0, noSignal: targets.noSignal || 0, blocked: targets.blocked || 0 },
    promotion: { total: promotion.total || 0, promoted: promotion.promoted || 0, t1 },
    gates,
    allGatesPass: gates.every((g) => g.pass)
  };
  ensureDir(path.join(OUT_ROOT, 'l5'));
  writeJson(path.join(OUT_ROOT, 'l5', 'summary.json'), summary);
  return summary;
}

module.exports = { buildL5Summary };
