'use strict';

/**
 * run-p1p2p7p8.js —— P1/P2/P7/P8 端到端 runner。
 *
 * audit -> facts -> fixtures -> claims -> verdicts -> summary -> calibration -> gates -> report
 * 不实现 L5；O10 固定 unproven；T1 固定 0。
 */

const fs = require('fs');
const path = require('path');
const {
  OUT_ROOT, ensureDir, readJsonl, writeJson, writeJsonl
} = require('../lib/util');
const { D4_ROOTS, isD4, provenanceOf } = require('../lib/p1p2p7p8/common');
const { runAudit } = require('./p1p2p7p8-audit');
const { runAllFixtures } = require('../lib/p1p2p7p8/fixtures');
const { selectP7Claims } = require('../lib/p1p2p7p8/facts-p7');
const { selectP8Claims } = require('../lib/p1p2p7p8/facts-p8');
const {
  buildP1Claims, buildP2Claims, buildP7Claims, buildP8Claims
} = require('../lib/p1p2p7p8/claims');
const { buildVerdicts, buildSummary, writeOutputs, countTiers } = require('../lib/p1p2p7p8/stats');
const { runCalibration, writeCalibration } = require('../lib/p1p2p7p8/calibration');
const { validateAll } = require('../eval/external-cve/p7-cases.js');
const { runGates } = require('../lib/agent/registry');

const OUT = path.join(OUT_ROOT, 'p1p2p7p8');
const REPORT = path.join(OUT_ROOT, 'report');

function readJsonSafe(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (_) { return null; }
}

function checkUtf8(files) {
  const bad = [];
  for (const f of files) {
    if (!fs.existsSync(f)) { bad.push({ file: f, reason: 'missing' }); continue; }
    const buf = fs.readFileSync(f);
    if (buf.length >= 3 && buf[0] === 0xEF && buf[1] === 0xBB && buf[2] === 0xBF) bad.push({ file: f, reason: 'bom' });
    const text = buf.toString('utf8');
    if (text.includes('\uFFFD')) bad.push({ file: f, reason: 'u+fffd' });
  }
  return { pass: bad.length === 0, bad };
}

function checkNoHumanPending(files) {
  const bad = [];
  for (const f of files) {
    if (!fs.existsSync(f)) continue;
    const text = fs.readFileSync(f, 'utf8');
    if (/needs-human|"pending"|: pending/i.test(text)) bad.push(f);
  }
  return { pass: bad.length === 0, bad };
}

function gate(key, pass, detail) {
  return { key, pass: Boolean(pass), detail };
}

function run() {
  ensureDir(OUT); ensureDir(REPORT);
  const auditResult = runAudit();
  const { candidates, p1, p2, p7, p8, audit } = auditResult;
  const fixtures = runAllFixtures();
  const selectedP7 = selectP7Claims(p7.units, 6);
  const selectedP8 = selectP8Claims(p8.units, 8);
  const claims = [
    ...buildP1Claims(p1, fixtures.classes.P1),
    ...buildP2Claims(p2, fixtures.classes.P2),
    ...buildP7Claims(p7, selectedP7, fixtures.classes.P7),
    ...buildP8Claims(p8, selectedP8)
  ];
  const verdicts = buildVerdicts(claims);
  const externalValidation = validateAll();
  const summary = buildSummary({ candidates, facts: { P1: p1, P2: p2, P7: p7, P8: p8 }, fixtures, claims, verdicts, selectedP7, selectedP8, externalValidation });
  const calibration = runCalibration(claims);
  writeOutputs({ facts: { P1: p1, P2: p2, P7: p7, P8: p8 }, claims, verdicts, summary });
  writeCalibration(calibration);

  const claimsByClass = (cls) => claims.filter((c) => c.class === cls);
  const verdictsByClass = (cls) => verdicts.filter((v) => v.class === cls);
  const p1Claims = claimsByClass('P1');
  const p2Claims = claimsByClass('P2');
  const p7Claims = claimsByClass('P7');
  const p8Claims = claimsByClass('P8');
  const p7Tiers = countTiers(verdictsByClass('P7'));
  const p8Tiers = countTiers(verdictsByClass('P8'));
  const p7Real = p7Claims.filter((c) => !c.fixture);
  const p7Amp = p7Real.filter((c) => {
    const u = p7.units.find((x) => x.unitId === c.unitId);
    return u && u.dosClass === 'amplification';
  });
  const p7AmpFixture = p7Claims.filter((c) => c.fixture && c.source && c.source.kind === 'fixture');
  const p8Patterns = new Set(p8Claims.filter((c) => !c.fixture).map((c) => {
    const u = p8.units.find((x) => x.unitId === c.unitId);
    return u && u.invariant.pattern;
  }).filter(Boolean));

  const reportFile = path.join(REPORT, 'p1p2p7p8-implementation.md');
  const reportText = fs.existsSync(reportFile) ? fs.readFileSync(reportFile, 'utf8') : '';
  const requiredReportPhrases = [
    'T1=0', 'L5', 'P7', 'P8', 'fixture', 'static-proxy', 'invariant', 'D4',
    '本目标', '不是漏报', 'recall', 'PROVEN-VULN'
  ];
  const reportMissing = requiredReportPhrases.filter((p) => !reportText.includes(p));

  const p1Fixture = fixtures.classes.P1;
  const p2Fixture = fixtures.classes.P2;
  const p7Fixture = fixtures.classes.P7;
  const p8Fixture = fixtures.classes.P8;
  const p1Seed = p1Claims.some((c) => c.candidateId === 'cd_G-P1_4ec01349f150');
  const p2Seed = p2Claims.some((c) => c.candidateId === 'cd_G-P2_623da2b57413');
  const p1Total = p1Claims.length;
  const p2Total = p2Claims.length;
  const p1LocalProduct = p1Fixture.historyLocal.summary.validated;
  const p2Local = p2Fixture.historyLocal.summary.validated;
  const p2Repos = p2Local > 0 ? (p2Fixture.summary.localRepos || []) : [];
  const noPv = claims.every((c) => c.productVerdict !== 'PROVEN-VULN' && c.tier !== 'T1-confirmed');
  const t1Zero = claims.every((c) => c.t1Eligible === false);

  const outputFiles = [
    path.join(OUT, 'data-audit.json'),
    path.join(OUT, 'p1-candidates.jsonl'),
    path.join(OUT, 'p2-candidates.jsonl'),
    path.join(OUT, 'claims.jsonl'),
    path.join(OUT, 'verdicts.jsonl'),
    path.join(OUT, 'summary.json'),
    path.join(REPORT, 'p1p2p7p8-implementation.md'),
    path.join(REPORT, 'P1P2P7P8-CALIBRATION-LOG.jsonl')
  ];
  const utf8 = checkUtf8(outputFiles);
  const human = checkNoHumanPending([path.join(OUT, 'claims.jsonl'), path.join(OUT, 'verdicts.jsonl')]);

  const regressionRun = readJsonSafe(path.join(REPORT, 'run-summary.json'));
  const regressionP5 = readJsonSafe(path.join(REPORT, 'p5-run-summary.json'));
  const p5Summary = readJsonSafe(path.join(OUT_ROOT, 'verdicts', 'p5-summary.json'));
  const regression = {
    p3p4p6: Boolean(regressionRun && regressionRun.allGatesPass === true),
    p5: Boolean(regressionP5 && regressionP5.allGatesPass === true && Array.isArray(regressionP5.gates) && regressionP5.gates.length === 13),
    p5T1Zero: Boolean(p5Summary && p5Summary.headline && p5Summary.headline.newConfirmed === 0)
  };

  const testReport = path.join(REPORT, 'p1p2p7p8-node-test.txt');
  const nodeTestPass = fs.existsSync(testReport)
    ? /fail 0\b/.test(fs.readFileSync(testReport, 'utf8')) && !/not ok/i.test(fs.readFileSync(testReport, 'utf8'))
    : false;

  const codeArtifacts = fs.existsSync(path.join(__dirname, '..', 'lib', 'p1p2p7p8', 'common.js'))
    && fs.existsSync(path.join(__dirname, 'p1p2p7p8-audit.js'))
    && fs.existsSync(path.join(__dirname, 'run-p1p2p7p8.js'));
  const gates = runGates('p1p2p7p8', {
    audit, d4Roots: D4_ROOTS, utf8, codeArtifacts,
    p1, p2, p7, p8, fixtures, verdicts, summary, calibration,
    p1Fixture, p2Fixture, p7Fixture, p8Fixture,
    p1Claims, p2Claims, p7Claims, p8Claims, claims,
    p1Seed, p2Seed, p1Total, p2Total, p1LocalProduct, p2Local, p2Repos,
    p7Tiers, p8Tiers, p7Amp, p7AmpFixture, p8Patterns,
    noPv, t1Zero, regression, reportMissing, human, isD4
  });
  const allGatesPass = gates.every((g) => g.pass);
  const runSummary = {
    generatedAt: new Date().toISOString(),
    allGatesPass,
    gates,
    nodeTestReport: { file: 'out/report/p1p2p7p8-node-test.txt', exists: fs.existsSync(testReport), pass: nodeTestPass },
    counts: {
      P1: { real: p1.summary.realD4Candidates, claims: p1Claims.length },
      P2: { real: p2.summary.realD4Candidates, claims: p2Claims.length },
      P7: { real: p7.summary.realD4Candidates, claims: p7Claims.length, tiers: p7Tiers },
      P8: { real: p8.summary.realD4Candidates, claims: p8Claims.length, tiers: p8Tiers }
    },
    calibration: { rounds: calibration.rounds.length, samples: calibration.totalSampled, passed: calibration.passed, falsePV: calibration.falseProvenVuln, boundary: calibration.boundaryCovered },
    fixtures: {
      P1: p1Fixture.summary.gate, P2: p2Fixture.summary.gate,
      P7: p7Fixture.summary.gate, P8: p8Fixture.summary.gate
    },
    outputs: outputFiles.map((f) => path.relative(path.join(__dirname, '..'), f).split(path.sep).join('/'))
  };
  writeJson(path.join(REPORT, 'p1p2p7p8-run-summary.json'), runSummary);
  const md = [];
  md.push('# P1/P2/P7/P8 验收门');
  md.push('');
  md.push(`allGatesPass：**${allGatesPass}**`);
  md.push('');
  md.push('| 门 | 结果 | 说明 |');
  md.push('| --- | --- | --- |');
  for (const g of gates) md.push(`| ${g.name} | ${g.pass ? 'PASS' : 'FAIL'} | ${typeof g.detail === 'string' ? g.detail : JSON.stringify(g.detail).slice(0, 300)} |`);
  md.push('');
  fs.writeFileSync(path.join(REPORT, 'p1p2p7p8-gates.md'), md.join('\n'), 'utf8');
  process.stdout.write(`P1P2P7P8 run: claims=${claims.length} verdicts=${verdicts.length} gates=${gates.filter((g) => g.pass).length}/${gates.length} all=${allGatesPass}\n`);
  for (const g of gates.filter((x) => !x.pass)) process.stdout.write(`  FAIL ${g.name}: ${JSON.stringify(g.detail).slice(0, 500)}\n`);
  return { claims, verdicts, summary, calibration, gates, runSummary };
}

if (require.main === module) {
  try { run(); } catch (e) { process.stderr.write(`${e && e.stack ? e.stack : e}\n`); process.exit(1); }
}

module.exports = { run, checkUtf8, checkNoHumanPending };
